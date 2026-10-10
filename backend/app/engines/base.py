"""引擎适配器接口。

这是整个产品的关键抽象：无论引擎是在本机跑子进程（Defender / ClamAV）、
在进程内跑（YARA）、在隔离 VM 里跑（ESET / Kaspersky）、还是走哈希查询，
对上层都只暴露 `available()` 和 `scan()` 两个方法。
"""

from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Verdict(str, Enum):
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    PUP = "pup"  # 潜在不受欢迎程序
    UNKNOWN = "unknown"
    ERROR = "error"
    SKIPPED = "skipped"

    @property
    def is_detection(self) -> bool:
        return self in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.PUP)


class EngineKind(str, Enum):
    SIGNATURE = "signature"  # 传统签名引擎
    RULE = "rule"  # YARA 等规则引擎
    EMULATION = "emulation"  # 模拟执行
    SANDBOX = "sandbox"  # 真实沙箱
    LOOKUP = "lookup"  # 哈希/信誉查询
    CAPABILITY = "capability"  # 能力识别（CAPA）——不看签名，看代码能干什么
    ANALYSIS = "analysis"  # 结构/加壳分析（DIE、Manalyze）


# --------------------------------------------------------------------------
# 网络行为等级
#
# "不外传"不是一个开关，实测下来至少有三个不同强度的事实状态。
# 把它们混成一个布尔值会导致要么过度保守（能用的引擎被禁），
# 要么过度宽松（把"仅元数据外传"说成"完全本地"）。
# --------------------------------------------------------------------------

#: 可证明不产生任何外部网络行为
NETWORK_LOCAL = "local"
#: 不外传样本内容，但会外传哈希/文件名等元数据
NETWORK_METADATA = "metadata"
#: 可能外传样本内容本身
NETWORK_SAMPLE = "sample"

NETWORK_LEVELS = (NETWORK_LOCAL, NETWORK_METADATA, NETWORK_SAMPLE)

NETWORK_LEVEL_TEXT = {
    NETWORK_LOCAL: "完全本地",
    NETWORK_METADATA: "仅元数据",
    NETWORK_SAMPLE: "可能外传样本",
}

#: 策略名 -> 该策略允许的等级集合
POLICY_ALLOWED: dict[str, tuple[str, ...]] = {
    # 只允许可证明不产生任何外部网络行为的引擎
    "local": (NETWORK_LOCAL,),
    # 允许不外传样本内容的引擎（默认）——对应"样本不上传云端"的要求
    "no-sample": (NETWORK_LOCAL, NETWORK_METADATA),
    # 不限制
    "any": NETWORK_LEVELS,
}

POLICY_TEXT = {
    "local": "仅限完全本地引擎",
    "no-sample": "允许不外传样本内容的引擎",
    "any": "不限制引擎网络行为",
}


@dataclass
class ScanContext:
    """一次扫描中传给每个引擎的上下文。"""

    sample_path: Path
    sha256: str
    md5: str
    size: int
    timeout_s: int


@dataclass
class EngineResult:
    engine: str
    verdict: Verdict
    signature: str | None = None
    detail: str = ""
    raw_output: str = ""
    duration_ms: int = 0
    error: str | None = None
    meta: dict = field(default_factory=dict)

    #: 由 timed_scan 从适配器的 source_group 填进来，供聚合判定按来源去重。
    source_group: str | None = None

    def to_dict(self) -> dict:
        return {
            "engine": self.engine,
            "verdict": self.verdict.value,
            "signature": self.signature,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "meta": self.meta,
        }


class EngineAdapter(ABC):
    """所有引擎的基类。"""

    name: str = "engine"
    kind: EngineKind = EngineKind.SIGNATURE

    #: 该引擎是否**可证明**不产生任何外部网络行为。
    #:
    #: 这是安全契约而非描述性标签：声明 True 意味着"我能保证不走网络"，
    #: 而不是"我希望它不走网络"。凡是无法证明的，必须声明 False。
    #: 数值上等价于 network_level() == NETWORK_LOCAL。
    offline: bool = True

    #: 资源占用等级，决定调度方式。
    #:
    #:   "light" — 快且省内存，可以和其他引擎**并发**跑
    #:   "heavy" — 单次占用上百 MB 内存，必须**串行**跑，一次只放一个
    #:
    #: 实测数据（cmd.exe，单核 6 GB 机器，clamd 未运行）：
    #:     ClamAV    1126 MB      CAPA      404 MB      Emsisoft   120 MB
    #:     DIE         37 MB      Manalyze    8 MB      Defender/YARA  0 MB
    #: ClamAV 那一项是重启后 clamd 没起来、clamscan 把签名库整个解开导致的；
    #: clamd 常驻时它是轻量的（实测 ~1 秒、几乎不额外占内存）。
    #: 分级依据是**内存**而非耗时——在这类弱机器上，把系统推进换页的元凶
    #: 是内存，不是 CPU 时间。
    resource_class: str = "light"

    #: 同源引擎分组。
    #:
    #: 跑同一批规则的引擎归为一组（YARA 和 YARA-X 就是），聚合判定时只算
    #: 一票。不分组的话，同一份规则命中一次会被数成两个引擎各命中一次，
    #: 检测比例从 "1/8" 变成 "2/9"——那是同一个证据被算了两次，虚高。
    source_group: str | None = None

    def network_level(self) -> str:
        """引擎实际的网络行为等级，见 NETWORK_LEVELS。

        默认由 offline 推导；像 Defender 这种行为取决于系统设置的引擎，
        应重写本方法做运行时查证。
        """
        return NETWORK_LOCAL if self.offline else NETWORK_SAMPLE

    @abstractmethod
    def available(self) -> bool:
        """引擎当前是否可用（已安装、守护进程在跑、规则已加载等）。"""

    @abstractmethod
    def scan(self, ctx: ScanContext) -> EngineResult:
        """执行扫描。实现方只负责返回结果，不要抛异常。"""

    @abstractmethod
    def unavailable_reason(self) -> str:
        """返回人类可读的不可用原因，用于在 UI 上提示用户。"""

    def network_note(self) -> str:
        """对网络行为的补充说明，用于向用户如实交代。"""
        return ""

    def load_note(self) -> str:
        """已加载资源的状态说明（规则数、跳过了多少等）。

        只有 YARA 这类"加载外部规则"的引擎需要。默认不产生说明。
        """
        return ""

    def timed_scan(self, ctx: ScanContext) -> EngineResult:
        """包一层计时与异常兜底，保证单个引擎崩溃不会拖垮整轮扫描。"""
        start = time.perf_counter()
        try:
            result = self.scan(ctx)
        except subprocess.TimeoutExpired:
            result = EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                error=f"扫描超时（>{ctx.timeout_s}s）",
            )
        except Exception as exc:  # noqa: BLE001 - 兜底，引擎故障不应中断扫描
            result = EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                error=f"{type(exc).__name__}: {exc}",
            )
        result.duration_ms = int((time.perf_counter() - start) * 1000)
        # 统一在这里填，免得每条构造路径都要记得写一遍
        result.source_group = self.source_group
        return result


# --------------------------------------------------------------------------
# 子进程引擎的共用工具
# --------------------------------------------------------------------------


def which(*candidates: str) -> str | None:
    """在 PATH 中查找第一个存在的可执行文件。"""
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def run_process(
    args: list[str],
    timeout_s: int,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """以不弹窗、不交互的方式运行子进程。"""
    return subprocess.run(  # noqa: S603 - 参数由各适配器静态构造
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_s,
        cwd=cwd,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
