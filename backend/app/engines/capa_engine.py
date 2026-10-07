"""CAPA 适配器（能力识别）。

CAPA 回答的是和签名引擎**完全不同**的问题。签名引擎问"这个文件
像不像已知的坏东西"，CAPA 问"**这段代码能干什么**"——它会识别出
"创建远程线程""读取键盘状态""枚举卷影副本""用 XOR 编码数据"
这类能力，并映射到 MITRE ATT&CK。

为什么这很重要：签到引擎对没见过的样本集体失明，但一个能注入进程、
能加密文件、能反弹连接的样本，无论签名库里有没有它，**能力都藏不住**。

实现说明：
  用 pip 版 ``flare-capa`` 而不是官方 Windows 发布包。官方包是
  PyInstaller 打包的，在这台机器上分析时死锁（1.4s CPU 卡 90s）。
  pip 版走普通 Python 解释器，无此问题。

  另外它需要显式指定规则集和 FLIRT 签名，官方发布包是把它们内嵌的。

完全本地，无网络行为。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..config import settings
from .base import (
    EngineAdapter,
    EngineKind,
    EngineResult,
    ScanContext,
    Verdict,
    run_process,
)

#: 命中即值得警惕的能力命名空间前缀。
#: 刻意不含 communication/http 这类"正常程序也有"的通用能力——
#: 误报会让人不再看结果，那比漏报更糟。
_NOTABLE_PREFIXES = (
    "anti-analysis",                      # 反调试/反虚拟机/反沙箱
    "host-interaction/process/inject",    # 进程注入
    "host-interaction/process/create",    # 创建进程（配合其它能力才有意义）
    "data-manipulation/encryption",       # 加密——勒索的核心动作
    "persistence",                        # 持久化
    "load-code",                          # 运行时加载/解密代码
    "host-interaction/registry",          # 注册表改写
    "impact",                             # 破坏性行为
    "collection",                         # 收集数据
    "credential",                         # 凭据访问
)


def _capa_rules_dir() -> Path | None:
    root = settings.base_dir / "tools" / "capa-rules"
    if not root.is_dir():
        return None
    # 解压后通常多一层 capa-rules-master/
    for candidate in [root, *[p for p in root.iterdir() if p.is_dir()]]:
        if any(candidate.glob("**/*.yml")):
            return candidate
    return None


def _capa_sigs_dir() -> Path:
    return settings.base_dir / "tools" / "capa-sigs"


def _is_capa_installed() -> bool:
    try:
        import capa.main  # noqa: F401
    except ImportError:
        return False
    return True


class CapaEngine(EngineAdapter):
    name = "CAPA"
    kind = EngineKind.CAPABILITY
    offline = True  # 纯本地静态分析
    # CAPA 是 Python + vivisect，实测峰值增量 404 MB，必须串行
    resource_class = "heavy"

    def __init__(self) -> None:
        self._rules = _capa_rules_dir()
        self._sigs = _capa_sigs_dir()
        self._installed = _is_capa_installed()

    def available(self) -> bool:
        return self._installed and self._rules is not None

    def unavailable_reason(self) -> str:
        if not self._installed:
            return "未安装 flare-capa。请运行 `python -m app.cli setup-tools`"
        if self._rules is None:
            return "未找到 CAPA 规则集。请运行 `python -m app.cli setup-tools`"
        return "不可用"

    def scan(self, ctx: ScanContext) -> EngineResult:
        assert self._rules is not None
        self._sigs.mkdir(parents=True, exist_ok=True)

        # 用自己的解释器跑模块，绕开官方 PyInstaller 包的死锁
        args = [
            sys.executable,
            "-m",
            "capa.main",
            "-q",                      # 只输出结果，不要进度噪音
            "-r",
            str(self._rules),
            "-s",
            str(self._sigs),
            "-j",
            str(ctx.sample_path),
        ]

        proc = run_process(
            args,
            # CAPA 很慢（实测 70s+），给它独立的上限而不是跟随全局超时
            timeout_s=max(180, min(ctx.timeout_s, 600)),
        )

        stdout = proc.stdout.strip()
        if not stdout:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                error=f"CAPA 无输出（退出码 {proc.returncode}）",
                raw_output=proc.stderr[:2000],
            )

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                error=f"无法解析 CAPA 输出：{exc}",
                raw_output=stdout[:1500],
            )

        # CAPA 的 rules 是以规则名为键的字典，不是数组
        rules = data.get("rules") or {}
        if not isinstance(rules, dict):
            rules = {}

        capabilities: list[dict] = []
        notable: list[str] = []
        attack: set[str] = set()
        mbc: set[str] = set()

        for rule_name, rule in rules.items():
            meta = (rule or {}).get("meta") or {}
            namespace = str(meta.get("namespace") or "")
            name = str(meta.get("name") or rule_name)
            capabilities.append({"name": name, "namespace": namespace})

            for technique in meta.get("attack") or []:
                if isinstance(technique, dict):
                    if technique.get("technique"):
                        attack.add(str(technique["technique"]))
                else:
                    attack.add(str(technique))
            for behaviour in meta.get("mbc") or []:
                if isinstance(behaviour, dict):
                    if behaviour.get("objective"):
                        mbc.add(str(behaviour["objective"]))
                else:
                    mbc.add(str(behaviour))

            if any(namespace.startswith(p) for p in _NOTABLE_PREFIXES):
                notable.append(name)

        meta_out = {
            "capabilities": capabilities,
            "attack": sorted(attack),
            "mbc": sorted(mbc),
            "notable": notable,
        }

        if notable:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.SUSPICIOUS,
                signature="; ".join(dict.fromkeys(notable))[:120],
                detail=f"识别到 {len(capabilities)} 项能力，其中 {len(notable)} 项值得警惕",
                meta=meta_out,
            )

        return EngineResult(
            engine=self.name,
            verdict=Verdict.CLEAN,
            detail=f"识别到 {len(capabilities)} 项能力，未发现高危能力",
            meta=meta_out,
        )
