"""全局配置。

所有路径都可以通过环境变量覆盖，便于打包成单机桌面工具后把 data 目录
放到用户目录下。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# backend/app/config.py -> backend/app -> backend -> 项目根
BASE_DIR = Path(__file__).resolve().parents[2]


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    return Path(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    base_dir: Path = BASE_DIR
    data_dir: Path = field(default_factory=lambda: _env_path("PEINSIGHT_DATA", BASE_DIR / "data"))
    rules_dir: Path = field(
        default_factory=lambda: _env_path("PEINSIGHT_YARA_RULES", BASE_DIR / "rules")
    )

    # 引擎与样本
    max_upload_mb: int = 512
    scan_timeout_s: int = 300

    #: 并发跑几个引擎。
    #:
    #: 实测（单核机器，7 引擎，persistence-sim.exe）：
    #:     并发 1 → 49.2 秒
    #:     并发 4 → 23.1 秒
    #: 并发明显更快——这些工具比看起来更偏 I/O（读文件、加载签名库），
    #: OS 调度多进程没有明显代价。"单核就该顺序跑"是错的。
    #: 用 PEINSIGHT_ENGINE_WORKERS 覆盖。
    engine_workers: int = 4

    # 引擎网络策略，决定哪些引擎被允许参与扫描：
    #   local      只允许可证明完全本地的引擎（最严）
    #   no-sample  允许不外传样本内容的引擎（默认）——对应"样本不上传云端"
    #   any        不限制
    network_policy: str = "no-sample"

    # 安全开关：为 True 时，扫描期间用 netguard 强制拦截一切外网连接。
    # 这是"样本不上传"从声明变成强制约束的地方。
    enforce_offline: bool = True

    # 服务启动时自动拉起 clamd。clamscan 每扫一个文件都要重载签名库（约 3 秒），
    # 常驻后降到毫秒级。设成 False 可关闭自动启动。
    auto_start_clamd: bool = True

    # 为 MinGW/GCC 编译的样本补齐 Speakeasy 缺失的 msvcrt 启动函数。
    # 见 dynamic/msvcrt_shim.py。关掉可还原为 Speakeasy 的原始行为。
    msvcrt_shim: bool = True

    #: 局域网 API 的共享密钥。为空表示**不鉴权**。
    #:
    #: 强烈建议在开放到局域网前设置。这个接口接收任意文件上传并把它送进
    #: 多个杀毒引擎和模拟器，放在内网上不设防等于给全网开了一个投毒入口。
    #: 通过 PEINSIGHT_API_KEY 环境变量设置。
    api_key: str = ""

    #: 是否允许任意来源的跨域请求。局域网给别的机器用时需要打开，
    #: 因为客户端可能来自不同主机。
    allow_lan_cors: bool = False

    #: 服务启动后在后台自动更新签名库与规则集。
    #:
    #: 只在超过 auto_update_max_age_hours 时才真正下载——否则重启十次服务
    #: 就会下载十次上百 MB 的签名库。
    auto_update: bool = True
    auto_update_max_age_hours: float = 24.0
    #: 启动后等多久再开始更新。给服务先跑起来的余量，避免刚启动就抢磁盘和带宽。
    auto_update_delay_s: float = 45.0

    # 单个引擎的开关（用环境变量关闭，例如 PEINSIGHT_DISABLE_CLAMAV=1）
    disabled_engines: tuple[str, ...] = ()

    @property
    def samples_dir(self) -> Path:
        return self.data_dir / "samples"

    @property
    def inbox_dir(self) -> Path:
        """用户投放待分析样本的目录。

        必须位于数据目录内部——因为整个数据目录会被加入 Defender 排除列表。
        样本放在排除区之外的话，一落盘就会被实时防护锁死，所有引擎都读不到。
        """
        return self.data_dir / "inbox"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "peinsight.db"

    def ensure_dirs(self) -> None:
        for d in (
            self.data_dir,
            self.samples_dir,
            self.inbox_dir,
            self.reports_dir,
            self.rules_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)


_VALID_POLICIES = ("local", "no-sample", "any")


def load_settings() -> Settings:
    disabled = tuple(
        name.strip().lower().replace(" ", "")
        for name in os.environ.get("PEINSIGHT_DISABLED_ENGINES", "").split(",")
        if name.strip()
    )

    policy = os.environ.get("PEINSIGHT_NETWORK_POLICY", "no-sample").strip().lower()
    if policy not in _VALID_POLICIES:
        policy = "no-sample"

    # 兼容旧开关：允许联网等价于不限制网络策略
    if os.environ.get("PEINSIGHT_ALLOW_ONLINE", "").strip().lower() in ("1", "true", "yes"):
        policy = "any"

    allow_network = os.environ.get("PEINSIGHT_ALLOW_NETWORK", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )

    # 并发数默认 4。实测过"单核降为 1"的假设，结果反而慢一倍，所以不按核数调。
    workers_raw = os.environ.get("PEINSIGHT_ENGINE_WORKERS", "").strip()
    workers = int(workers_raw) if workers_raw.isdigit() and int(workers_raw) > 0 else 4

    settings = Settings(
        network_policy=policy,
        enforce_offline=not allow_network,
        disabled_engines=disabled,
        engine_workers=workers,
        api_key=os.environ.get("PEINSIGHT_API_KEY", "").strip(),
        allow_lan_cors=os.environ.get("PEINSIGHT_ALLOW_LAN_CORS", "").strip().lower()
        in ("1", "true", "yes"),
        auto_update=os.environ.get("PEINSIGHT_AUTO_UPDATE", "1").strip().lower()
        not in ("0", "false", "no"),
    )
    settings.ensure_dirs()
    return settings


settings = load_settings()
