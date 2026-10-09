"""PE Insight — 本地多引擎 PE 文件分析平台。"""

from __future__ import annotations

import warnings

# Speakeasy 依赖的 unicorn 在导入时会用 pkg_resources，触发 setuptools 的
# 弃用告警。它纯粹是噪音，但危害不止于难看：安装脚本用 PowerShell 跑 CLI 时，
# 这条告警写到 stderr，会被 5.1 包成 NativeCommandError，在
# $ErrorActionPreference='Stop' 下直接变成终止错误（详见 setup.ps1 的注释）。
# 在包初始化处一次性精确滤掉，比在每个入口各滤一次可靠。
warnings.filterwarnings(
    "ignore",
    message=r"pkg_resources is deprecated as an API",
    category=UserWarning,
)

__version__ = "0.1.0"
