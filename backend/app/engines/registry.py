"""引擎注册表。

集中构造所有引擎适配器，并按网络策略过滤：
1. 配置中显式禁用的引擎
2. 外传等级超出当前策略允许范围的引擎

注意"无法证明"和"会外传"是两回事，而"会外传元数据"和"会外传样本"
又是两回事。像 Defender 这种，实际行为取决于系统设置，只能运行时查证——
查不到就按最坏情况处理，绝不做无法兑现的承诺。

被过滤掉的引擎仍会在 UI 上如实列出来并说明原因，而不是悄悄消失。
"""

from __future__ import annotations

import logging

from ..config import settings
from .base import (
    NETWORK_LEVEL_TEXT,
    NETWORK_LOCAL,
    POLICY_ALLOWED,
    POLICY_TEXT,
    EngineAdapter,
)
from .capa_engine import CapaEngine
from .clamav import ClamAVEngine
from .defender import DefenderEngine
from .die import DieEngine
from .emsisoft import EmsisoftEngine
from .manalyze import ManalyzeEngine
from .yara_engine import YaraEngine
from .yara_x_engine import YaraXEngine

log = logging.getLogger(__name__)


def all_engines() -> list[EngineAdapter]:
    """构造全部引擎适配器，含会被过滤掉的，便于如实展示。"""
    return [
        # 签名引擎：比对已知特征
        DefenderEngine(),
        ClamAVEngine(),
        EmsisoftEngine(),
        # YARA 与 YARA-X 跑同一批规则，互为交叉验证（见 yara_x_engine 的说明）。
        # 两者同属一个 source_group，聚合判定时只算一票。
        YaraEngine(settings.rules_dirs),
        YaraXEngine(settings.rules_dirs),
        # 结构/能力分析：不看签名，看这个文件"是什么"和"能干什么"。
        # 签名引擎对新型样本集体失明时，这一层是唯一的线索来源。
        DieEngine(),
        ManalyzeEngine(),
        CapaEngine(),
        # 后续在此追加：
        #   RemoteVmEngine(host=..., ...)     —— 商业引擎，每个跑在独立 VM
        #                                        （ESET ecls / Kaspersky avp.com 等
        #                                         装在同一台机器上会争抢驱动）
    ]


def exclusion_reason(engine: EngineAdapter) -> str | None:
    """返回该引擎被排除的原因；None 表示本次扫描会使用它。"""
    key = engine.name.lower().replace(" ", "")
    if key in settings.disabled_engines:
        return f"已在配置中禁用（PEINSIGHT_DISABLED_ENGINES 包含 {engine.name}）"

    allowed = POLICY_ALLOWED.get(settings.network_policy, POLICY_ALLOWED["no-sample"])
    level = engine.network_level()
    if level not in allowed:
        head = (
            f"当前网络策略为「{POLICY_TEXT.get(settings.network_policy, settings.network_policy)}」，"
            f"而它的外传等级是「{NETWORK_LEVEL_TEXT[level]}」"
        )
        note = engine.network_note()
        return f"{head}。{note}" if note else head

    return None


def build_engines() -> list[EngineAdapter]:
    """构造本次扫描实际启用的引擎。"""
    active: list[EngineAdapter] = []
    for engine in all_engines():
        reason = exclusion_reason(engine)
        if reason:
            log.warning("引擎 %s 已跳过：%s", engine.name, reason)
            continue
        active.append(engine)
    return active


def describe_engines() -> list[dict]:
    """给 API / UI 用的完整引擎清单，含被排除者及其原因。"""
    rows: list[dict] = []
    for engine in all_engines():
        reason = exclusion_reason(engine)
        available = engine.available()
        level = engine.network_level()
        rows.append(
            {
                "name": engine.name,
                "kind": engine.kind.value,
                "network_level": level,
                "network_level_text": NETWORK_LEVEL_TEXT[level],
                "offline": level == NETWORK_LOCAL,
                "network_note": engine.network_note(),
                "available": available,
                "load_note": engine.load_note(),
                "reason": None if available else engine.unavailable_reason(),
                # active=False 表示本次扫描不会用它
                "active": reason is None,
                "excluded_reason": reason,
            }
        )
    return rows
