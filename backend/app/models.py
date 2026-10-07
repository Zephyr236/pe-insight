"""数据模型。

MVP 阶段把各层报告以 JSON 字符串整存整取——报告结构会随分析能力演进，
过早拆成关系表会带来大量无谓的迁移工作。样本本体按 SHA256 落在文件系统，
数据库只存元数据和报告。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ScanRecord(SQLModel, table=True):
    __tablename__ = "scans"

    id: str = Field(primary_key=True)
    # 记录创建时扫描还没跑，哈希要等扫描完成才填。必须有默认值，
    # 否则 pending 行会撞上 NOT NULL 约束。
    sha256: str = Field(default="", index=True)
    md5: str = ""
    sha1: str = ""
    size: int = 0
    filename: str = ""

    status: str = "pending"  # pending | running | done | failed
    created_at: datetime = Field(default_factory=_now)
    finished_at: Optional[datetime] = None

    # 聚合结论
    verdict: Optional[str] = None
    detection_ratio: Optional[str] = None  # 形如 "1/3"
    detections: int = 0
    engine_total: int = 0

    # 各层报告（JSON 字符串）
    static_json: Optional[str] = None
    engines_json: Optional[str] = None
    dynamic_json: Optional[str] = None
    # 出网守卫的执行记录——"样本未外传"的实证
    network_json: Optional[str] = None

    error: Optional[str] = None
