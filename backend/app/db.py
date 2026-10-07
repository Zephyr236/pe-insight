"""数据库连接与会话管理。"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlmodel import Session, SQLModel, create_engine

from .config import settings

# check_same_thread=False：扫描在后台线程里跑，SQLite 默认禁止跨线程复用连接
_engine = create_engine(
    f"sqlite:///{settings.db_path}",
    connect_args={"check_same_thread": False},
    echo=False,
)


def init_db() -> None:
    # 导入以触发模型注册
    from . import models  # noqa: F401

    SQLModel.metadata.create_all(_engine)


@contextmanager
def session_scope() -> Iterator[Session]:
    # expire_on_commit=False 是必需的：默认行为会在 commit 后让所有已加载属性
    # 失效，于是"在 with 块外使用 ORM 对象"就会抛 DetachedInstanceError。
    # 列表接口天然是"查完再用"，所以必须关掉过期机制。
    session = Session(_engine, expire_on_commit=False)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
