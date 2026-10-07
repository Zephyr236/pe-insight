"""哈希与内容寻址存储工具。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Hashes:
    md5: str
    sha1: str
    sha256: str
    size: int


def hash_file(path: Path) -> Hashes:
    md5 = hashlib.md5()  # noqa: S324 - 用于样本标识与情报比对，非安全用途
    sha1 = hashlib.sha1()  # noqa: S324 - 同上
    sha256 = hashlib.sha256()
    size = 0

    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return Hashes(
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size=size,
    )


def store_sample(src: Path, sha256: str, samples_dir: Path) -> Path:
    """按 SHA256 内容寻址落盘：samples/ab/abcdef...bin

    内容寻址的好处是同一个样本重复提交不会产生副本，且天然去重。
    """
    bucket = samples_dir / sha256[:2]
    bucket.mkdir(parents=True, exist_ok=True)
    dest = bucket / f"{sha256}.bin"

    if not dest.exists():
        # 先写临时文件再改名，避免扫描过程中读到半个文件
        tmp = dest.with_suffix(".tmp")
        tmp.write_bytes(src.read_bytes())
        tmp.replace(dest)
    return dest
