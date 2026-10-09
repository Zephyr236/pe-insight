"""下载第三方 YARA 规则集（signature-base）。

本产品不再自带手写的启发式规则——那种"API 存在性"判据在系统文件上误报
率高得没法用（实测 8/124）。改用 Florian Roth 维护的 signature-base：
5200+ 条规则，专业分析师编写，绑定具体家族，实测在 124 个系统文件上
**零误报**。

**为什么是逐文件下载，而不是下一个 zip**

因为 zip 会被 Windows Defender 拦掉。实测：整包下载到本地后立刻被检出
（`ThreatID 2147965225`），文件被锁死，读取直接 `OSError Errno 22`。
而把同样的 `.yar` 单独拉下来则安然无恙——Defender 拦的是"一个包含大量
恶意软件特征串的压缩包"这个形态本身。

所以这里走 GitHub API 列目录 + 逐个文件抓 `download_url`。顺带还有个
好处：规则集更新时可以精确同步，删掉上游已经移除的文件。

规则集放在 `tools/yara-rules/`（不进版本库），跟 capa-rules 一个待遇。
"""

from __future__ import annotations

import json
import shutil
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .config import settings

#: GitHub 仓库 API，列出 yara/ 目录。未认证请求每小时 60 次，一次更新用 1 次。
LIST_URL = "https://api.github.com/repos/Neo23x0/signature-base/contents/yara"

_UA = {"User-Agent": "pe-insight-setup"}

#: 并发抓取数。raw.githubusercontent.com 对并发不敏感，但别太过分。
_WORKERS = 12


def rules_dir() -> Path:
    return settings.community_rules_dir


def installed_count() -> int:
    root = rules_dir()
    return len(list(root.glob("*.yar"))) if root.is_dir() else 0


def _fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


def _list_rules(progress) -> list[tuple[str, str]]:
    """返回 [(文件名, 下载地址)]。"""
    progress("  读取规则清单…")
    try:
        payload = json.loads(_fetch(LIST_URL).decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RuntimeError(f"无法读取规则清单：{exc}") from exc

    if not isinstance(payload, list):
        raise RuntimeError(f"规则清单格式异常：{str(payload)[:120]}")

    out: list[tuple[str, str]] = []
    for entry in payload:
        name = entry.get("name", "")
        url = entry.get("download_url")
        if name.endswith(".yar") and url:
            out.append((name, url))
    return out


def install(force: bool = False, progress=print) -> bool:
    """下载（或更新）signature-base 规则集。

    先全部抓到临时目录，确认抓够了再整体换上去——中途失败时不会把已有的
    规则集清空，扫描能力不会因为一次网络抖动而归零。
    """
    root = rules_dir()
    existing = installed_count()
    if existing and not force:
        progress(f"signature-base 已存在（{existing} 个规则文件），跳过")
        return True

    try:
        entries = _list_rules(progress)
    except RuntimeError as exc:
        progress(f"    失败：{exc}")
        return False

    if not entries:
        progress("    失败：清单里没有 .yar 文件")
        return False

    total = len(entries)
    progress(f"  下载 {total} 个规则文件…")

    staging = root.parent / "_yara-rules_staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)

    failed: list[str] = []
    done = 0

    def grab(item: tuple[str, str]) -> str | None:
        name, url = item
        try:
            blob = _fetch(url)
        except (urllib.error.URLError, OSError):
            return name
        try:
            (staging / name).write_bytes(blob)
        except OSError:
            return name
        return None

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        futures = [pool.submit(grab, item) for item in entries]
        for fut in as_completed(futures):
            done += 1
            if fut.result():
                failed.append(fut.result())
            if done % 25 == 0 or done == total:
                progress(f"\r    {done}/{total}（失败 {len(failed)}）")

    progress("")
    got = len(list(staging.glob("*.yar")))

    # 少于一半就别换了，多半是网络问题
    if got < max(1, total // 2):
        progress(f"    失败：只抓到 {got}/{total} 个，保留原有规则集")
        shutil.rmtree(staging, ignore_errors=True)
        return False

    root.mkdir(parents=True, exist_ok=True)
    # 清掉上游已移除的旧规则，避免越积越多
    for old in root.glob("*.yar"):
        old.unlink(missing_ok=True)
    for src in staging.glob("*.yar"):
        shutil.move(str(src), str(root / src.name))
    shutil.rmtree(staging, ignore_errors=True)

    note = f"完成：{got} 个规则文件"
    if failed:
        note += f"，{len(failed)} 个下载失败"
    progress(f"    {note}")
    return True
