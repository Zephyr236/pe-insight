"""签名库与规则集更新。

**为什么需要这个模块**：安装时拉过一次签名库，之后就再没人管了。实测发现
DIE 的检测库已经 **800 天**没更新——这两年新出的加壳器它认不出来。

各组件的新鲜度来源不同：
    ClamAV      tools/clamav/database/*.cvd|cld
    Emsisoft    tools/eek/bin64/Signatures/BD/*
    DIE         tools/die/db/**
    CAPA 规则   tools/capa-rules/**/*.yml
    Defender    由 Windows 自己管，这里只报告状态

**更新与扫描的关系**：更新需要联网下载，而扫描期间是强制断网的。两者不冲突
——更新下载的是**签名**，不是样本；而且更新走的是独立进程，不经过扫描时的
出网守卫。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .config import settings

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass
class ComponentStatus:
    name: str
    label: str
    installed: bool
    age_hours: float | None
    detail: str

    @property
    def age_text(self) -> str:
        if not self.installed:
            return "未安装"
        if self.age_hours is None:
            return "无法判断"
        if self.age_hours < 1:
            return f"{self.age_hours * 60:.0f} 分钟前"
        if self.age_hours < 48:
            return f"{self.age_hours:.1f} 小时前"
        return f"{self.age_hours / 24:.1f} 天前"


# --------------------------------------------------------------------------
# 新鲜度探测
# --------------------------------------------------------------------------


def _newest_mtime(paths) -> float | None:
    newest: float | None = None
    for path in paths:
        try:
            mtime = Path(path).stat().st_mtime
        except OSError:
            continue
        if newest is None or mtime > newest:
            newest = mtime
    return newest


def _clamsig_age() -> tuple[bool, float | None, str]:
    base = settings.base_dir / "tools" / "clamav" / "database"
    files = list(base.glob("*.cvd")) + list(base.glob("*.cld"))
    if not files:
        return False, None, "未找到签名库"
    newest = _newest_mtime(files)
    age = (time.time() - newest) / 3600 if newest else None
    names = "、".join(sorted(f.name for f in files))
    return True, age, names


def _emsisoft_age() -> tuple[bool, float | None, str]:
    base = settings.base_dir / "tools" / "eek" / "bin64" / "Signatures"
    files = list(base.rglob("*")) if base.is_dir() else []
    files = [f for f in files if f.is_file()]
    if not files:
        return False, None, "未找到签名库"
    newest = _newest_mtime(files)
    age = (time.time() - newest) / 3600 if newest else None
    return True, age, f"{len(files)} 个签名文件"


def _die_age() -> tuple[bool, float | None, str]:
    base = settings.base_dir / "tools" / "die" / "db"
    files = [f for f in base.rglob("*") if f.is_file()] if base.is_dir() else []
    if not files:
        return False, None, "未找到检测库"
    newest = _newest_mtime(files)
    age = (time.time() - newest) / 3600 if newest else None
    return True, age, f"{len(files)} 个签名文件"


def _capa_age() -> tuple[bool, float | None, str]:
    base = settings.base_dir / "tools" / "capa-rules"
    files = list(base.rglob("*.yml")) if base.is_dir() else []
    if not files:
        return False, None, "未找到规则集"
    newest = _newest_mtime(files)
    age = (time.time() - newest) / 3600 if newest else None
    return True, age, f"{len(files)} 条规则"


def _yara_age() -> tuple[bool, float | None, str]:
    from . import setup_yara

    files = list(settings.community_rules_dir.glob("*.yar"))
    if not files:
        return False, None, "未找到规则集"
    newest = _newest_mtime(files)
    age = (time.time() - newest) / 3600 if newest else None
    return True, age, f"{len(files)} 个规则文件"


_PROBES = {
    "clamav": ("ClamAV 签名库", _clamsig_age),
    "emsisoft": ("Emsisoft 签名库", _emsisoft_age),
    "die": ("DIE 检测库", _die_age),
    "capa": ("CAPA 规则集", _capa_age),
    "yara": ("signature-base 规则集", _yara_age),
}

COMPONENTS = tuple(_PROBES)


def status() -> list[ComponentStatus]:
    out: list[ComponentStatus] = []
    for name, (label, probe) in _PROBES.items():
        installed, age, detail = probe()
        out.append(ComponentStatus(name, label, installed, age, detail))
    return out


# --------------------------------------------------------------------------
# 更新动作
# --------------------------------------------------------------------------


def _run(args: list[str], cwd: Path | None, timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return -1, f"超时（>{timeout}s）"
    except OSError as exc:
        return -1, f"{type(exc).__name__}: {exc}"


def _update_clamav(progress) -> tuple[bool, str]:
    exe = settings.base_dir / "tools" / "clamav" / "freshclam.exe"
    conf = settings.base_dir / "tools" / "clamav" / "freshclam.conf"
    if not exe.is_file():
        return False, "未安装 ClamAV"
    code, out = _run(
        [str(exe), f"--config-file={conf}"], exe.parent, timeout=3600
    )
    ok = any((exe.parent / "database").glob("*.c*"))
    tail = out.splitlines()[-1] if out else ""
    return ok, tail[:120] or f"退出码 {code}"


def _update_emsisoft(progress) -> tuple[bool, str]:
    exe = settings.base_dir / "tools" / "eek" / "bin64" / "a2cmd.exe"
    if not exe.is_file():
        return False, "未安装 Emsisoft EEK"
    code, out = _run([str(exe), "/u"], exe.parent, timeout=3600)
    # 退出码 8 = 更新失败；0/1 = 正常（1 是"有检出"，但仍算更新成功）
    if code == 8:
        return False, "a2cmd 报告更新失败"
    tail = out.splitlines()[-1] if out else ""
    return True, tail[:120] or f"退出码 {code}"


def _merge_tree(src: Path, dst: Path) -> tuple[int, int]:
    """把 src 合并进 dst，返回 (成功项数, 冲突跳过数)。

    为什么不用 shutil.copytree：Windows 文件系统大小写不敏感，而签名库
    在不同版本之间会出现同名但类型不同的条目（旧版是文件、新版是目录）。
    直接 copytree 会在这种冲突上整棵树失败，一个条目的问题把几千个文件的
    更新全判成失败。这里逐项处理，冲突时把挡路的删掉再放，实在不行才跳过。
    """
    copied = conflicts = 0
    for root, _dirs, files in os.walk(src):
        rel = Path(root).relative_to(src)
        target_dir = dst / rel if rel != Path(".") else dst

        try:
            target_dir.mkdir(parents=True, exist_ok=True)
        except (FileExistsError, OSError):
            # 目标位置被一个同名文件占着，删掉它才能建目录
            try:
                target_dir.unlink()
                target_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                conflicts += 1
                continue

        for name in files:
            source_file = Path(root) / name
            dest_file = target_dir / name
            try:
                if dest_file.is_dir():
                    shutil.rmtree(dest_file, ignore_errors=True)
                shutil.copy2(source_file, dest_file)
                copied += 1
            except OSError:
                conflicts += 1

    return copied, conflicts


def _download_zip(url: str, dest: Path, target: Path, progress, label: str) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pe-insight-update"})
        with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310
            blob = resp.read()
    except (urllib.error.URLError, OSError) as exc:
        return False, f"下载失败：{exc}"

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(blob)

    # 先解到临时目录再合并，不要直接 extractall 到已有目录：
    # Windows 上 extractall 覆盖已有路径会抛 WinError 183
    #（"当文件已存在时，无法创建该文件"）。
    staging = target.parent / f"_{target.name}_staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        staging.mkdir(parents=True)
        with zipfile.ZipFile(dest) as zf:
            zf.extractall(staging)
        target.mkdir(parents=True, exist_ok=True)
        copied, conflicts = _merge_tree(staging, target)
    except (zipfile.BadZipFile, OSError) as exc:
        return False, f"解压失败：{exc}"
    finally:
        dest.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)

    if copied == 0:
        return False, "没有写入任何文件"

    note = f"已更新 {label}（{copied} 项"
    note += f"，跳过 {conflicts} 个类型冲突项）" if conflicts else "）"
    return True, note


def _update_die(progress) -> tuple[bool, str]:
    from .setup_tools import DIE_DB_URL

    root = settings.base_dir / "tools" / "die"
    if not (root / "diec.exe").is_file():
        return False, "未安装 DIE"
    return _download_zip(
        DIE_DB_URL, root.parent / "_die_db.zip", root, progress, "DIE 检测库"
    )


def _update_capa(progress) -> tuple[bool, str]:
    from .setup_tools import CAPA_RULES_URL

    root = settings.base_dir / "tools" / "capa-rules"
    if not root.is_dir():
        return False, "未安装 CAPA 规则集"

    archive = root.parent / "_capa_rules.zip"
    if not _download_zip(CAPA_RULES_URL, archive, root, progress, "CAPA 规则集")[0]:
        return False, "下载失败"

    # 压缩包解压后通常多一层 capa-rules-master/，把它里面的内容提上来
    nested = root / "capa-rules-master"
    if nested.is_dir():
        for item in nested.iterdir():
            dest = root / item.name
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True) if dest.is_dir() else dest.unlink()
            shutil.move(str(item), str(dest))
        shutil.rmtree(nested, ignore_errors=True)

    count = len(list(root.rglob("*.yml")))
    return count > 0, f"{count} 条规则"


def _update_yara(progress) -> tuple[bool, str]:
    from . import setup_yara

    if not setup_yara.install(force=True, progress=progress):
        return False, "下载失败"
    return True, f"{setup_yara.installed_count()} 个规则文件"


_UPDATERS = {
    "clamav": _update_clamav,
    "emsisoft": _update_emsisoft,
    "die": _update_die,
    "capa": _update_capa,
    "yara": _update_yara,
}


def update(
    names: list[str] | None = None,
    max_age_hours: float | None = None,
    progress=print,
) -> list[dict]:
    """更新指定组件（默认全部）。

    max_age_hours 不为空时，只更新比这个阈值更旧的组件——服务每次启动都会
    调用它，没有阈值的话重启十次就下载十次。
    """
    targets = names or list(_UPDATERS)
    results: list[dict] = []

    for name in targets:
        if name not in _UPDATERS:
            results.append({"name": name, "updated": False, "message": "未知组件"})
            continue

        label = _PROBES[name][0]
        installed, age, detail = _PROBES[name][1]()

        if not installed:
            results.append({"name": name, "label": label, "updated": False, "message": "未安装，跳过"})
            continue

        if max_age_hours is not None and age is not None and age < max_age_hours:
            results.append(
                {
                    "name": name,
                    "label": label,
                    "updated": False,
                    "skipped": True,
                    "message": f"还新鲜（{age:.1f} 小时），跳过",
                }
            )
            continue

        progress(f"  更新 {label}…")
        try:
            ok, message = _UPDATERS[name](progress)
        except Exception as exc:  # noqa: BLE001 - 更新失败不该影响任何调用方
            ok, message = False, f"{type(exc).__name__}: {exc}"

        results.append({"name": name, "label": label, "updated": ok, "message": message})

    return results
