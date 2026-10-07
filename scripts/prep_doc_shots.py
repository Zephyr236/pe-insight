"""为文档截图准备干净的演示数据。

在 8090 端口实例（独立数据目录）上跑一次完整扫描，供 docs-shots.mjs 截图。

刻意绕开 CLI 的 demo 命令：那个命令会对每个样本跑全套引擎，
CAPA 单次 110 秒，4 个样本要 8 分钟。这里只扫描一个样本。
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8090"
ROOT = Path(r"C:\Users\user\Desktop\pe-insight")
SHOT_DATA = ROOT / "data" / "_shots"

sys.path.insert(0, str(ROOT / "backend"))


def call(path: str, payload: dict | None = None) -> object:
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method="POST" if data else "GET",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read()
        return json.loads(body) if body else None


# ------------------------------------------------------------------ 造样本
# 用一个干净的系统 PE 作载体，尾部附加能触发 YARA 规则的字符串。
# 这样截图里能看到"检出"而不是清一色的干净，同时样本完全无害。
from app.demo import CASES  # noqa: E402

carrier = None
for cand in (
    Path(r"C:\Windows\System32\calc.exe"),
    Path(r"C:\Windows\System32\notepad.exe"),
):
    if cand.is_file():
        carrier = cand
        break

if carrier is None:
    sys.exit("找不到可用的 PE 载体")

inbox = SHOT_DATA / "inbox" / "demo"
inbox.mkdir(parents=True, exist_ok=True)
base = carrier.read_bytes()

made: list[Path] = []
for case in CASES[:2]:  # 两个就够截图用了
    target = inbox / f"{case.name}.exe"
    target.write_bytes(base + b"\r\n" + case.payload + b"\r\n")
    made.append(target)
    print(f"  生成 {target.name}  —— {case.description}")

# ------------------------------------------------------------------ 扫描
print(f"\n数据目录：{SHOT_DATA}")
print(f"当前记录：{len(call('/api/scans') or [])}")

for path in made:
    job = call("/api/scans/local", {"path": str(path), "run_dynamic": False})
    print(f"  已提交 {path.name}  id={job['id'][:8]}…")

print("\n等待扫描完成（含 CAPA，约 2 分钟）…")
deadline = time.time() + 600
while time.time() < deadline:
    time.sleep(5)
    scans = call("/api/scans") or []
    if scans and all(s["status"] in ("done", "failed") for s in scans):
        break

print()
for s in call("/api/scans") or []:
    print(f"  {s['filename']:<22} {s['status']:<8} {s['verdict']:<12} {s['detection_ratio']}")
