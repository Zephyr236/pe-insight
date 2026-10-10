"""经典 YARA 与 YARA-X 两个引擎共用的东西。

两者是同一套语法、同一批规则的两个实现，但接口差异不小：yara-python 用
`compile(filepaths=..., externals=...)`，yara-x 用 `Compiler` / `Scanner`，
连元数据的取法都不同。

**判定语义必须一致**——同一个样本在两条路径上给出不同结论是灾难性的。
所以规则文件发现、命名空间命名、判定等级映射都放在这里，两边共用。

（命名空间在 YARA-X 里目前只能通过 `Compiler.new_namespace()` 设置，粒度
比 yara-python 的 per-file 粗，见 yara_x_engine 的说明。）
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from pathlib import Path

#: 两个引擎共享同一个规则来源，聚合判定时算作同一票。
#: 它们跑的是同一批规则——如果各算一票，一次命中会变成两票，检测比例虚高。
SOURCE_GROUP = "yara-rules"

RULE_SUFFIXES = (".yar", ".yara")

#: 命名空间只允许字母数字下划线，其余一律替换掉
_NS_SAFE = re.compile(r"[^0-9A-Za-z_]")

#: signature-base 用规则名前缀标注类别，PUA 单独一档
PUP_PREFIXES = ("PUA_", "PUP_")

#: 这些前缀表示"已确认的恶意家族"，比中性规则高一档
MALICIOUS_PREFIXES = (
    "MAL_",
    "RANSOM_",
    "APT_",
    "WEBSHELL_",
    "HKTL_",  # 黑客工具：分析场景下按恶意处理
    "EXPL_",
    "IMPLANT_",
    "RAT_",
    "CRIME_",
    "CobaltStrike",
    "Cobaltbaltstrike",
)

#: signature-base 用 score 表示置信度（0-100）。75 以上是它自己标注的高置信，
#: 实测 2835 条带分规则里只有 627 条达到。取这个阈值是因为 70 分是个巨大的
#: 默认档（1211 条），拿它当恶意线会让一切都变恶意。
SCORE_MALICIOUS = 75

#: 判定等级排序，用于把最重的一条排到最前面
_SEVERITY_RANK = {"malicious": 0, "pup": 1, "suspicious": 2, "clean": 3}


# --------------------------------------------------------------------------
# 外部变量
# --------------------------------------------------------------------------
#
# signature-base 里有 13 个规则文件（652 条规则）用到了外部变量——那些规则
# 原本是给 THOR / LOKI 这类会通过 `-d` 把文件名传进去的扫描器用的，单独
# 交给 YARA 编译只会报 `undefined identifier`，整个文件被跳过。
#
# 这些值我们自己知道，填进去就能启用。但**填错比不填危险**：像
# `filetype != "GIF"` 这种否定条件，一旦给了错误的非空值就会被错误地满足，
# 直接变成误报。所以下面每个值都必须是准确知道的，认不出来就留空。

#: 声明给规则的外部变量。改这个元组会同时影响两个引擎。
EXTERNAL_NAMES = ("filename", "filepath", "extension", "filetype")

#: `filetype` 是 magic 推导出的文件类型。本项目只做 PE，所以只认得出 EXE；
#: 其余类型留空——留空时 `filetype == "EXE"` 为假（安全），`!=` 为真
#: （实测唯一活着的否定条件是 `extension != ".msi"`，不受影响）。
FILETYPE_PE = "EXE"


def empty_externals() -> dict[str, str]:
    """编译期用来声明外部变量的占位值。"""
    return dict.fromkeys(EXTERNAL_NAMES, "")


def external_values(sample_path: Path, *, is_pe: bool) -> dict[str, str]:
    """每次扫描时传给规则的外部变量取值。

    - `filename` / `filepath`：调用方实际扫描的路径，准确无误。
    - `extension`：带前导点、小写的后缀。规则里写的就是 `.jpg` / `.exe` /
      `.msi` 这种形式。
    - `filetype`：只认得 PE。**认不出就留空，不要猜。**
    """
    return {
        "filename": sample_path.name,
        "filepath": str(sample_path),
        "extension": sample_path.suffix.lower(),
        "filetype": FILETYPE_PE if is_pe else "",
    }


def namespace_for(path: Path, root: Path) -> str:
    """给规则文件取一个跨目录唯一的命名空间名。

    直接用 stem 会在两个目录有同名文件时撞车，所以要带上相对路径。
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(path.name)
    return _NS_SAFE.sub("_", str(rel.with_suffix("")))


def collect_rule_files(rules_dirs: Sequence[Path]) -> list[tuple[Path, Path]]:
    """返回 [(规则文件, 所属根目录)]，顺序稳定。"""
    out: list[tuple[Path, Path]] = []
    for root in rules_dirs:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix.lower() in RULE_SUFFIXES:
                out.append((path, root))
    return out


def unique_namespaces(found: Iterable[tuple[Path, Path]]) -> list[tuple[Path, str]]:
    """给每个规则文件分配一个互不冲突的命名空间名。"""
    out: list[tuple[Path, str]] = []
    used: set[str] = set()
    for path, root in found:
        ns = namespace_for(path, root)
        if ns in used:
            i = 2
            while f"{ns}_{i}" in used:
                i += 1
            ns = f"{ns}_{i}"
        used.add(ns)
        out.append((path, ns))
    return out


def verdict_for(name: str, meta: dict) -> str:
    """把一条命中翻译成判定等级。

    判据按可靠性排序，从最明确的开始退：

    1. `meta.verdict` —— 规则自己声明了，直接用（项目自有规则的约定）。
    2. `PUA_` 前缀 —— 潜在不受欢迎程序，单独一档。
    3. `meta.score >= 75` —— signature-base 的置信度分。
    4. 恶意家族前缀（`MAL_` / `APT_` / `RANSOM_` …）。
    5. 其余一律 suspicious：命中终归是命中，但不替分析员下结论。

    第三方规则集不带 `meta.verdict`，只按"命中了"就报 malicious 会把
    exploit 探测痕迹、日志残留这类低置信规则也抬成恶意，所以必须有这套
    降级逻辑。
    """
    declared = str(meta.get("verdict", "")).strip().lower()
    if declared in {"malicious", "suspicious", "pup", "clean"}:
        return declared

    if name.startswith(PUP_PREFIXES):
        return "pup"

    try:
        score = int(meta.get("score", -1))
    except (TypeError, ValueError):
        score = -1
    if score >= SCORE_MALICIOUS:
        return "malicious"

    if name.startswith(MALICIOUS_PREFIXES):
        return "malicious"

    return "suspicious"


def severity_rank(level: str) -> int:
    """排序用：数字越小越严重。"""
    return _SEVERITY_RANK.get(level, 4)


def sort_hits(hits: list[dict]) -> list[dict]:
    """按严重度排序，让 signature 取到最重的那条。

    不排的话顺序由引擎决定，命中多条时会拿一条次要规则去当签名，
    分析员看到的结论和真正的原因对不上。
    """
    return sorted(hits, key=lambda h: severity_rank(str(h.get("verdict", ""))))
