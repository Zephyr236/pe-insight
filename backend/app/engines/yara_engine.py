"""YARA 规则引擎适配器。

YARA 不是杀毒引擎，但在定向样本上往往比签名引擎更有效——你可以为特定的
家族、APT、加壳器写规则。规则文件放 `rules/`（项目自有）和
`tools/yara-rules/`（第三方规则集，由 `setup-yara` 下载）。

规则可以用 meta 控制判定：
    meta:
        verdict = "malicious"     # 默认为 suspicious
        family  = "Emotet"
        author  = "..."

**加载方式是容错的**，这一点不是随手加的：第三方规则集动辄几百个文件、
上千条规则，其中总有几个用到了本机 yara 构建没编进去的模块（`magic`、
`macho`、`cuckoo`）或需要外部变量（`filepath` 之类，要 `-d` 传值）。
`yara.compile(filepaths=...)` 是原子的——一个文件编译不过，整个规则库
就全军覆没。实测 signature-base 747 个文件里 13 个是这样，整体编译直接
失败。所以这里的策略是：整体编译失败就退化成逐文件编译，剔除坏的、
保留好的，并如实报告跳过了哪些。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from pathlib import Path

from .base import (
    EngineAdapter,
    EngineKind,
    EngineResult,
    ScanContext,
    Verdict,
)

try:
    import yara

    _YARA_IMPORT_ERROR: str | None = None
except ImportError as exc:  # pragma: no cover - 取决于安装环境
    yara = None  # type: ignore[assignment]
    _YARA_IMPORT_ERROR = str(exc)

_RULE_SUFFIXES = (".yar", ".yara")

#: 命名空间只允许字母数字下划线，其余一律替换掉
_NS_SAFE = re.compile(r"[^0-9A-Za-z_]")

#: signature-base 的规则名用前缀标注类别，PUA 单独一档。
_PUP_PREFIXES = ("PUA_", "PUP_")

#: 这些前缀表示"已确认的恶意家族"，比中性规则高一档。
_MALICIOUS_PREFIXES = (
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

#: signature-base 用 score 表示置信度（0-100）。75 以上是它自己标注的
#: 高置信，实测 2835 条带分规则里只有 627 条达到。取这个阈值是因为
#: 70 分是个巨大的默认档（1211 条），拿它当恶意线会让一切都变恶意。
_SCORE_MALICIOUS = 75


def _verdict_for(name: str, meta: dict) -> str:
    """把一条命中翻译成判定等级。

    判据按可靠性排序，从最明确的开始退：

    1. `meta.verdict` —— 规则自己声明了，直接用（项目自有规则的约定）。
    2. `PUA_` 前缀 —— 潜在不受欢迎程序，单独一档。
    3. `meta.score >= 75` —— signature-base 的置信度分。
    4. 恶意家族前缀（`MAL_` / `APT_` / `RANSOM_` …）。
    5. 其余一律 suspicious：命中终归是命中，但不替分析员下结论。

    第三方规则集不带 `meta.verdict`，只按"命中了"就报 malicious 会把
    exploit 探测痕迹、日志残留这类低置信规则也抬成恶意，所以这里必须
    有这套降级逻辑。
    """
    declared = str(meta.get("verdict", "")).strip().lower()
    if declared in {"malicious", "suspicious", "pup", "clean"}:
        return declared

    if name.startswith(_PUP_PREFIXES):
        return "pup"

    try:
        score = int(meta.get("score", -1))
    except (TypeError, ValueError):
        score = -1
    if score >= _SCORE_MALICIOUS:
        return "malicious"

    if name.startswith(_MALICIOUS_PREFIXES):
        return "malicious"

    return "suspicious"


def _namespace_for(path: Path, root: Path) -> str:
    """给规则文件取一个跨目录唯一的命名空间名。

    直接用 stem 会在两个目录有同名文件时撞车（`yara.compile` 的
    filepaths 键必须唯一），所以要带上相对路径。
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(path.name)
    return _NS_SAFE.sub("_", str(rel.with_suffix("")))


class YaraEngine(EngineAdapter):
    name = "YARA"
    kind = EngineKind.RULE
    offline = True

    def __init__(
        self,
        rules_dir: Path | Sequence[Path],
        *,
        timeout_s: int = 60,
    ) -> None:
        if isinstance(rules_dir, (str, Path)):
            dirs: tuple[Path, ...] = (Path(rules_dir),)
        else:
            dirs = tuple(Path(p) for p in rules_dir)
        self._rules_dirs = dirs
        self._rule_timeout = timeout_s
        self._compiled = None
        self._load_error: str | None = None
        self._loaded_files = 0
        self._skipped: list[tuple[str, str]] = []
        self._load()

    # ------------------------------------------------------------------ 加载

    def _collect(self) -> list[tuple[Path, Path]]:
        """返回 [(规则文件, 所属根目录)]，顺序稳定。"""
        out: list[tuple[Path, Path]] = []
        for root in self._rules_dirs:
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*")):
                if path.is_file() and path.suffix.lower() in _RULE_SUFFIXES:
                    out.append((path, root))
        return out

    def _load(self) -> None:
        if yara is None:
            self._load_error = f"yara-python 未安装：{_YARA_IMPORT_ERROR}"
            return

        found = self._collect()
        if not found:
            dirs = "、".join(str(d) for d in self._rules_dirs)
            self._load_error = (
                f"规则目录为空：{dirs}。放入 .yar 规则文件后重启即可生效；"
                "第三方规则集用 `python -m app.cli setup-yara` 下载。"
            )
            return

        namespaces = self._unique_namespaces(found)

        # 先整体编译：一次编完最省事，也是绝大多数情况下的路径
        try:
            self._compiled = yara.compile(
                filepaths={ns: str(path) for path, ns in namespaces}
            )
            self._loaded_files = len(namespaces)
            return
        except Exception as exc:  # noqa: BLE001 - 退化到逐文件，不在这里失败
            first_error = str(exc).splitlines()[0][:160]

        # 整体编译失败：逐文件找出能编的，剔除编不过的
        good: dict[str, str] = {}
        skipped: list[tuple[str, str]] = []
        for path, ns in namespaces:
            try:
                yara.compile(filepaths={ns: str(path)})
                good[ns] = str(path)
            except Exception as exc:  # noqa: BLE001 - 单个坏文件不应影响其它
                skipped.append((path.name, str(exc).splitlines()[0][:120]))

        if not good:
            self._load_error = (
                f"全部 {len(namespaces)} 个规则文件都编译失败。首个错误：{first_error}"
            )
            return

        try:
            self._compiled = yara.compile(filepaths=good)
        except Exception as exc:  # noqa: BLE001
            self._load_error = (
                f"剔除 {len(skipped)} 个坏文件后仍无法编译："
                f"{str(exc).splitlines()[0][:160]}"
            )
            return

        self._loaded_files = len(good)
        self._skipped = skipped

    @staticmethod
    def _unique_namespaces(
        found: Iterable[tuple[Path, Path]],
    ) -> list[tuple[Path, str]]:
        out: list[tuple[Path, str]] = []
        used: set[str] = set()
        for path, root in found:
            ns = _namespace_for(path, root)
            if ns in used:
                i = 2
                while f"{ns}_{i}" in used:
                    i += 1
                ns = f"{ns}_{i}"
            used.add(ns)
            out.append((path, ns))
        return out

    # ------------------------------------------------------------ EngineAdapter

    def available(self) -> bool:
        return self._compiled is not None

    def unavailable_reason(self) -> str:
        return self._load_error or "规则未加载"

    @property
    def loaded_files(self) -> int:
        """成功加载的规则文件数。"""
        return self._loaded_files

    @property
    def skipped(self) -> list[tuple[str, str]]:
        """被跳过的规则文件 [(文件名, 失败原因)]。"""
        return list(self._skipped)

    def load_note(self) -> str:
        """一行加载结果说明，供 CLI / 引擎列表展示。"""
        if not self.available():
            return self.unavailable_reason()
        note = f"已加载 {self._loaded_files} 个规则文件"
        if self._skipped:
            note += f"，跳过 {len(self._skipped)} 个（模块缺失或需外部变量）"
        return note

    def scan(self, ctx: ScanContext) -> EngineResult:
        assert self._compiled is not None

        matches = self._compiled.match(
            str(ctx.sample_path),
            timeout=self._rule_timeout,
        )
        if not matches:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.CLEAN,
                detail=f"未命中任何规则（{self.load_note()}）",
            )

        hits: list[dict] = []
        worst = Verdict.SUSPICIOUS

        for match in matches:
            meta = dict(match.meta or {})
            level = _verdict_for(match.rule, meta)
            if level == "malicious":
                worst = Verdict.MALICIOUS
            elif level == "pup" and worst != Verdict.MALICIOUS:
                worst = Verdict.PUP

            hits.append(
                {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags or []),
                    "family": meta.get("family"),
                    "description": meta.get("description"),
                    "score": meta.get("score"),
                    "verdict": level,
                }
            )

        # 按严重度排序，让 signature 取到的是最重的那条。
        # 不排的话顺序由 YARA 决定，命中多条时会拿一条次要规则去当签名，
        # 分析员看到的结论和真正的原因对不上。
        _rank = {"malicious": 0, "pup": 1, "suspicious": 2, "clean": 3}
        hits.sort(key=lambda h: _rank.get(str(h["verdict"]), 4))
        primary = hits[0]
        return EngineResult(
            engine=self.name,
            verdict=worst,
            signature=primary.get("family") or primary["rule"],
            detail=f"命中 {len(hits)} 条规则",
            meta={"matches": hits},
        )
