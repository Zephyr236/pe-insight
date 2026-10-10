"""YARA 规则引擎适配器（经典实现，yara-python）。

规则文件放 `rules/`（项目自有）和 `tools/yara-rules/`（第三方规则集，由
`setup-yara` 下载）。另有一个跑同一批规则的 YARA-X 引擎，见
`yara_x_engine.py`。

**加载方式是容错的**，这一点不是随手加的：第三方规则集动辄几百个文件、
上千条规则，其中总有几个需要外部变量（`filepath` / `filename` 之类，
THOR、LOKI 那类扫描器会通过 `-d` 传进去）。而
`yara.compile(filepaths=...)` 是原子的——一个文件编译不过，整个规则库
就全军覆没。实测 signature-base 747 个文件里有 13 个是这样。所以这里的
策略是：整体编译失败就退化成逐文件编译，剔除坏的、保留好的，并如实
报告跳过了哪些。
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .base import (
    EngineAdapter,
    EngineKind,
    EngineResult,
    ScanContext,
    Verdict,
)
from ..static.pe_analyzer import looks_like_pe
from .yara_common import (
    SOURCE_GROUP,
    collect_rule_files,
    empty_externals,
    external_values,
    sort_hits,
    unique_namespaces,
    verdict_for,
)

try:
    import yara

    _YARA_IMPORT_ERROR: str | None = None
except ImportError as exc:  # pragma: no cover - 取决于安装环境
    yara = None  # type: ignore[assignment]
    _YARA_IMPORT_ERROR = str(exc)


class YaraEngine(EngineAdapter):
    name = "YARA"
    kind = EngineKind.RULE
    offline = True
    source_group = SOURCE_GROUP

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

    def _load(self) -> None:
        if yara is None:
            self._load_error = f"yara-python 未安装：{_YARA_IMPORT_ERROR}"
            return

        found = collect_rule_files(self._rules_dirs)
        if not found:
            dirs = "、".join(str(d) for d in self._rules_dirs)
            self._load_error = (
                f"规则目录为空：{dirs}。放入 .yar 规则文件后重启即可生效；"
                "第三方规则集用 `python -m app.cli setup-yara` 下载。"
            )
            return

        namespaces = unique_namespaces(found)

        # 外部变量必须在编译期就声明，扫描时再传实际值覆盖。
        # signature-base 里有 13 个文件（652 条规则）依赖它们。
        externals = empty_externals()

        # 先整体编译：一次编完最省事，也是绝大多数情况下的路径
        try:
            self._compiled = yara.compile(
                filepaths={ns: str(path) for path, ns in namespaces},
                externals=externals,
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
                yara.compile(filepaths={ns: str(path)}, externals=externals)
                good[ns] = str(path)
            except Exception as exc:  # noqa: BLE001 - 单个坏文件不应影响其它
                skipped.append((path.name, str(exc).splitlines()[0][:120]))

        if not good:
            self._load_error = (
                f"全部 {len(namespaces)} 个规则文件都编译失败。首个错误：{first_error}"
            )
            return

        try:
            self._compiled = yara.compile(filepaths=good, externals=externals)
        except Exception as exc:  # noqa: BLE001
            self._load_error = (
                f"剔除 {len(skipped)} 个坏文件后仍无法编译："
                f"{str(exc).splitlines()[0][:160]}"
            )
            return

        self._loaded_files = len(good)
        self._skipped = skipped

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
            note += f"，跳过 {len(self._skipped)} 个（编译失败）"
        return note

    def scan(self, ctx: ScanContext) -> EngineResult:
        assert self._compiled is not None

        matches = self._compiled.match(
            str(ctx.sample_path),
            timeout=self._rule_timeout,
            externals=external_values(
                ctx.sample_path, is_pe=looks_like_pe(ctx.sample_path)
            ),
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
            level = verdict_for(match.rule, meta)
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

        hits = sort_hits(hits)
        primary = hits[0]
        return EngineResult(
            engine=self.name,
            verdict=worst,
            signature=primary.get("family") or primary["rule"],
            detail=f"命中 {len(hits)} 条规则",
            meta={"matches": hits},
        )
