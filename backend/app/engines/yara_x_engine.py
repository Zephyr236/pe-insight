"""YARA-X 规则引擎适配器（VirusTotal 的 Rust 重写版，yara-x 绑定）。

跑的是**和经典 YARA 引擎同一批规则**（`rules/` + `tools/yara-rules/`），
两个引擎归在同一个 `source_group`，聚合判定时只算一票——否则同一份规则
命中一次会被数成两个引擎，检测比例虚高。

那为什么还要留着经典 YARA？

- **规则兼容性**：YARA-X 是重新实现的，个别规则的行为与经典版有差异。
  两个引擎都跑，等于对同一批规则做了一次交叉验证；只跑一个的话，某个
  规则在某一边静默失效不会被发现。
- **编译容错不同**：两边对同一批规则各自决定能编哪些，覆盖面不完全重合。
- **可对照**：分析员看到两边的命中列表不一致时，那条规则值得单独看一眼。

代价是内存和启动时间各多一份。实测 yara-x 在 747 个规则文件上
`add_source` 约 5 秒、`build` 约 2 秒，进程内运行、内存占用可忽略。

与经典版的两处接口差异（已在 yara_common 里对齐语义）：

- 命名空间：YARA-X 用 `Compiler.new_namespace()` 切换，粒度是"下一次
  add_source 用哪个命名空间"，不能像 yara-python 那样一次传整个 filepaths
  映射。这里按文件逐个切换，效果一致。
- 元数据：`Match.metadata` 是 dict 且保留原始类型（`score` 是 int），
  比 yara-python 更省事。
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
    import yara_x

    _YARA_X_IMPORT_ERROR: str | None = None
except ImportError as exc:  # pragma: no cover - 取决于安装环境
    yara_x = None  # type: ignore[assignment]
    _YARA_X_IMPORT_ERROR = str(exc)


class YaraXEngine(EngineAdapter):
    name = "YARA-X"
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
        self._rules = None
        self._load_error: str | None = None
        self._loaded_files = 0
        self._skipped: list[tuple[str, str]] = []
        self._load()

    # ------------------------------------------------------------------ 加载

    def _load(self) -> None:
        if yara_x is None:
            self._load_error = f"yara-x 未安装：{_YARA_X_IMPORT_ERROR}"
            return

        found = collect_rule_files(self._rules_dirs)
        if not found:
            dirs = "、".join(str(d) for d in self._rules_dirs)
            self._load_error = (
                f"规则目录为空：{dirs}。第三方规则集用 "
                "`python -m app.cli setup-yara` 下载。"
            )
            return

        compiler = yara_x.Compiler()

        # 外部变量必须在 add_source 之前定义。signature-base 里有 13 个文件
        # （652 条规则）依赖它们，不定义就整份文件编译不过。
        for name, value in empty_externals().items():
            compiler.define_global(name, value)

        loaded = 0
        skipped: list[tuple[str, str]] = []

        for path, ns in unique_namespaces(found):
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                skipped.append((path.name, f"读取失败：{exc}"))
                continue

            compiler.new_namespace(ns)
            try:
                compiler.add_source(source, origin=path.name)
                loaded += 1
            except Exception as exc:  # noqa: BLE001 - 单个坏文件不应影响其它
                # 失败的 add_source 不会污染编译器：实测逐个添加时 13 个文件
                # 报错，随后的 build() 依然成功，坏文件被丢弃。
                skipped.append((path.name, str(exc).splitlines()[0][:120]))

        if not loaded:
            self._load_error = (
                f"全部 {len(found)} 个规则文件都无法编译。"
                f"首个错误：{skipped[0][1] if skipped else '未知'}"
            )
            return

        try:
            self._rules = compiler.build()
        except Exception as exc:  # noqa: BLE001
            self._load_error = (
                f"剔除 {len(skipped)} 个坏文件后仍无法编译："
                f"{str(exc).splitlines()[0][:160]}"
            )
            return

        self._loaded_files = loaded
        self._skipped = skipped

    # ------------------------------------------------------------ EngineAdapter

    def available(self) -> bool:
        return self._rules is not None

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
        assert self._rules is not None

        scanner = yara_x.Scanner(self._rules)
        scanner.set_timeout(self._rule_timeout)

        for name, value in external_values(
            ctx.sample_path, is_pe=looks_like_pe(ctx.sample_path)
        ).items():
            scanner.set_global(name, value)

        try:
            results = scanner.scan_file(str(ctx.sample_path))
        except Exception as exc:  # noqa: BLE001 - 读不了的文件不该让整轮扫描失败
            return EngineResult(
                engine=self.name,
                verdict=Verdict.ERROR,
                detail=f"扫描失败：{str(exc)[:160]}",
                error=str(exc)[:300],
            )

        hits: list[dict] = []
        worst = Verdict.SUSPICIOUS

        for match in results.matching_rules:
            meta = dict(match.metadata or {})
            level = verdict_for(match.identifier, meta)
            if level == "malicious":
                worst = Verdict.MALICIOUS
            elif level == "pup" and worst != Verdict.MALICIOUS:
                worst = Verdict.PUP

            hits.append(
                {
                    "rule": match.identifier,
                    "namespace": match.namespace,
                    "tags": list(match.tags or []),
                    "family": meta.get("family"),
                    "description": meta.get("description"),
                    "score": meta.get("score"),
                    "verdict": level,
                }
            )

        if not hits:
            return EngineResult(
                engine=self.name,
                verdict=Verdict.CLEAN,
                detail=f"未命中任何规则（{self.load_note()}）",
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
