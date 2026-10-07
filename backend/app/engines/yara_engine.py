"""YARA 规则引擎适配器。

YARA 不是杀毒引擎，但在定向样本上往往比签名引擎更有效——你可以为特定的
家族、APT、加壳器写规则。规则文件放在 PEINSIGHT_YARA_RULES 指向的目录。

规则可以用 meta 控制判定：
    meta:
        verdict = "malicious"     # 默认为 suspicious
        family  = "Emotet"
        author  = "..."
"""

from __future__ import annotations

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


class YaraEngine(EngineAdapter):
    name = "YARA"
    kind = EngineKind.RULE
    offline = True

    def __init__(self, rules_dir: Path, *, timeout_s: int = 60) -> None:
        self._rules_dir = rules_dir
        self._rule_timeout = timeout_s
        self._compiled = None
        self._load_error: str | None = None
        self._rule_count = 0
        self._load()

    def _load(self) -> None:
        if yara is None:
            self._load_error = f"yara-python 未安装：{_YARA_IMPORT_ERROR}"
            return

        files = sorted(
            p
            for p in self._rules_dir.rglob("*")
            if p.suffix.lower() in _RULE_SUFFIXES and p.is_file()
        )
        if not files:
            self._load_error = (
                f"规则目录为空：{self._rules_dir}。"
                "放入 .yar 规则文件后重启即可生效。"
            )
            return

        try:
            # 每个文件单独编译成命名空间，避免不同规则间标识符冲突
            self._compiled = yara.compile(
                filepaths={f.stem: str(f) for f in files}
            )
            self._rule_count = len(files)
        except Exception as exc:  # noqa: BLE001 - 规则语法错误不应导致进程崩溃
            self._load_error = f"规则编译失败：{exc}"

    def available(self) -> bool:
        return self._compiled is not None

    def unavailable_reason(self) -> str:
        return self._load_error or "规则未加载"

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
                detail=f"未命中任何规则（已加载 {self._rule_count} 个规则文件）",
            )

        hits: list[dict] = []
        worst = Verdict.SUSPICIOUS

        for match in matches:
            meta = dict(match.meta or {})
            declared = str(meta.get("verdict", "")).lower()
            if declared == "malicious":
                worst = Verdict.MALICIOUS
            elif declared == "pup" and worst != Verdict.MALICIOUS:
                worst = Verdict.PUP

            hits.append(
                {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags or []),
                    "family": meta.get("family"),
                    "description": meta.get("description"),
                    "verdict": declared or "suspicious",
                }
            )

        primary = hits[0]
        return EngineResult(
            engine=self.name,
            verdict=worst,
            signature=primary.get("family") or primary["rule"],
            detail=f"命中 {len(hits)} 条规则",
            meta={"matches": hits},
        )
