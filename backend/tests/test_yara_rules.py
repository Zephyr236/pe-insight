"""YARA 引擎的规则测试。

**这是整个测试套件里最重要的一组。**

历史上吃过一次亏：反调试规则写成"出现 3 个以上反调试 API 就算"，结果在
notepad.exe 上误报了——正常 Windows 程序合法导入 IsDebuggerPresent 这类
API。一条会在系统文件上误报的规则，比没有规则更糟：它会让人不再看结果。

规则现在来自第三方（signature-base，由 setup-yara 下载），但契约不变，
而且更重要：5000+ 条规则全都要在干净的系统文件上保持沉默。

这里的测试分三层：
    1. 真阳性——规则确实能检出东西（否则"零误报"靠不加载任何规则就能满足）
    2. 真阴性——干净的系统文件一个都不能命中
    3. 加载器与判定映射——容错行为、等级推导
"""

from __future__ import annotations

import glob
import re
from pathlib import Path

import pytest

from app.config import settings
from app.engines.yara_engine import YaraEngine

#: 与 tools/diag_fp.py 保持一致的取样口径。
#: 早期测试只取前 40 个，比诊断脚本窄，结果会漏报误报。
SCAN_PATTERNS = (
    r"C:\Windows\System32\*.exe",
    r"C:\Windows\System32\*.dll",
    r"C:\Windows\System32\*.sys",
)
LIMIT_PER_PATTERN = 60

#: 用于真阳性验证的规则。挑判据是纯字符串、且字符串条数少的——
#: 这类规则最稳定，不会被上游频繁改动。
SYNTHETIC_CASES = (
    ("APT_RANSOM_Lockbit_ForensicArtifacts_Nov23", "apt_ransom_lockbit_citrixbleed_nov23.yar"),
    ("RAT_DarkComet", "gen_rats_malwareconfig.yar"),
    ("APT_CryWiper_Dec22", "apt_ru_crywiper.yar"),
)


@pytest.fixture(scope="module")
def engine() -> YaraEngine:
    eng = YaraEngine(settings.rules_dirs)
    if not eng.available():
        pytest.skip(f"YARA 规则未加载：{eng.unavailable_reason()}")
    return eng


def _system_binaries() -> list[Path]:
    out: list[Path] = []
    for pattern in SCAN_PATTERNS:
        out.extend(Path(p) for p in glob.glob(pattern)[:LIMIT_PER_PATTERN])
    return out


_RULE_RE = re.compile(r"^\s*(?:private\s+)?rule\s+(\w+)\s*(?::[\w\s]+)?\{", re.M)
_LIT_RE = re.compile(r'=\s*"((?:[^"\\]|\\.)*)"')


def _synthetic_payload(rule_name: str, source: str) -> bytes | None:
    """把某条规则的字符串抽出来拼成载荷。

    这样样本总是跟着规则走：规则改了就跟着改，规则没了就返回 None 让测试
    跳过，而不是留一个悄悄失效的硬编码字符串。
    """
    path = settings.community_rules_dir / source
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")

    body = None
    for m in _RULE_RE.finditer(text):
        if m.group(1) != rule_name:
            continue
        start = i = m.end() - 1
        depth = 0
        while i < len(text):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    body = text[start : i + 1]
                    break
            elif ch in "\"'":
                quote = ch
                i += 1
                while i < len(text) and text[i] != quote:
                    if text[i] == "\\":
                        i += 1
                    i += 1
            i += 1
        break
    if body is None:
        return None

    parts = body.split("strings:", 1)
    if len(parts) < 2:
        return None
    seg = parts[1].split("condition:", 1)[0]

    lits: list[str] = []
    for m in _LIT_RE.finditer(seg):
        raw = m.group(1)
        try:
            val = raw.encode().decode("unicode_escape")
        except UnicodeDecodeError:
            val = raw
        if 4 <= len(val) <= 300:
            lits.append(val)
    if not lits:
        return None
    return b"\r\n".join(s.encode("latin-1", "ignore") for s in lits) + b"\r\n"


class TestTruePositives:
    """规则确实能检出东西。

    没有这组测试，"零误报"可以靠一条规则都不加载来满足——那测试就是摆设。
    """

    @pytest.mark.parametrize("rule_name, source", SYNTHETIC_CASES, ids=[c[0] for c in SYNTHETIC_CASES])
    def test_synthetic_sample_detected(
        self, engine: YaraEngine, make_context, tmp_path: Path, benign_pe_bytes: bytes,
        rule_name: str, source: str,
    ):
        payload = _synthetic_payload(rule_name, source)
        if payload is None:
            pytest.skip(
                f"规则 {rule_name} 不在 {source} 里——上游规则集可能已改名，"
                "跑 `python -m app.cli update yara` 后重试"
            )

        target = tmp_path / "synthetic.exe"
        target.write_bytes(benign_pe_bytes + b"\r\n" + payload)

        result = engine.timed_scan(make_context(target))
        assert result.verdict.is_detection, (
            f"规则 {rule_name} 没能检出由它自己的字符串构造的样本。"
            "要么规则没被加载，要么判据不只是字符串匹配。"
        )

        matches = (result.meta or {}).get("matches") or []
        assert matches, "命中时没有返回 matches 详情"
        assert matches[0].get("rule"), "matches 里缺少规则名"
        assert "namespace" in matches[0], "matches 里缺少命名空间"


@pytest.mark.windows_only
class TestNoFalsePositives:
    """干净的系统文件绝不能被任何规则命中。"""

    def test_calc_not_flagged(self, engine: YaraEngine, make_context, benign_pe: Path):
        result = engine.timed_scan(make_context(benign_pe))
        assert result.verdict.value == "clean", (
            f"{benign_pe.name} 被规则误报为 {result.verdict.value}："
            f"{result.signature}（命中 {result.meta.get('matches')}）"
        )

    def test_all_system_binaries_clean(self, engine: YaraEngine, make_context):
        """扫描一批系统程序，任何一个被命中都算失败。

        只测一个文件不够——不同程序的导入表差异很大。
        """
        candidates = _system_binaries()
        if not candidates:
            pytest.skip("找不到系统二进制")

        flagged = []
        for path in candidates:
            try:
                result = engine.timed_scan(make_context(path))
            except Exception:  # noqa: BLE001 - 个别文件可能读不了
                continue
            if result.verdict.value != "clean":
                flagged.append((path.name, result.signature))

        assert not flagged, (
            f"有 {len(flagged)} 个系统文件被误报（共扫描 {len(candidates)} 个）：\n"
            + "\n".join(f"  {name}  ←  {sig}" for name, sig in flagged[:10])
            + "\n\n定位用：python tools/diag_fp.py"
        )


class TestLoader:
    """加载器必须容错——第三方规则集里总有编不过的文件。"""

    def test_skips_broken_rules_instead_of_dying(self, tmp_path: Path):
        """一个编不过的规则文件，不能让整个规则库失效。

        这是真实场景：signature-base 747 个文件里有 13 个用到了本机 yara
        构建没编进去的模块，或需要 filepath 之类的外部变量。而
        `yara.compile(filepaths=...)` 是原子的——不退化就全军覆没。
        """
        (tmp_path / "good.yar").write_text(
            "rule Good_Rule { condition: uint16(0) == 0x5A4D }", encoding="utf-8"
        )
        (tmp_path / "broken.yar").write_text(
            "rule Broken_Rule { condition: this_function_does_not_exist }",
            encoding="utf-8",
        )

        eng = YaraEngine(tmp_path)
        assert eng.available(), "坏文件不应该让整个规则库加载失败"
        assert eng.skipped, "被跳过的坏文件应该被如实记录下来"
        assert eng.skipped[0][0] == "broken.yar"

    def test_empty_dir_gives_actionable_error(self, tmp_path: Path):
        eng = YaraEngine(tmp_path)
        assert not eng.available()
        assert "setup-yara" in eng.unavailable_reason(), (
            "规则目录为空时应该告诉用户怎么装规则集"
        )


class TestVerdictMapping:
    """第三方规则不带 verdict meta，判定等级由这里推导。"""

    def test_score_maps_to_malicious(self):
        from app.engines.yara_engine import _verdict_for

        assert _verdict_for("Anything", {"score": 100}) == "malicious"
        assert _verdict_for("Anything", {"score": 75}) == "malicious"
        assert _verdict_for("Anything", {"score": 70}) == "suspicious"

    def test_explicit_verdict_wins(self):
        from app.engines.yara_engine import _verdict_for

        assert _verdict_for("SUSP_Whatever", {"verdict": "malicious"}) == "malicious"

    def test_pup_prefix(self):
        from app.engines.yara_engine import _verdict_for

        assert _verdict_for("PUA_SomeAdware", {}) == "pup"

    def test_known_family_prefix(self):
        from app.engines.yara_engine import _verdict_for

        assert _verdict_for("MAL_Win_Emotet", {}) == "malicious"
        assert _verdict_for("RANSOM_LockBit", {}) == "malicious"

    def test_unknown_defaults_to_suspicious(self):
        from app.engines.yara_engine import _verdict_for

        assert _verdict_for("Some_Random_Rule", {}) == "suspicious"
