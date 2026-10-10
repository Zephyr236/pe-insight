"""YARA 引擎的规则测试——**两个引擎跑同一套契约**。

经典 YARA 和 YARA-X 跑的是同一批规则，所以这里用参数化夹具让每个用例
在两个引擎上各跑一遍。只测一个的话，某个引擎静默加载失败或行为漂移
不会被发现——而"两个引擎结果不一致"恰恰是最需要被发现的。

历史上吃过一次亏：反调试规则写成"出现 3 个以上反调试 API 就算"，结果在
notepad.exe 上误报了——正常 Windows 程序合法导入 IsDebuggerPresent 这类
API。一条会在系统文件上误报的规则，比没有规则更糟：它会让人不再看结果。

规则现在来自第三方（signature-base，由 setup-yara 下载），但契约不变，
而且更重要：5000+ 条规则全都要在干净的系统文件上保持沉默。
"""

from __future__ import annotations

import glob
import re
from pathlib import Path

import pytest

from app.config import settings
from app.engines.base import EngineAdapter
from app.engines.yara_engine import YaraEngine
from app.engines.yara_x_engine import YaraXEngine

#: 两个引擎共用的契约，在这里各跑一遍
ENGINE_CLASSES = {"yara": YaraEngine, "yara-x": YaraXEngine}

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


@pytest.fixture(scope="module", params=sorted(ENGINE_CLASSES))
def engine(request) -> EngineAdapter:
    eng = ENGINE_CLASSES[request.param](settings.rules_dirs)
    if not eng.available():
        pytest.skip(f"{eng.name} 规则未加载：{eng.unavailable_reason()}")
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

    @pytest.mark.parametrize(
        "rule_name, source", SYNTHETIC_CASES, ids=[c[0] for c in SYNTHETIC_CASES]
    )
    def test_synthetic_sample_detected(
        self,
        engine: EngineAdapter,
        make_context,
        tmp_path: Path,
        benign_pe_bytes: bytes,
        rule_name: str,
        source: str,
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
            f"{engine.name} 没能用规则 {rule_name} 检出由它自己的字符串构造的样本。"
            "要么规则没被加载，要么判据不只是字符串匹配。"
        )

        matches = (result.meta or {}).get("matches") or []
        assert matches, "命中时没有返回 matches 详情"
        assert matches[0].get("rule"), "matches 里缺少规则名"


@pytest.mark.windows_only
class TestNoFalsePositives:
    """干净的系统文件绝不能被任何规则命中。"""

    def test_calc_not_flagged(self, engine: EngineAdapter, make_context, benign_pe: Path):
        result = engine.timed_scan(make_context(benign_pe))
        assert result.verdict.value == "clean", (
            f"{engine.name} 把 {benign_pe.name} 误报为 {result.verdict.value}："
            f"{result.signature}（命中 {result.meta.get('matches')}）"
        )

    def test_all_system_binaries_clean(self, engine: EngineAdapter, make_context):
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
            f"{engine.name} 误报了 {len(flagged)} 个系统文件"
            f"（共扫描 {len(candidates)} 个）：\n"
            + "\n".join(f"  {name}  ←  {sig}" for name, sig in flagged[:10])
            + "\n\n定位用：python tools/diag_fp.py"
        )


class TestLoader:
    """加载器必须容错——第三方规则集里总有编不过的文件。"""

    def test_skips_broken_rules_instead_of_dying(self, engine_cls, tmp_path: Path):
        """一个编不过的规则文件，不能让整个规则库失效。

        这是真实场景：signature-base 747 个文件里有 13 个用到外部变量
        （filename / filepath / extension），需要 THOR 那类扫描器通过 -d
        传值。不退化就是整个规则库全废。
        """
        (tmp_path / "good.yar").write_text(
            "rule Good_Rule { condition: uint16(0) == 0x5A4D }", encoding="utf-8"
        )
        (tmp_path / "broken.yar").write_text(
            "rule Broken_Rule { condition: this_function_does_not_exist }",
            encoding="utf-8",
        )

        eng = engine_cls(tmp_path)
        assert eng.available(), "坏文件不应该让整个规则库加载失败"
        assert eng.skipped, "被跳过的坏文件应该被如实记录下来"
        assert eng.skipped[0][0] == "broken.yar"

    def test_empty_dir_gives_actionable_error(self, engine_cls, tmp_path: Path):
        eng = engine_cls(tmp_path)
        assert not eng.available()
        assert "setup-yara" in eng.unavailable_reason(), (
            "规则目录为空时应该告诉用户怎么装规则集"
        )


@pytest.fixture(params=sorted(ENGINE_CLASSES))
def engine_cls(request):
    return ENGINE_CLASSES[request.param]


class TestEngineAgreement:
    """两个引擎跑同一批规则，必须给出同样的结论。"""

    def test_same_source_group(self):
        for cls in ENGINE_CLASSES.values():
            eng = cls(settings.rules_dirs)
            assert eng.source_group == "yara-rules", (
                f"{eng.name} 必须和另一个 YARA 引擎同组，否则聚合判定会把"
                "同一次命中数成两票"
            )

    def test_hit_the_same_rule(self, make_context, tmp_path: Path, benign_pe_bytes: bytes):
        """同一个合成样本，两个引擎应该命中同一批规则。

        这是加 YARA-X 的意义所在：互为交叉验证。如果两边结果对不上，
        说明某一边对这条规则的处理有问题，值得单独查。
        """
        rule_name, source = SYNTHETIC_CASES[0]
        payload = _synthetic_payload(rule_name, source)
        if payload is None:
            pytest.skip("规则缺失")

        target = tmp_path / "agree.exe"
        target.write_bytes(benign_pe_bytes + b"\r\n" + payload)
        ctx = make_context(target)

        hits = {}
        for label, cls in ENGINE_CLASSES.items():
            eng = cls(settings.rules_dirs)
            if not eng.available():
                pytest.skip(f"{eng.name} 未就绪")
            result = eng.timed_scan(ctx)
            hits[label] = {m["rule"] for m in (result.meta or {}).get("matches", [])}

        assert hits["yara"], "经典 YARA 没命中"
        assert hits["yara-x"], "YARA-X 没命中"
        assert hits["yara"] == hits["yara-x"], (
            f"两个引擎命中的规则不一致：\n"
            f"  只在 YARA   : {hits['yara'] - hits['yara-x']}\n"
            f"  只在 YARA-X : {hits['yara-x'] - hits['yara']}"
        )
