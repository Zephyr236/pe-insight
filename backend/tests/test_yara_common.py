"""两个 YARA 引擎共用的判定语义。

第三方规则集不带 `meta.verdict`，判定等级要从规则名前缀和 `meta.score`
推导。这套逻辑必须两边共用——同一个样本在两个引擎上给出不同结论是
灾难性的。
"""

from __future__ import annotations

from pathlib import Path

from app.engines.yara_common import (
    SOURCE_GROUP,
    collect_rule_files,
    namespace_for,
    sort_hits,
    unique_namespaces,
    verdict_for,
)


class TestVerdictMapping:
    def test_score_maps_to_malicious(self):
        assert verdict_for("Anything", {"score": 100}) == "malicious"
        assert verdict_for("Anything", {"score": 75}) == "malicious"
        assert verdict_for("Anything", {"score": 70}) == "suspicious"

    def test_score_accepts_string(self):
        """YARA-X 的 metadata 保留原始类型，但 yara-python 可能给字符串。"""
        assert verdict_for("Anything", {"score": "90"}) == "malicious"

    def test_explicit_verdict_wins(self):
        assert verdict_for("SUSP_Whatever", {"verdict": "malicious"}) == "malicious"

    def test_pup_prefix(self):
        assert verdict_for("PUA_SomeAdware", {}) == "pup"
        assert verdict_for("PUP_Something", {}) == "pup"

    def test_known_family_prefix(self):
        assert verdict_for("MAL_Win_Emotet", {}) == "malicious"
        assert verdict_for("RANSOM_LockBit", {}) == "malicious"
        assert verdict_for("APT_APT29", {}) == "malicious"

    def test_unknown_defaults_to_suspicious(self):
        assert verdict_for("Some_Random_Rule", {}) == "suspicious"

    def test_garbage_score_does_not_crash(self):
        assert verdict_for("Some_Rule", {"score": "not-a-number"}) == "suspicious"


class TestSortHits:
    def test_most_severe_first(self):
        """顺序不能由引擎决定——否则 signature 会取到次要规则。"""
        hits = [
            {"rule": "low", "verdict": "suspicious"},
            {"rule": "high", "verdict": "malicious"},
            {"rule": "mid", "verdict": "pup"},
        ]
        assert [h["rule"] for h in sort_hits(hits)] == ["high", "mid", "low"]


class TestRuleDiscovery:
    def test_collects_both_suffixes(self, tmp_path: Path):
        (tmp_path / "a.yar").write_text("rule A { condition: true }", encoding="utf-8")
        (tmp_path / "b.yara").write_text("rule B { condition: true }", encoding="utf-8")
        (tmp_path / "c.txt").write_text("not a rule", encoding="utf-8")

        found = collect_rule_files([tmp_path])
        assert sorted(p.name for p, _ in found) == ["a.yar", "b.yara"]

    def test_missing_dir_is_not_an_error(self, tmp_path: Path):
        assert collect_rule_files([tmp_path / "nope"]) == []

    def test_namespaces_are_unique_across_dirs(self, tmp_path: Path):
        """两个目录里的同名文件不能撞命名空间——撞了 compile 会直接失败。"""
        (tmp_path / "one").mkdir()
        (tmp_path / "two").mkdir()
        for sub in ("one", "two"):
            (tmp_path / sub / "same.yar").write_text("rule R { condition: true }", encoding="utf-8")

        found = collect_rule_files([tmp_path / "one", tmp_path / "two"])
        names = [ns for _, ns in unique_namespaces(found)]
        assert len(names) == len(set(names)), f"命名空间重复：{names}"


class TestSourceGroup:
    def test_constant_is_stable(self):
        """聚合判定按这个字符串分组，改了会让去重失效。"""
        assert SOURCE_GROUP == "yara-rules"
