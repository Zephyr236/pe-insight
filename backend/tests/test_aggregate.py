"""聚合判定的同源去重。

YARA 和 YARA-X 跑的是同一批规则。如果各算一票，一次命中会显示成
"2/9"——同一个证据被数了两次，检测比例虚高。所以比例按"来源"统计。

这个测试很重要：去重逻辑写错的后果是**结论看起来更严重**，不会报错，
只会让人高估证据强度。
"""

from __future__ import annotations

from app.engines.base import EngineResult, Verdict
from app.orchestrator import aggregate


def _result(engine: str, verdict: Verdict, group: str | None = None) -> EngineResult:
    return EngineResult(engine=engine, verdict=verdict, source_group=group)


class TestSameSourceDedup:
    def test_two_same_group_detections_count_once(self):
        """同组两个引擎都命中，只算一票，但引擎命中数如实保留。"""
        results = [
            _result("YARA", Verdict.MALICIOUS, "yara-rules"),
            _result("YARA-X", Verdict.MALICIOUS, "yara-rules"),
            _result("ClamAV", Verdict.CLEAN),
            _result("Defender", Verdict.CLEAN),
        ]
        agg = aggregate(results)

        assert agg["verdict"] == "malicious"
        assert agg["detection_ratio"] == "1/3", "同源的两个引擎应该只占一票"
        assert agg["engines_hit"] == 2, "引擎层面的命中数仍要如实反映"

    def test_group_counts_when_only_one_member_hits(self):
        """组内只要有一个命中，这一票就算命中。"""
        results = [
            _result("YARA", Verdict.CLEAN, "yara-rules"),
            _result("YARA-X", Verdict.MALICIOUS, "yara-rules"),
            _result("ClamAV", Verdict.CLEAN),
        ]
        agg = aggregate(results)
        assert agg["detection_ratio"] == "1/2"
        assert agg["engines_hit"] == 1

    def test_group_clean_when_no_member_hits(self):
        results = [
            _result("YARA", Verdict.CLEAN, "yara-rules"),
            _result("YARA-X", Verdict.CLEAN, "yara-rules"),
            _result("ClamAV", Verdict.CLEAN),
        ]
        agg = aggregate(results)
        assert agg["verdict"] == "clean"
        assert agg["detection_ratio"] == "0/2"

    def test_ungrouped_engines_count_separately(self):
        """没有分组的引擎各自一票——去重只作用于声明了同源的引擎。"""
        results = [
            _result("ClamAV", Verdict.MALICIOUS),
            _result("Defender", Verdict.MALICIOUS),
        ]
        agg = aggregate(results)
        assert agg["detection_ratio"] == "2/2"
        assert agg["engines_hit"] == 2


class TestRatioConsistency:
    def test_ratio_matches_the_numbers(self):
        results = [
            _result("YARA", Verdict.SUSPICIOUS, "yara-rules"),
            _result("YARA-X", Verdict.SUSPICIOUS, "yara-rules"),
            _result("ClamAV", Verdict.CLEAN),
        ]
        agg = aggregate(results)
        assert agg["detection_ratio"] == f"{agg['detections']}/{agg['engine_total']}"

    def test_skipped_engines_excluded(self):
        results = [
            _result("YARA", Verdict.MALICIOUS, "yara-rules"),
            _result("Emsisoft", Verdict.SKIPPED),
        ]
        agg = aggregate(results)
        assert agg["engine_total"] == 1
        assert agg["detection_ratio"] == "1/1"

    def test_all_errored_gives_unknown(self):
        results = [_result("YARA", Verdict.ERROR, "yara-rules")]
        agg = aggregate(results)
        assert agg["verdict"] == "unknown"
        assert agg["errored_engines"] == ["YARA"]
