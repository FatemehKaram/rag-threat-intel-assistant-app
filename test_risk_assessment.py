"""Offline regression tests for deterministic risk classification."""

import unittest
from risk_assessment import assess_feed_risk


class RiskAssessmentTests(unittest.TestCase):
    def test_clean_ip_zero_scores_is_low(self):
        feeds = [{"source": "AlienVault OTX", "pulse_count": 0},
                 {"source": "AbuseIPDB", "confidence": 0}]
        self.assertEqual(assess_feed_risk(feeds, "ip"), ("Low", 0.15))

    def test_one_valid_zero_feed_is_low_for_ip(self):
        feeds = [{"error": "request timeout"},
                 {"source": "AbuseIPDB", "confidence": 0}]
        self.assertEqual(assess_feed_risk(feeds, "ip"), ("Low", 0.15))

    def test_both_feeds_unavailable_is_unknown(self):
        self.assertEqual(assess_feed_risk([{"error": "timeout"}], "ip"), ("Unknown", 0.0))
        self.assertEqual(assess_feed_risk([], "ip"), ("Unknown", 0.0))

    def test_missing_api_keys_do_not_count_as_zero(self):
        feeds = [{"source": "AlienVault OTX", "pulse_count": 0, "note": "API key not configured"},
                 {"source": "AbuseIPDB", "confidence": 0, "note": "API key not configured"}]
        self.assertEqual(assess_feed_risk(feeds, "ip"), ("Unknown", 0.0))

    def test_malformed_empty_feed_is_unknown(self):
        self.assertEqual(assess_feed_risk([{"source": "AbuseIPDB"}], "ip"), ("Unknown", 0.0))
        self.assertEqual(assess_feed_risk([{"source": "AlienVault OTX"}], "ip"), ("Unknown", 0.0))

    def test_unverifiable_domain_and_hash_are_unknown(self):
        feeds = [{"source": "AlienVault OTX", "pulse_count": 0}]
        self.assertEqual(assess_feed_risk(feeds, "domain"), ("Unknown", 0.0))
        self.assertEqual(assess_feed_risk(feeds, "hash"), ("Unknown", 0.0))

    def test_otx_positive_domain_is_medium(self):
        self.assertEqual(assess_feed_risk([{"source": "AlienVault OTX", "pulse_count": 1}], "domain"),
                         ("Medium", 0.5))

    def test_high_thresholds(self):
        self.assertEqual(assess_feed_risk([{"source": "AbuseIPDB", "confidence": 90}], "ip"), ("High", 0.9))
        self.assertEqual(assess_feed_risk([{"source": "AlienVault OTX", "pulse_count": 5}], "domain"),
                         ("High", 0.75))

    def test_medium_threshold(self):
        self.assertEqual(assess_feed_risk([{"source": "AbuseIPDB", "confidence": 50}], "ip"),
                         ("Medium", 0.5))

    def test_low_nonzero_below_threshold(self):
        self.assertEqual(assess_feed_risk([{"source": "AbuseIPDB", "confidence": 10}], "ip"), ("Low", 0.15))

    def test_invalid_numeric_values_do_not_count(self):
        for bad in (None, -1, 101, float('nan'), float('inf'), True, "0"):
            self.assertEqual(assess_feed_risk([{"source": "AbuseIPDB", "confidence": bad}], "ip"),
                             ("Unknown", 0.0))
        for bad in (None, -1, float('nan'), float('inf'), True, 0.5, "0"):
            self.assertEqual(assess_feed_risk([{"source": "AlienVault OTX", "pulse_count": bad}], "ip"),
                             ("Unknown", 0.0))


if __name__ == "__main__":
    unittest.main()
