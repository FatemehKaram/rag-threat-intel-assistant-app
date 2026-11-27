"""Deterministic risk assessment from usable threat-intelligence feed results."""

import math
from typing import Any, Dict, List, Tuple


def assess_feed_risk(raw_data: List[Dict[str, Any]], indicator_type: str) -> Tuple[str, float]:
    """Classify an indicator without mistaking missing evidence for a zero score.

    A valid, zero-valued reputation lookup supports LOW for an IP. An OTX lookup
    with no pulses does not establish whether a domain/hash is verifiable, so
    those indicators remain UNKNOWN without a positive intelligence signal.
    """
    max_abuse_confidence = None
    total_pulse_count = 0
    valid_otx = False
    valid_abuseipdb = False

    for entry in raw_data or []:
        if not isinstance(entry, dict) or entry.get("error") or entry.get("note"):
            continue

        source = entry.get("source")
        if source == "AbuseIPDB":
            confidence = entry.get("confidence")
            if (type(confidence) in (int, float)
                    and math.isfinite(confidence) and 0 <= confidence <= 100):
                valid_abuseipdb = True
                max_abuse_confidence = (float(confidence) if max_abuse_confidence is None
                                        else max(max_abuse_confidence, float(confidence)))
        elif source == "AlienVault OTX":
            count = entry.get("pulse_count")
            if (type(count) in (int, float)
                    and math.isfinite(count) and count >= 0 and float(count).is_integer()):
                valid_otx = True
                total_pulse_count += int(count)

    # Preserve the existing HIGH and MEDIUM rules and scores.
    if (max_abuse_confidence is not None and max_abuse_confidence >= 70) or total_pulse_count >= 5:
        return "High", 0.9 if max_abuse_confidence is not None and max_abuse_confidence >= 90 else 0.75

    if (max_abuse_confidence is not None and max_abuse_confidence >= 30) or total_pulse_count >= 1:
        base = 0.5
        if max_abuse_confidence is not None:
            base = max(base, 0.3 + (max_abuse_confidence / 100) * 0.4)
        if total_pulse_count:
            base = max(base, 0.45 + min(total_pulse_count, 5) * 0.05)
        return "Medium", min(base, 0.7)

    # For domains/hashes, zero OTX pulses alone does not verify the indicator.
    if indicator_type == "ip" and (valid_otx or valid_abuseipdb):
        return "Low", 0.15

    return "Unknown", 0.0
