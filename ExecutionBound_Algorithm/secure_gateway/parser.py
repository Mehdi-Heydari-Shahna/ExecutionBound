"""Strict parsing of untrusted action proposals."""
from __future__ import annotations

import json
import math

ALLOWED_FIELDS = frozenset(("skill", "target_xyz", "destination", "speed_m_s", "depth_m", "volume_m3", "frame", "units"))


def parse_candidate(raw):
    """Strict finite JSON; one optional entire-response Markdown fence is tolerated.

    No substring search, Python evaluation, coerced numeric strings, unknown keys,
    duplicated JSON keys, or model-selected authority metadata are accepted.
    """
    if not isinstance(raw, str):
        raise ValueError("model response is not text")
    text = raw.strip()
    if text.startswith("```json\n") and text.endswith("\n```"):
        text = text[len("```json\n"):-len("\n```")].strip()
    elif text.startswith("```\n") and text.endswith("\n```"):
        text = text[len("```\n"):-len("\n```")].strip()
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate JSON key:" + k)
            out[k] = v
        return out
    def nonfinite(value):
        raise ValueError("nonfinite JSON literal:" + value)
    def finite(v):
        try:
            return math.isfinite(v)
        except OverflowError:
            return False
    try:
        result = json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    except RecursionError as exc:
        raise ValueError("JSON nesting too deep") from exc
    if not isinstance(result, dict) or "target_xyz" not in result or set(result) - ALLOWED_FIELDS:
        raise ValueError("candidate must contain target_xyz and only permitted action-value keys")
    xyz = result["target_xyz"]
    if not isinstance(xyz, list) or len(xyz) != 3:
        raise ValueError("target_xyz must be a three-number array")
    numbers = list(xyz) + [result[k] for k in ("speed_m_s", "depth_m", "volume_m3") if k in result]
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not finite(v) for v in numbers):
        raise ValueError("candidate numerics must be finite JSON numbers")
    if any(not isinstance(result[k], str) for k in ("skill", "destination", "frame", "units") if k in result):
        raise ValueError("candidate names must be JSON strings")
    return result
