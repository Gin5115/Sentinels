"""
Detection mode configuration for Sentinels.

Controls which detection engines are active:
  'heuristic' — rule-based ThreatEngine only
  'ml'        — RandomForest flow classifier only (requires model)
  'both'      — run both engines independently (default)
"""

_VALID_MODES = ('heuristic', 'ml', 'both')
_detection_mode = 'both'


def get_detection_mode() -> str:
    return _detection_mode


def set_detection_mode(mode: str) -> bool:
    global _detection_mode
    if mode in _VALID_MODES:
        _detection_mode = mode
        return True
    return False
