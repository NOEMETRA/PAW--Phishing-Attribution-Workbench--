"""Shared nullable contract for whole-day scalar ages, not registry verification."""
import math


def usable_age_days(value):
    """Accept whole numeric days representable in SQLite; never coerce unknown to zero."""
    if isinstance(value,bool) or not isinstance(value,(int,float)):
        return None
    if isinstance(value,float) and (not math.isfinite(value) or not value.is_integer()):
        return None
    # Check before conversion: huge ints/floats must not overflow storage or be
    # rounded into a valid-looking age. The limit is storage, not plausible age.
    if not 0 <= value <= 2**63-1:
        return None
    return int(value)
