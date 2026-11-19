"""Strict RFC 8785 JSON Canonicalization Scheme (JCS) + anti-differential parser.

Fixes prior orchestrators defects F-01 and F-02:
- Exact ECMAScript Number::toString formatting for floats (1e-5 -> 0.00001, 1e-7 -> 1e-7, -0.0 -> 0)
- Rejects NaN, +-Infinity, lone UTF-16 surrogates, and duplicate JSON object keys
- Rejects integers exceeding IEEE-754 exact safe integer range (|n| > 2^53 - 1)
"""
from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any, List, Tuple


MAX_SAFE_INT = (1 << 53) - 1


class JCSValidationError(ValueError):
    """Raised when input violates RFC 8785 JCS or anti-differential safety rules."""


class DuplicateKeyError(JCSValidationError):
    """Raised when raw JSON bytes contain duplicate object keys."""


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> dict:
    obj: dict = {}
    for k, v in pairs:
        if k in obj:
            raise DuplicateKeyError(f"Duplicate JSON object key rejected: {k!r}")
        _validate_string_no_surrogates(k)
        obj[k] = v
    return obj


def parse_json_strict(raw: str | bytes) -> Any:
    """Parse JSON rejecting duplicate keys, NaN/Infinity, and lone surrogates."""
    if isinstance(raw, bytes):
        try:
            raw_str = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise JCSValidationError(f"Invalid UTF-8 in JSON frame: {exc}") from exc
    elif isinstance(raw, str):
        raw_str = raw
    else:
        raise JCSValidationError(f"Expected str or bytes, got {type(raw).__name__}")

    def _bad_constant(val: str) -> Any:
        raise JCSValidationError(f"Non-RFC-8785 JSON constant rejected: {val}")

    try:
        parsed = json.loads(
            raw_str,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_bad_constant,
        )
    except JCSValidationError:
        raise
    except Exception as exc:
        raise JCSValidationError(f"Malformed JSON payload: {exc}") from exc

    return parsed


def _validate_string_no_surrogates(s: str) -> None:
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise JCSValidationError(f"Lone UTF-16 surrogate U+{cp:04X} rejected")


def _utf16_sort_key(s: str) -> bytes:
    _validate_string_no_surrogates(s)
    return s.encode("utf-16-be")


def _format_ecmascript_number(value: int | float) -> str:
    if isinstance(value, bool):
        raise JCSValidationError("Boolean is not a JSON number")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise JCSValidationError(
                f"Integer {value} exceeds IEEE-754 safe range (+/-{MAX_SAFE_INT})"
            )
        return str(value)
    if not math.isfinite(value):
        raise JCSValidationError(f"Non-finite float rejected by RFC 8785: {value}")
    if value == 0.0:
        return "0"

    sign = "-" if value < 0 else ""
    abs_val = abs(value)
    # Python 3.11+ repr(float) uses David Gay's shortest round-trip algorithm (ECMAScript compatible)
    d = Decimal(repr(abs_val)).normalize()
    sign_d, digits, exp = d.as_tuple()
    digits_str = "".join(str(dg) for dg in digits)
    # Strip trailing zeros in mantissa
    digits_stripped = digits_str.rstrip("0") or "0"
    num_stripped = len(digits_str) - len(digits_stripped)
    exp += num_stripped
    k = len(digits_stripped)
    # Scientific exponent n such that abs_val = d0.d1... * 10^(n-1), matching ECMAScript §7.1.12.1
    n = k + exp

    if k <= n <= 21:
        return sign + digits_stripped + ("0" * (n - k))
    if 0 < n <= 21:
        return sign + digits_stripped[:n] + "." + digits_stripped[n:]
    if -6 < n <= 0:
        return sign + "0." + ("0" * (-n)) + digits_stripped
    # Exponential notation
    e_val = n - 1
    e_sign = "+" if e_val >= 0 else "-"
    e_str = f"e{e_sign}{abs(e_val)}"
    if k == 1:
        return sign + digits_stripped + e_str
    return sign + digits_stripped[0] + "." + digits_stripped[1:] + e_str


def _serialize_jcs(obj: Any) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return _format_ecmascript_number(obj)
    if isinstance(obj, Decimal):
        if not obj.is_finite():
            raise JCSValidationError(f"Non-finite Decimal rejected: {obj}")
        return _format_ecmascript_number(float(obj))
    if isinstance(obj, str):
        _validate_string_no_surrogates(obj)
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_serialize_jcs(item) for item in obj) + "]"
    if isinstance(obj, dict):
        items = []
        for k in sorted(obj.keys(), key=_utf16_sort_key):
            if not isinstance(k, str):
                raise JCSValidationError(f"JSON object keys must be str, got {type(k).__name__}")
            items.append(f"{_serialize_jcs(k)}:{_serialize_jcs(obj[k])}")
        return "{" + ",".join(items) + "}"
    raise JCSValidationError(f"Unsupported type for RFC 8785 JCS: {type(obj).__name__}")


def jcs_dumps(obj: Any) -> str:
    """Serialize Python object to canonical RFC 8785 JCS string."""
    return _serialize_jcs(obj)


def jcs_bytes(obj: Any) -> bytes:
    """Serialize Python object to canonical UTF-8 RFC 8785 JCS bytes."""
    return _serialize_jcs(obj).encode("utf-8", errors="strict")


def jcs_sha256(obj: Any) -> str:
    """Return lowercase hex SHA-256 of the RFC 8785 JCS canonical encoding."""
    return hashlib.sha256(jcs_bytes(obj)).hexdigest()
