"""A deterministic JSON value with canonical (JCS-style) encoding.

Objects are stored in a plain ``dict`` but always serialised with keys sorted
ascending by Unicode code point, so the output is deterministic. Numbers are
integers only; floats and exponents are rejected, as the specification requires
(SPEC.md §2.2).

Parsing uses the standard library :mod:`json` for correct lexing, with hooks
that reject floats (``parse_float``) and non-canonical integers such as ``-0``
or leading zeros (``parse_int``).

SPDX-License-Identifier: CC-BY-4.0
"""

from __future__ import annotations

import json as _json
from typing import Any, Iterator

from .errors import ERR_MALFORMED, GdwError

# A JSON value in canonical GDW form: None, bool, int, str, list, dict.
Json = Any


def obj() -> dict:
    """A new empty JSON object."""
    return {}


def get(value: Json, key: str) -> Any:
    """Fetch a key from a JSON object, or ``None``."""
    if isinstance(value, dict):
        return value.get(key)
    return None


def has(value: Json, key: str) -> bool:
    return isinstance(value, dict) and key in value


def as_str(value: Json) -> "str | None":
    return value if isinstance(value, str) else None


def as_int(value: Json) -> "int | None":
    # bool is a subclass of int in Python; exclude it explicitly.
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def is_object(value: Json) -> bool:
    return isinstance(value, dict)


def is_array(value: Json) -> bool:
    return isinstance(value, list)


def entries(value: Json) -> Iterator[tuple[str, Any]]:
    """Iterate object entries in canonical (sorted) order."""
    if isinstance(value, dict):
        for key in sorted(value.keys()):
            yield key, value[key]


def _reject_float(_text: str) -> Any:
    raise GdwError(ERR_MALFORMED)


def _parse_int(text: str) -> int:
    # Reject non-canonical integer forms ("-0", leading zeros).
    stripped = text[1:] if text.startswith("-") else text
    if stripped != "0" and stripped.startswith("0"):
        raise GdwError(ERR_MALFORMED)
    if text == "-0":
        raise GdwError(ERR_MALFORMED)
    value = int(text)
    if value < -(2**53 - 1) or value > 2**53 - 1:
        raise GdwError(ERR_MALFORMED)
    return value


def parse(text: str) -> Json:
    """Parse a JSON document, rejecting floats/exponents (integers only)."""
    try:
        return _json.loads(
            text,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_float,
        )
    except GdwError:
        raise
    except (ValueError, TypeError, RecursionError):
        raise GdwError(ERR_MALFORMED)


def _write_string(out: list[str], value: str) -> None:
    out.append('"')
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')


def _write(out: list[str], value: Json) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, str):
        _write_string(out, value)
    elif isinstance(value, list):
        out.append("[")
        for i, item in enumerate(value):
            if i > 0:
                out.append(",")
            _write(out, item)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for i, key in enumerate(sorted(value.keys())):
            if i > 0:
                out.append(",")
            _write_string(out, key)
            out.append(":")
            _write(out, value[key])
        out.append("}")
    else:
        raise GdwError(ERR_MALFORMED)


def canonical(value: Json) -> str:
    """Canonical serialisation (sorted keys, no whitespace, integers only)."""
    out: list[str] = []
    _write(out, value)
    return "".join(out)
