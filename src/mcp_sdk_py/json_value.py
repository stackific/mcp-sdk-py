"""JSON Value Model, Type Notation, Numeric Handling & Forward Compatibility — S02.

Delivers:
- JSONValue / JSONObject / JSONArray type aliases (the universal wire value model)
- Object semantics: duplicate-name handling, order-independence
- Array semantics: order significance
- UTF-8 encoding/decoding helpers
- Case-sensitivity helper
- Forward-compatibility helpers (strip / preserve unknown keys)
- Numeric handling: safe-integer bounds and field validation
- Reserved _meta key grammar and namespace rules
- Extension method-name collision detection
- Enumeration policy (OPEN / CLOSED) and unknown-value handling
- ExtensionNotSupportedError for gating violations

Spec: §2.3–§2.6
"""

from __future__ import annotations

import enum
import json
import re
from typing import Any

from mcp_sdk_py.foundations import ConformanceError


# ---------------------------------------------------------------------------
# §2.3  JSONValue union and component type aliases  [R-2.3-a]
# ---------------------------------------------------------------------------

#: Unordered, string-keyed JSON object (§2.3.1).
JSONObject = dict[str, Any]

#: Ordered JSON array (§2.3.1).
JSONArray = list[Any]

#: The single value model for every wire value: one of six JSON forms.
#: (Recursive: JSONObject / JSONArray nest further JSONValues.)
JSONValue = str | int | float | bool | None | JSONObject | JSONArray


# ---------------------------------------------------------------------------
# §2.5  Numeric handling  [R-2.5-a – R-2.5-g]
# ---------------------------------------------------------------------------

#: Inclusive lower bound of the safe-integer range (R-2.5-c).
SAFE_INTEGER_MIN: int = -(2 ** 53 - 1)   # -9007199254740991

#: Inclusive upper bound of the safe-integer range (R-2.5-c).
SAFE_INTEGER_MAX: int = 2 ** 53 - 1       # 9007199254740991


def is_integer_value(value: int | float) -> bool:
  """Return True if value has no fractional component (R-2.5-a).

  booleans are excluded: Python's bool is a subclass of int, but
  ``true``/``false`` are not integer field values in the protocol.
  """
  if isinstance(value, bool):
    return False
  if isinstance(value, int):
    return True
  return value == int(value) and not isinstance(value, bool)


def is_within_safe_range(value: int | float) -> bool:
  """Return True if value lies within the safe-integer range (R-2.5-c, e)."""
  return SAFE_INTEGER_MIN <= value <= SAFE_INTEGER_MAX


def validate_integer_field(value: Any, field_name: str = "field") -> None:
  """Raise if value has a fractional component where an integer is required (R-2.5-b).

  Also rejects booleans and non-numeric types.
  """
  if isinstance(value, bool):
    raise TypeError(f"{field_name}: bool is not a valid integer field value")
  if not isinstance(value, (int, float)):
    raise TypeError(
      f"{field_name}: expected a number, got {type(value).__name__}"
    )
  if not is_integer_value(value):
    raise ValueError(
      f"{field_name}: integer field must have no fractional part (R-2.5-b); "
      f"got {value!r}"
    )


def validate_safe_integer(value: Any, field_name: str = "field") -> None:
  """Raise if value is outside the safe-integer range (R-2.5-c, R-2.5-d).

  Identifiers and counters (request ids, error codes, progress counters,
  pagination counters) MUST lie within the safe-integer range.
  """
  validate_integer_field(value, field_name)
  if not is_within_safe_range(value):
    raise ValueError(
      f"{field_name}: identifier/counter {value!r} is outside the safe-integer "
      f"range [{SAFE_INTEGER_MIN}, {SAFE_INTEGER_MAX}] (R-2.5-d)"
    )


def numbers_are_equal(a: int | float, b: int | float) -> bool:
  """Compare two JSON numbers for numeric equality regardless of textual form (R-2.5-g)."""
  return a == b


# ---------------------------------------------------------------------------
# §2.3.1  Object semantics — duplicate names  [R-2.3.1-a–f]
# ---------------------------------------------------------------------------

def last_occurrence_wins(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
  """Build a dict from key-value pairs, keeping only the last value per key.

  When a receiver encounters duplicate member names and does not reject the
  document as malformed, it MUST behave as though only the last occurrence of
  each name is present (R-2.3.1-c).
  """
  return dict(pairs)   # dict() natively keeps the last value for duplicate keys


# ---------------------------------------------------------------------------
# §2.3.2  Encoding  [R-2.3.2-a–d]
# ---------------------------------------------------------------------------

def encode_as_utf8(obj: Any) -> bytes:
  """Serialise obj to a UTF-8 JSON byte string (R-2.3.2-a, R-2.3.2-c)."""
  return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def decode_utf8_json(data: bytes) -> Any:
  """Parse a well-formed UTF-8 JSON document (R-2.3.2-b)."""
  return json.loads(data.decode("utf-8"))


# ---------------------------------------------------------------------------
# §2.3.3  Case sensitivity  [R-2.3.3-a, R-2.3.3-b]
# ---------------------------------------------------------------------------

def names_match(a: str, b: str) -> bool:
  """Protocol-defined name matching is case-sensitive (R-2.3.3-a).

  This is exactly ``a == b``.  Provided as a named function so call sites
  can signal their intent rather than relying on an implicit equality check.
  """
  return a == b


# ---------------------------------------------------------------------------
# §2.3.4  Forward compatibility: unknown object members  [R-2.3.4-a–g]
# ---------------------------------------------------------------------------

def strip_unknown_keys(
  data: dict[str, Any],
  known_keys: frozenset[str],
) -> dict[str, Any]:
  """Return a dict with only the recognised keys (R-2.3.4-a).

  Unknown members are silently dropped; the recognised members are returned
  unchanged.  Callers that want to preserve unknown keys should use
  :func:`preserve_unknown_keys` instead (R-2.3.4-d).
  """
  return {k: v for k, v in data.items() if k in known_keys}


def preserve_unknown_keys(
  data: dict[str, Any],
  known_keys: frozenset[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
  """Split data into (known, unknown) dicts (R-2.3.4-a, R-2.3.4-d).

  A receiver MAY preserve or forward unknown members (R-2.3.4-d).
  Returns ``(known, unknown)`` so the caller may choose what to do with
  the unrecognised portion.
  """
  known = {k: v for k, v in data.items() if k in known_keys}
  unknown = {k: v for k, v in data.items() if k not in known_keys}
  return known, unknown


# ---------------------------------------------------------------------------
# §2.6.1  Reserved method and notification prefixes  [R-2.6.1-a, R-2.6.1-b]
# ---------------------------------------------------------------------------

#: Base-protocol method and notification names.  Extensions MUST NOT use these
#: names and MUST namespace any names they introduce (R-2.6.1-a, R-2.6.1-b).
#: (Extended as later stories are implemented.)
BASE_METHOD_NAMES: frozenset[str] = frozenset({
  "ping",
  "server/discover",
  "tools/list", "tools/call",
  "resources/list", "resources/read",
  "resources/subscribe", "resources/unsubscribe",
  "prompts/list", "prompts/get",
  "completion/complete",
  "elicitation/create",
  "notifications/progress",
  "notifications/cancelled",
  "notifications/resources/updated",
  "notifications/resources/list_changed",
  "notifications/tools/list_changed",
  "notifications/prompts/list_changed",
  "notifications/message",
})


def is_base_method_name(name: str) -> bool:
  """Return True if name is reserved by the base protocol (R-2.6.1-a)."""
  return name in BASE_METHOD_NAMES


def validate_extension_method_name(name: str) -> None:
  """Raise if an extension's proposed name collides with the base protocol (R-2.6.1-a, b)."""
  if name in BASE_METHOD_NAMES:
    raise ValueError(
      f"Extension method/notification name {name!r} collides with a "
      f"base-protocol name (R-2.6.1-a)"
    )


# ---------------------------------------------------------------------------
# §2.6.2  Reserved _meta keys  [R-2.6.2-a–j]
# ---------------------------------------------------------------------------

# Grammar:
#   label    = [a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?   (single char ok)
#   prefix   = label ('.' label)* '/'
#   name     = '' | [a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?
#   meta_key = prefix? name

_LABEL_RE = re.compile(r'^[a-zA-Z]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$')
_PREFIX_RE = re.compile(
  r'^([a-zA-Z]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*'
  r'[a-zA-Z]([a-zA-Z0-9\-]*[a-zA-Z0-9])?/$'
)
_NAME_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9._\-]*[a-zA-Z0-9])?)?$')

#: Second-label values that mark a prefix as reserved (R-2.6.2-f).
RESERVED_SECOND_LABELS: frozenset[str] = frozenset({
  "modelcontextprotocol",
  "mcp",
})

#: Bare keys reserved for W3C trace-context propagation (R-2.6.2-i).
W3C_TRACE_KEYS: frozenset[str] = frozenset({
  "traceparent",
  "tracestate",
  "baggage",
})

# W3C Trace Context Level 1 traceparent format (https://www.w3.org/TR/trace-context/)
#   version "-" trace-id "-" parent-id "-" trace-flags
#   All fields are lowercase hexadecimal; version must not be "ff" (reserved).
_TRACEPARENT_RE = re.compile(
  r'^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
)
_TRACE_ID_ALL_ZEROS: str = '0' * 32
_PARENT_ID_ALL_ZEROS: str = '0' * 16


def validate_w3c_traceparent(value: str) -> None:
  """Validate a traceparent value against W3C Trace Context Level 1 (R-2.6.2-i).

  Format: version-traceId-parentId-flags (4 lowercase-hex fields, dash-separated).
  Rejects: wrong number of fields, non-hex chars, version 'ff', all-zero trace-id
  or parent-id.
  """
  if not _TRACEPARENT_RE.match(value):
    raise ValueError(
      f"traceparent value {value!r} does not match the W3C Trace Context format "
      f"'version-traceId-parentId-flags' (all lowercase hex) (R-2.6.2-i)"
    )
  parts = value.split('-', 3)
  version, trace_id, parent_id = parts[0], parts[1], parts[2]
  if version == 'ff':
    raise ValueError(
      f"traceparent version 'ff' is reserved and MUST NOT be used (R-2.6.2-i)"
    )
  if trace_id == _TRACE_ID_ALL_ZEROS:
    raise ValueError(
      f"traceparent trace-id MUST NOT be all zeros (R-2.6.2-i)"
    )
  if parent_id == _PARENT_ID_ALL_ZEROS:
    raise ValueError(
      f"traceparent parent-id MUST NOT be all zeros (R-2.6.2-i)"
    )


def validate_w3c_tracestate(value: str) -> None:
  """Validate a tracestate value against W3C Trace Context format (R-2.6.2-i).

  Each comma-separated list-member must be a 'key=value' pair with non-empty
  key and value.
  """
  if not value or not value.strip():
    raise ValueError("tracestate must not be empty (R-2.6.2-i)")
  members = [m.strip() for m in value.split(',')]
  members = [m for m in members if m]
  if not members:
    raise ValueError(
      "tracestate must contain at least one list-member (R-2.6.2-i)"
    )
  for member in members:
    if '=' not in member:
      raise ValueError(
        f"tracestate list-member {member!r} must be 'key=value' form (R-2.6.2-i)"
      )
    key, val = member.split('=', 1)
    if not key:
      raise ValueError(
        f"tracestate list-member key must not be empty (R-2.6.2-i)"
      )
    if not val:
      raise ValueError(
        f"tracestate list-member value for key {key!r} must not be empty (R-2.6.2-i)"
      )


def validate_w3c_baggage(value: str) -> None:
  """Validate a baggage value against W3C Baggage format (R-2.6.2-i).

  Each comma-separated list-member must be a 'name=value' pair (with optional
  ';property' suffixes) with non-empty name and value.
  """
  if not value or not value.strip():
    raise ValueError("baggage must not be empty (R-2.6.2-i)")
  members = [m.strip() for m in value.split(',')]
  members = [m for m in members if m]
  if not members:
    raise ValueError(
      "baggage must contain at least one list-member (R-2.6.2-i)"
    )
  for member in members:
    name_value_part = member.split(';')[0].strip()
    if '=' not in name_value_part:
      raise ValueError(
        f"baggage list-member {member!r} must be 'name=value' form (R-2.6.2-i)"
      )
    name, val = name_value_part.split('=', 1)
    if not name.strip():
      raise ValueError(
        f"baggage list-member name must not be empty (R-2.6.2-i)"
      )
    if not val:
      raise ValueError(
        f"baggage list-member value for name {name!r} must not be empty (R-2.6.2-i)"
      )


def validate_w3c_trace_value(key: str, value: str) -> None:
  """Validate the value of a W3C trace-context bare _meta key (R-2.6.2-i).

  Dispatches to the format-specific validator for traceparent, tracestate,
  or baggage.  Raises ValueError for an unrecognized key name.
  """
  if key == "traceparent":
    validate_w3c_traceparent(value)
  elif key == "tracestate":
    validate_w3c_tracestate(value)
  elif key == "baggage":
    validate_w3c_baggage(value)
  else:
    raise ValueError(
      f"{key!r} is not a W3C trace-context bare key "
      f"(expected one of {sorted(W3C_TRACE_KEYS)}) (R-2.6.2-i)"
    )


def is_valid_meta_label(label: str) -> bool:
  """Return True if label is a valid prefix label (R-2.6.2-c)."""
  return bool(_LABEL_RE.match(label))


def is_valid_meta_prefix(prefix: str) -> bool:
  """Return True if prefix conforms to the label grammar (R-2.6.2-b)."""
  return bool(_PREFIX_RE.match(prefix))


def is_reserved_meta_prefix(prefix: str) -> bool:
  """Return True if prefix's second label is 'modelcontextprotocol' or 'mcp' (R-2.6.2-f)."""
  if not prefix.endswith("/"):
    return False
  labels = prefix[:-1].split(".")
  return len(labels) >= 2 and labels[1] in RESERVED_SECOND_LABELS


def is_valid_meta_name(name: str) -> bool:
  """Return True if name conforms to the _meta key name grammar (R-2.6.2-g, h)."""
  return bool(_NAME_RE.match(name))


def parse_meta_key(key: str) -> tuple[str | None, str]:
  """Split a _meta key into (prefix_with_slash, name).

  Returns ``(None, key)`` when no slash is present.
  """
  slash_idx = key.find("/")
  if slash_idx == -1:
    return None, key
  return key[:slash_idx + 1], key[slash_idx + 1:]


def validate_meta_key_grammar(key: str) -> None:
  """Validate a _meta key against the grammar rules (R-2.6.2-b–h).

  Does NOT check for reserved-prefix violations; call
  :func:`validate_meta_key_not_reserved` for that check.
  """
  prefix, name = parse_meta_key(key)
  if prefix is not None and not is_valid_meta_prefix(prefix):
    raise ValueError(
      f"_meta key prefix {prefix!r} does not conform to the label grammar "
      f"(R-2.6.2-b, R-2.6.2-c)"
    )
  if not is_valid_meta_name(name):
    raise ValueError(
      f"_meta key name {name!r} does not conform to the name grammar (R-2.6.2-g)"
    )


def validate_meta_key_not_reserved(key: str) -> None:
  """Raise if key uses a reserved prefix (R-2.6.2-f)."""
  prefix, _ = parse_meta_key(key)
  if prefix is not None and is_reserved_meta_prefix(prefix):
    raise ValueError(
      f"_meta key {key!r} uses a reserved prefix (R-2.6.2-f); "
      f"reserved second labels: {sorted(RESERVED_SECOND_LABELS)}"
    )


# ---------------------------------------------------------------------------
# §2.6.3  Enumeration policy  [R-2.6.3-a–f]
# ---------------------------------------------------------------------------

class EnumerationPolicy(enum.Enum):
  """Controls handling of unrecognized values in an enumeration (§2.6.3).

  OPEN:   unknown values are tolerated; the defining section supplies the
          default handling rule (R-2.6.3-b).
  CLOSED: unknown values MUST be treated as invalid for that field (R-2.6.3-c).
  """

  OPEN = "open"
  CLOSED = "closed"


class UnknownEnumerationValueError(ConformanceError):
  """Raised when a CLOSED enumeration field receives an unrecognised value (R-2.6.3-c)."""


def handle_unknown_enum_value(
  value: str,
  policy: EnumerationPolicy,
  field_name: str = "field",
) -> None:
  """Apply the enumeration handling rule for an unrecognised value (R-2.6.3-a–c).

  For OPEN enumerations: no error (the value is tolerated; per-feature handling
  rules apply).  For CLOSED enumerations: raises UnknownEnumerationValueError.
  Either way the receiver MUST NOT crash or corrupt unrelated processing
  (R-2.6.3-a).
  """
  if policy is EnumerationPolicy.CLOSED:
    raise UnknownEnumerationValueError(
      f"{field_name}: unrecognised value {value!r} in a CLOSED enumeration (R-2.6.3-c)"
    )
  # OPEN: value is tolerated — do nothing (R-2.6.3-a)


# ---------------------------------------------------------------------------
# §2.6.4  Extension model  [R-2.6.4-a–d]
# ---------------------------------------------------------------------------

class ExtensionNotSupportedError(ConformanceError):
  """Raised when an endpoint uses an extension not declared by the peer (R-2.6.4-b).

  An endpoint MUST NOT use a method, notification, result type, error code, or
  capability contributed by an extension unless that extension is supported by
  the peer for the request in question.
  """
