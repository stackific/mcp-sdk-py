"""Tests for S02 — JSON Value Model, Type Notation, Numeric Handling & Forward Compatibility.

Every test maps to one or more acceptance criteria (AC-02.x).
"""

import json

import pytest

from mcp_sdk_py.json_value import (
  BASE_METHOD_NAMES,
  RESERVED_SECOND_LABELS,
  SAFE_INTEGER_MAX,
  SAFE_INTEGER_MIN,
  W3C_TRACE_KEYS,
  EnumerationPolicy,
  ExtensionNotSupportedError,
  JSONArray,
  JSONObject,
  JSONValue,
  UnknownEnumerationValueError,
  decode_utf8_json,
  encode_as_utf8,
  handle_unknown_enum_value,
  is_base_method_name,
  is_integer_value,
  is_reserved_meta_prefix,
  is_valid_meta_label,
  is_valid_meta_name,
  is_valid_meta_prefix,
  is_within_safe_range,
  last_occurrence_wins,
  names_match,
  numbers_are_equal,
  parse_meta_key,
  preserve_unknown_keys,
  strip_unknown_keys,
  validate_extension_method_name,
  validate_integer_field,
  validate_meta_key_grammar,
  validate_meta_key_not_reserved,
  validate_safe_integer,
)
from mcp_sdk_py.foundations import ConformanceError


# ---------------------------------------------------------------------------
# AC-02.1  JSONValue covers all six wire forms  [R-2.3-a]
# ---------------------------------------------------------------------------

class TestJSONValueModel:
  """AC-02.1: Every wire value is one of six JSONValue forms."""

  def test_type_aliases_exist(self):
    assert JSONValue is not None
    assert JSONObject is not None
    assert JSONArray is not None

  def test_string_is_valid_json_value(self):
    v: JSONValue = "hello"
    assert isinstance(v, str)

  def test_int_is_valid_json_value(self):
    v: JSONValue = 42
    assert isinstance(v, int)

  def test_float_is_valid_json_value(self):
    v: JSONValue = 3.14
    assert isinstance(v, float)

  def test_bool_is_valid_json_value(self):
    v: JSONValue = True
    assert isinstance(v, bool)

  def test_none_is_valid_json_value(self):
    v: JSONValue = None
    assert v is None

  def test_dict_is_valid_json_object(self):
    obj: JSONObject = {"key": "value", "count": 3}
    assert isinstance(obj, dict)

  def test_list_is_valid_json_array(self):
    arr: JSONArray = [1, "two", True, None]
    assert isinstance(arr, list)

  def test_nested_structure_is_valid(self):
    """The spec example from §2.3: a JSONObject whose values are JSONValues."""
    obj: JSONObject = {
      "name": "example",
      "count": 3,
      "enabled": True,
      "tags": ["a", "b"],
      "nested": {"ratio": 0.5},
      "absentMarker": None,
    }
    assert obj["name"] == "example"
    assert obj["tags"] == ["a", "b"]
    assert obj["absentMarker"] is None


# ---------------------------------------------------------------------------
# AC-02.2  Senders MUST NOT emit duplicate names  [R-2.3.1-d]
# ---------------------------------------------------------------------------

class TestObjectNoduplicateNames:
  """AC-02.2: Senders MUST NOT emit objects with duplicate member names."""

  def test_python_dict_cannot_have_duplicate_keys(self):
    """Python dicts enforce uniqueness; the last value wins when parsing JSON."""
    d = {"a": 1, "a": 2}  # type: ignore[dict-item]  # Python keeps last
    assert d == {"a": 2}
    assert len(d) == 1

  def test_json_loads_keeps_last_occurrence(self):
    """json.loads keeps the last occurrence of a duplicate key."""
    raw = '{"a": 1, "a": 2}'
    d = json.loads(raw)
    assert d["a"] == 2

  def test_encode_as_utf8_produces_no_duplicates(self):
    """Standard serialisation never introduces duplicates."""
    data = {"x": 1, "y": 2}
    encoded = encode_as_utf8(data)
    decoded = json.loads(encoded)
    assert set(decoded.keys()) == {"x", "y"}


# ---------------------------------------------------------------------------
# AC-02.3  Duplicate name handling by receiver  [R-2.3.1-a, -b, -c]
# ---------------------------------------------------------------------------

class TestDuplicateKeyHandling:
  """AC-02.3: Receiver uses last occurrence; MAY also reject as malformed."""

  def test_last_occurrence_wins_from_pairs(self):
    pairs = [("key", "first"), ("other", "x"), ("key", "last")]
    result = last_occurrence_wins(pairs)
    assert result["key"] == "last"
    assert result["other"] == "x"

  def test_last_occurrence_wins_preserves_all_unique_keys(self):
    pairs = [("a", 1), ("b", 2), ("c", 3)]
    result = last_occurrence_wins(pairs)
    assert result == {"a": 1, "b": 2, "c": 3}


# ---------------------------------------------------------------------------
# AC-02.4  Member order irrelevant  [R-2.3.1-e, -f]
# ---------------------------------------------------------------------------

class TestObjectOrderIndependence:
  """AC-02.4: Two objects differing only in member order are equivalent."""

  def test_dicts_with_same_keys_different_order_are_equal(self):
    a = {"a": 1, "b": 2}
    b = {"b": 2, "a": 1}
    assert a == b

  def test_encode_decode_produces_same_content_regardless_of_order(self):
    original = {"z": 26, "a": 1, "m": 13}
    encoded = encode_as_utf8(original)
    decoded = decode_utf8_json(encoded)
    assert decoded == original


# ---------------------------------------------------------------------------
# AC-02.5  Array order preserved  [R-2.3.1-g]
# ---------------------------------------------------------------------------

class TestArrayOrderPreserved:
  """AC-02.5: Array element order is significant and MUST be preserved."""

  def test_array_order_preserved_through_encode_decode(self):
    arr = [3, 1, 4, 1, 5, 9, 2, 6]
    encoded = encode_as_utf8(arr)
    decoded = decode_utf8_json(encoded)
    assert decoded == arr

  def test_string_array_order_preserved(self):
    arr = ["z", "a", "m", "b"]
    encoded = encode_as_utf8(arr)
    decoded = decode_utf8_json(encoded)
    assert decoded == arr


# ---------------------------------------------------------------------------
# AC-02.6  UTF-8 encoding  [R-2.3.2-a, -b, -c]
# ---------------------------------------------------------------------------

class TestUTF8Encoding:
  """AC-02.6: Messages MUST be UTF-8 encoded; receivers MUST accept UTF-8 JSON."""

  def test_encode_as_utf8_returns_bytes(self):
    result = encode_as_utf8({"key": "value"})
    assert isinstance(result, bytes)

  def test_encode_as_utf8_produces_valid_utf8(self):
    result = encode_as_utf8({"greeting": "héllo wörld"})
    # Decoding as UTF-8 must not raise
    text = result.decode("utf-8")
    assert "héllo" in text

  def test_decode_utf8_json_round_trips(self):
    original = {"msg": "MCP — 模型上下文协议", "n": 42}
    encoded = encode_as_utf8(original)
    decoded = decode_utf8_json(encoded)
    assert decoded == original

  def test_encode_does_not_use_ascii_escapes_for_non_ascii(self):
    """ensure_ascii=False: non-ASCII chars are emitted as UTF-8, not \\uXXXX."""
    result = encode_as_utf8({"k": "ñ"})
    assert b"\\u" not in result
    assert "ñ".encode("utf-8") in result


# ---------------------------------------------------------------------------
# AC-02.7  Transport framing delivers UTF-8  [R-2.3.2-d]  (structural)
# ---------------------------------------------------------------------------

class TestTransportUTF8:
  """AC-02.7: A framing layer MUST deliver the enclosed JSON as UTF-8.

  This rule governs transport implementations (S08, S09); the foundation
  layer enforces it through encode_as_utf8/decode_utf8_json being the only
  encoding entry points.
  """

  def test_encode_and_decode_are_inverses(self):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert decode_utf8_json(encode_as_utf8(payload)) == payload


# ---------------------------------------------------------------------------
# AC-02.8  Case sensitivity  [R-2.3.3-a, -b]
# ---------------------------------------------------------------------------

class TestCaseSensitivity:
  """AC-02.8: Protocol-defined names are matched case-sensitively."""

  def test_names_match_exact(self):
    assert names_match("tools/call", "tools/call") is True

  def test_names_do_not_match_different_case(self):
    assert names_match("tools/call", "Tools/Call") is False
    assert names_match("tools/call", "TOOLS/CALL") is False
    assert names_match("jsonrpc", "JSONRPC") is False

  def test_names_match_uses_exact_equality(self):
    assert names_match("mimeType", "mimetype") is False
    assert names_match("mimeType", "MimeType") is False
    assert names_match("mimeType", "mimeType") is True


# ---------------------------------------------------------------------------
# AC-02.9  Unknown members ignored  [R-2.3.4-a, -b, -c, -d]
# ---------------------------------------------------------------------------

class TestUnknownMembersIgnored:
  """AC-02.9: Unknown members are ignored; message is not treated as malformed."""

  def test_strip_unknown_keys_removes_unrecognised_members(self):
    data = {"known": "value", "futureField": {"introducedBy": "some-extension"}}
    result = strip_unknown_keys(data, known_keys=frozenset({"known"}))
    assert result == {"known": "value"}
    assert "futureField" not in result

  def test_strip_unknown_keys_passes_recognised_members_unchanged(self):
    data = {"a": 1, "b": 2, "unknown": 99}
    result = strip_unknown_keys(data, known_keys=frozenset({"a", "b"}))
    assert result == {"a": 1, "b": 2}

  def test_preserve_unknown_keys_splits_data(self):
    data = {"known": 1, "extra": 2}
    known, unknown = preserve_unknown_keys(data, frozenset({"known"}))
    assert known == {"known": 1}
    assert unknown == {"extra": 2}

  def test_all_known_keys_produces_empty_unknown(self):
    data = {"a": 1, "b": 2}
    _, unknown = preserve_unknown_keys(data, frozenset({"a", "b"}))
    assert unknown == {}


# ---------------------------------------------------------------------------
# AC-02.10  Senders don't depend on unknown members being acted upon [R-2.3.4-e]
# (structural: the SDK's strip_unknown_keys is the only processing path)
# ---------------------------------------------------------------------------

class TestSendersDoNotDependOnUnknownMembers:
  """AC-02.10: A sender's behaviour MUST NOT depend on a receiver acting upon
  a member the receiver is not required to understand.
  """

  def test_stripping_unknown_member_does_not_affect_processing(self):
    data = {"required_field": "processed", "vendor_extension": "ignored"}
    known, _ = preserve_unknown_keys(data, frozenset({"required_field"}))
    assert known["required_field"] == "processed"


# ---------------------------------------------------------------------------
# AC-02.11  Optional absent = unset; required absent = error  [R-2.3.4-f, -g]
# ---------------------------------------------------------------------------

class TestOptionalAndRequired:
  """AC-02.11: Absent optional members are unset (no error); absent required
  members MUST be rejected.
  """

  def test_absent_optional_treated_as_unset(self):
    data = {"name": "server"}
    title = data.get("title")  # OPTIONAL field absent
    assert title is None  # treated as unset

  def test_absent_required_raises_key_error(self):
    data = {"version": "1.0"}
    with pytest.raises(KeyError):
      _ = data["name"]  # REQUIRED but absent


# ---------------------------------------------------------------------------
# AC-02.12  Type notation conventions  [R-2.4-a–h]
# (structural: Python dataclasses enforce REQUIRED/OPTIONAL shape)
# ---------------------------------------------------------------------------

class TestTypeNotation:
  """AC-02.12: Type notation semantics are implemented by the Python type system."""

  def test_required_field_must_be_present(self):
    """A REQUIRED field (field: T) MUST be present and conform to T."""
    # Demonstrated by Implementation.__post_init__ raising on missing name
    from mcp_sdk_py.common_types import Implementation
    with pytest.raises((ValueError, TypeError)):
      Implementation(name="", version="1.0")

  def test_optional_field_may_be_absent(self):
    """An OPTIONAL field (field?: T) MAY be absent."""
    from mcp_sdk_py.common_types import Implementation
    impl = Implementation(name="x", version="1")
    assert impl.title is None   # OPTIONAL, absent → unset

  def test_optional_null_not_used_for_absent(self):
    """An OPTIONAL member MUST NOT be present as null to mean 'absent'
    unless T explicitly includes null (R-2.4-f).  SDK omits optional fields
    from to_dict() rather than emitting null.
    """
    from mcp_sdk_py.common_types import Implementation
    impl = Implementation(name="x", version="1")
    d = impl.to_dict()
    assert "title" not in d   # not emitted as null

  def test_union_value_conforms_to_at_least_one_alternative(self):
    """T | U: value must conform to at least one alternative (R-2.4-g)."""
    value: str | int = "hello"
    assert isinstance(value, (str, int))
    value2: str | int = 42
    assert isinstance(value2, (str, int))


# ---------------------------------------------------------------------------
# AC-02.13  Integer fields: no fractional part  [R-2.5-a, -b]
# ---------------------------------------------------------------------------

class TestIntegerFields:
  """AC-02.13: Integer fields must have no fractional part; reject fractional values."""

  def test_plain_int_is_integer(self):
    assert is_integer_value(42) is True

  def test_float_with_no_fraction_is_integer(self):
    assert is_integer_value(42.0) is True

  def test_float_with_fraction_is_not_integer(self):
    assert is_integer_value(42.5) is False

  def test_bool_is_not_an_integer_field_value(self):
    assert is_integer_value(True) is False
    assert is_integer_value(False) is False

  def test_validate_integer_field_accepts_int(self):
    validate_integer_field(100, "id")  # no exception

  def test_validate_integer_field_accepts_whole_float(self):
    validate_integer_field(100.0, "id")  # no exception

  def test_validate_integer_field_rejects_fractional(self):
    with pytest.raises(ValueError, match="fractional"):
      validate_integer_field(1.5, "id")

  def test_validate_integer_field_rejects_bool(self):
    with pytest.raises(TypeError):
      validate_integer_field(True, "id")

  def test_validate_integer_field_rejects_non_number(self):
    with pytest.raises(TypeError):
      validate_integer_field("42", "id")


# ---------------------------------------------------------------------------
# AC-02.14  Safe-integer range  [R-2.5-c, -d, -e]
# ---------------------------------------------------------------------------

class TestSafeIntegerRange:
  """AC-02.14: Identifier/counter values must stay within the safe-integer range."""

  def test_safe_integer_min(self):
    assert SAFE_INTEGER_MIN == -(2 ** 53 - 1)
    assert SAFE_INTEGER_MIN == -9007199254740991

  def test_safe_integer_max(self):
    assert SAFE_INTEGER_MAX == 2 ** 53 - 1
    assert SAFE_INTEGER_MAX == 9007199254740991

  def test_boundary_values_are_within_range(self):
    assert is_within_safe_range(SAFE_INTEGER_MIN) is True
    assert is_within_safe_range(SAFE_INTEGER_MAX) is True

  def test_zero_is_within_range(self):
    assert is_within_safe_range(0) is True

  def test_beyond_max_is_outside_range(self):
    assert is_within_safe_range(SAFE_INTEGER_MAX + 1) is False

  def test_below_min_is_outside_range(self):
    assert is_within_safe_range(SAFE_INTEGER_MIN - 1) is False

  def test_validate_safe_integer_accepts_boundary(self):
    validate_safe_integer(SAFE_INTEGER_MAX, "id")  # no exception
    validate_safe_integer(SAFE_INTEGER_MIN, "id")  # no exception

  def test_validate_safe_integer_rejects_too_large(self):
    with pytest.raises(ValueError, match="safe-integer"):
      validate_safe_integer(SAFE_INTEGER_MAX + 1, "id")

  def test_validate_safe_integer_rejects_too_small(self):
    with pytest.raises(ValueError, match="safe-integer"):
      validate_safe_integer(SAFE_INTEGER_MIN - 1, "id")

  def test_spec_example_max_id(self):
    """The spec shows { "id": 9007199254740991 } as valid."""
    validate_safe_integer(9007199254740991, "id")  # no exception


# ---------------------------------------------------------------------------
# AC-02.15  Numeric equality independent of textual form  [R-2.5-f, -g]
# ---------------------------------------------------------------------------

class TestNumericEquality:
  """AC-02.15: Numerically equal JSON numbers are equal regardless of form."""

  def test_100_equals_1e2(self):
    assert numbers_are_equal(100, 1e2) is True

  def test_100_equals_100_0(self):
    assert numbers_are_equal(100, 100.0) is True

  def test_different_values_not_equal(self):
    assert numbers_are_equal(100, 101) is False

  def test_json_parse_treats_1e2_and_100_as_equal(self):
    a = json.loads("100")
    b = json.loads("1e2")
    assert a == b


# ---------------------------------------------------------------------------
# AC-02.16  Extension method names must not collide  [R-2.6.1-a, -b]
# ---------------------------------------------------------------------------

class TestMethodNameCollision:
  """AC-02.16: Extension method names must be namespaced; no base-protocol collision."""

  def test_base_method_names_exist(self):
    assert len(BASE_METHOD_NAMES) > 0

  def test_tools_list_is_base_method(self):
    assert is_base_method_name("tools/list") is True

  def test_unknown_name_is_not_base_method(self):
    assert is_base_method_name("com.example/my-tool") is False

  def test_validate_extension_method_name_accepts_namespaced(self):
    validate_extension_method_name("com.example/do-thing")  # no exception

  def test_validate_extension_method_name_rejects_collision(self):
    with pytest.raises(ValueError, match="collides"):
      validate_extension_method_name("tools/list")

  def test_validate_extension_method_name_rejects_ping(self):
    with pytest.raises(ValueError):
      validate_extension_method_name("ping")


# ---------------------------------------------------------------------------
# AC-02.17  _meta prefix validation  [R-2.6.2-b, -c, -d, -e, -f]
# ---------------------------------------------------------------------------

class TestMetaPrefixValidation:
  """AC-02.17: _meta key prefixes must conform to the label grammar and not be reserved."""

  @pytest.mark.parametrize("prefix", [
    "com.example/",
    "io.myorg/",
    "x/",
    "org.modelcontextprotocol.api/",  # reserved (second label = modelcontextprotocol)
  ])
  def test_valid_prefix_grammar(self, prefix):
    assert is_valid_meta_prefix(prefix) is True

  @pytest.mark.parametrize("prefix", [
    "io./",          # empty second label
    "io..mcp/",      # double dot
    "io.mcp",        # no trailing slash
    "/",             # no labels
    "123.com/",      # label starts with digit
    "com.-example/", # label starts with hyphen
  ])
  def test_invalid_prefix_grammar(self, prefix):
    assert is_valid_meta_prefix(prefix) is False

  @pytest.mark.parametrize("label", [
    "com", "io", "example", "my-org", "a1", "x",
  ])
  def test_valid_labels(self, label):
    assert is_valid_meta_label(label) is True

  @pytest.mark.parametrize("label", [
    "1abc",   # starts with digit
    "-abc",   # starts with hyphen
    "abc-",   # ends with hyphen
    "",       # empty
  ])
  def test_invalid_labels(self, label):
    assert is_valid_meta_label(label) is False

  def test_reserved_second_labels_set(self):
    assert "modelcontextprotocol" in RESERVED_SECOND_LABELS
    assert "mcp" in RESERVED_SECOND_LABELS

  @pytest.mark.parametrize("prefix", [
    "io.modelcontextprotocol/",
    "dev.mcp/",
    "org.modelcontextprotocol.api/",
    "com.mcp.tools/",
  ])
  def test_reserved_prefix_detected(self, prefix):
    assert is_reserved_meta_prefix(prefix) is True

  @pytest.mark.parametrize("prefix", [
    "com.example/",
    "com.example.mcp/",   # third label is mcp, second is 'example' → NOT reserved
    "io.example/",
    "x/",
  ])
  def test_non_reserved_prefix_not_detected(self, prefix):
    assert is_reserved_meta_prefix(prefix) is False

  def test_validate_meta_key_rejects_reserved_prefix(self):
    with pytest.raises(ValueError, match="reserved"):
      validate_meta_key_not_reserved("io.modelcontextprotocol/protocolVersion")

  def test_validate_meta_key_allows_non_reserved(self):
    validate_meta_key_not_reserved("com.example/tenant")  # no exception


# ---------------------------------------------------------------------------
# AC-02.18  _meta name validation  [R-2.6.2-a, -g, -h]
# ---------------------------------------------------------------------------

class TestMetaNameValidation:
  """AC-02.18: _meta key names must conform to the name grammar."""

  @pytest.mark.parametrize("name", [
    "tenant",
    "my-key",
    "key_name",
    "key.name",
    "a1",
    "",       # empty name is allowed
  ])
  def test_valid_meta_names(self, name):
    assert is_valid_meta_name(name) is True

  @pytest.mark.parametrize("name", [
    "-key",    # starts with hyphen
    "key-",    # ends with hyphen
    ".key",    # starts with dot
    "key.",    # ends with dot
  ])
  def test_invalid_meta_names(self, name):
    assert is_valid_meta_name(name) is False

  def test_parse_meta_key_no_prefix(self):
    prefix, name = parse_meta_key("traceparent")
    assert prefix is None
    assert name == "traceparent"

  def test_parse_meta_key_with_prefix(self):
    prefix, name = parse_meta_key("com.example/tenant")
    assert prefix == "com.example/"
    assert name == "tenant"

  def test_validate_meta_key_grammar_valid(self):
    validate_meta_key_grammar("com.example/tenant")  # no exception
    validate_meta_key_grammar("traceparent")           # no exception

  def test_validate_meta_key_grammar_rejects_bad_prefix(self):
    with pytest.raises(ValueError):
      validate_meta_key_grammar("123.bad/key")


# ---------------------------------------------------------------------------
# AC-02.19  Trace keys and unknown _meta keys  [R-2.6.2-i, -j]
# ---------------------------------------------------------------------------

class TestMetaTraceAndUnknownKeys:
  """AC-02.19: Bare trace keys are reserved; unknown _meta keys are ignored."""

  def test_w3c_trace_keys_are_defined(self):
    assert "traceparent" in W3C_TRACE_KEYS
    assert "tracestate" in W3C_TRACE_KEYS
    assert "baggage" in W3C_TRACE_KEYS

  def test_unknown_meta_keys_are_ignored_via_strip(self):
    """Receivers MUST ignore _meta keys they do not recognize (R-2.6.2-j)."""
    meta = {
      "traceparent": "00-abc-def-01",
      "com.example/tenant": "acme",
      "unknown-future-key": "value",
    }
    known = frozenset({"traceparent", "com.example/tenant"})
    result = strip_unknown_keys(meta, known)
    assert "unknown-future-key" not in result
    assert result["traceparent"] == "00-abc-def-01"


# ---------------------------------------------------------------------------
# AC-02.20  Unknown enumeration values  [R-2.6.3-a, -b, -c]
# ---------------------------------------------------------------------------

class TestEnumerationHandling:
  """AC-02.20: Unknown enum values don't crash; OPEN tolerates, CLOSED rejects."""

  def test_open_enum_tolerates_unknown_value(self):
    handle_unknown_enum_value("future-value", EnumerationPolicy.OPEN)  # no exception

  def test_closed_enum_rejects_unknown_value(self):
    with pytest.raises(UnknownEnumerationValueError):
      handle_unknown_enum_value("unknown", EnumerationPolicy.CLOSED, "myField")

  def test_unknown_enum_error_is_conformance_error(self):
    assert issubclass(UnknownEnumerationValueError, ConformanceError)

  def test_open_enum_does_not_crash(self):
    """AC-02.20: MUST NOT crash or corrupt unrelated processing (R-2.6.3-a)."""
    results = []
    for val in ["known", "unknown-future", "another-unknown"]:
      try:
        handle_unknown_enum_value(val, EnumerationPolicy.OPEN)
        results.append("ok")
      except Exception:
        results.append("error")
    assert results == ["ok", "ok", "ok"]


# ---------------------------------------------------------------------------
# AC-02.21  Extension enum values only with capability  [R-2.6.3-d]
# (structural: gating is enforced by capability system in later stories)
# ---------------------------------------------------------------------------

class TestExtensionEnumGating:
  """AC-02.21: Extension enum values must only be emitted when the peer supports them."""

  def test_extension_not_supported_error_exists(self):
    assert issubclass(ExtensionNotSupportedError, ConformanceError)

  def test_extension_not_supported_error_can_be_raised(self):
    with pytest.raises(ExtensionNotSupportedError):
      raise ExtensionNotSupportedError("extension 'my-ext' not supported by peer")


# ---------------------------------------------------------------------------
# AC-02.22  Well-known-key maps can have extra keys  [R-2.6.3-e, -f]
# ---------------------------------------------------------------------------

class TestWellKnownKeyMaps:
  """AC-02.22: Maps of well-known keys MAY be extended; unknown keys are ignored."""

  def test_well_known_map_tolerates_extra_keys(self):
    """A receiver ignores unrecognized keys per §2.3.4 (R-2.6.3-f)."""
    capabilities_map = {
      "tools": {},           # known
      "resources": {},       # known
      "x-vendor-feature": {"enabled": True},  # unknown extension
    }
    known = frozenset({"tools", "resources"})
    result = strip_unknown_keys(capabilities_map, known)
    assert "tools" in result
    assert "x-vendor-feature" not in result


# ---------------------------------------------------------------------------
# AC-02.23  Extension contributions gated by capability  [R-2.6.4-a, -b]
# ---------------------------------------------------------------------------

class TestExtensionContributionGating:
  """AC-02.23: Extension methods/types are only used when peer supports the extension."""

  def test_extension_not_supported_error_is_raised_for_violation(self):
    """Demonstrates the error an endpoint MUST raise when trying to use an
    extension method the peer has not declared support for.
    """
    with pytest.raises(ConformanceError):
      raise ExtensionNotSupportedError(
        "extension 'tasks' is not declared by the peer for this request"
      )


# ---------------------------------------------------------------------------
# AC-02.24  Graceful handling of absent extension  [R-2.6.4-c, -d]
# ---------------------------------------------------------------------------

class TestGracefulExtensionAbsence:
  """AC-02.24: Endpoints without an extension handle its absence gracefully."""

  def test_unknown_extension_method_treated_as_unknown_not_error(self):
    """An unrecognized extension method name is just an unknown key to ignore."""
    incoming_request_method = "com.myext/custom-operation"
    is_known = is_base_method_name(incoming_request_method)
    assert is_known is False   # not an error, just unrecognised → ignore gracefully
