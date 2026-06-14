"""Tests for S05 — The _meta Object & Metadata Naming Rules.

Coverage map (25 ACs):
  AC-05.1  → TestMetaObjectPlacement
  AC-05.2  → TestMetaObjectOptional
  AC-05.3  → TestClientRequestRequiresMeta
  AC-05.4  → TestUnknownMetaKeysIgnored
  AC-05.5  → TestReservedKeyValueNotAssumed
  AC-05.6  → TestPurposeSpecificMetaNames
  AC-05.7  → TestMetaObjectMustBeDict
  AC-05.8  → TestPrefixedKeyGrammar
  AC-05.9  → TestNameSegmentGrammar
  AC-05.10 → TestReverseDnsConvention
  AC-05.11 → TestReservedPrefixRejected
  AC-05.12 → TestVendorKeyRequiresPrefix
  AC-05.13 → TestReservedBareKeysAccepted
  AC-05.14 → TestTraceValuesCarriedUnchanged
  AC-05.15 → TestW3cTraceConformance
  AC-05.16 → TestNonTracingReceiverIgnoresTraceKeys
  AC-05.17 → TestRequiredPerRequestKeys
  AC-05.18 → TestMissingRequiredKeyRejection
  AC-05.19 → TestLogLevel
  AC-05.20 → TestProgressTokenOptional
  AC-05.21 → TestImplementationValidation
  AC-05.22 → TestUnsupportedProtocolVersion
  AC-05.23 → TestHttpVersionHeaderCheck
  AC-05.24 → TestCapabilityNotInferredFromPriorRequest
  AC-05.25 → TestMissingRequiredClientCapability
"""

import pytest

from mcp_sdk_py.meta_object import (
  CANONICAL_PROTOCOL_PREFIX,
  CURRENT_PROTOCOL_VERSION,
  KEY_CLIENT_CAPABILITIES,
  KEY_CLIENT_INFO,
  KEY_LOG_LEVEL,
  KEY_PROTOCOL_VERSION,
  LOGGING_LEVELS_ASCENDING,
  LOGGING_LEVEL_DEBUG,
  LOGGING_LEVEL_EMERGENCY,
  LOGGING_LEVEL_WARNING,
  REQUIRED_CLIENT_REQUEST_KEYS,
  RESERVED_BARE_KEYS,
  MissingRequiredClientCapabilityError,
  MissingRequiredMetaKeyError,
  UnsupportedProtocolVersionError,
  is_log_notification_allowed,
  require_client_capability,
  validate_logging_level,
  validate_meta_object,
  validate_protocol_version_header,
  validate_request_meta_object,
  validate_third_party_meta_key,
)


def _minimal_request_meta() -> dict:
  """Minimal valid client request _meta with the three required keys."""
  return {
    KEY_PROTOCOL_VERSION: "2026-07-28",
    KEY_CLIENT_INFO: {"name": "test-client", "version": "1.0.0"},
    KEY_CLIENT_CAPABILITIES: {},
  }


# ---------------------------------------------------------------------------
# AC-05.1 — _meta accepted on request, notification, and result placements
#            (R-4.1-a, R-4.1-b)
# ---------------------------------------------------------------------------

class TestMetaObjectPlacement:
  def test_meta_on_request_params_accepted(self):
    """_meta dict is accepted on request params."""
    meta = {KEY_PROTOCOL_VERSION: "2026-07-28",
            KEY_CLIENT_INFO: {"name": "c", "version": "1"},
            KEY_CLIENT_CAPABILITIES: {}}
    validate_request_meta_object(meta)

  def test_meta_with_any_json_values(self):
    """_meta member values may be any JSON value (R-4.1-b)."""
    meta = {
      "io.example/str": "hello",
      "io.example/num": 42,
      "io.example/float": 3.14,
      "io.example/bool": True,
      "io.example/null": None,
      "io.example/obj": {"nested": True},
      "io.example/arr": [1, 2, 3],
    }
    assert validate_meta_object(meta) == meta

  def test_meta_on_notification_params_accepted(self):
    """_meta is accepted as a dict on notification params."""
    from mcp_sdk_py.result_error import parse_notification_params
    p = parse_notification_params({"_meta": {"io.example/k": "v"}})
    assert p.meta == {"io.example/k": "v"}

  def test_meta_on_result_accepted(self):
    """_meta is accepted on a Result object."""
    from mcp_sdk_py.result_error import parse_result
    r = parse_result({"resultType": "complete", "_meta": {"com.example/region": "eu"}})
    assert r.meta == {"com.example/region": "eu"}


# ---------------------------------------------------------------------------
# AC-05.2 — _meta optional on notifications and results  (R-4.1-c, R-4.3-o)
# ---------------------------------------------------------------------------

class TestMetaObjectOptional:
  def test_notification_without_meta_is_valid(self):
    from mcp_sdk_py.result_error import parse_notification_params
    p = parse_notification_params({"progress": 0.5})
    assert p.meta is None

  def test_result_without_meta_is_valid(self):
    from mcp_sdk_py.result_error import parse_result
    r = parse_result({"resultType": "complete"})
    assert r.meta is None


# ---------------------------------------------------------------------------
# AC-05.3 — Client request without _meta is rejected  (R-4.1-d)
# ---------------------------------------------------------------------------

class TestClientRequestRequiresMeta:
  def test_request_params_without_meta_raises(self):
    """parse_request_params requires _meta on request params."""
    from mcp_sdk_py.result_error import parse_request_params
    with pytest.raises(ValueError, match="_meta is REQUIRED"):
      parse_request_params({})

  def test_validate_request_meta_missing_all_keys_raises(self):
    """validate_request_meta_object raises for empty _meta (all keys absent)."""
    with pytest.raises(MissingRequiredMetaKeyError):
      validate_request_meta_object({})


# ---------------------------------------------------------------------------
# AC-05.4 — Unknown _meta keys do not cause rejection  (R-4.1-e, R-4.1-f)
# ---------------------------------------------------------------------------

class TestUnknownMetaKeysIgnored:
  def test_unknown_keys_do_not_cause_rejection(self):
    """Receiver does not reject for unrecognized _meta keys."""
    meta = _minimal_request_meta()
    meta["io.example/unknownFutureKey"] = "some-value"
    meta["com.vendor/customTag"] = 99
    # Should succeed without error.
    validate_request_meta_object(meta)

  def test_unknown_vendor_key_ignored_after_required_key_validation(self):
    """Unknown vendor keys appear in the meta and are preserved as-is."""
    meta = _minimal_request_meta()
    meta["com.example/tag"] = "nightly-sync"
    validate_request_meta_object(meta)  # no error


# ---------------------------------------------------------------------------
# AC-05.5 — Receiver makes no assumptions about reserved-key values (R-4.1-g)
# ---------------------------------------------------------------------------

class TestReservedKeyValueNotAssumed:
  def test_reserved_key_value_not_inspected(self):
    """validate_request_meta_object reads protocolVersion as a type (string),
    not its semantic meaning, unless supported_versions is supplied."""
    meta = _minimal_request_meta()
    meta[KEY_PROTOCOL_VERSION] = "9999-99-99"
    # Without supported_versions, no assumption about the value is made.
    validate_request_meta_object(meta)

  def test_arbitrary_capability_value_not_assumed(self):
    """clientCapabilities dict content is accepted without semantic assumptions."""
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_CAPABILITIES] = {"elicitation": {}, "sampling": {"model": "x"}}
    validate_request_meta_object(meta)


# ---------------------------------------------------------------------------
# AC-05.6 — Purpose-specific _meta names (R-4.1-h) — behavioral note
# ---------------------------------------------------------------------------

class TestPurposeSpecificMetaNames:
  def test_per_request_protocol_keys_are_accepted(self):
    """The protocol-defined per-request keys are accepted as purpose-specific."""
    meta = _minimal_request_meta()
    validate_request_meta_object(meta)

  def test_log_level_key_is_reserved_for_specific_purpose(self):
    """logLevel is a purpose-specific optional key (R-4.1-h, R-4.3-d)."""
    meta = _minimal_request_meta()
    meta[KEY_LOG_LEVEL] = "warning"
    validate_request_meta_object(meta)


# ---------------------------------------------------------------------------
# AC-05.7 — _meta as array or scalar is rejected  (R-4.1-i, R-4.1-j)
# ---------------------------------------------------------------------------

class TestMetaObjectMustBeDict:
  def test_meta_as_list_raises(self):
    with pytest.raises(TypeError, match="_meta MUST be a JSON object"):
      validate_meta_object([1, 2, 3])

  def test_meta_as_string_raises(self):
    with pytest.raises(TypeError, match="_meta MUST be a JSON object"):
      validate_meta_object("string")

  def test_meta_as_integer_raises(self):
    with pytest.raises(TypeError, match="_meta MUST be a JSON object"):
      validate_meta_object(42)

  def test_meta_as_none_raises(self):
    with pytest.raises(TypeError, match="_meta MUST be a JSON object"):
      validate_meta_object(None)

  def test_meta_as_bool_raises(self):
    with pytest.raises(TypeError, match="_meta MUST be a JSON object"):
      validate_meta_object(True)

  def test_meta_as_dict_is_valid(self):
    assert validate_meta_object({"key": "value"}) == {"key": "value"}

  def test_empty_dict_is_valid(self):
    assert validate_meta_object({}) == {}


# ---------------------------------------------------------------------------
# AC-05.8 — Prefixed key grammar validation  (R-4.2-a–d)
# ---------------------------------------------------------------------------

class TestPrefixedKeyGrammar:
  def test_valid_prefixed_vendor_key(self):
    validate_third_party_meta_key("com.example/requestTag")

  def test_valid_multi_label_prefix(self):
    validate_third_party_meta_key("io.example.sub/myKey")

  def test_prefix_starting_with_digit_rejected(self):
    with pytest.raises(ValueError):
      validate_third_party_meta_key("1com.example/key")

  def test_label_ending_with_hyphen_rejected(self):
    with pytest.raises(ValueError):
      validate_third_party_meta_key("com-.example/key")

  def test_label_with_underscore_interior_rejected(self):
    with pytest.raises(ValueError):
      validate_third_party_meta_key("com_ex.vendor/key")

  def test_valid_single_label_prefix(self):
    validate_third_party_meta_key("example/key")

  def test_label_with_interior_hyphen_is_valid(self):
    validate_third_party_meta_key("com.my-company/key")


# ---------------------------------------------------------------------------
# AC-05.9 — Name segment grammar  (R-4.2-g, R-4.2-h)
# ---------------------------------------------------------------------------

class TestNameSegmentGrammar:
  def test_alphanumeric_name_is_valid(self):
    validate_third_party_meta_key("com.example/requestTag123")

  def test_name_with_hyphen_is_valid(self):
    validate_third_party_meta_key("com.example/request-tag")

  def test_name_with_underscore_is_valid(self):
    validate_third_party_meta_key("com.example/request_tag")

  def test_name_with_dot_is_valid(self):
    validate_third_party_meta_key("com.example/request.tag")

  def test_name_starting_with_hyphen_rejected(self):
    with pytest.raises(ValueError):
      validate_third_party_meta_key("com.example/-invalid")

  def test_name_ending_with_hyphen_rejected(self):
    with pytest.raises(ValueError):
      validate_third_party_meta_key("com.example/invalid-")

  def test_name_starting_with_uppercase_is_valid(self):
    validate_third_party_meta_key("com.example/RequestTag")


# ---------------------------------------------------------------------------
# AC-05.10 — SHOULD use reverse-DNS notation  (R-4.2-e)
# ---------------------------------------------------------------------------

class TestReverseDnsConvention:
  def test_reverse_dns_prefix_is_valid(self):
    """com.example/ is the canonical reverse-DNS form."""
    validate_third_party_meta_key("com.example/key")

  def test_forward_dns_like_prefix_is_grammatically_valid_but_warned(self):
    """example.com/ is grammatically valid (can't enforce SHOULD via exception)."""
    validate_third_party_meta_key("example.com/key")


# ---------------------------------------------------------------------------
# AC-05.11 — Reserved prefix rejected for third parties  (R-4.2-f)
# ---------------------------------------------------------------------------

class TestReservedPrefixRejected:
  def test_dev_mcp_prefix_is_reserved(self):
    """Second label 'mcp' is reserved."""
    with pytest.raises(ValueError, match="reserved prefix"):
      validate_third_party_meta_key("dev.mcp/key")

  def test_io_modelcontextprotocol_prefix_is_reserved(self):
    """Canonical protocol prefix is reserved."""
    with pytest.raises(ValueError, match="reserved prefix"):
      validate_third_party_meta_key("io.modelcontextprotocol/key")

  def test_org_modelcontextprotocol_api_is_reserved(self):
    """Second label 'modelcontextprotocol' is reserved regardless of other labels."""
    with pytest.raises(ValueError, match="reserved prefix"):
      validate_third_party_meta_key("org.modelcontextprotocol.api/key")

  def test_com_example_mcp_is_not_reserved(self):
    """Second label is 'example', not 'mcp'; not reserved."""
    validate_third_party_meta_key("com.example.mcp/key")

  def test_mcp_first_label_not_second_is_not_reserved(self):
    """'mcp' as first label with a non-reserved second label is allowed."""
    validate_third_party_meta_key("mcp.example/key")


# ---------------------------------------------------------------------------
# AC-05.12 — Vendor key must use non-reserved prefix  (R-4.2-i)
# ---------------------------------------------------------------------------

class TestVendorKeyRequiresPrefix:
  def test_bare_key_rejected_for_third_party(self):
    """Third parties MUST use a prefix; bare keys are reserved for protocol."""
    with pytest.raises(ValueError, match="must use a prefix"):
      validate_third_party_meta_key("customTag")

  def test_vendor_key_with_valid_prefix_accepted(self):
    validate_third_party_meta_key("com.example/requestTag")

  def test_reserved_prefix_rejected(self):
    with pytest.raises(ValueError, match="reserved prefix"):
      validate_third_party_meta_key("io.modelcontextprotocol/newKey")


# ---------------------------------------------------------------------------
# AC-05.13 — Reserved bare keys are accepted in _meta  (R-4.2-j)
# ---------------------------------------------------------------------------

class TestReservedBareKeysAccepted:
  def test_progress_token_bare_key_in_reserved_set(self):
    assert "progressToken" in RESERVED_BARE_KEYS

  def test_traceparent_in_reserved_set(self):
    assert "traceparent" in RESERVED_BARE_KEYS

  def test_tracestate_in_reserved_set(self):
    assert "tracestate" in RESERVED_BARE_KEYS

  def test_baggage_in_reserved_set(self):
    assert "baggage" in RESERVED_BARE_KEYS

  def test_reserved_bare_keys_accepted_in_request_meta(self):
    """Bare keys are accepted in _meta on a request and not rejected."""
    meta = _minimal_request_meta()
    meta["progressToken"] = "req-1-progress"
    meta["traceparent"] = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    # Does not raise.
    validate_request_meta_object(meta)

  def test_bare_keys_accepted_in_generic_meta_object(self):
    meta = {
      "progressToken": "tok-abc",
      "tracestate": "vendor1=value1",
      "baggage": "key=value",
    }
    validate_meta_object(meta)


# ---------------------------------------------------------------------------
# AC-05.14 — Trace values carried unchanged  (R-4.2-k)
# ---------------------------------------------------------------------------

class TestTraceValuesCarriedUnchanged:
  def test_traceparent_value_is_preserved(self):
    """Trace values are opaque and must be carried unchanged."""
    tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    meta = {"traceparent": tp}
    result = validate_meta_object(meta)
    assert result["traceparent"] == tp

  def test_tracestate_value_is_preserved(self):
    ts = "vendor1=value1,vendor2=value2"
    meta = {"tracestate": ts}
    assert validate_meta_object(meta)["tracestate"] == ts


# ---------------------------------------------------------------------------
# AC-05.15 — W3C trace format conformance  (R-4.2-l, R-4.2-m)
# ---------------------------------------------------------------------------

class TestW3cTraceConformance:
  def test_valid_traceparent_conforms(self):
    from mcp_sdk_py.json_value import validate_w3c_traceparent
    # Should not raise.
    validate_w3c_traceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")

  def test_invalid_traceparent_format_rejected(self):
    from mcp_sdk_py.json_value import validate_w3c_traceparent
    with pytest.raises(ValueError):
      validate_w3c_traceparent("bad-format")

  def test_valid_tracestate_conforms(self):
    from mcp_sdk_py.json_value import validate_w3c_tracestate
    validate_w3c_tracestate("vendor1=value1,vendor2=value2")

  def test_invalid_tracestate_rejected(self):
    from mcp_sdk_py.json_value import validate_w3c_tracestate
    with pytest.raises(ValueError):
      validate_w3c_tracestate("no-equals-sign")

  def test_valid_baggage_conforms(self):
    from mcp_sdk_py.json_value import validate_w3c_baggage
    validate_w3c_baggage("key=value;property")

  def test_invalid_baggage_rejected(self):
    from mcp_sdk_py.json_value import validate_w3c_baggage
    with pytest.raises(ValueError):
      validate_w3c_baggage("bad-baggage-no-equals")


# ---------------------------------------------------------------------------
# AC-05.16 — Non-tracing receiver ignores trace keys  (R-4.2-n, R-4.2-o)
# ---------------------------------------------------------------------------

class TestNonTracingReceiverIgnoresTraceKeys:
  def test_trace_keys_do_not_cause_rejection(self):
    """A non-tracing receiver ignores trace keys and does not reject (R-4.2-n/o)."""
    meta = _minimal_request_meta()
    meta["traceparent"] = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    meta["tracestate"] = "vendor=value"
    meta["baggage"] = "key=value"
    # Non-tracing receiver just processes the required keys and ignores trace keys.
    validate_request_meta_object(meta)

  def test_invalid_trace_value_does_not_cause_rejection_at_meta_level(self):
    """validate_request_meta_object doesn't enforce W3C format — that's optional."""
    meta = _minimal_request_meta()
    meta["traceparent"] = "some-non-w3c-value"
    # validate_request_meta_object doesn't reject for this (non-tracing receiver).
    validate_request_meta_object(meta)


# ---------------------------------------------------------------------------
# AC-05.17 — Required per-request keys present  (R-4.3-a, R-4.3-b, R-4.3-c)
# ---------------------------------------------------------------------------

class TestRequiredPerRequestKeys:
  def test_all_three_required_keys_present_is_valid(self):
    validate_request_meta_object(_minimal_request_meta())

  def test_required_keys_registry_contains_expected_keys(self):
    assert KEY_PROTOCOL_VERSION in REQUIRED_CLIENT_REQUEST_KEYS
    assert KEY_CLIENT_INFO in REQUIRED_CLIENT_REQUEST_KEYS
    assert KEY_CLIENT_CAPABILITIES in REQUIRED_CLIENT_REQUEST_KEYS
    assert len(REQUIRED_CLIENT_REQUEST_KEYS) == 3

  def test_wire_example_meta_is_valid(self):
    """Wire example from the spec is fully valid."""
    meta = {
      KEY_PROTOCOL_VERSION: "2026-07-28",
      KEY_CLIENT_INFO: {
        "name": "example-client",
        "version": "1.4.0",
        "title": "Example Client",
      },
      KEY_CLIENT_CAPABILITIES: {},
      KEY_LOG_LEVEL: "warning",
      "progressToken": "req-1-progress",
      "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
      "com.example/requestTag": "nightly-sync",
    }
    validate_request_meta_object(meta)

  def test_protocol_version_must_be_string(self):
    meta = _minimal_request_meta()
    meta[KEY_PROTOCOL_VERSION] = 20260728
    with pytest.raises(TypeError, match="must be a string"):
      validate_request_meta_object(meta)

  def test_client_capabilities_must_be_dict(self):
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_CAPABILITIES] = "not-an-object"
    with pytest.raises(TypeError, match="must be a JSON object"):
      validate_request_meta_object(meta)

  def test_client_info_must_be_dict(self):
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_INFO] = "example-client"
    with pytest.raises(TypeError, match="must be a JSON object"):
      validate_request_meta_object(meta)


# ---------------------------------------------------------------------------
# AC-05.18 — Missing required key → -32602  (R-4.3-n)
# ---------------------------------------------------------------------------

class TestMissingRequiredKeyRejection:
  def test_missing_protocol_version_raises(self):
    meta = _minimal_request_meta()
    del meta[KEY_PROTOCOL_VERSION]
    with pytest.raises(MissingRequiredMetaKeyError) as exc_info:
      validate_request_meta_object(meta)
    assert exc_info.value.missing_key == KEY_PROTOCOL_VERSION
    assert exc_info.value.json_rpc_code == -32602

  def test_missing_client_info_raises(self):
    meta = _minimal_request_meta()
    del meta[KEY_CLIENT_INFO]
    with pytest.raises(MissingRequiredMetaKeyError) as exc_info:
      validate_request_meta_object(meta)
    assert exc_info.value.missing_key == KEY_CLIENT_INFO
    assert exc_info.value.json_rpc_code == -32602

  def test_missing_client_capabilities_raises(self):
    meta = _minimal_request_meta()
    del meta[KEY_CLIENT_CAPABILITIES]
    with pytest.raises(MissingRequiredMetaKeyError) as exc_info:
      validate_request_meta_object(meta)
    assert exc_info.value.missing_key == KEY_CLIENT_CAPABILITIES
    assert exc_info.value.json_rpc_code == -32602

  def test_error_message_names_the_missing_key(self):
    meta = _minimal_request_meta()
    del meta[KEY_CLIENT_CAPABILITIES]
    with pytest.raises(MissingRequiredMetaKeyError, match=KEY_CLIENT_CAPABILITIES):
      validate_request_meta_object(meta)


# ---------------------------------------------------------------------------
# AC-05.19 — logLevel optional and deprecated; controls log emission  (R-4.3-d/l/m)
# ---------------------------------------------------------------------------

class TestLogLevel:
  def test_log_level_absent_means_no_log_notifications(self):
    """R-4.3-l: absent logLevel → server MUST NOT emit log notifications."""
    meta = _minimal_request_meta()
    assert not is_log_notification_allowed(meta, "warning")
    assert not is_log_notification_allowed(meta, "debug")

  def test_log_level_warning_allows_warning_and_above(self):
    meta = _minimal_request_meta()
    meta[KEY_LOG_LEVEL] = "warning"
    assert is_log_notification_allowed(meta, "warning")
    assert is_log_notification_allowed(meta, "error")
    assert is_log_notification_allowed(meta, "critical")
    assert is_log_notification_allowed(meta, "emergency")

  def test_log_level_warning_rejects_below_warning(self):
    meta = _minimal_request_meta()
    meta[KEY_LOG_LEVEL] = "warning"
    assert not is_log_notification_allowed(meta, "debug")
    assert not is_log_notification_allowed(meta, "info")
    assert not is_log_notification_allowed(meta, "notice")

  def test_logging_levels_in_ascending_order(self):
    """Severity order: debug < info < notice < warning < error < critical < alert < emergency."""
    assert LOGGING_LEVELS_ASCENDING.index(LOGGING_LEVEL_DEBUG) < \
           LOGGING_LEVELS_ASCENDING.index(LOGGING_LEVEL_WARNING)
    assert LOGGING_LEVELS_ASCENDING.index(LOGGING_LEVEL_WARNING) < \
           LOGGING_LEVELS_ASCENDING.index(LOGGING_LEVEL_EMERGENCY)

  def test_log_level_must_be_string_when_present(self):
    meta = _minimal_request_meta()
    meta[KEY_LOG_LEVEL] = 42
    with pytest.raises(TypeError, match="must be a string"):
      validate_request_meta_object(meta)

  def test_validate_logging_level_accepts_known_values(self):
    for lvl in LOGGING_LEVELS_ASCENDING:
      assert validate_logging_level(lvl) == lvl

  def test_validate_logging_level_rejects_non_string(self):
    with pytest.raises(TypeError, match="must be a string"):
      validate_logging_level(99)


# ---------------------------------------------------------------------------
# AC-05.20 — progressToken is optional  (R-4.3-e)
# ---------------------------------------------------------------------------

class TestProgressTokenOptional:
  def test_progress_token_string_is_accepted(self):
    meta = _minimal_request_meta()
    meta["progressToken"] = "req-1-progress"
    validate_request_meta_object(meta)

  def test_progress_token_integer_is_accepted(self):
    meta = _minimal_request_meta()
    meta["progressToken"] = 42
    validate_request_meta_object(meta)

  def test_absent_progress_token_is_valid(self):
    meta = _minimal_request_meta()
    assert "progressToken" not in meta
    validate_request_meta_object(meta)


# ---------------------------------------------------------------------------
# AC-05.21 — Implementation requires name and version  (R-4.3-h)
# ---------------------------------------------------------------------------

class TestImplementationValidation:
  def test_implementation_with_name_and_version_is_valid(self):
    meta = _minimal_request_meta()
    validate_request_meta_object(meta)

  def test_implementation_missing_name_raises(self):
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_INFO] = {"version": "1.0.0"}
    with pytest.raises(ValueError, match="name is REQUIRED"):
      validate_request_meta_object(meta)

  def test_implementation_missing_version_raises(self):
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_INFO] = {"name": "test-client"}
    with pytest.raises(ValueError, match="version is REQUIRED"):
      validate_request_meta_object(meta)

  def test_implementation_empty_name_raises(self):
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_INFO] = {"name": "", "version": "1.0.0"}
    with pytest.raises(ValueError, match="name is REQUIRED"):
      validate_request_meta_object(meta)

  def test_implementation_optional_fields_accepted(self):
    """title, description, websiteUrl, icons are optional (R-4.3-h)."""
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_INFO] = {
      "name": "test-client",
      "version": "1.0.0",
      "title": "Test Client",
      "description": "A test client",
      "websiteUrl": "https://example.com",
    }
    validate_request_meta_object(meta)


# ---------------------------------------------------------------------------
# AC-05.22 — Unsupported protocolVersion → rejection  (R-4.3-f)
# ---------------------------------------------------------------------------

class TestUnsupportedProtocolVersion:
  def test_supported_version_accepted(self):
    meta = _minimal_request_meta()
    meta[KEY_PROTOCOL_VERSION] = "2026-07-28"
    validate_request_meta_object(
      meta, supported_versions=frozenset({"2026-07-28"})
    )

  def test_unsupported_version_raises(self):
    meta = _minimal_request_meta()
    meta[KEY_PROTOCOL_VERSION] = "1999-01-01"
    with pytest.raises(UnsupportedProtocolVersionError) as exc_info:
      validate_request_meta_object(
        meta, supported_versions=frozenset({"2026-07-28"})
      )
    assert exc_info.value.version == "1999-01-01"
    assert exc_info.value.json_rpc_code == -32004

  def test_no_supported_versions_arg_means_all_accepted(self):
    """Without supported_versions, any string version is accepted."""
    meta = _minimal_request_meta()
    meta[KEY_PROTOCOL_VERSION] = "9999-01-01"
    validate_request_meta_object(meta)


# ---------------------------------------------------------------------------
# AC-05.23 — HTTP: protocolVersion must match MCP-Protocol-Version header  (R-4.3-g)
# ---------------------------------------------------------------------------

class TestHttpVersionHeaderCheck:
  def test_matching_header_is_valid(self):
    validate_protocol_version_header("2026-07-28", "2026-07-28")

  def test_differing_header_raises(self):
    with pytest.raises(ValueError, match="differs from"):
      validate_protocol_version_header("2026-07-28", "2025-01-01")

  def test_absent_header_raises(self):
    with pytest.raises(ValueError, match="absent"):
      validate_protocol_version_header("2026-07-28", None)


# ---------------------------------------------------------------------------
# AC-05.24 — Server MUST NOT infer capabilities from prior requests  (R-4.3-i/j)
# ---------------------------------------------------------------------------

class TestCapabilityNotInferredFromPriorRequest:
  def test_second_request_evaluated_independently(self):
    """Each call to require_client_capability uses only the provided meta."""
    req1_meta = _minimal_request_meta()
    req1_meta[KEY_CLIENT_CAPABILITIES] = {"elicitation": {}}

    req2_meta = _minimal_request_meta()
    req2_meta[KEY_CLIENT_CAPABILITIES] = {}  # capability absent in second request

    # First request has the capability.
    require_client_capability(req1_meta, {"elicitation": {}})

    # Second request does NOT have it; MUST raise regardless of first.
    with pytest.raises(MissingRequiredClientCapabilityError):
      require_client_capability(req2_meta, {"elicitation": {}})

  def test_capability_present_in_second_request_is_honored(self):
    """If the second request declares a capability, it is accepted for that request."""
    req2_meta = _minimal_request_meta()
    req2_meta[KEY_CLIENT_CAPABILITIES] = {"elicitation": {}}
    require_client_capability(req2_meta, {"elicitation": {}})


# ---------------------------------------------------------------------------
# AC-05.25 — Missing required client capability → -32003  (R-4.3-k)
# ---------------------------------------------------------------------------

class TestMissingRequiredClientCapability:
  def test_required_capability_present_is_ok(self):
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_CAPABILITIES] = {"elicitation": {}}
    require_client_capability(meta, {"elicitation": {}})

  def test_missing_capability_raises_with_code_32003(self):
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_CAPABILITIES] = {}
    with pytest.raises(MissingRequiredClientCapabilityError) as exc_info:
      require_client_capability(meta, {"elicitation": {}})
    assert exc_info.value.json_rpc_code == -32003
    assert "elicitation" in exc_info.value.required_capabilities

  def test_partial_capabilities_missing_raises(self):
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_CAPABILITIES] = {"elicitation": {}}
    with pytest.raises(MissingRequiredClientCapabilityError) as exc_info:
      require_client_capability(meta, {"elicitation": {}, "sampling": {}})
    assert "sampling" in exc_info.value.required_capabilities
    assert "elicitation" not in exc_info.value.required_capabilities

  def test_error_carries_requiredCapabilities_for_data_field(self):
    """Exception carries the map for populating data.requiredCapabilities (R-4.3-k)."""
    meta = _minimal_request_meta()
    meta[KEY_CLIENT_CAPABILITIES] = {}
    with pytest.raises(MissingRequiredClientCapabilityError) as exc_info:
      require_client_capability(meta, {"elicitation": {}, "sampling": {}})
    caps = exc_info.value.required_capabilities
    assert "elicitation" in caps
    assert "sampling" in caps
