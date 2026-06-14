"""Tests for S23 — Deprecated Logging & Trace Context Propagation.

Coverage map (19 ACs):
  AC-23.1  → TestLoggingDeprecationMarkers
  AC-23.2  → TestLoggingLevelSet
  AC-23.3  → TestValidateKnownLoggingLevel
  AC-23.4  → TestInvalidLoggingLevelError
  AC-23.5  → TestCompareLoggingLevels
  AC-23.6  → TestShouldEmitLogNotification
  AC-23.7  → TestLoggingMessageParams
  AC-23.8  → TestLoggingMessageParamsToDict
  AC-23.9  → TestLoggingMessageValidationErrors
  AC-23.10 → TestExtractTraceContext
  AC-23.11 → TestPropagateTraceContext
  AC-23.12 → TestValidateTraceContextValues
  AC-23.13 → TestTraceparentFormat
  AC-23.14 → TestTracestateFormat
  AC-23.15 → TestBaggageFormat
  AC-23.16 → TestTraceContextIsOptional
  AC-23.17 → TestLoggingMethodName
  AC-23.18 → TestLoggingLevelOrdering
  AC-23.19 → TestLoggingDataAny
"""

import pytest

from mcp_sdk_py.logging_utils import (
  LOGGING_DEPRECATED_SEP,
  LOGGING_IS_DEPRECATED,
  LOGGING_LEVELS,
  LOGGING_MESSAGE_METHOD,
  InvalidLoggingLevelError,
  LoggingMessageNotificationParams,
  compare_logging_levels,
  extract_trace_context,
  propagate_trace_context,
  should_emit_log_notification,
  validate_known_logging_level,
  validate_logging_message_notification_params,
  validate_trace_context_values,
)
from mcp_sdk_py.meta_object import KEY_LOG_LEVEL, LOGGING_LEVELS_ASCENDING
from mcp_sdk_py.json_value import W3C_TRACE_KEYS


# ---------------------------------------------------------------------------
# AC-23.1 — Deprecation markers  (R-15.3-a)
# ---------------------------------------------------------------------------

class TestLoggingDeprecationMarkers:
  def test_logging_is_deprecated_true(self):
    assert LOGGING_IS_DEPRECATED is True

  def test_logging_deprecated_sep(self):
    assert isinstance(LOGGING_DEPRECATED_SEP, str)
    assert len(LOGGING_DEPRECATED_SEP) > 0
    assert "SEP" in LOGGING_DEPRECATED_SEP


# ---------------------------------------------------------------------------
# AC-23.2 — Eight recognized logging levels  (§15.3.1)
# ---------------------------------------------------------------------------

class TestLoggingLevelSet:
  def test_logging_levels_frozenset(self):
    assert isinstance(LOGGING_LEVELS, frozenset)

  def test_eight_levels(self):
    assert len(LOGGING_LEVELS) == 8

  def test_all_eight_names_present(self):
    expected = {
      "debug", "info", "notice", "warning",
      "error", "critical", "alert", "emergency",
    }
    assert LOGGING_LEVELS == expected

  def test_levels_ascending_has_same_content(self):
    assert set(LOGGING_LEVELS_ASCENDING) == LOGGING_LEVELS


# ---------------------------------------------------------------------------
# AC-23.3 — validate_known_logging_level: closed-set check  (R-15.3.2-a)
# ---------------------------------------------------------------------------

class TestValidateKnownLoggingLevel:
  def test_all_valid_levels_pass(self):
    for lvl in LOGGING_LEVELS:
      assert validate_known_logging_level(lvl) == lvl

  def test_unrecognized_level_raises(self):
    with pytest.raises(InvalidLoggingLevelError):
      validate_known_logging_level("verbose")

  def test_non_string_raises(self):
    with pytest.raises(InvalidLoggingLevelError):
      validate_known_logging_level(3)

  def test_empty_string_raises(self):
    with pytest.raises(InvalidLoggingLevelError):
      validate_known_logging_level("")

  def test_case_sensitive(self):
    with pytest.raises(InvalidLoggingLevelError):
      validate_known_logging_level("Debug")


# ---------------------------------------------------------------------------
# AC-23.4 — InvalidLoggingLevelError has json_rpc_code -32602  (R-15.3.3-g)
# ---------------------------------------------------------------------------

class TestInvalidLoggingLevelError:
  def test_error_json_rpc_code(self):
    assert InvalidLoggingLevelError.json_rpc_code == -32602

  def test_error_is_value_error(self):
    with pytest.raises(ValueError):
      validate_known_logging_level("unknown-level")

  def test_error_carries_value(self):
    try:
      validate_known_logging_level("INVALID")
    except InvalidLoggingLevelError as e:
      assert e.value == "INVALID"


# ---------------------------------------------------------------------------
# AC-23.5 — compare_logging_levels ordinal order  (R-15.3.1-a)
# ---------------------------------------------------------------------------

class TestCompareLoggingLevels:
  def test_debug_lt_info(self):
    assert compare_logging_levels("debug", "info") < 0

  def test_emergency_gt_debug(self):
    assert compare_logging_levels("emergency", "debug") > 0

  def test_same_level_is_zero(self):
    assert compare_logging_levels("warning", "warning") == 0

  def test_full_ascending_order(self):
    levels = LOGGING_LEVELS_ASCENDING
    for i in range(len(levels) - 1):
      assert compare_logging_levels(levels[i], levels[i + 1]) < 0

  def test_invalid_level_raises(self):
    with pytest.raises(InvalidLoggingLevelError):
      compare_logging_levels("debug", "verbose")


# ---------------------------------------------------------------------------
# AC-23.6 — should_emit_log_notification  (R-15.3.3-a/b/c/d)
# ---------------------------------------------------------------------------

class TestShouldEmitLogNotification:
  def test_no_log_level_in_meta_returns_false(self):
    assert not should_emit_log_notification({}, "debug")

  def test_emit_at_or_above_minimum(self):
    meta = {KEY_LOG_LEVEL: "warning"}
    assert should_emit_log_notification(meta, "warning")
    assert should_emit_log_notification(meta, "error")
    assert should_emit_log_notification(meta, "emergency")

  def test_do_not_emit_below_minimum(self):
    meta = {KEY_LOG_LEVEL: "warning"}
    assert not should_emit_log_notification(meta, "debug")
    assert not should_emit_log_notification(meta, "info")
    assert not should_emit_log_notification(meta, "notice")


# ---------------------------------------------------------------------------
# AC-23.7 — LoggingMessageNotificationParams dataclass  (§15.3.2)
# ---------------------------------------------------------------------------

class TestLoggingMessageParams:
  def test_minimal_valid(self):
    p = validate_logging_message_notification_params({
      "level": "info",
      "data": {"msg": "hello"},
    })
    assert p.level == "info"
    assert p.data == {"msg": "hello"}

  def test_all_fields_parsed(self):
    p = validate_logging_message_notification_params({
      "level": "warning",
      "data": "text data",
      "logger": "my-logger",
      "_meta": {"trace": "x"},
    })
    assert p.logger == "my-logger"
    assert p.meta == {"trace": "x"}

  def test_level_required(self):
    with pytest.raises(ValueError, match="level"):
      validate_logging_message_notification_params({"data": "x"})

  def test_data_required(self):
    with pytest.raises(ValueError, match="data"):
      validate_logging_message_notification_params({"level": "info"})


# ---------------------------------------------------------------------------
# AC-23.8 — LoggingMessageNotificationParams.to_dict()  (§15.3.2)
# ---------------------------------------------------------------------------

class TestLoggingMessageParamsToDict:
  def test_minimal_serialization(self):
    p = LoggingMessageNotificationParams(level="error", data="boom")
    d = p.to_dict()
    assert d == {"level": "error", "data": "boom"}

  def test_full_serialization(self):
    p = LoggingMessageNotificationParams(
      level="debug",
      data={"detail": True},
      logger="srv",
      meta={"t": "p"},
    )
    d = p.to_dict()
    assert d["level"] == "debug"
    assert d["data"] == {"detail": True}
    assert d["logger"] == "srv"
    assert d["_meta"] == {"t": "p"}

  def test_absent_optionals_excluded(self):
    p = LoggingMessageNotificationParams(level="info", data=42)
    d = p.to_dict()
    assert "logger" not in d
    assert "_meta" not in d


# ---------------------------------------------------------------------------
# AC-23.9 — Logging notification validation errors
# ---------------------------------------------------------------------------

class TestLoggingMessageValidationErrors:
  def test_unrecognized_level_raises(self):
    with pytest.raises(InvalidLoggingLevelError):
      validate_logging_message_notification_params({
        "level": "trace",
        "data": "x",
      })

  def test_not_a_dict_raises(self):
    with pytest.raises(TypeError):
      validate_logging_message_notification_params("not a dict")

  def test_logger_must_be_string(self):
    with pytest.raises(TypeError):
      validate_logging_message_notification_params({
        "level": "info",
        "data": "x",
        "logger": 99,
      })

  def test_meta_must_be_dict(self):
    with pytest.raises(TypeError):
      validate_logging_message_notification_params({
        "level": "info",
        "data": "x",
        "_meta": "not-dict",
      })


# ---------------------------------------------------------------------------
# AC-23.10 — extract_trace_context returns only present W3C keys  (§15.4)
# ---------------------------------------------------------------------------

class TestExtractTraceContext:
  def test_extracts_present_keys(self):
    meta = {
      "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
      "other-key": "ignored",
    }
    ctx = extract_trace_context(meta)
    assert "traceparent" in ctx
    assert "other-key" not in ctx

  def test_empty_meta_returns_empty(self):
    assert extract_trace_context({}) == {}

  def test_all_three_trace_keys_extracted(self):
    meta = {
      "traceparent": "00-aabbcc-ddeeff-00",
      "tracestate": "vendor=opaque",
      "baggage": "k=v",
    }
    ctx = extract_trace_context(meta)
    assert set(ctx.keys()) == {"traceparent", "tracestate", "baggage"}

  def test_w3c_trace_keys_constant(self):
    assert "traceparent" in W3C_TRACE_KEYS
    assert "tracestate" in W3C_TRACE_KEYS
    assert "baggage" in W3C_TRACE_KEYS


# ---------------------------------------------------------------------------
# AC-23.11 — propagate_trace_context copies verbatim  (R-15.4.2-h)
# ---------------------------------------------------------------------------

class TestPropagateTraceContext:
  def test_copies_trace_keys_to_outbound(self):
    inbound = {
      "traceparent": "00-abc-def-01",
      "other": "ignored",
    }
    outbound = {}
    result = propagate_trace_context(inbound, outbound)
    assert result["traceparent"] == "00-abc-def-01"
    assert "other" not in result

  def test_returns_updated_outbound(self):
    inbound = {"traceparent": "00-x-y-00"}
    outbound = {"existing-key": "value"}
    result = propagate_trace_context(inbound, outbound)
    assert result["existing-key"] == "value"
    assert result["traceparent"] == "00-x-y-00"

  def test_modifies_outbound_in_place(self):
    outbound = {}
    propagate_trace_context({"tracestate": "k=v"}, outbound)
    assert outbound["tracestate"] == "k=v"

  def test_no_trace_keys_in_inbound_leaves_outbound_unchanged(self):
    outbound = {"my": "data"}
    result = propagate_trace_context({"other": "stuff"}, outbound)
    assert result == {"my": "data"}


# ---------------------------------------------------------------------------
# AC-23.12 — validate_trace_context_values validates present keys  (§15.4.1)
# ---------------------------------------------------------------------------

class TestValidateTraceContextValues:
  def test_absent_keys_not_validated(self):
    result = validate_trace_context_values({})
    assert result == {}

  def test_valid_traceparent_passes(self):
    meta = {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
    result = validate_trace_context_values(meta)
    assert "traceparent" in result

  def test_non_trace_keys_ignored(self):
    meta = {"not-a-trace-key": "something"}
    result = validate_trace_context_values(meta)
    assert result == {}


# ---------------------------------------------------------------------------
# AC-23.13 — traceparent: W3C Trace Context format  (R-15.4.1-a)
# ---------------------------------------------------------------------------

class TestTraceparentFormat:
  def test_valid_traceparent(self):
    from mcp_sdk_py.json_value import validate_w3c_traceparent
    # Standard 00 version traceparent.
    validate_w3c_traceparent(
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    )

  def test_invalid_traceparent_raises(self):
    from mcp_sdk_py.json_value import validate_w3c_traceparent
    with pytest.raises(ValueError):
      validate_w3c_traceparent("not-a-traceparent")


# ---------------------------------------------------------------------------
# AC-23.14 — tracestate: W3C Trace Context format  (R-15.4.1-b)
# ---------------------------------------------------------------------------

class TestTracestateFormat:
  def test_valid_tracestate(self):
    from mcp_sdk_py.json_value import validate_w3c_tracestate
    validate_w3c_tracestate("vendor=value")

  def test_multi_vendor_tracestate(self):
    from mcp_sdk_py.json_value import validate_w3c_tracestate
    validate_w3c_tracestate("rojo=00f067aa0ba902b7,congo=t61rcWkgMzE")


# ---------------------------------------------------------------------------
# AC-23.15 — baggage: W3C Baggage format  (R-15.4.1-c)
# ---------------------------------------------------------------------------

class TestBaggageFormat:
  def test_valid_baggage(self):
    from mcp_sdk_py.json_value import validate_w3c_baggage
    validate_w3c_baggage("key=value,other=thing")

  def test_invalid_baggage_raises(self):
    from mcp_sdk_py.json_value import validate_w3c_baggage
    with pytest.raises(ValueError):
      validate_w3c_baggage("no-equals-sign-here!!")


# ---------------------------------------------------------------------------
# AC-23.16 — Trace keys are optional; receiver MUST NOT require  (R-15.4.2-b)
# ---------------------------------------------------------------------------

class TestTraceContextIsOptional:
  def test_no_trace_keys_extract_returns_empty(self):
    assert extract_trace_context({"other": "data"}) == {}

  def test_propagate_with_no_trace_keys_is_noop(self):
    outbound = {}
    result = propagate_trace_context({"no-trace": "here"}, outbound)
    assert result == {}

  def test_validate_with_no_trace_keys_returns_empty(self):
    result = validate_trace_context_values({"foo": "bar"})
    assert result == {}


# ---------------------------------------------------------------------------
# AC-23.17 — Logging method name constant  (§15.3)
# ---------------------------------------------------------------------------

class TestLoggingMethodName:
  def test_logging_method_name(self):
    assert LOGGING_MESSAGE_METHOD == "notifications/message"


# ---------------------------------------------------------------------------
# AC-23.18 — Logging level ordering invariants  (R-15.3.1-a)
# ---------------------------------------------------------------------------

class TestLoggingLevelOrdering:
  def test_debug_is_lowest(self):
    for other in LOGGING_LEVELS - {"debug"}:
      assert compare_logging_levels("debug", other) < 0

  def test_emergency_is_highest(self):
    for other in LOGGING_LEVELS - {"emergency"}:
      assert compare_logging_levels("emergency", other) > 0

  def test_info_above_debug(self):
    assert compare_logging_levels("info", "debug") > 0

  def test_error_above_warning(self):
    assert compare_logging_levels("error", "warning") > 0


# ---------------------------------------------------------------------------
# AC-23.19 — data field accepts any JSON value  (R-15.3.2-c/d)
# ---------------------------------------------------------------------------

class TestLoggingDataAny:
  def test_data_as_string(self):
    p = validate_logging_message_notification_params({"level": "info", "data": "text"})
    assert p.data == "text"

  def test_data_as_number(self):
    p = validate_logging_message_notification_params({"level": "info", "data": 42})
    assert p.data == 42

  def test_data_as_bool(self):
    p = validate_logging_message_notification_params({"level": "info", "data": True})
    assert p.data is True

  def test_data_as_null(self):
    p = validate_logging_message_notification_params({"level": "info", "data": None})
    assert p.data is None

  def test_data_as_list(self):
    p = validate_logging_message_notification_params({"level": "info", "data": [1, 2]})
    assert p.data == [1, 2]

  def test_data_as_nested_object(self):
    payload = {"key": {"nested": True}}
    p = validate_logging_message_notification_params({"level": "debug", "data": payload})
    assert p.data == payload
