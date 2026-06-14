"""Tests for S03 — JSON-RPC Base Message Framing.

Every test class maps to one or more acceptance criteria (AC-03.x).
"""

import pytest

from mcp_sdk_py.jsonrpc import (
  FramingError,
  InFlightTracker,
  JSONRPCErrorResponse,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResultResponse,
  MethodDescriptor,
  RequestDispatcher,
  classify_message,
  ids_are_equal,
  validate_request_id,
)


# ---------------------------------------------------------------------------
# AC-03.1: batch arrays forbidden (R-3.1-b, R-3.1-c)
# ---------------------------------------------------------------------------

class TestAC031BatchForbidden:
  def test_top_level_array_raises_framing_error(self):
    with pytest.raises(FramingError):
      classify_message([{"jsonrpc": "2.0", "id": 1, "method": "a"}])

  def test_empty_array_raises_framing_error(self):
    with pytest.raises(FramingError):
      classify_message([])

  def test_batch_error_is_not_notification(self):
    with pytest.raises(FramingError) as exc_info:
      classify_message([])
    assert not exc_info.value.is_notification

  def test_sender_never_emits_array(self):
    # All to_dict() methods return dicts, never lists
    assert isinstance(JSONRPCRequest(id=1, method="a").to_dict(), dict)
    assert isinstance(JSONRPCNotification(method="a").to_dict(), dict)
    assert isinstance(JSONRPCResultResponse(id=1, result={}).to_dict(), dict)
    assert isinstance(JSONRPCErrorResponse(error={"code": -1, "message": "x"}).to_dict(), dict)


# ---------------------------------------------------------------------------
# AC-03.2: emitted messages are single JSON objects (R-3.1-a)
# ---------------------------------------------------------------------------

class TestAC032EmittedMessages:
  def test_request_to_dict_is_dict(self):
    d = JSONRPCRequest(id=1, method="tools/call").to_dict()
    assert isinstance(d, dict)

  def test_notification_to_dict_is_dict(self):
    d = JSONRPCNotification(method="notifications/progress").to_dict()
    assert isinstance(d, dict)

  def test_result_response_to_dict_is_dict(self):
    d = JSONRPCResultResponse(id=1, result={}).to_dict()
    assert isinstance(d, dict)

  def test_error_response_to_dict_is_dict(self):
    d = JSONRPCErrorResponse(error={"code": -32601, "message": "x"}).to_dict()
    assert isinstance(d, dict)


# ---------------------------------------------------------------------------
# AC-03.3: wrong/absent jsonrpc rejected; every emitted message has "2.0" (R-3.1-d/e)
# ---------------------------------------------------------------------------

class TestAC033JsonrpcVersion:
  def test_missing_jsonrpc_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"id": 1, "method": "ping"})

  def test_wrong_version_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": "1.0", "id": 1, "method": "ping"})

  def test_null_jsonrpc_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": None, "id": 1, "method": "ping"})

  def test_request_emits_jsonrpc_20(self):
    assert JSONRPCRequest(id=1, method="ping").to_dict()["jsonrpc"] == "2.0"

  def test_notification_emits_jsonrpc_20(self):
    assert JSONRPCNotification(method="a").to_dict()["jsonrpc"] == "2.0"

  def test_result_response_emits_jsonrpc_20(self):
    assert JSONRPCResultResponse(id=1, result={}).to_dict()["jsonrpc"] == "2.0"

  def test_error_response_emits_jsonrpc_20(self):
    assert JSONRPCErrorResponse(error={"code": -1, "message": "x"}).to_dict()["jsonrpc"] == "2.0"


# ---------------------------------------------------------------------------
# AC-03.4: contradictory member combinations rejected (R-3.1-f)
# ---------------------------------------------------------------------------

class TestAC034ContradictoryCombinations:
  def test_method_with_result_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": "2.0", "id": 1, "method": "a", "result": {}})

  def test_method_with_error_rejected(self):
    with pytest.raises(FramingError):
      classify_message({
        "jsonrpc": "2.0", "id": 1, "method": "a",
        "error": {"code": -32603, "message": "x"},
      })

  def test_result_and_error_rejected(self):
    with pytest.raises(FramingError):
      classify_message({
        "jsonrpc": "2.0", "id": 9,
        "result": {},
        "error": {"code": -32603, "message": "Internal error"},
      })

  def test_method_result_without_id_is_notification_path(self):
    # method + result, no id: still contradictory; framing error
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": "2.0", "method": "a", "result": {}})


# ---------------------------------------------------------------------------
# AC-03.5: RequestId is string or number, never null (R-3.2-a, R-3.2-b)
# ---------------------------------------------------------------------------

class TestAC035RequestId:
  def test_string_id_valid(self):
    assert validate_request_id("abc") == "abc"

  def test_int_id_valid(self):
    assert validate_request_id(42) == 42

  def test_float_id_valid(self):
    assert validate_request_id(3.14) == 3.14

  def test_null_id_rejected(self):
    with pytest.raises(TypeError):
      validate_request_id(None)

  def test_bool_id_rejected(self):
    with pytest.raises(TypeError):
      validate_request_id(True)

  def test_list_id_rejected(self):
    with pytest.raises(TypeError):
      validate_request_id([1])

  def test_dict_id_rejected(self):
    with pytest.raises(TypeError):
      validate_request_id({})

  def test_request_with_null_id_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": "2.0", "id": None, "method": "ping"})


# ---------------------------------------------------------------------------
# AC-03.6: in-flight id uniqueness (R-3.2-c, R-3.2-d)
# ---------------------------------------------------------------------------

class TestAC036InFlightUniqueness:
  def test_unique_ids_accepted(self):
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.send(2)
    tracker.send("three")
    assert tracker.is_in_flight(1)
    assert tracker.is_in_flight(2)
    assert tracker.is_in_flight("three")

  def test_duplicate_in_flight_id_rejected(self):
    tracker = InFlightTracker()
    tracker.send(1)
    with pytest.raises(ValueError):
      tracker.send(1)

  def test_id_reusable_after_response(self):
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.receive(1)
    tracker.send(1)  # allowed now: response was received

  def test_string_and_int_same_value_are_distinct_ids(self):
    # str "1" and int 1 are different RequestIds
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.send("1")  # different type; not a duplicate
    assert tracker.is_in_flight(1)
    assert tracker.is_in_flight("1")

  def test_in_flight_ids_snapshot(self):
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.send("abc")
    ids = tracker.in_flight_ids
    assert 1 in ids
    assert "abc" in ids

  def test_receive_clears_id(self):
    tracker = InFlightTracker()
    tracker.send(5)
    tracker.receive(5)
    assert not tracker.is_in_flight(5)


# ---------------------------------------------------------------------------
# AC-03.7: id echoed with same JSON type and value; no coercion (R-3.2-e/f/g)
# ---------------------------------------------------------------------------

class TestAC037IdEcho:
  def test_numeric_id_echoed_as_number(self):
    msg = classify_message({"jsonrpc": "2.0", "id": 7, "result": {}})
    assert isinstance(msg, JSONRPCResultResponse)
    assert msg.id == 7
    assert not isinstance(msg.id, str)

  def test_string_id_echoed_as_string(self):
    msg = classify_message({"jsonrpc": "2.0", "id": "req-1", "result": {}})
    assert isinstance(msg, JSONRPCResultResponse)
    assert msg.id == "req-1"
    assert isinstance(msg.id, str)

  def test_ids_equal_same_int(self):
    assert ids_are_equal(7, 7)

  def test_ids_equal_same_string(self):
    assert ids_are_equal("abc", "abc")

  def test_ids_equal_int_and_float_same_value(self):
    # Both are JSON numbers with the same value
    assert ids_are_equal(7, 7.0)

  def test_ids_not_equal_type_mismatch_int_vs_str(self):
    assert not ids_are_equal(7, "7")

  def test_ids_not_equal_different_numeric_value(self):
    assert not ids_are_equal(1, 2)

  def test_ids_not_equal_different_string(self):
    assert not ids_are_equal("a", "b")


# ---------------------------------------------------------------------------
# AC-03.8: request contains jsonrpc, id, method (R-3.3-a/b/c)
# ---------------------------------------------------------------------------

class TestAC038RequestFields:
  def test_request_classified_with_all_required_fields(self):
    msg = classify_message({
      "jsonrpc": "2.0",
      "id": 7,
      "method": "tools/call",
      "params": {"name": "search", "arguments": {"query": "mcp"}},
    })
    assert isinstance(msg, JSONRPCRequest)
    assert msg.jsonrpc == "2.0"
    assert msg.id == 7
    assert msg.method == "tools/call"

  def test_request_without_params_is_valid(self):
    msg = classify_message({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert isinstance(msg, JSONRPCRequest)
    assert msg.params is None

  def test_request_missing_method_raises_framing_error(self):
    with pytest.raises(FramingError):
      # Has id and result — classified as success response, but no result
      classify_message({"jsonrpc": "2.0", "id": 1})


# ---------------------------------------------------------------------------
# AC-03.9: method names are case-sensitive and reproduced verbatim (R-3.3-d)
# ---------------------------------------------------------------------------

class TestAC039MethodCaseSensitive:
  def test_different_case_methods_are_distinct(self):
    msg_a = classify_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call"})
    msg_b = classify_message({"jsonrpc": "2.0", "id": 2, "method": "Tools/Call"})
    assert isinstance(msg_a, JSONRPCRequest)
    assert isinstance(msg_b, JSONRPCRequest)
    assert msg_a.method != msg_b.method

  def test_method_reproduced_verbatim(self):
    method = "notifications/Progress"
    msg = classify_message({"jsonrpc": "2.0", "method": method})
    assert isinstance(msg, JSONRPCNotification)
    assert msg.method == method


# ---------------------------------------------------------------------------
# AC-03.10: params must be a JSON object, not array (R-3.3-e/f/g)
# ---------------------------------------------------------------------------

class TestAC0310Params:
  def test_params_as_object_accepted(self):
    msg = classify_message({
      "jsonrpc": "2.0", "id": 1, "method": "a",
      "params": {"key": "val"},
    })
    assert isinstance(msg, JSONRPCRequest)
    assert msg.params == {"key": "val"}

  def test_params_as_array_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": "2.0", "id": 1, "method": "a", "params": [1, 2]})

  def test_params_absent_is_valid(self):
    msg = classify_message({"jsonrpc": "2.0", "id": 1, "method": "a"})
    assert isinstance(msg, JSONRPCRequest)
    assert msg.params is None

  def test_params_absent_omitted_from_to_dict(self):
    d = JSONRPCRequest(id=1, method="ping").to_dict()
    assert "params" not in d


# ---------------------------------------------------------------------------
# AC-03.11: params optional unless _meta required (R-3.3-h/i)
# ---------------------------------------------------------------------------

class TestAC0311ParamsOptional:
  def test_params_may_be_omitted_for_no_arg_method(self):
    req = JSONRPCRequest(id=1, method="ping")
    assert req.params is None
    assert "params" not in req.to_dict()

  def test_params_present_carries_meta(self):
    req = JSONRPCRequest(id=1, method="ping", params={"_meta": {"progressToken": "tok"}})
    d = req.to_dict()
    assert "params" in d
    assert d["params"]["_meta"]["progressToken"] == "tok"

  def test_dispatcher_meta_required_method_absent_params_rejected(self):
    """R-3.3-i: _meta-REQUIRED method with absent params → error response (AC-03.11)."""
    dispatcher = RequestDispatcher()
    dispatcher.register("tools/call", requires_meta=True)
    req = JSONRPCRequest(id=99, method="tools/call")  # params absent
    result = dispatcher.dispatch(req)
    assert isinstance(result, JSONRPCErrorResponse)
    assert result.id == 99

  def test_dispatcher_meta_required_method_params_present_accepted(self):
    """R-3.3-i: _meta-REQUIRED method with params present → no error (AC-03.11)."""
    dispatcher = RequestDispatcher()
    dispatcher.register("tools/call", requires_meta=True)
    req = JSONRPCRequest(
      id=100, method="tools/call",
      params={"_meta": {"progressToken": "tok"}},
    )
    result = dispatcher.dispatch(req)
    assert result is None


# ---------------------------------------------------------------------------
# AC-03.12: method-not-found / invalid-params obligations (R-3.3-j/k)
# ---------------------------------------------------------------------------

class TestAC0312MethodNotFoundObligation:
  def test_classify_succeeds_for_unrecognized_method(self):
    # classify_message passes the request through; the dispatcher enforces R-3.3-j
    msg = classify_message({"jsonrpc": "2.0", "id": 1, "method": "unknown/method"})
    assert isinstance(msg, JSONRPCRequest)
    assert msg.method == "unknown/method"

  def test_dispatcher_unknown_method_returns_error_response(self):
    """R-3.3-j: unrecognized method → error response (AC-03.12)."""
    dispatcher = RequestDispatcher()
    dispatcher.register("known/method")
    req = JSONRPCRequest(id=1, method="unknown/method")
    result = dispatcher.dispatch(req)
    assert isinstance(result, JSONRPCErrorResponse)

  def test_dispatcher_unknown_method_error_echoes_request_id(self):
    """Error response id matches the request id (R-3.5.2-c)."""
    dispatcher = RequestDispatcher()
    dispatcher.register("known/method")
    req = JSONRPCRequest(id="req-5", method="no-such-method")
    result = dispatcher.dispatch(req)
    assert isinstance(result, JSONRPCErrorResponse)
    assert result.id == "req-5"
    assert isinstance(result.id, str)

  def test_dispatcher_invalid_params_returns_error_response(self):
    """R-3.3-k: params schema violation → error response (AC-03.12)."""
    def validator(params: dict) -> None:
      if "name" not in params:
        raise ValueError("name is required")

    dispatcher = RequestDispatcher()
    dispatcher.register("tools/call", params_validator=validator)
    req = JSONRPCRequest(id=2, method="tools/call", params={})
    result = dispatcher.dispatch(req)
    assert isinstance(result, JSONRPCErrorResponse)
    assert result.id == 2

  def test_dispatcher_valid_params_returns_none(self):
    """No error when method is known and params satisfy the schema."""
    def validator(params: dict) -> None:
      if "name" not in params:
        raise ValueError("name required")

    dispatcher = RequestDispatcher()
    dispatcher.register("tools/call", params_validator=validator)
    req = JSONRPCRequest(id=3, method="tools/call", params={"name": "search"})
    result = dispatcher.dispatch(req)
    assert result is None

  def test_dispatcher_known_method_no_params_no_validator_returns_none(self):
    """Known method without params and no validator → passes cleanly."""
    dispatcher = RequestDispatcher()
    dispatcher.register("ping")
    req = JSONRPCRequest(id=4, method="ping")
    result = dispatcher.dispatch(req)
    assert result is None


# ---------------------------------------------------------------------------
# AC-03.13: notifications are one-way; malformed notifications get no response
#           (R-3.4-a, R-3.4-f)
# ---------------------------------------------------------------------------

class TestAC0313NotificationOneWay:
  def test_notification_classified(self):
    msg = classify_message({"jsonrpc": "2.0", "method": "notifications/progress"})
    assert isinstance(msg, JSONRPCNotification)

  def test_malformed_notification_params_raises_with_is_notification_true(self):
    with pytest.raises(FramingError) as exc_info:
      classify_message({"jsonrpc": "2.0", "method": "a", "params": [1, 2]})
    assert exc_info.value.is_notification is True

  def test_malformed_notification_no_originating_id(self):
    with pytest.raises(FramingError) as exc_info:
      classify_message({"jsonrpc": "2.0", "method": "a", "params": [1, 2]})
    assert exc_info.value.originating_id is None


# ---------------------------------------------------------------------------
# AC-03.14: notification has jsonrpc + method; params is object (R-3.4-b/c/d)
# ---------------------------------------------------------------------------

class TestAC0314NotificationFields:
  def test_notification_with_params(self):
    msg = classify_message({
      "jsonrpc": "2.0",
      "method": "notifications/progress",
      "params": {"progress": 0.5},
    })
    assert isinstance(msg, JSONRPCNotification)
    assert msg.jsonrpc == "2.0"
    assert msg.method == "notifications/progress"
    assert msg.params == {"progress": 0.5}

  def test_notification_method_is_case_sensitive(self):
    msg = classify_message({"jsonrpc": "2.0", "method": "Notifications/Progress"})
    assert isinstance(msg, JSONRPCNotification)
    assert msg.method == "Notifications/Progress"

  def test_notification_params_as_array_raises_is_notification(self):
    with pytest.raises(FramingError) as exc_info:
      classify_message({"jsonrpc": "2.0", "method": "a", "params": ["positional"]})
    assert exc_info.value.is_notification is True


# ---------------------------------------------------------------------------
# AC-03.15: notification has no id member (R-3.4-e)
# ---------------------------------------------------------------------------

class TestAC0315NotificationNoId:
  def test_notification_instance_has_no_id_attribute(self):
    msg = JSONRPCNotification(method="a")
    assert not hasattr(msg, "id")

  def test_notification_to_dict_has_no_id(self):
    d = JSONRPCNotification(method="a").to_dict()
    assert "id" not in d

  def test_classified_notification_has_no_id(self):
    msg = classify_message({"jsonrpc": "2.0", "method": "a"})
    assert isinstance(msg, JSONRPCNotification)
    assert "id" not in msg.to_dict()


# ---------------------------------------------------------------------------
# AC-03.16: response has exactly one of result or error (R-3.5-a/b/c)
# ---------------------------------------------------------------------------

class TestAC0316ResponseExactlyOne:
  def test_result_response_has_result_not_error(self):
    d = JSONRPCResultResponse(id=1, result={}).to_dict()
    assert "result" in d
    assert "error" not in d

  def test_error_response_has_error_not_result(self):
    d = JSONRPCErrorResponse(error={"code": -32601, "message": "x"}).to_dict()
    assert "error" in d
    assert "result" not in d

  def test_both_result_and_error_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1, "message": "x"}})


# ---------------------------------------------------------------------------
# AC-03.17: success response has jsonrpc, id, result (R-3.5.1-a/b/c)
# ---------------------------------------------------------------------------

class TestAC0317SuccessResponse:
  def test_success_response_fields(self):
    msg = classify_message({"jsonrpc": "2.0", "id": 7, "result": {"content": []}})
    assert isinstance(msg, JSONRPCResultResponse)
    assert msg.jsonrpc == "2.0"
    assert msg.id == 7
    assert msg.result == {"content": []}

  def test_success_response_missing_id_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": "2.0", "result": {}})

  def test_success_response_non_dict_result_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": "2.0", "id": 1, "result": "not a dict"})


# ---------------------------------------------------------------------------
# AC-03.18: error response has jsonrpc, error; id is optional (R-3.5.2-a/b/f)
# ---------------------------------------------------------------------------

class TestAC0318ErrorResponse:
  def test_error_response_with_id(self):
    msg = classify_message({
      "jsonrpc": "2.0", "id": 7,
      "error": {"code": -32601, "message": "Method not found"},
    })
    assert isinstance(msg, JSONRPCErrorResponse)
    assert msg.jsonrpc == "2.0"
    assert msg.id == 7

  def test_error_response_without_id(self):
    msg = classify_message({
      "jsonrpc": "2.0",
      "error": {"code": -32700, "message": "Parse error"},
    })
    assert isinstance(msg, JSONRPCErrorResponse)
    assert msg.id is None

  def test_error_response_to_dict_omits_none_id(self):
    d = JSONRPCErrorResponse(error={"code": -32700, "message": "Parse error"}).to_dict()
    assert "id" not in d

  def test_error_response_non_dict_error_rejected(self):
    with pytest.raises(FramingError):
      classify_message({"jsonrpc": "2.0", "id": 1, "error": "not a dict"})


# ---------------------------------------------------------------------------
# AC-03.19: error response id rules (R-3.5.2-c/d/e)
# ---------------------------------------------------------------------------

class TestAC0319ErrorResponseId:
  def test_error_response_id_set_when_known(self):
    msg = classify_message({
      "jsonrpc": "2.0", "id": 7,
      "error": {"code": -32601, "message": "x"},
    })
    assert isinstance(msg, JSONRPCErrorResponse)
    assert msg.id == 7

  def test_error_response_id_may_be_omitted_when_unknown(self):
    resp = JSONRPCErrorResponse(error={"code": -32700, "message": "Parse error"}, id=None)
    assert resp.id is None
    assert "id" not in resp.to_dict()

  def test_error_response_id_equals_originating_string_id(self):
    msg = classify_message({
      "jsonrpc": "2.0", "id": "req-42",
      "error": {"code": -32600, "message": "x"},
    })
    assert isinstance(msg, JSONRPCErrorResponse)
    assert msg.id == "req-42"
    assert isinstance(msg.id, str)

  def test_framing_error_carries_originating_id(self):
    with pytest.raises(FramingError) as exc_info:
      classify_message({"jsonrpc": "2.0", "id": 5, "result": "not-a-dict"})
    assert exc_info.value.originating_id == 5


# ---------------------------------------------------------------------------
# RequestDispatcher: comprehensive dispatch-surface tests (R-3.3-i/j/k)
# ---------------------------------------------------------------------------

class TestRequestDispatcher:
  """Comprehensive tests for RequestDispatcher (R-3.3-i, R-3.3-j, R-3.3-k)."""

  def test_empty_dispatcher_rejects_any_method(self):
    dispatcher = RequestDispatcher()
    result = dispatcher.dispatch(JSONRPCRequest(id=1, method="ping"))
    assert isinstance(result, JSONRPCErrorResponse)

  def test_method_descriptor_accessible(self):
    desc = MethodDescriptor(name="tools/call", requires_meta=True)
    assert desc.name == "tools/call"
    assert desc.requires_meta is True
    assert desc.params_validator is None

  def test_register_and_dispatch_known_method(self):
    dispatcher = RequestDispatcher()
    dispatcher.register("ping")
    result = dispatcher.dispatch(JSONRPCRequest(id=1, method="ping"))
    assert result is None

  def test_dispatch_error_carries_error_object(self):
    dispatcher = RequestDispatcher()
    result = dispatcher.dispatch(JSONRPCRequest(id=1, method="no-such"))
    assert isinstance(result, JSONRPCErrorResponse)
    assert isinstance(result.error, dict)
    assert "code" in result.error
    assert "message" in result.error

  def test_dispatch_invalid_params_error_carries_error_object(self):
    def validator(params: dict) -> None:
      raise ValueError("bad params")

    dispatcher = RequestDispatcher()
    dispatcher.register("tools/call", params_validator=validator)
    result = dispatcher.dispatch(JSONRPCRequest(id=1, method="tools/call", params={}))
    assert isinstance(result, JSONRPCErrorResponse)
    assert isinstance(result.error, dict)
    assert "code" in result.error

  def test_dispatch_meta_required_error_carries_error_object(self):
    dispatcher = RequestDispatcher()
    dispatcher.register("tools/call", requires_meta=True)
    result = dispatcher.dispatch(JSONRPCRequest(id=1, method="tools/call"))
    assert isinstance(result, JSONRPCErrorResponse)
    assert isinstance(result.error, dict)

  def test_dispatch_does_not_raise(self):
    """dispatch() always returns, never raises."""
    def bad_validator(params: dict) -> None:
      raise ValueError("boom")

    dispatcher = RequestDispatcher()
    dispatcher.register("x", params_validator=bad_validator)
    result = dispatcher.dispatch(JSONRPCRequest(id=1, method="x", params={}))
    assert isinstance(result, JSONRPCErrorResponse)

  def test_type_error_in_validator_produces_invalid_params_response(self):
    def validator(params: dict) -> None:
      raise TypeError("wrong type")

    dispatcher = RequestDispatcher()
    dispatcher.register("x", params_validator=validator)
    result = dispatcher.dispatch(JSONRPCRequest(id=2, method="x", params={"k": "v"}))
    assert isinstance(result, JSONRPCErrorResponse)

  def test_validator_not_called_when_params_absent(self):
    """Validator is only called when params is present; absent params does not invoke it."""
    called = []

    def validator(params: dict) -> None:
      called.append(params)

    dispatcher = RequestDispatcher()
    dispatcher.register("ping", params_validator=validator)
    result = dispatcher.dispatch(JSONRPCRequest(id=1, method="ping"))
    assert result is None        # no error: params absent, no requires_meta
    assert called == []          # validator was NOT called

  def test_requires_meta_and_params_present_calls_validator(self):
    """When requires_meta=True and params is present, the validator is still called."""
    def validator(params: dict) -> None:
      if "bad" in params:
        raise ValueError("bad key")

    dispatcher = RequestDispatcher()
    dispatcher.register("tools/call", requires_meta=True, params_validator=validator)

    # params present (satisfies requires_meta) but fails validator
    result = dispatcher.dispatch(
      JSONRPCRequest(id=1, method="tools/call", params={"bad": True})
    )
    assert isinstance(result, JSONRPCErrorResponse)

  def test_method_registration_is_case_sensitive(self):
    """Method names in the dispatcher are case-sensitive (R-3.3-d)."""
    dispatcher = RequestDispatcher()
    dispatcher.register("tools/call")
    # "Tools/Call" is distinct from "tools/call"
    result = dispatcher.dispatch(JSONRPCRequest(id=1, method="Tools/Call"))
    assert isinstance(result, JSONRPCErrorResponse)  # not found
