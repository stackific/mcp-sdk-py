"""Tests for S15 — Streamable HTTP: Responses, Status Mapping & HeaderMismatch.

AC → test coverage map (25 story ACs):
  AC-15.1  (R-9.6-a)                 → TestResponseShapeChoice
  AC-15.2  (R-9.6.1-a)              → TestSingleJsonResponse
  AC-15.3  (R-9.6.2-a)              → TestEventStreamShape
  AC-15.4  (R-9.6.2-b, R-9.6.2-c)   → TestRequestScopedNotifications
  AC-15.5  (R-9.6.2-d)              → TestNoIndependentRequestOnStream
  AC-15.6  (R-9.6.2-e, R-9.6.2-f)   → TestFinalResponseTerminates
  AC-15.7  (R-9.6.2-g)              → TestXAccelBuffering
  AC-15.8  (R-9.6.2-h, R-9.9-g)     → TestLastEventIdIgnored
  AC-15.9  (R-9.6.2-i/j/k)          → TestStreamCloseCancellation
  AC-15.10 (R-9.7-b)                → TestMethodNotFound404
  AC-15.11 (R-9.8-a/b/c/d)          → TestHeaderMismatch400
  AC-15.12 (R-9.8-e, R-9.8-f)       → TestIntermediaryRejection
  AC-15.13 (R-9.8-g, R-9.8-h)       → TestIntermediaryTrust
  AC-15.14 (R-9.9-a)                → TestStateless
  AC-15.15 (R-9.9-b/c/d)            → TestSessionIdentifierIgnored
  AC-15.16 (R-9.9-e)                → TestNoServerAffinity
  AC-15.17 (R-9.9-f)                → TestGetDeleteRejected405
  AC-15.18 (R-9.11-a/b/c, R-9.7-a)  → TestOriginValidation403
  AC-15.19 (R-9.11-d)               → TestLoopbackBinding
  AC-15.20 (R-9.11-e, R-9.11-f)     → TestAuthenticationRecommendation
  AC-15.21 (R-9.12-a, R-9.12-b)     → TestProbeInspectsBody
  AC-15.22 (R-9.12-c, R-9.12-d)     → TestRecognizedErrorRetry
  AC-15.23 (R-9.12-e)               → TestUnrecognizedBodyFallback
  AC-15.24 (R-9.12-f)               → TestDualHosting
  AC-15.25 (R-9.12-g, R-9.12-h)     → TestLegacyGetProbe

  Status-table coverage (§9.7)        → TestStatusMapping
"""

import json

import pytest

from mcp_sdk_py.jsonrpc import (
  JSONRPCErrorResponse,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResultResponse,
)
from mcp_sdk_py.negotiation import (
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
  build_unsupported_protocol_version_response,
)
from mcp_sdk_py.revision import PROTOCOL_REVISION_CURRENT
from mcp_sdk_py.streamable_http import HEADER_MISMATCH_CODE, MCP_PROTOCOL_VERSION_HEADER

from mcp_sdk_py.http_responses import (
  ALL_INTERFACES,
  CONTENT_TYPE_EVENT_STREAM,
  CONTENT_TYPE_HEADER,
  CONTENT_TYPE_JSON,
  DUAL_HOSTING_RECOMMENDED,
  HEADER_MISMATCH_NAME,
  HTTP_ACCEPTED,
  HTTP_BAD_REQUEST,
  HTTP_FORBIDDEN,
  HTTP_METHOD_NOT_ALLOWED,
  HTTP_NOT_FOUND,
  HTTP_OK,
  INVALID_PARAMS_CODE,
  INVALID_REQUEST_CODE,
  LAST_EVENT_ID_HEADER,
  LEGACY_ENDPOINT_EVENT,
  LOOPBACK_INTERFACE,
  METHOD_NOT_FOUND_CODE,
  PARSE_ERROR_CODE,
  RECOGNIZED_REVISION_ERROR_CODES,
  X_ACCEL_BUFFERING_HEADER,
  X_ACCEL_BUFFERING_VALUE,
  Condition,
  EventStreamError,
  EventStreamResponse,
  FallbackAction,
  HTTPResponse,
  OriginValidator,
  ResponseShape,
  build_error_response,
  build_header_mismatch_error,
  build_header_mismatch_response,
  build_invalid_params_response,
  build_invalid_request_response,
  build_method_not_found_response,
  build_parse_error_response,
  build_single_json_response,
  choose_response_shape,
  encode_sse_event,
  get_only_transport_status,
  handle_get_or_delete,
  header_mismatch_code_in_server_range,
  header_mismatch_http,
  interpret_legacy_get,
  intermediary_rejection,
  intermediary_should_trust_headers,
  is_legacy_endpoint_event,
  is_recognized_revision_error,
  is_stateless_endpoint,
  map_condition_to_status,
  method_not_found_http,
  react_to_modern_post_400,
  recommended_bind_interface,
  requires_handshake,
  should_implement_authentication,
  should_probe_legacy_get,
  sse_data_line,
  strip_last_event_id,
  strip_session_identifier_headers,
)


# Helpers -------------------------------------------------------------------

def make_request(rid=1, *, progress_token=None):
  meta = {"io.modelcontextprotocol/protocolVersion": PROTOCOL_REVISION_CURRENT}
  if progress_token is not None:
    meta["progressToken"] = progress_token
  return JSONRPCRequest(id=rid, method="tools/call", params={"name": "x", "_meta": meta})


def result_response(rid=1):
  return JSONRPCResultResponse(id=rid, result={"resultType": "complete"})


def progress_notification(token, progress, total=100):
  return JSONRPCNotification(
    method="notifications/progress",
    params={"progressToken": token, "progress": progress, "total": total},
  )


# AC-15.1 -------------------------------------------------------------------

class TestResponseShapeChoice:
  """AC-15.1: exactly one of two shapes per request; either is HTTP 200 (R-9.6-a)."""

  def test_no_notifications_picks_single_json(self):
    shape = choose_response_shape(will_emit_request_scoped_notifications=False)
    assert shape is ResponseShape.SINGLE_JSON

  def test_notifications_pick_event_stream(self):
    shape = choose_response_shape(will_emit_request_scoped_notifications=True)
    assert shape is ResponseShape.EVENT_STREAM

  def test_exactly_two_shapes_exist(self):
    assert set(ResponseShape) == {ResponseShape.SINGLE_JSON, ResponseShape.EVENT_STREAM}

  def test_both_shapes_deliver_with_http_200(self):
    single = build_single_json_response(result_response(1), 1)
    stream = EventStreamResponse(make_request(1))
    assert single.status == HTTP_OK
    assert stream.status == HTTP_OK


# AC-15.2 -------------------------------------------------------------------

class TestSingleJsonResponse:
  """AC-15.2: 200 + application/json + one response whose id equals request id (R-9.6.1-a)."""

  def test_status_and_content_type(self):
    resp = build_single_json_response(result_response(7), 7)
    assert resp.status == HTTP_OK
    assert resp.headers[CONTENT_TYPE_HEADER] == CONTENT_TYPE_JSON
    assert CONTENT_TYPE_JSON == "application/json"

  def test_body_is_exactly_one_response_with_matching_id(self):
    resp = build_single_json_response(result_response(7), 7)
    body = json.loads(resp.body)
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 7
    assert "result" in body

  def test_error_response_shape_is_allowed(self):
    err = JSONRPCErrorResponse(id=3, error={"code": -32000, "message": "boom"})
    resp = build_single_json_response(err, 3)
    body = json.loads(resp.body)
    assert body["id"] == 3 and "error" in body

  def test_id_must_equal_request_id(self):
    with pytest.raises(ValueError, match="MUST equal the request id"):
      build_single_json_response(result_response(2), 9)

  def test_string_id_round_trips(self):
    resp = build_single_json_response(result_response("abc"), "abc")
    assert json.loads(resp.body)["id"] == "abc"


# AC-15.3 -------------------------------------------------------------------

class TestEventStreamShape:
  """AC-15.3: 200 + text/event-stream, scoped to one request, SSE data framing (R-9.6.2-a)."""

  def test_status_and_content_type(self):
    stream = EventStreamResponse(make_request(1))
    assert stream.status == HTTP_OK
    assert stream.response_headers()[CONTENT_TYPE_HEADER] == CONTENT_TYPE_EVENT_STREAM
    assert CONTENT_TYPE_EVENT_STREAM == "text/event-stream"

  def test_scoped_to_one_request(self):
    req = make_request(1)
    stream = EventStreamResponse(req)
    assert stream.request is req

  def test_data_line_carries_one_json_message(self):
    line = sse_data_line({"jsonrpc": "2.0", "method": "x"})
    assert line.startswith("data: ")
    assert json.loads(line[len("data: "):]) == {"jsonrpc": "2.0", "method": "x"}

  def test_event_is_data_line_terminated_by_blank_line(self):
    event = encode_sse_event({"jsonrpc": "2.0", "method": "x"})
    assert event.startswith("data: ")
    assert event.endswith("\n\n")
    # Exactly one data line; the blank line terminates the event.
    assert event.count("\ndata:") == 0


# AC-15.4 -------------------------------------------------------------------

class TestRequestScopedNotifications:
  """AC-15.4: MAY emit notifications; each MUST relate to the request (R-9.6.2-b/c)."""

  def test_may_emit_progress_referencing_progress_token(self):
    req = make_request(1, progress_token="sql-1")
    stream = EventStreamResponse(req)
    event = stream.send_notification(progress_notification("sql-1", 50))
    assert event in stream.events
    payload = json.loads(stream.events[0][len("data: "):])
    assert payload["params"]["progressToken"] == "sql-1"

  def test_message_log_entry_without_token_is_request_scoped(self):
    stream = EventStreamResponse(make_request(1, progress_token="sql-1"))
    log = JSONRPCNotification(method="notifications/message", params={"level": "info"})
    stream.send_notification(log)
    assert len(stream.events) == 1

  def test_notification_with_wrong_progress_token_is_rejected(self):
    stream = EventStreamResponse(make_request(1, progress_token="sql-1"))
    with pytest.raises(EventStreamError, match="relate to the originating request"):
      stream.send_notification(progress_notification("other-token", 10))


# AC-15.5 -------------------------------------------------------------------

class TestNoIndependentRequestOnStream:
  """AC-15.5: the server never sends an independent JSON-RPC request (R-9.6.2-d)."""

  def test_sending_a_request_on_the_stream_is_rejected(self):
    stream = EventStreamResponse(make_request(1))
    rogue = JSONRPCRequest(id=99, method="server/ask", params={})
    with pytest.raises(EventStreamError, match="MUST NOT send an independent JSON-RPC request"):
      stream.send_notification(rogue)


# AC-15.6 -------------------------------------------------------------------

class TestFinalResponseTerminates:
  """AC-15.6: final response SHOULD terminate; no further messages after (R-9.6.2-e/f)."""

  def test_final_response_closes_the_stream(self):
    stream = EventStreamResponse(make_request(1))
    stream.send_final_response(result_response(1))
    assert stream.closed is True

  def test_no_notification_after_final_response(self):
    stream = EventStreamResponse(make_request(1, progress_token="t"))
    stream.send_final_response(result_response(1))
    with pytest.raises(EventStreamError, match="already terminated"):
      stream.send_notification(progress_notification("t", 100))

  def test_no_second_final_response(self):
    stream = EventStreamResponse(make_request(1))
    stream.send_final_response(result_response(1))
    with pytest.raises(EventStreamError, match="already terminated"):
      stream.send_final_response(result_response(1))

  def test_final_response_id_must_equal_request_id(self):
    stream = EventStreamResponse(make_request(5))
    with pytest.raises(ValueError, match="MUST equal the request id"):
      stream.send_final_response(result_response(8))

  def test_progress_then_final_in_order(self):
    stream = EventStreamResponse(make_request(1, progress_token="t"))
    stream.send_notification(progress_notification("t", 50))
    stream.send_notification(progress_notification("t", 100))
    stream.send_final_response(result_response(1))
    assert len(stream.events) == 3
    last = json.loads(stream.events[-1][len("data: "):])
    assert "result" in last and last["id"] == 1


# AC-15.7 -------------------------------------------------------------------

class TestXAccelBuffering:
  """AC-15.7: SHOULD include X-Accel-Buffering: no when opening the stream (R-9.6.2-g)."""

  def test_x_accel_buffering_header_present_by_default(self):
    headers = EventStreamResponse(make_request(1)).response_headers()
    assert headers[X_ACCEL_BUFFERING_HEADER] == X_ACCEL_BUFFERING_VALUE
    assert X_ACCEL_BUFFERING_HEADER == "X-Accel-Buffering"
    assert X_ACCEL_BUFFERING_VALUE == "no"

  def test_can_be_disabled(self):
    headers = EventStreamResponse(make_request(1), x_accel_buffering=False).response_headers()
    assert X_ACCEL_BUFFERING_HEADER not in headers


# AC-15.8 -------------------------------------------------------------------

class TestLastEventIdIgnored:
  """AC-15.8: Last-Event-ID has no effect; streams are not resumable (R-9.6.2-h, R-9.9-g)."""

  def test_strip_last_event_id_removes_it(self):
    headers = {"Last-Event-ID": "42", "Content-Type": "application/json"}
    cleaned = strip_last_event_id(headers)
    assert "Last-Event-ID" not in cleaned
    assert cleaned["Content-Type"] == "application/json"

  def test_strip_is_case_insensitive(self):
    cleaned = strip_last_event_id({"last-event-id": "9"})
    assert cleaned == {}

  def test_constant_value(self):
    assert LAST_EVENT_ID_HEADER == "Last-Event-ID"

  def test_no_header_is_a_noop(self):
    headers = {"X": "y"}
    assert strip_last_event_id(headers) == headers


# AC-15.9 -------------------------------------------------------------------

class TestStreamCloseCancellation:
  """AC-15.9: stream close = cancellation; stop work; no further messages (R-9.6.2-i/j/k)."""

  def test_cancel_marks_cancelled_and_closed(self):
    stream = EventStreamResponse(make_request(1))
    stream.cancel()
    assert stream.cancelled is True
    assert stream.closed is True

  def test_no_notification_after_cancel(self):
    stream = EventStreamResponse(make_request(1, progress_token="t"))
    stream.cancel()
    with pytest.raises(EventStreamError, match="closed by the client"):
      stream.send_notification(progress_notification("t", 10))

  def test_no_final_response_after_cancel(self):
    stream = EventStreamResponse(make_request(1))
    stream.cancel()
    with pytest.raises(EventStreamError, match="closed by the client"):
      stream.send_final_response(result_response(1))

  def test_cancel_is_idempotent(self):
    stream = EventStreamResponse(make_request(1))
    stream.cancel()
    stream.cancel()
    assert stream.cancelled is True


# AC-15.10 ------------------------------------------------------------------

class TestMethodNotFound404:
  """AC-15.10: unimplemented method → 404 + JSON-RPC body code -32601 (R-9.7-b)."""

  def test_status_is_404(self):
    status, _body = method_not_found_http("tools/teleport", 7)
    assert status == HTTP_NOT_FOUND == 404

  def test_body_always_carries_minus_32601(self):
    _status, body = method_not_found_http("tools/teleport", 7)
    wire = body.to_dict()
    assert wire["error"]["code"] == METHOD_NOT_FOUND_CODE == -32601
    assert wire["id"] == 7
    assert "tools/teleport" in wire["error"]["message"]

  def test_builder_message_override(self):
    body = build_method_not_found_response("m", 1, message="nope")
    assert body.to_dict()["error"]["message"] == "nope"


# AC-15.11 ------------------------------------------------------------------

class TestHeaderMismatch400:
  """AC-15.11: missing/malformed/disagreeing header → 400 + -32001 (R-9.8-a/b/c/d)."""

  def test_http_status_is_400(self):
    status, _body = header_mismatch_http(1)
    assert status == HTTP_BAD_REQUEST == 400

  def test_error_object_code_and_name(self):
    err = build_header_mismatch_error()
    assert err.code == HEADER_MISMATCH_CODE == -32001
    assert HEADER_MISMATCH_NAME == "HeaderMismatch"

  def test_code_lies_in_server_error_range(self):
    assert header_mismatch_code_in_server_range() is True

  def test_response_echoes_request_id_when_known(self):
    status, body = header_mismatch_http(1, message="Mcp-Name 'foo' != body 'bar'")
    wire = body.to_dict()
    assert wire["id"] == 1
    assert wire["error"]["code"] == -32001
    assert "foo" in wire["error"]["message"]

  def test_response_omits_id_when_unknown(self):
    body = build_header_mismatch_response(None)
    assert "id" not in body.to_dict()

  def test_covers_missing_required_header_value_mismatch_and_bad_chars(self):
    # R-9.8-b missing header, R-9.8-c value mismatch, R-9.8-d invalid characters
    # all funnel through the same -32001/400 surface (only the message differs).
    for msg in (
      "MCP-Protocol-Version header is missing",
      "Mcp-Name header value disagrees with body",
      "Mcp-Param-Region contains invalid characters",
    ):
      status, body = header_mismatch_http(1, message=msg)
      assert status == 400
      assert body.to_dict()["error"]["code"] == -32001


# AC-15.12 ------------------------------------------------------------------

class TestIntermediaryRejection:
  """AC-15.12: intermediary returns an HTTP error and MAY omit a body (R-9.8-e/f)."""

  def test_default_is_status_only_no_body(self):
    status, body = intermediary_rejection()
    assert status == HTTP_BAD_REQUEST
    assert body is None

  def test_may_include_a_body(self):
    status, body = intermediary_rejection(include_body=True, request_id=2)
    assert status == HTTP_BAD_REQUEST
    assert body is not None
    assert body.to_dict()["error"]["code"] == HEADER_MISMATCH_CODE

  def test_custom_status_allowed(self):
    status, _body = intermediary_rejection(status=403)
    assert status == 403


# AC-15.13 ------------------------------------------------------------------

class TestIntermediaryTrust:
  """AC-15.13: trust mirrored headers only with a validating version; else reject (R-9.8-g/h)."""

  def test_present_supported_version_permits_trust(self):
    headers = {MCP_PROTOCOL_VERSION_HEADER: PROTOCOL_REVISION_CURRENT}
    assert intermediary_should_trust_headers(headers) is True

  def test_absent_version_means_do_not_trust(self):
    assert intermediary_should_trust_headers({}) is False

  def test_unsupported_version_means_do_not_trust(self):
    headers = {MCP_PROTOCOL_VERSION_HEADER: "1999-01-01"}
    assert intermediary_should_trust_headers(headers) is False

  def test_header_name_case_insensitive(self):
    headers = {"mcp-protocol-version": PROTOCOL_REVISION_CURRENT}
    assert intermediary_should_trust_headers(headers) is True


# AC-15.14 ------------------------------------------------------------------

class TestStateless:
  """AC-15.14: no handshake, no session-establishment request, no session state (R-9.9-a)."""

  def test_requires_no_handshake(self):
    assert requires_handshake() is False

  def test_endpoint_is_stateless(self):
    assert is_stateless_endpoint() is True


# AC-15.15 ------------------------------------------------------------------

class TestSessionIdentifierIgnored:
  """AC-15.15: no session-id header; client-supplied one is ignored (R-9.9-b/c/d)."""

  def test_session_header_is_stripped(self):
    headers = {"Mcp-Session-Id": "abc", "Content-Type": "application/json"}
    cleaned = strip_session_identifier_headers(headers)
    assert "Mcp-Session-Id" not in cleaned
    assert cleaned["Content-Type"] == "application/json"

  def test_strip_is_case_insensitive(self):
    cleaned = strip_session_identifier_headers({"mcp-session-id": "x", "session-id": "y"})
    assert cleaned == {}

  def test_no_session_header_is_a_noop(self):
    headers = {"A": "b"}
    assert strip_session_identifier_headers(headers) == headers


# AC-15.16 ------------------------------------------------------------------

class TestNoServerAffinity:
  """AC-15.16: any instance serves any request; no affinity/sticky routing (R-9.9-e)."""

  def test_two_instances_produce_identical_responses(self):
    # No per-instance state exists: building the response is a pure function of
    # the request, so distinct "instances" (calls) agree byte-for-byte.
    instance_a = build_single_json_response(result_response(1), 1)
    instance_b = build_single_json_response(result_response(1), 1)
    assert instance_a == instance_b

  def test_stateless_endpoint_flag(self):
    assert is_stateless_endpoint() is True


# AC-15.17 ------------------------------------------------------------------

class TestGetDeleteRejected405:
  """AC-15.17: GET/DELETE at the endpoint → 405 on a this-transport-only server (R-9.9-f)."""

  @pytest.mark.parametrize("method", ["GET", "DELETE", "get", "delete"])
  def test_get_and_delete_map_to_405(self, method):
    assert get_only_transport_status(method) == HTTP_METHOD_NOT_ALLOWED == 405

  def test_post_is_not_rejected(self):
    assert get_only_transport_status("POST") == HTTP_OK

  def test_handle_returns_empty_405_for_get(self):
    resp = handle_get_or_delete("GET")
    assert resp is not None
    assert resp.status == 405
    assert resp.body == ""

  def test_handle_returns_none_for_post(self):
    assert handle_get_or_delete("POST") is None


# AC-15.18 ------------------------------------------------------------------

class TestOriginValidation403:
  """AC-15.18: validate Origin; present+invalid → 403 with optional id-less body (R-9.11-a/b/c)."""

  def test_accepted_origin_passes(self):
    v = OriginValidator(["https://app.example"])
    assert v.is_accepted({"Origin": "https://app.example"}) is True

  def test_absent_origin_is_not_rejected_by_this_rule(self):
    v = OriginValidator(["https://app.example"])
    assert v.is_accepted({}) is True

  def test_present_unaccepted_origin_is_rejected(self):
    v = OriginValidator(["https://app.example"])
    assert v.is_accepted({"Origin": "https://evil.example"}) is False

  def test_reject_response_is_403_with_idless_body(self):
    v = OriginValidator(["https://app.example"])
    resp = v.reject_response()
    assert resp.status == HTTP_FORBIDDEN == 403
    body = json.loads(resp.body)
    assert "id" not in body
    assert "error" in body

  def test_reject_body_is_optional(self):
    v = OriginValidator([])
    resp = v.reject_response(include_body=False)
    assert resp.status == 403
    assert resp.body == ""

  def test_origin_lookup_case_insensitive(self):
    v = OriginValidator(["https://app.example"])
    assert v.origin_of({"origin": "https://app.example"}) == "https://app.example"


# AC-15.19 ------------------------------------------------------------------

class TestLoopbackBinding:
  """AC-15.19: local servers SHOULD bind to 127.0.0.1, not 0.0.0.0 (R-9.11-d)."""

  def test_local_binds_loopback(self):
    assert recommended_bind_interface(is_local=True) == LOOPBACK_INTERFACE == "127.0.0.1"

  def test_non_local_uses_all_interfaces(self):
    assert recommended_bind_interface(is_local=False) == ALL_INTERFACES == "0.0.0.0"


# AC-15.20 ------------------------------------------------------------------

class TestAuthenticationRecommendation:
  """AC-15.20: SHOULD authenticate; where authz used it MUST satisfy §23 (R-9.11-e/f)."""

  def test_authentication_is_recommended(self):
    assert should_implement_authentication() is True


# AC-15.21 ------------------------------------------------------------------

class TestProbeInspectsBody:
  """AC-15.21: on a modern-POST 400, the client inspects the body first (R-9.12-a/b)."""

  def test_recognized_400_body_does_not_fall_back(self):
    body = build_header_mismatch_response(1).to_dict()
    decision = react_to_modern_post_400(body)
    assert decision.action is FallbackAction.RETRY_THIS_REVISION
    assert decision.may_fall_back is False

  def test_negotiation_codes_are_recognized(self):
    for code in (UNSUPPORTED_PROTOCOL_VERSION_CODE, MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
                 HEADER_MISMATCH_CODE):
      assert code in RECOGNIZED_REVISION_ERROR_CODES

  def test_inspection_accepts_raw_json_string(self):
    raw = json.dumps(build_header_mismatch_response(1).to_dict())
    assert is_recognized_revision_error(raw) is True


# AC-15.22 ------------------------------------------------------------------

class TestRecognizedErrorRetry:
  """AC-15.22: recognized 400 → retry via data.supported, never initialize (R-9.12-c/d)."""

  def test_unsupported_version_yields_supported_set_to_retry(self):
    resp = build_unsupported_protocol_version_response(
      1, [PROTOCOL_REVISION_CURRENT, "2025-01-01"], "1999-01-01"
    )
    decision = react_to_modern_post_400(resp.to_dict())
    assert decision.action is FallbackAction.RETRY_THIS_REVISION
    assert decision.may_fall_back is False
    assert PROTOCOL_REVISION_CURRENT in decision.supported_versions

  def test_recognized_error_never_falls_back(self):
    body = build_invalid_request_response(1).to_dict()
    decision = react_to_modern_post_400(body)
    assert decision.may_fall_back is False
    assert decision.action is FallbackAction.RETRY_THIS_REVISION


# AC-15.23 ------------------------------------------------------------------

class TestUnrecognizedBodyFallback:
  """AC-15.23: empty/unrecognized 400 body MAY fall back to initialize (R-9.12-e)."""

  def test_empty_body_allows_fallback(self):
    decision = react_to_modern_post_400("")
    assert decision.action is FallbackAction.FALL_BACK_TO_INITIALIZE
    assert decision.may_fall_back is True

  def test_none_body_allows_fallback(self):
    decision = react_to_modern_post_400(None)
    assert decision.may_fall_back is True

  def test_non_revision_error_code_allows_fallback(self):
    legacy = {"jsonrpc": "2.0", "id": 1, "error": {"code": 12345, "message": "legacy"}}
    decision = react_to_modern_post_400(legacy)
    assert decision.action is FallbackAction.FALL_BACK_TO_INITIALIZE

  def test_non_error_body_is_not_recognized(self):
    assert is_recognized_revision_error({"jsonrpc": "2.0", "id": 1, "result": {}}) is False

  def test_garbage_string_is_not_recognized(self):
    assert is_recognized_revision_error("not json") is False


# AC-15.24 ------------------------------------------------------------------

class TestDualHosting:
  """AC-15.24: a server SHOULD also host the deprecated HTTP+SSE endpoints (R-9.12-f)."""

  def test_dual_hosting_is_recommended(self):
    assert DUAL_HOSTING_RECOMMENDED is True


# AC-15.25 ------------------------------------------------------------------

class TestLegacyGetProbe:
  """AC-15.25: unrecognized 400/404/405 → GET; endpoint-event first → legacy (R-9.12-g/h)."""

  @pytest.mark.parametrize("status", [400, 404, 405])
  def test_unrecognized_failure_triggers_get_probe(self, status):
    assert should_probe_legacy_get(status, "") is True

  def test_recognized_400_does_not_probe(self):
    body = build_header_mismatch_response(1).to_dict()
    assert should_probe_legacy_get(400, body) is False

  def test_other_status_does_not_probe(self):
    assert should_probe_legacy_get(500, "") is False

  def test_endpoint_first_event_is_legacy(self):
    assert is_legacy_endpoint_event(LEGACY_ENDPOINT_EVENT) is True
    assert LEGACY_ENDPOINT_EVENT == "endpoint"

  def test_interpret_legacy_get_true_on_endpoint_event(self):
    assert interpret_legacy_get("endpoint") is True

  def test_interpret_legacy_get_false_on_other_event(self):
    assert interpret_legacy_get("message") is False
    assert interpret_legacy_get(None) is False


# §9.7 status table ---------------------------------------------------------

class TestStatusMapping:
  """The full §9.7 condition→status mapping table (200/202/400/403/404/405)."""

  @pytest.mark.parametrize(
    "condition,status,code",
    [
      (Condition.REQUEST_HANDLED, 200, None),
      (Condition.NOTIFICATION_ACCEPTED, 202, None),
      (Condition.REQUIRED_HEADER_MISSING, 400, HEADER_MISMATCH_CODE),
      (Condition.HEADER_DISAGREES_OR_MALFORMED, 400, HEADER_MISMATCH_CODE),
      (Condition.UNSUPPORTED_PROTOCOL_VERSION, 400, UNSUPPORTED_PROTOCOL_VERSION_CODE),
      (Condition.MISSING_REQUIRED_CLIENT_CAPABILITY, 400, MISSING_REQUIRED_CLIENT_CAPABILITY_CODE),
      (Condition.INVALID_PARAMS, 400, INVALID_PARAMS_CODE),
      (Condition.MALFORMED_JSON, 400, PARSE_ERROR_CODE),
      (Condition.NOT_A_REQUEST_OBJECT, 400, INVALID_REQUEST_CODE),
      (Condition.METHOD_NOT_IMPLEMENTED, 404, METHOD_NOT_FOUND_CODE),
      (Condition.ORIGIN_INVALID, 403, None),
      (Condition.GET_OR_DELETE_ON_ENDPOINT, 405, None),
    ],
  )
  def test_each_condition_maps_to_status_and_code(self, condition, status, code):
    mapping = map_condition_to_status(condition)
    assert mapping.status == status
    assert mapping.json_rpc_code == code

  def test_status_constants(self):
    assert (HTTP_OK, HTTP_ACCEPTED, HTTP_BAD_REQUEST) == (200, 202, 400)
    assert (HTTP_FORBIDDEN, HTTP_NOT_FOUND, HTTP_METHOD_NOT_ALLOWED) == (403, 404, 405)

  def test_error_body_builders_carry_correct_codes(self):
    assert build_parse_error_response().to_dict()["error"]["code"] == PARSE_ERROR_CODE
    assert build_invalid_request_response().to_dict()["error"]["code"] == INVALID_REQUEST_CODE
    assert build_invalid_params_response(1).to_dict()["error"]["code"] == INVALID_PARAMS_CODE

  def test_parse_error_body_has_no_id_by_default(self):
    assert "id" not in build_parse_error_response().to_dict()

  def test_generic_error_builder_supports_data(self):
    resp = build_error_response(-32000, "m", 1, data={"k": "v"})
    assert resp.to_dict()["error"]["data"] == {"k": "v"}

  def test_http_response_dataclass_defaults(self):
    r = HTTPResponse(status=200)
    assert r.headers == {} and r.body == ""
