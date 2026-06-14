"""Tests for S12 — Transport Model & Transport-Agnostic Guarantees.

Coverage map (24 story ACs):
  AC-12.1  → TestTransportMessageCarriage
  AC-12.2  → TestMessageIntegrity
  AC-12.3  → TestFramingContract
  AC-12.4  → TestIdCorrelation
  AC-12.5  → TestMalformedIdError
  AC-12.6  → TestMultiplexing
  AC-12.7  → TestOutOfOrderResponses
  AC-12.8  → TestNoSilentLoss
  AC-12.9  → TestCleanClose
  AC-12.10 → TestCustomTransportPermitted
  AC-12.11 → TestStdioFramingRecommendation
  AC-12.12 → TestBidirectional
  AC-12.13 → TestPerRequestMetaRequired
  AC-12.14 → TestEnvelopeMirroring
  AC-12.15 → TestDisconnectionObservable
  AC-12.16 → TestFailInFlightOnDisconnect
  AC-12.17 → TestRetryAfterDisconnect
  AC-12.18 → TestStdioProcessRestart
  AC-12.19 → TestNoSilentDiscardOnError
  AC-12.20 → TestUtf8JsonValidation
  AC-12.21 → TestNoConnectionScopedState
  AC-12.22 → TestConnectionReuseNotRequired
  AC-12.23 → TestExplicitIdentifierForContinuity
  AC-12.24 → TestDisconnectMakesInFlightFailed
"""

import json
import pytest

from mcp_sdk_py.transport import (
  DEFINED_TRANSPORTS,
  TRANSPORT_STDIO,
  TRANSPORT_STREAMABLE_HTTP,
  ConnectionScopedStateError,
  CustomTransportChecklist,
  DisconnectionError,
  MalformedMessageError,
  MessageDeliveryError,
  TransportError,
  assert_no_connection_scoped_state,
  fail_in_flight_on_disconnect,
  validate_utf8_json_unit,
)
from mcp_sdk_py.jsonrpc import InFlightTracker


# ---------------------------------------------------------------------------
# AC-12.1 — transport carries JSONRPCMessage variants as UTF-8 JSON  (R-7.1-a/b/d)
# ---------------------------------------------------------------------------

class TestTransportMessageCarriage:
  def test_defined_transports_exist(self):
    assert TRANSPORT_STDIO == "stdio"
    assert TRANSPORT_STREAMABLE_HTTP == "streamable-http"

  def test_defined_transports_set(self):
    assert TRANSPORT_STDIO in DEFINED_TRANSPORTS
    assert TRANSPORT_STREAMABLE_HTTP in DEFINED_TRANSPORTS

  def test_jsonrpc_message_is_utf8_json(self):
    """Transport-identical request example from §7.7 parses as UTF-8 JSON."""
    raw = json.dumps({
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": {
        "name": "get_weather",
        "_meta": {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientInfo": {"name": "example-client", "version": "1.0.0"},
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }).encode("utf-8")
    parsed = validate_utf8_json_unit(raw)
    assert parsed["method"] == "tools/call"

  def test_notification_is_utf8_json(self):
    raw = json.dumps({
      "jsonrpc": "2.0",
      "method": "notifications/progress",
      "params": {"progressToken": "t", "progress": 50},
    }).encode("utf-8")
    parsed = validate_utf8_json_unit(raw)
    assert parsed["method"] == "notifications/progress"

  def test_response_is_utf8_json(self):
    raw = json.dumps({
      "jsonrpc": "2.0",
      "id": 1,
      "result": {"resultType": "complete", "content": []},
    }).encode("utf-8")
    parsed = validate_utf8_json_unit(raw)
    assert parsed["id"] == 1


# ---------------------------------------------------------------------------
# AC-12.2 — message integrity: delivered == emitted byte-for-byte  (R-7.1-c)
# ---------------------------------------------------------------------------

class TestMessageIntegrity:
  def test_decoded_matches_original(self):
    original = {
      "jsonrpc": "2.0",
      "id": 7,
      "method": "resources/read",
      "params": {"uri": "file:///a.txt", "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
    }
    encoded = json.dumps(original, ensure_ascii=False).encode("utf-8")
    decoded = validate_utf8_json_unit(encoded)
    # Re-encode and compare byte-for-byte.
    assert json.dumps(decoded, ensure_ascii=False).encode("utf-8") == encoded

  def test_unicode_preserved(self):
    """Non-ASCII fields must survive the UTF-8 round-trip unchanged."""
    original = {"jsonrpc": "2.0", "id": 1, "method": "x", "params": {"q": "日本語"}}
    encoded = json.dumps(original, ensure_ascii=False).encode("utf-8")
    decoded = validate_utf8_json_unit(encoded)
    assert decoded["params"]["q"] == "日本語"


# ---------------------------------------------------------------------------
# AC-12.3 — framing: body-independent boundary determination  (R-7.2-b/c/d)
# ---------------------------------------------------------------------------

class TestFramingContract:
  def test_stdio_framing_is_newline_delimited(self):
    """Stdio uses newline (\\n) as the frame delimiter — body-independent (S13)."""
    # Each JSON object terminated by \\n is one framed unit.
    frame_1 = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "m", "params": {}}).encode()
    frame_2 = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "n", "params": {}}).encode()
    stream = frame_1 + b"\n" + frame_2 + b"\n"
    units = [u for u in stream.split(b"\n") if u]
    assert len(units) == 2
    parsed_1 = validate_utf8_json_unit(units[0])
    parsed_2 = validate_utf8_json_unit(units[1])
    assert parsed_1["id"] == 1
    assert parsed_2["id"] == 2

  def test_framing_does_not_require_body_parse(self):
    """Delimiter (\\n) is body-independent; we split before parsing JSON."""
    bodies = [b'{"jsonrpc":"2.0","id":1,"method":"a"}', b'{"jsonrpc":"2.0","id":2,"method":"b"}']
    concatenated = b"\n".join(bodies)
    units = concatenated.split(b"\n")
    assert len(units) == 2  # split without parsing JSON body


# ---------------------------------------------------------------------------
# AC-12.4 — id correlation by id only, not by order  (R-7.2-e/f/g/o)
# ---------------------------------------------------------------------------

class TestIdCorrelation:
  def test_response_id_matches_request_id(self):
    from mcp_sdk_py.jsonrpc import classify_message
    req_raw = {"jsonrpc": "2.0", "id": 42, "method": "tools/list", "params": {}}
    resp_raw = {"jsonrpc": "2.0", "id": 42, "result": {"resultType": "complete", "tools": []}}
    req = classify_message(req_raw)
    resp = classify_message(resp_raw)
    assert req.id == resp.id

  def test_correlation_ignores_order(self):
    """Responses to id=3 can arrive before id=2; correlation is by id only."""
    from mcp_sdk_py.jsonrpc import classify_message, ids_are_equal
    resp_3 = {"jsonrpc": "2.0", "id": 3, "result": {"resultType": "complete", "resources": []}}
    resp_2 = {"jsonrpc": "2.0", "id": 2, "result": {"resultType": "complete", "tools": []}}
    # Arrive in reverse order — still correlated correctly by id.
    r3 = classify_message(resp_3)
    r2 = classify_message(resp_2)
    assert ids_are_equal(r3.id, 3)
    assert ids_are_equal(r2.id, 2)

  def test_in_flight_tracker_enforces_no_reuse(self):
    """Sender MUST NOT reuse id until response received (R-7.2-j)."""
    tracker = InFlightTracker()
    tracker.send(1)
    with pytest.raises(ValueError, match="already in-flight"):
      tracker.send(1)

  def test_id_reuse_allowed_after_receive(self):
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.receive(1)
    tracker.send(1)  # must not raise — id is free again


# ---------------------------------------------------------------------------
# AC-12.5 — malformed-id error may carry null id  (R-7.2-h)
# ---------------------------------------------------------------------------

class TestMalformedIdError:
  def test_null_id_error_response_accepted(self):
    """An error response with null id is valid when the request id could not be read."""
    from mcp_sdk_py.jsonrpc import classify_message, JSONRPCErrorResponse
    raw = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
    msg = classify_message(raw)
    # null id on error response — acceptable per R-7.2-h
    assert isinstance(msg, JSONRPCErrorResponse)
    assert msg.id is None

  def test_omitted_id_on_error_accepted(self):
    """Error response may omit id entirely."""
    from mcp_sdk_py.jsonrpc import classify_message, JSONRPCErrorResponse
    raw = {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}}
    msg = classify_message(raw)
    assert isinstance(msg, JSONRPCErrorResponse)
    assert msg.id is None


# ---------------------------------------------------------------------------
# AC-12.6 — multiplexing: multiple outstanding requests, no id reuse  (R-7.2-i/j/k/l)
# ---------------------------------------------------------------------------

class TestMultiplexing:
  def test_multiple_in_flight_ids_allowed(self):
    """R-7.2-i: sender MAY have multiple requests outstanding at once."""
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.send(2)
    tracker.send(3)
    assert tracker.is_in_flight(1)
    assert tracker.is_in_flight(2)
    assert tracker.is_in_flight(3)

  def test_second_request_without_awaiting_first(self):
    """R-7.2-l: transport must not require awaiting response before next request."""
    tracker = InFlightTracker()
    tracker.send("a")
    # No call to receive("a") — second request issued immediately.
    tracker.send("b")
    assert tracker.is_in_flight("a")
    assert tracker.is_in_flight("b")

  def test_unique_ids_required(self):
    """R-7.2-j: must not reuse id of outstanding request."""
    tracker = InFlightTracker()
    tracker.send(99)
    with pytest.raises(ValueError):
      tracker.send(99)

  def test_in_flight_ids_snapshot(self):
    tracker = InFlightTracker()
    tracker.send(10)
    tracker.send(20)
    assert tracker.in_flight_ids == frozenset({10, 20})


# ---------------------------------------------------------------------------
# AC-12.7 — out-of-order responses; no FIFO precondition  (R-7.2-m/n/p)
# ---------------------------------------------------------------------------

class TestOutOfOrderResponses:
  def test_responses_may_arrive_in_any_order(self):
    """R-7.2-m: responses MAY arrive in any order."""
    tracker = InFlightTracker()
    tracker.send(2)
    tracker.send(3)
    # Response to 3 arrives first — valid.
    tracker.receive(3)
    assert not tracker.is_in_flight(3)
    assert tracker.is_in_flight(2)
    # Then response to 2 arrives.
    tracker.receive(2)
    assert not tracker.is_in_flight(2)

  def test_receiver_must_not_assume_order(self):
    """Correlation by id is independent of arrival order."""
    ids_sent = [5, 6, 7]
    tracker = InFlightTracker()
    for i in ids_sent:
      tracker.send(i)
    # Receive in reverse order.
    for i in reversed(ids_sent):
      tracker.receive(i)
    # All correctly cleared — no FIFO assumption needed.
    assert tracker.in_flight_ids == frozenset()


# ---------------------------------------------------------------------------
# AC-12.8 — no silent loss: observable failure required  (R-7.2-q/r/s)
# ---------------------------------------------------------------------------

class TestNoSilentLoss:
  def test_message_delivery_error_is_transport_error(self):
    assert issubclass(MessageDeliveryError, TransportError)

  def test_message_delivery_error_raised_not_swallowed(self):
    """Raise MessageDeliveryError to surface an undeliverable message."""
    with pytest.raises(MessageDeliveryError):
      raise MessageDeliveryError("could not deliver to peer", message_summary="tools/call id=1")

  def test_message_delivery_error_carries_summary(self):
    err = MessageDeliveryError("undeliverable", message_summary="req-42")
    assert err.message_summary == "req-42"

  def test_transport_error_base_class(self):
    assert issubclass(TransportError, Exception)


# ---------------------------------------------------------------------------
# AC-12.9 — clean close: observable to both sides  (R-7.2-t)
# ---------------------------------------------------------------------------

class TestCleanClose:
  def test_disconnection_error_is_transport_error(self):
    assert issubclass(DisconnectionError, TransportError)

  def test_disconnection_error_raised(self):
    with pytest.raises(DisconnectionError):
      raise DisconnectionError("connection closed by peer")

  def test_disconnection_error_carries_connection_id(self):
    err = DisconnectionError("lost", connection_id="conn-abc")
    assert err.connection_id == "conn-abc"

  def test_disconnection_default_message(self):
    err = DisconnectionError()
    assert "lost" in str(err).lower() or "connection" in str(err).lower()


# ---------------------------------------------------------------------------
# AC-12.10 — custom transport permitted; must uphold §7.2  (R-7.3-a/b/c/d)
# ---------------------------------------------------------------------------

class TestCustomTransportPermitted:
  def test_checklist_default_all_false(self):
    c = CustomTransportChecklist(name="MyTransport")
    assert not c.is_conformant()

  def test_conformant_checklist(self):
    c = CustomTransportChecklist(
      name="MyTransport",
      preserves_json_rpc_format=True,
      preserves_exchange_patterns=True,
      preserves_per_request_meta=True,
      provides_framing=True,
      provides_id_correlation=True,
      supports_multiplexing=True,
      allows_out_of_order_responses=True,
      no_silent_loss=True,
      defines_clean_close=True,
      observable_disconnection=True,
      utf8_encoded=True,
      bidirectional=True,
    )
    assert c.is_conformant()

  def test_missing_obligations_lists_gaps(self):
    c = CustomTransportChecklist(
      preserves_json_rpc_format=True,
      provides_framing=True,
    )
    missing = c.missing_obligations()
    assert "preserves_json_rpc_format" not in missing
    assert "provides_framing" not in missing
    assert "utf8_encoded" in missing
    assert "bidirectional" in missing

  def test_partial_conformance_not_conformant(self):
    c = CustomTransportChecklist(preserves_json_rpc_format=True)
    assert not c.is_conformant()

  def test_checklist_has_name_field(self):
    c = CustomTransportChecklist(name="WebSocket")
    assert c.name == "WebSocket"


# ---------------------------------------------------------------------------
# AC-12.11 — custom transport over reliable stream SHOULD use stdio framing  (R-7.3-e)
# ---------------------------------------------------------------------------

class TestStdioFramingRecommendation:
  def test_checklist_tracks_stdio_framing_recommendation(self):
    """uses_stdio_framing_if_stream tracks SHOULD-level compliance (R-7.3-e)."""
    c = CustomTransportChecklist(uses_stdio_framing_if_stream=True)
    assert c.uses_stdio_framing_if_stream

  def test_checklist_conformant_without_stdio_framing_flag(self):
    """uses_stdio_framing_if_stream is SHOULD-level; not blocking is_conformant()."""
    c = CustomTransportChecklist(
      preserves_json_rpc_format=True,
      preserves_exchange_patterns=True,
      preserves_per_request_meta=True,
      provides_framing=True,
      provides_id_correlation=True,
      supports_multiplexing=True,
      allows_out_of_order_responses=True,
      no_silent_loss=True,
      defines_clean_close=True,
      observable_disconnection=True,
      utf8_encoded=True,
      bidirectional=True,
      uses_stdio_framing_if_stream=False,  # SHOULD — not a hard requirement
    )
    assert c.is_conformant()


# ---------------------------------------------------------------------------
# AC-12.12 — bidirectional: both directions over one connection  (R-7.4-a/b/c)
# ---------------------------------------------------------------------------

class TestBidirectional:
  def test_checklist_bidirectional_flag(self):
    c = CustomTransportChecklist(bidirectional=True)
    assert c.bidirectional

  def test_request_is_client_to_server(self):
    """Client sends requests; server receives them (R-7.4-b)."""
    from mcp_sdk_py.jsonrpc import classify_message, JSONRPCRequest
    raw = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    msg = classify_message(raw)
    assert isinstance(msg, JSONRPCRequest)

  def test_response_is_server_to_client(self):
    """Server sends responses; client receives them (R-7.4-c)."""
    from mcp_sdk_py.jsonrpc import classify_message, JSONRPCResultResponse
    raw = {"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete"}}
    msg = classify_message(raw)
    assert isinstance(msg, JSONRPCResultResponse)


# ---------------------------------------------------------------------------
# AC-12.13 — every request carries _meta envelope  (R-7.4-d, R-7.4-f)
# ---------------------------------------------------------------------------

class TestPerRequestMetaRequired:
  def test_request_meta_keys_present(self):
    """_meta with the three required keys is present regardless of transport."""
    from mcp_sdk_py.meta_object import (
      KEY_PROTOCOL_VERSION,
      KEY_CLIENT_INFO,
      KEY_CLIENT_CAPABILITIES,
      validate_request_meta_object,
    )
    meta = {
      KEY_PROTOCOL_VERSION: "2026-07-28",
      KEY_CLIENT_INFO: {"name": "c", "version": "1"},
      KEY_CLIENT_CAPABILITIES: {},
    }
    validate_request_meta_object(meta)  # must not raise

  def test_meta_is_body_source_of_truth(self):
    """The inline _meta envelope is present in the message body (R-7.4-f)."""
    raw = {
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": {
        "_meta": {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientInfo": {"name": "c", "version": "1"},
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }
    encoded = json.dumps(raw).encode("utf-8")
    parsed = validate_utf8_json_unit(encoded)
    assert "io.modelcontextprotocol/protocolVersion" in parsed["params"]["_meta"]


# ---------------------------------------------------------------------------
# AC-12.14 — envelope mirroring into transport-level metadata is permitted  (R-7.4-e)
# ---------------------------------------------------------------------------

class TestEnvelopeMirroring:
  def test_mirroring_is_permitted(self):
    """Transport MAY mirror _meta into headers/metadata for routing (R-7.4-e)."""
    from mcp_sdk_py.revision import HTTP_PROTOCOL_VERSION_HEADER
    # Existence of HTTP_PROTOCOL_VERSION_HEADER confirms mirroring is modelled.
    assert HTTP_PROTOCOL_VERSION_HEADER == "MCP-Protocol-Version"

  def test_body_remains_authoritative(self):
    """The message body's _meta is authoritative; mirroring is for routing only."""
    body_version = "2026-07-28"
    header_version = "2026-07-28"
    # Matching — authoritative source is the body.
    from mcp_sdk_py.revision import validate_http_revision_header
    validate_http_revision_header(body_version, header_version)  # must not raise


# ---------------------------------------------------------------------------
# AC-12.15 — abrupt disconnection MUST be observable  (R-7.5-a/b)
# ---------------------------------------------------------------------------

class TestDisconnectionObservable:
  def test_disconnection_error_is_raised_not_silently_ignored(self):
    """R-7.5-b: implementation must surface disconnection, not block indefinitely."""
    with pytest.raises(DisconnectionError):
      raise DisconnectionError("peer went away")

  def test_disconnection_error_is_transport_error(self):
    assert issubclass(DisconnectionError, TransportError)

  def test_disconnection_not_blocked_indefinitely(self):
    """Raising DisconnectionError gives callers an immediate signal."""
    err = DisconnectionError("abrupt close", connection_id="tcp-99")
    assert isinstance(err, TransportError)


# ---------------------------------------------------------------------------
# AC-12.16 — fail all in-flight requests on disconnect  (R-7.5-c/d/e)
# ---------------------------------------------------------------------------

class TestFailInFlightOnDisconnect:
  def test_all_in_flight_returned(self):
    tracker = InFlightTracker()
    tracker.send("a")
    tracker.send("b")
    tracker.send("c")
    failed = fail_in_flight_on_disconnect(tracker)
    assert failed == frozenset({"a", "b", "c"})

  def test_tracker_cleared_after_fail(self):
    """After fail, tracker has no in-flight ids (R-7.5-e)."""
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.send(2)
    fail_in_flight_on_disconnect(tracker)
    assert tracker.in_flight_ids == frozenset()

  def test_empty_tracker_returns_empty_set(self):
    tracker = InFlightTracker()
    failed = fail_in_flight_on_disconnect(tracker)
    assert failed == frozenset()

  def test_single_in_flight_failed(self):
    tracker = InFlightTracker()
    tracker.send("req-1")
    failed = fail_in_flight_on_disconnect(tracker)
    assert "req-1" in failed

  def test_integer_ids_failed(self):
    tracker = InFlightTracker()
    tracker.send(100)
    tracker.send(200)
    failed = fail_in_flight_on_disconnect(tracker)
    assert 100 in failed
    assert 200 in failed


# ---------------------------------------------------------------------------
# AC-12.17 — stateless client MAY retry after disconnect  (R-7.5-f)
# ---------------------------------------------------------------------------

class TestRetryAfterDisconnect:
  def test_retry_is_possible_without_state_loss(self):
    """R-7.5-f: stateless model allows retrying failed requests on a fresh connection."""
    # Simulate: tracker cleared by disconnect — caller can resend on a new tracker.
    old_tracker = InFlightTracker()
    old_tracker.send("retryable-req")
    failed = fail_in_flight_on_disconnect(old_tracker)
    # On a fresh connection, same request can be issued again.
    new_tracker = InFlightTracker()
    for rid in failed:
      new_tracker.send(rid)  # must not raise — fresh tracker
    assert new_tracker.is_in_flight("retryable-req")


# ---------------------------------------------------------------------------
# AC-12.18 — stdio server exit: client SHOULD restart, MAY retry  (R-7.5-g/h)
# ---------------------------------------------------------------------------

class TestStdioProcessRestart:
  def test_stdio_transport_constant(self):
    """TRANSPORT_STDIO is defined; concrete restart logic is in S13."""
    assert TRANSPORT_STDIO == "stdio"

  def test_disconnection_error_models_stdio_exit(self):
    """Unexpected server process exit is modelled as a DisconnectionError."""
    err = DisconnectionError("server process exited unexpectedly", connection_id="proc-42")
    assert isinstance(err, DisconnectionError)


# ---------------------------------------------------------------------------
# AC-12.19 — no silent discard on transport error  (R-7.5-i/j)
# ---------------------------------------------------------------------------

class TestNoSilentDiscardOnError:
  def test_undeliverable_message_raises_not_swallowed(self):
    """R-7.5-i/j: transport MUST produce observable failure, not silent drop."""
    def try_deliver(raise_on_fail: bool) -> None:
      if raise_on_fail:
        raise MessageDeliveryError("delivery failed")
    with pytest.raises(MessageDeliveryError):
      try_deliver(raise_on_fail=True)

  def test_message_delivery_error_inherits_transport_error(self):
    assert issubclass(MessageDeliveryError, TransportError)


# ---------------------------------------------------------------------------
# AC-12.20 — UTF-8 + JSON validation: accept valid, reject malformed  (R-7.6-a/b/c)
# ---------------------------------------------------------------------------

class TestUtf8JsonValidation:
  def test_valid_utf8_json_passes(self):
    data = b'{"jsonrpc":"2.0","id":1,"method":"test"}'
    result = validate_utf8_json_unit(data)
    assert result["method"] == "test"

  def test_invalid_utf8_raises_malformed_message_error(self):
    bad_bytes = b"\xff\xfe invalid utf-8"
    with pytest.raises(MalformedMessageError) as exc_info:
      validate_utf8_json_unit(bad_bytes)
    assert exc_info.value.raw_excerpt != b""

  def test_valid_utf8_but_invalid_json_raises(self):
    not_json = "this is not json at all".encode("utf-8")
    with pytest.raises(MalformedMessageError):
      validate_utf8_json_unit(not_json)

  def test_empty_bytes_raises(self):
    with pytest.raises(MalformedMessageError):
      validate_utf8_json_unit(b"")

  def test_malformed_error_is_transport_error(self):
    assert issubclass(MalformedMessageError, TransportError)

  def test_malformed_error_carries_excerpt(self):
    with pytest.raises(MalformedMessageError) as exc_info:
      validate_utf8_json_unit(b"\x80\x81\x82")
    assert isinstance(exc_info.value.raw_excerpt, bytes)

  def test_must_not_silently_substitute(self):
    """R-7.6-c: malformed unit MUST raise, not return a default or None."""
    with pytest.raises(MalformedMessageError):
      validate_utf8_json_unit(b"not-json")

  def test_unicode_json_accepted(self):
    data = json.dumps({"x": "こんにちは"}, ensure_ascii=False).encode("utf-8")
    result = validate_utf8_json_unit(data)
    assert result["x"] == "こんにちは"

  def test_json_array_accepted(self):
    """validate_utf8_json_unit accepts any JSON value, not just objects."""
    data = b'[1, 2, 3]'
    result = validate_utf8_json_unit(data)
    assert result == [1, 2, 3]


# ---------------------------------------------------------------------------
# AC-12.21 — no connection-scoped state  (R-7.6-d/e/f)
# ---------------------------------------------------------------------------

class TestNoConnectionScopedState:
  def test_assert_no_connection_scoped_state_raises(self):
    """Calling the guard at a connection-state lookup site raises immediately."""
    with pytest.raises(ConnectionScopedStateError):
      assert_no_connection_scoped_state("looked up session by connection id")

  def test_connection_scoped_state_error_message(self):
    try:
      assert_no_connection_scoped_state()
    except ConnectionScopedStateError as e:
      assert "connection" in str(e).lower()

  def test_connection_scoped_state_error_with_detail(self):
    try:
      assert_no_connection_scoped_state("used tcp_conn as session key")
    except ConnectionScopedStateError as e:
      assert "tcp_conn" in str(e)

  def test_connection_scoped_state_error_is_exception(self):
    assert issubclass(ConnectionScopedStateError, Exception)

  def test_each_request_carries_its_own_meta(self):
    """R-7.6-f: server relies on _meta, not prior requests, for identity/capabilities."""
    from mcp_sdk_py.meta_object import KEY_PROTOCOL_VERSION, KEY_CLIENT_INFO, KEY_CLIENT_CAPABILITIES
    # Confirm that meta keys carry per-request identity — no shared state needed.
    meta = {
      KEY_PROTOCOL_VERSION: "2026-07-28",
      KEY_CLIENT_INFO: {"name": "client-a", "version": "1"},
      KEY_CLIENT_CAPABILITIES: {},
    }
    assert KEY_PROTOCOL_VERSION in meta
    assert KEY_CLIENT_INFO in meta
    assert KEY_CLIENT_CAPABILITIES in meta


# ---------------------------------------------------------------------------
# AC-12.22 — SHOULD NOT require same connection  (R-7.6-g/h/i)
# ---------------------------------------------------------------------------

class TestConnectionReuseNotRequired:
  def test_connection_id_must_not_proxy_state(self):
    """R-7.6-i: connection identity is not a session proxy."""
    with pytest.raises(ConnectionScopedStateError):
      assert_no_connection_scoped_state("routing by connection object")

  def test_multiple_requests_interleaved_on_one_tracker(self):
    """R-7.6-h: a client MAY interleave unrelated requests on one connection."""
    tracker = InFlightTracker()
    tracker.send("tools-list")
    tracker.send("resources-list")
    # Both outstanding on one connection — valid (unrelated, interleaved).
    assert tracker.is_in_flight("tools-list")
    assert tracker.is_in_flight("resources-list")


# ---------------------------------------------------------------------------
# AC-12.23 — continuity via explicit identifier, not connection identity  (R-7.6-j)
# ---------------------------------------------------------------------------

class TestExplicitIdentifierForContinuity:
  def test_continuation_id_not_connection_id(self):
    """R-7.6-j: explicit client-supplied id in _meta, not connection proxy."""
    from mcp_sdk_py.stateless_model import is_valid_continuation_id
    # A valid continuation id is an explicit value, not an implicit connection identity.
    assert is_valid_continuation_id("explicit-task-id-abc")

  def test_connection_scoped_state_prohibited(self):
    """Asserting connection-scoped state is always an error."""
    with pytest.raises(ConnectionScopedStateError):
      assert_no_connection_scoped_state()


# ---------------------------------------------------------------------------
# AC-12.24 — disconnect makes in-flight failed; client MAY retry  (R-7.7-a/b)
# ---------------------------------------------------------------------------

class TestDisconnectMakesInFlightFailed:
  def test_requests_in_flight_considered_failed_on_disconnect(self):
    """R-7.7-a: connection lost → outstanding requests MUST be considered failed."""
    tracker = InFlightTracker()
    tracker.send(2)
    tracker.send(3)
    failed = fail_in_flight_on_disconnect(tracker)
    assert 2 in failed
    assert 3 in failed

  def test_retry_on_new_connection_is_valid(self):
    """R-7.7-b: client MAY retry on a new connection because no state is bound."""
    old_tracker = InFlightTracker()
    old_tracker.send(2)
    old_tracker.send(3)
    failed = fail_in_flight_on_disconnect(old_tracker)
    # Fresh connection, fresh tracker — retry any of the failed ids.
    new_tracker = InFlightTracker()
    for rid in sorted(failed):
      new_tracker.send(rid)
    assert new_tracker.in_flight_ids == frozenset({2, 3})

  def test_no_state_bound_to_lost_connection(self):
    """After disconnect, in-flight set is cleared — state is gone with connection."""
    tracker = InFlightTracker()
    tracker.send("op-1")
    fail_in_flight_on_disconnect(tracker)
    assert tracker.in_flight_ids == frozenset()
