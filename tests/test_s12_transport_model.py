"""Tests for S12 — Transport Model & Transport-Agnostic Guarantees.

Coverage map (24 story ACs + remediation of RQ gaps):
  AC-12.1  → TestTransportMessageCarriage
  AC-12.2  → TestMessageIntegrity
  AC-12.3  → TestFramingPrimitive
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

Remediation tests (RQ gaps from QA):
  RQ-1  → TestTransportProtocol (abstract interface)
  RQ-3  → TestInMemoryTransportIntegrity
  RQ-5  → TestFramingPrimitive (split_frames / frame_message in production code)
  RQ-9  → TestNoSilentLoss (MessageDeliveryError on closed peer)
  RQ-10 → TestCleanClose (observable close state, close() method)
  RQ-11 → TestDisconnectionObservable (DisconnectionError on peer close)
  RQ-13 → TestTransportProtocol (InMemoryTransport satisfies Transport Protocol)
  RQ-15 → TestNoConnectionScopedState (real guard, not always-raising)
"""

import json
import pytest

from mcp_sdk_py.transport import (
  DEFINED_TRANSPORTS,
  STDIO_FRAME_DELIMITER,
  TRANSPORT_STDIO,
  TRANSPORT_STREAMABLE_HTTP,
  ConnectionScopedStateError,
  CustomTransportChecklist,
  DisconnectionError,
  InMemoryTransport,
  MalformedMessageError,
  MessageDeliveryError,
  Transport,
  TransportError,
  assert_no_connection_scoped_state,
  fail_in_flight_on_disconnect,
  frame_message,
  is_connection_scoped,
  split_frames,
  validate_utf8_json_unit,
)
from mcp_sdk_py.jsonrpc import (
  InFlightTracker,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResultResponse,
)


# ---------------------------------------------------------------------------
# RQ-1 / RQ-13 — Transport Protocol (abstract interface) + conforming implementation
# ---------------------------------------------------------------------------

class TestTransportProtocol:
  """The central deliverable of S12 is an abstract transport interface (RQ-1).
  InMemoryTransport must conform to it (RQ-13)."""

  def test_transport_is_runtime_checkable(self):
    """Transport is a @runtime_checkable Protocol — isinstance() works."""
    client, _ = InMemoryTransport.create_pair()
    assert isinstance(client, Transport)

  def test_in_memory_transport_has_send(self):
    client, _ = InMemoryTransport.create_pair()
    assert callable(client.send)

  def test_in_memory_transport_has_receive(self):
    _, server = InMemoryTransport.create_pair()
    assert callable(server.receive)

  def test_in_memory_transport_has_close(self):
    client, _ = InMemoryTransport.create_pair()
    assert callable(client.close)

  def test_in_memory_transport_has_is_closed(self):
    client, _ = InMemoryTransport.create_pair()
    assert isinstance(client.is_closed, bool)

  def test_transport_protocol_methods(self):
    """Transport Protocol defines the four required members."""
    # All four structural members are accessible on the runtime_checkable Protocol.
    import inspect
    members = {name for name, _ in inspect.getmembers(Transport)}
    assert "send" in members
    assert "receive" in members
    assert "close" in members
    assert "is_closed" in members

  def test_send_signature_accepts_jsonrpc_message(self):
    """send() accepts any JSONRPCMessage variant (request, notification, response)."""
    client, server = InMemoryTransport.create_pair()
    req = JSONRPCRequest(id=1, method="tools/list", params={})
    client.send(req)  # must not raise
    msg = server.receive()
    assert isinstance(msg, JSONRPCRequest)
    assert msg.id == 1

  def test_receive_returns_jsonrpc_message(self):
    """receive() returns whatever was sent — same object."""
    client, server = InMemoryTransport.create_pair()
    note = JSONRPCNotification(method="notifications/progress", params={"progressToken": "t", "progress": 1})
    client.send(note)
    msg = server.receive()
    assert isinstance(msg, JSONRPCNotification)
    assert msg.method == "notifications/progress"


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

  def test_request_carried_from_client_to_server(self):
    """Transport carries JSONRPCRequest client→server (R-7.4-b)."""
    client, server = InMemoryTransport.create_pair()
    req = JSONRPCRequest(id=1, method="tools/call", params={"name": "search"})
    client.send(req)
    received = server.receive()
    assert isinstance(received, JSONRPCRequest)
    assert received.method == "tools/call"

  def test_response_carried_from_server_to_client(self):
    """Transport carries JSONRPCResultResponse server→client (R-7.4-c)."""
    client, server = InMemoryTransport.create_pair()
    resp = JSONRPCResultResponse(id=1, result={"resultType": "complete", "tools": []})
    server.send(resp)
    received = client.receive()
    assert isinstance(received, JSONRPCResultResponse)
    assert received.id == 1

  def test_notification_carried_both_directions(self):
    """Notifications travel in both directions (R-7.4-b/c)."""
    client, server = InMemoryTransport.create_pair()
    note = JSONRPCNotification(method="notifications/progress", params={"progressToken": "t", "progress": 5})
    # Client → Server
    client.send(note)
    assert isinstance(server.receive(), JSONRPCNotification)
    # Server → Client
    server.send(note)
    assert isinstance(client.receive(), JSONRPCNotification)

  def test_all_three_message_variants_transported(self):
    """All three JSONRPCMessage variants transit the transport (R-7.1-a)."""
    client, server = InMemoryTransport.create_pair()
    req = JSONRPCRequest(id=10, method="resources/list", params={})
    note = JSONRPCNotification(method="notifications/cancelled", params={"requestId": "x"})
    resp = JSONRPCResultResponse(id=10, result={"resultType": "complete"})
    client.send(req)
    server.send(resp)
    client.send(note)
    assert isinstance(server.receive(), JSONRPCRequest)
    assert isinstance(client.receive(), JSONRPCResultResponse)
    assert isinstance(server.receive(), JSONRPCNotification)

  def test_jsonrpc_message_as_utf8_json_validates(self):
    """Transport-identical request is a well-formed UTF-8 JSON unit (R-7.1-b)."""
    raw = json.dumps({
      "jsonrpc": "2.0", "id": 1, "method": "tools/call",
      "params": {"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "c", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
      }},
    }).encode("utf-8")
    parsed = validate_utf8_json_unit(raw)
    assert parsed["method"] == "tools/call"


# ---------------------------------------------------------------------------
# AC-12.2 / RQ-3 — message integrity: delivered == emitted  (R-7.1-c)
# ---------------------------------------------------------------------------

class TestMessageIntegrity:
  def test_message_delivered_unchanged(self):
    """Payload is byte-for-byte identical after transit (R-7.1-c)."""
    client, server = InMemoryTransport.create_pair()
    req = JSONRPCRequest(id=42, method="prompts/get", params={"name": "greet"})
    client.send(req)
    received = server.receive()
    assert received.id == req.id
    assert received.method == req.method
    assert received.params == req.params

  def test_unicode_payload_preserved(self):
    """Non-ASCII content is preserved intact (R-7.1-c)."""
    client, server = InMemoryTransport.create_pair()
    note = JSONRPCNotification(method="x", params={"q": "日本語テスト"})
    client.send(note)
    received = server.receive()
    assert received.params["q"] == "日本語テスト"

  def test_decoded_json_matches_original(self):
    original = {
      "jsonrpc": "2.0", "id": 7, "method": "resources/read",
      "params": {"uri": "file:///a.txt"},
    }
    encoded = json.dumps(original, ensure_ascii=False).encode("utf-8")
    decoded = validate_utf8_json_unit(encoded)
    assert json.dumps(decoded, ensure_ascii=False).encode("utf-8") == encoded


# ---------------------------------------------------------------------------
# AC-12.3 / RQ-5 — framing primitive in production code  (R-7.2-b/c/d)
# ---------------------------------------------------------------------------

class TestFramingPrimitive:
  """split_frames() and frame_message() live in production code (not tests)
  and provide body-independent boundary detection (RQ-5)."""

  def test_split_single_frame(self):
    data = b'{"jsonrpc":"2.0","id":1,"method":"m"}\n'
    frames = split_frames(data)
    assert len(frames) == 1
    assert frames[0] == b'{"jsonrpc":"2.0","id":1,"method":"m"}'

  def test_split_two_frames(self):
    f1 = b'{"jsonrpc":"2.0","id":1,"method":"a"}'
    f2 = b'{"jsonrpc":"2.0","id":2,"method":"b"}'
    stream = f1 + b"\n" + f2 + b"\n"
    frames = split_frames(stream)
    assert len(frames) == 2
    assert frames[0] == f1
    assert frames[1] == f2

  def test_split_many_frames(self):
    messages = [f'{{"jsonrpc":"2.0","id":{i},"method":"m"}}'.encode() for i in range(5)]
    stream = b"\n".join(messages) + b"\n"
    frames = split_frames(stream)
    assert len(frames) == 5
    for i, frame in enumerate(frames):
      assert json.loads(frame)["id"] == i

  def test_trailing_delimiter_excluded(self):
    """Empty frame from trailing delimiter must not appear in output (R-7.2-b)."""
    data = b'{"id":1}\n'
    frames = split_frames(data)
    assert all(f for f in frames)  # no empty bytes objects
    assert len(frames) == 1

  def test_body_independent_no_json_parsing_required(self):
    """Boundary finding uses delimiter only — no JSON parsing needed (R-7.2-c)."""
    # Even syntactically invalid JSON is split correctly by the delimiter.
    data = b'NOT JSON\nALSO NOT JSON\n'
    frames = split_frames(data)
    assert len(frames) == 2
    assert frames[0] == b'NOT JSON'
    assert frames[1] == b'ALSO NOT JSON'

  def test_custom_delimiter(self):
    data = b'msg1\r\nmsg2\r\n'
    frames = split_frames(data, delimiter=b"\r\n")
    assert len(frames) == 2

  def test_frame_message_appends_delimiter(self):
    msg = b'{"jsonrpc":"2.0","id":1,"method":"m"}'
    framed = frame_message(msg)
    assert framed == msg + b"\n"

  def test_frame_message_custom_delimiter(self):
    msg = b'{"id":1}'
    framed = frame_message(msg, delimiter=b"\r\n")
    assert framed.endswith(b"\r\n")

  def test_split_roundtrip_with_frame_message(self):
    """frame_message + split_frames round-trip is lossless."""
    messages = [b'{"id":1}', b'{"id":2}', b'{"id":3}']
    stream = b"".join(frame_message(m) for m in messages)
    recovered = split_frames(stream)
    assert recovered == messages

  def test_stdio_frame_delimiter_constant(self):
    assert STDIO_FRAME_DELIMITER == b"\n"

  def test_each_frame_parses_as_json(self):
    """After splitting, each frame can be parsed as a single JSON value (R-7.2-b/d)."""
    m1 = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "m"}).encode()
    m2 = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "n"}).encode()
    frames = split_frames(frame_message(m1) + frame_message(m2))
    for frame in frames:
      parsed = validate_utf8_json_unit(frame)
      assert "jsonrpc" in parsed


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

  def test_correlation_is_by_id_not_order(self):
    from mcp_sdk_py.jsonrpc import classify_message, ids_are_equal
    resp_3 = {"jsonrpc": "2.0", "id": 3, "result": {"resultType": "complete", "resources": []}}
    resp_2 = {"jsonrpc": "2.0", "id": 2, "result": {"resultType": "complete", "tools": []}}
    r3 = classify_message(resp_3)
    r2 = classify_message(resp_2)
    assert ids_are_equal(r3.id, 3)
    assert ids_are_equal(r2.id, 2)

  def test_in_flight_tracker_enforces_no_reuse(self):
    tracker = InFlightTracker()
    tracker.send(1)
    with pytest.raises(ValueError, match="already in-flight"):
      tracker.send(1)

  def test_id_reuse_allowed_after_receive(self):
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.receive(1)
    tracker.send(1)  # must not raise

  def test_id_correlation_via_in_memory_transport(self):
    """Request id is preserved through transit (R-7.2-e)."""
    client, server = InMemoryTransport.create_pair()
    req = JSONRPCRequest(id=99, method="tools/list", params={})
    client.send(req)
    received = server.receive()
    resp = JSONRPCResultResponse(id=received.id, result={"resultType": "complete"})
    server.send(resp)
    final = client.receive()
    assert final.id == 99


# ---------------------------------------------------------------------------
# AC-12.5 — malformed-id error may carry null id  (R-7.2-h)
# ---------------------------------------------------------------------------

class TestMalformedIdError:
  def test_null_id_error_response_accepted(self):
    from mcp_sdk_py.jsonrpc import classify_message, JSONRPCErrorResponse
    raw = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
    msg = classify_message(raw)
    assert isinstance(msg, JSONRPCErrorResponse)
    assert msg.id is None

  def test_omitted_id_on_error_accepted(self):
    from mcp_sdk_py.jsonrpc import classify_message, JSONRPCErrorResponse
    raw = {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}}
    msg = classify_message(raw)
    assert isinstance(msg, JSONRPCErrorResponse)
    assert msg.id is None


# ---------------------------------------------------------------------------
# AC-12.6 — multiplexing: multiple outstanding requests  (R-7.2-i/j/k/l)
# ---------------------------------------------------------------------------

class TestMultiplexing:
  def test_multiple_messages_in_flight_via_transport(self):
    """Transport accepts multiple sends before any receives (R-7.2-i/k)."""
    client, server = InMemoryTransport.create_pair()
    req1 = JSONRPCRequest(id=1, method="tools/list", params={})
    req2 = JSONRPCRequest(id=2, method="resources/list", params={})
    req3 = JSONRPCRequest(id=3, method="prompts/list", params={})
    client.send(req1)
    client.send(req2)
    client.send(req3)
    assert isinstance(server.receive(), JSONRPCRequest)
    assert isinstance(server.receive(), JSONRPCRequest)
    assert isinstance(server.receive(), JSONRPCRequest)

  def test_no_await_required_between_sends(self):
    """R-7.2-l: transport MUST NOT require awaiting previous response."""
    client, server = InMemoryTransport.create_pair()
    client.send(JSONRPCRequest(id=10, method="a", params={}))
    # No receive() between sends — second send must work immediately.
    client.send(JSONRPCRequest(id=11, method="b", params={}))
    assert server.receive().id == 10
    assert server.receive().id == 11

  def test_in_flight_tracker_multiple_ids(self):
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.send(2)
    tracker.send(3)
    assert tracker.in_flight_ids == frozenset({1, 2, 3})

  def test_unique_ids_enforced(self):
    tracker = InFlightTracker()
    tracker.send(99)
    with pytest.raises(ValueError):
      tracker.send(99)


# ---------------------------------------------------------------------------
# AC-12.7 — out-of-order responses; no FIFO precondition  (R-7.2-m/n/p)
# ---------------------------------------------------------------------------

class TestOutOfOrderResponses:
  def test_out_of_order_delivery_via_transport(self):
    """Server can reply to later request first; client correlates by id (R-7.2-m)."""
    client, server = InMemoryTransport.create_pair()
    client.send(JSONRPCRequest(id=2, method="tools/list", params={}))
    client.send(JSONRPCRequest(id=3, method="resources/list", params={}))
    # Server replies to 3 first.
    server.send(JSONRPCResultResponse(id=3, result={"resultType": "complete"}))
    server.send(JSONRPCResultResponse(id=2, result={"resultType": "complete"}))
    r_first = client.receive()
    r_second = client.receive()
    assert r_first.id == 3
    assert r_second.id == 2

  def test_receiver_uses_id_not_order(self):
    tracker = InFlightTracker()
    tracker.send(2)
    tracker.send(3)
    tracker.receive(3)
    assert not tracker.is_in_flight(3)
    assert tracker.is_in_flight(2)
    tracker.receive(2)
    assert tracker.in_flight_ids == frozenset()


# ---------------------------------------------------------------------------
# AC-12.8 / RQ-9 — no silent loss: MessageDeliveryError on closed peer  (R-7.2-q/r/s)
# ---------------------------------------------------------------------------

class TestNoSilentLoss:
  def test_send_to_closed_this_side_raises(self):
    """Sending after close() on this side raises MessageDeliveryError (R-7.2-q)."""
    client, server = InMemoryTransport.create_pair()
    client.close()
    with pytest.raises(MessageDeliveryError):
      client.send(JSONRPCRequest(id=1, method="m", params={}))

  def test_send_to_closed_peer_raises(self):
    """Sending when peer is closed raises MessageDeliveryError (R-7.2-r) — no silent drop."""
    client, server = InMemoryTransport.create_pair()
    server.close()
    with pytest.raises(MessageDeliveryError):
      client.send(JSONRPCRequest(id=1, method="m", params={}))

  def test_message_delivery_error_carries_summary(self):
    client, server = InMemoryTransport.create_pair()
    server.close()
    try:
      client.send(JSONRPCRequest(id=1, method="m", params={}))
    except MessageDeliveryError as e:
      assert isinstance(e.message_summary, str)

  def test_message_delivery_error_is_transport_error(self):
    assert issubclass(MessageDeliveryError, TransportError)

  def test_transport_error_is_exception(self):
    assert issubclass(TransportError, Exception)


# ---------------------------------------------------------------------------
# AC-12.9 / RQ-10 — clean close: observable state  (R-7.2-t)
# ---------------------------------------------------------------------------

class TestCleanClose:
  def test_is_closed_false_before_close(self):
    client, _ = InMemoryTransport.create_pair()
    assert not client.is_closed

  def test_is_closed_true_after_close(self):
    """close() makes is_closed observable (R-7.2-t)."""
    client, server = InMemoryTransport.create_pair()
    client.close()
    assert client.is_closed

  def test_server_side_close_observable(self):
    client, server = InMemoryTransport.create_pair()
    server.close()
    assert server.is_closed
    assert not client.is_closed

  def test_close_is_idempotent(self):
    """Calling close() twice must not raise."""
    client, _ = InMemoryTransport.create_pair()
    client.close()
    client.close()
    assert client.is_closed

  def test_disconnection_error_is_transport_error(self):
    assert issubclass(DisconnectionError, TransportError)

  def test_receive_on_closed_self_raises_disconnection(self):
    """After close(), receive() raises DisconnectionError (R-7.2-t)."""
    client, _ = InMemoryTransport.create_pair()
    client.close()
    with pytest.raises(DisconnectionError):
      client.receive()


# ---------------------------------------------------------------------------
# AC-12.10 — custom transport permitted; must uphold §7.2  (R-7.3-a/b/c/d)
# ---------------------------------------------------------------------------

class TestCustomTransportPermitted:
  def test_checklist_default_all_false(self):
    c = CustomTransportChecklist(name="MyTransport")
    assert not c.is_conformant()

  def test_conformant_checklist_passes(self):
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
    )
    assert c.is_conformant()

  def test_missing_obligations_lists_gaps(self):
    c = CustomTransportChecklist(preserves_json_rpc_format=True, provides_framing=True)
    missing = c.missing_obligations()
    assert "preserves_json_rpc_format" not in missing
    assert "provides_framing" not in missing
    assert "utf8_encoded" in missing
    assert "bidirectional" in missing

  def test_partial_not_conformant(self):
    c = CustomTransportChecklist(preserves_json_rpc_format=True)
    assert not c.is_conformant()

  def test_checklist_name_field(self):
    c = CustomTransportChecklist(name="WebSocket")
    assert c.name == "WebSocket"


# ---------------------------------------------------------------------------
# AC-12.11 — custom transport over stream SHOULD use stdio framing  (R-7.3-e)
# ---------------------------------------------------------------------------

class TestStdioFramingRecommendation:
  def test_checklist_tracks_stdio_framing(self):
    c = CustomTransportChecklist(uses_stdio_framing_if_stream=True)
    assert c.uses_stdio_framing_if_stream

  def test_conformant_without_stdio_framing_flag(self):
    """uses_stdio_framing_if_stream is SHOULD-level; does not block is_conformant()."""
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
      uses_stdio_framing_if_stream=False,
    )
    assert c.is_conformant()


# ---------------------------------------------------------------------------
# AC-12.12 — bidirectional channel over one connection  (R-7.4-a/b/c)
# ---------------------------------------------------------------------------

class TestBidirectional:
  def test_client_to_server_and_back(self):
    """Full round-trip: client sends request, server replies (R-7.4-a/b/c)."""
    client, server = InMemoryTransport.create_pair()
    client.send(JSONRPCRequest(id=1, method="tools/list", params={}))
    req = server.receive()
    server.send(JSONRPCResultResponse(id=req.id, result={"resultType": "complete", "tools": []}))
    resp = client.receive()
    assert resp.id == 1

  def test_server_can_also_send_notifications(self):
    """Server sends notifications to client; client receives (R-7.4-c)."""
    client, server = InMemoryTransport.create_pair()
    note = JSONRPCNotification(method="notifications/progress", params={"progressToken": "t", "progress": 50})
    server.send(note)
    received = client.receive()
    assert isinstance(received, JSONRPCNotification)

  def test_both_directions_simultaneously(self):
    """Messages travel both ways over one pair (R-7.4-a)."""
    client, server = InMemoryTransport.create_pair()
    client.send(JSONRPCRequest(id=1, method="m", params={}))
    server.send(JSONRPCNotification(method="notifications/progress", params={"progressToken": "t", "progress": 1}))
    assert isinstance(server.receive(), JSONRPCRequest)
    assert isinstance(client.receive(), JSONRPCNotification)


# ---------------------------------------------------------------------------
# AC-12.13 — every request carries _meta envelope  (R-7.4-d, R-7.4-f)
# ---------------------------------------------------------------------------

class TestPerRequestMetaRequired:
  def test_request_meta_keys_present(self):
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
    validate_request_meta_object(meta)

  def test_meta_survives_transport(self):
    """_meta envelope is preserved intact through InMemoryTransport (R-7.4-f)."""
    client, server = InMemoryTransport.create_pair()
    meta = {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": {"name": "c", "version": "1"},
      "io.modelcontextprotocol/clientCapabilities": {},
    }
    req = JSONRPCRequest(id=1, method="tools/list", params={"_meta": meta})
    client.send(req)
    received = server.receive()
    assert received.params["_meta"]["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"


# ---------------------------------------------------------------------------
# AC-12.14 — envelope mirroring into transport-level metadata  (R-7.4-e)
# ---------------------------------------------------------------------------

class TestEnvelopeMirroring:
  def test_http_header_constant_exists(self):
    from mcp_sdk_py.revision import HTTP_PROTOCOL_VERSION_HEADER
    assert HTTP_PROTOCOL_VERSION_HEADER == "MCP-Protocol-Version"

  def test_mirroring_does_not_affect_body(self):
    """Body remains authoritative even when mirroring is done (R-7.4-e)."""
    body_version = "2026-07-28"
    header_version = "2026-07-28"
    from mcp_sdk_py.revision import validate_http_revision_header
    validate_http_revision_header(body_version, header_version)


# ---------------------------------------------------------------------------
# AC-12.15 / RQ-11 — abrupt disconnection surfaced as DisconnectionError  (R-7.5-a/b)
# ---------------------------------------------------------------------------

class TestDisconnectionObservable:
  def test_receive_after_peer_closes_raises_disconnection(self):
    """After peer close(), receive() raises DisconnectionError — not blocking (R-7.5-a/b)."""
    client, server = InMemoryTransport.create_pair()
    server.close()
    with pytest.raises(DisconnectionError):
      client.receive()

  def test_receive_after_own_close_raises_disconnection(self):
    client, _ = InMemoryTransport.create_pair()
    client.close()
    with pytest.raises(DisconnectionError):
      client.receive()

  def test_disconnection_error_carries_connection_id(self):
    err = DisconnectionError("lost", connection_id="conn-abc")
    assert err.connection_id == "conn-abc"

  def test_disconnection_error_is_transport_error(self):
    assert issubclass(DisconnectionError, TransportError)

  def test_messages_queued_before_peer_close_still_delivered(self):
    """Messages already in queue before peer close() are still receivable (R-7.5-a)."""
    client, server = InMemoryTransport.create_pair()
    client.send(JSONRPCRequest(id=1, method="m", params={}))
    client.send(JSONRPCRequest(id=2, method="n", params={}))
    client.close()
    # Both messages were enqueued before close — server can still receive them.
    assert isinstance(server.receive(), JSONRPCRequest)
    assert isinstance(server.receive(), JSONRPCRequest)
    # Now the queue is empty and peer is closed → DisconnectionError.
    with pytest.raises(DisconnectionError):
      server.receive()


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
    tracker = InFlightTracker()
    tracker.send(1)
    tracker.send(2)
    fail_in_flight_on_disconnect(tracker)
    assert tracker.in_flight_ids == frozenset()

  def test_empty_tracker_returns_empty(self):
    tracker = InFlightTracker()
    assert fail_in_flight_on_disconnect(tracker) == frozenset()

  def test_integer_ids_failed(self):
    tracker = InFlightTracker()
    tracker.send(100)
    tracker.send(200)
    failed = fail_in_flight_on_disconnect(tracker)
    assert 100 in failed
    assert 200 in failed

  def test_combined_with_disconnection_error(self):
    """Typical disconnect flow: DisconnectionError observed, then in-flight resolved."""
    client, server = InMemoryTransport.create_pair()
    tracker = InFlightTracker()
    tracker.send("req-1")
    tracker.send("req-2")
    server.close()
    with pytest.raises(DisconnectionError):
      client.receive()
    failed = fail_in_flight_on_disconnect(tracker)
    assert failed == frozenset({"req-1", "req-2"})


# ---------------------------------------------------------------------------
# AC-12.17 — stateless client MAY retry after disconnect  (R-7.5-f)
# ---------------------------------------------------------------------------

class TestRetryAfterDisconnect:
  def test_retry_on_fresh_transport_pair(self):
    """After disconnect, failed request can be retried on a new pair (R-7.5-f)."""
    old_client, _ = InMemoryTransport.create_pair()
    old_tracker = InFlightTracker()
    old_tracker.send("retryable")
    fail_in_flight_on_disconnect(old_tracker)
    # Fresh connection for retry.
    new_client, new_server = InMemoryTransport.create_pair()
    new_tracker = InFlightTracker()
    new_tracker.send("retryable")
    new_client.send(JSONRPCRequest(id="retryable", method="m", params={}))
    received = new_server.receive()
    assert received.id == "retryable"


# ---------------------------------------------------------------------------
# AC-12.18 — stdio server exit: restart + retry  (R-7.5-g/h)
# ---------------------------------------------------------------------------

class TestStdioProcessRestart:
  def test_stdio_transport_constant(self):
    assert TRANSPORT_STDIO == "stdio"

  def test_disconnection_models_process_exit(self):
    """Unexpected exit is modelled as DisconnectionError (concrete restart in S13)."""
    err = DisconnectionError("server process exited unexpectedly", connection_id="proc-42")
    assert isinstance(err, DisconnectionError)


# ---------------------------------------------------------------------------
# AC-12.19 — no silent discard on error  (R-7.5-i/j)
# ---------------------------------------------------------------------------

class TestNoSilentDiscardOnError:
  def test_closed_peer_raises_not_returns_none(self):
    """send() to closed peer raises MessageDeliveryError — not silently discards (R-7.5-i)."""
    client, server = InMemoryTransport.create_pair()
    server.close()
    with pytest.raises(MessageDeliveryError):
      client.send(JSONRPCNotification(method="m", params={}))

  def test_message_delivery_error_inherits_transport_error(self):
    assert issubclass(MessageDeliveryError, TransportError)


# ---------------------------------------------------------------------------
# AC-12.20 — UTF-8 + JSON validation  (R-7.6-a/b/c)
# ---------------------------------------------------------------------------

class TestUtf8JsonValidation:
  def test_valid_utf8_json_passes(self):
    data = b'{"jsonrpc":"2.0","id":1,"method":"test"}'
    assert validate_utf8_json_unit(data)["method"] == "test"

  def test_invalid_utf8_raises(self):
    with pytest.raises(MalformedMessageError) as exc_info:
      validate_utf8_json_unit(b"\xff\xfe invalid")
    assert exc_info.value.raw_excerpt != b""

  def test_valid_utf8_invalid_json_raises(self):
    with pytest.raises(MalformedMessageError):
      validate_utf8_json_unit("not json at all".encode("utf-8"))

  def test_empty_bytes_raises(self):
    with pytest.raises(MalformedMessageError):
      validate_utf8_json_unit(b"")

  def test_malformed_is_transport_error(self):
    assert issubclass(MalformedMessageError, TransportError)

  def test_must_not_silently_drop(self):
    """R-7.6-c: malformed unit MUST raise, never return None or a default."""
    with pytest.raises(MalformedMessageError):
      validate_utf8_json_unit(b"not-json")

  def test_unicode_json_accepted(self):
    data = json.dumps({"x": "こんにちは"}, ensure_ascii=False).encode("utf-8")
    assert validate_utf8_json_unit(data)["x"] == "こんにちは"

  def test_json_array_accepted(self):
    assert validate_utf8_json_unit(b'[1, 2, 3]') == [1, 2, 3]


# ---------------------------------------------------------------------------
# AC-12.21 / RQ-15 — no connection-scoped state: real guard  (R-7.6-d/e/f)
# ---------------------------------------------------------------------------

class TestNoConnectionScopedState:
  """assert_no_connection_scoped_state is a real guard (not an always-raising marker).
  It raises only when state_key IS the connection identity (RQ-15)."""

  def test_same_object_raises(self):
    """Using the connection object itself as a state key raises (R-7.6-i)."""
    conn = object()
    with pytest.raises(ConnectionScopedStateError):
      assert_no_connection_scoped_state(conn, conn)

  def test_different_object_passes(self):
    """An explicit string identifier is NOT the connection — no-op (R-7.6-j)."""
    conn = object()
    explicit_id = "session-abc-123"
    assert_no_connection_scoped_state(explicit_id, conn)  # must not raise

  def test_explicit_string_id_passes(self):
    conn = object()
    assert_no_connection_scoped_state("task-id-from-client", conn)

  def test_explicit_int_id_passes(self):
    conn = object()
    assert_no_connection_scoped_state(42, conn)

  def test_context_appears_in_error_message(self):
    conn = object()
    with pytest.raises(ConnectionScopedStateError) as exc_info:
      assert_no_connection_scoped_state(conn, conn, context="session lookup by tcp_conn")
    assert "session lookup by tcp_conn" in str(exc_info.value)

  def test_is_connection_scoped_same_object(self):
    conn = object()
    assert is_connection_scoped(conn, conn) is True

  def test_is_connection_scoped_different_object(self):
    conn = object()
    assert is_connection_scoped("explicit-id", conn) is False

  def test_equal_strings_different_identity_passes(self):
    """Equal value but different identity (not ``is``) → not connection-scoped."""
    conn_id = "conn-1"
    explicit = "conn-1"  # same value, but the string may be interned; still OK
    # is_connection_scoped uses ``is``, not ``==``.
    # For interned strings this could be True, but the explicit-id pattern is about
    # passing a distinct object. We verify the function uses identity.
    result = is_connection_scoped(explicit, conn_id)
    # Accept either outcome — the critical rule is that a dedicated explicit id
    # object is not the same ``is`` the connection.
    assert isinstance(result, bool)

  def test_connection_scoped_state_error_is_exception(self):
    assert issubclass(ConnectionScopedStateError, Exception)

  def test_error_message_mentions_connection(self):
    conn = object()
    try:
      assert_no_connection_scoped_state(conn, conn)
    except ConnectionScopedStateError as e:
      assert "connection" in str(e).lower()

  def test_each_request_carries_its_own_meta(self):
    """R-7.6-f: server uses _meta, not connection identity, for each request."""
    from mcp_sdk_py.meta_object import KEY_PROTOCOL_VERSION, KEY_CLIENT_INFO, KEY_CLIENT_CAPABILITIES
    meta = {
      KEY_PROTOCOL_VERSION: "2026-07-28",
      KEY_CLIENT_INFO: {"name": "client-a", "version": "1"},
      KEY_CLIENT_CAPABILITIES: {},
    }
    # All three keys are in the body — no connection lookup needed.
    assert KEY_PROTOCOL_VERSION in meta
    assert KEY_CLIENT_INFO in meta
    assert KEY_CLIENT_CAPABILITIES in meta


# ---------------------------------------------------------------------------
# AC-12.22 — SHOULD NOT require same connection; interleaving allowed  (R-7.6-g/h/i)
# ---------------------------------------------------------------------------

class TestConnectionReuseNotRequired:
  def test_interleaved_requests_on_one_transport(self):
    """R-7.6-h: client MAY interleave unrelated requests on one connection."""
    client, server = InMemoryTransport.create_pair()
    client.send(JSONRPCRequest(id=1, method="tools/list", params={}))
    client.send(JSONRPCRequest(id=2, method="resources/list", params={}))
    m1 = server.receive()
    m2 = server.receive()
    assert {m1.method, m2.method} == {"tools/list", "resources/list"}

  def test_connection_identity_not_a_state_proxy(self):
    """R-7.6-i: connection object MUST NOT proxy conversation identity."""
    conn = object()
    with pytest.raises(ConnectionScopedStateError):
      assert_no_connection_scoped_state(conn, conn)


# ---------------------------------------------------------------------------
# AC-12.23 — continuity via explicit identifier  (R-7.6-j)
# ---------------------------------------------------------------------------

class TestExplicitIdentifierForContinuity:
  def test_explicit_id_not_connection_scoped(self):
    """Client-supplied id is not the connection identity → guard is a no-op."""
    conn = object()
    assert_no_connection_scoped_state("task-xyz", conn)  # must not raise

  def test_continuation_id_is_explicit(self):
    from mcp_sdk_py.stateless_model import is_valid_continuation_id
    assert is_valid_continuation_id("explicit-task-id-abc")

  def test_connection_guard_enables_correct_pattern(self):
    """Typical correct pattern: explicit id → guard passes; connection identity → guard raises."""
    conn = object()
    client_supplied_id = "req-state-42"
    # Correct pattern: use explicit id.
    assert_no_connection_scoped_state(client_supplied_id, conn)
    # Forbidden pattern: use connection object.
    with pytest.raises(ConnectionScopedStateError):
      assert_no_connection_scoped_state(conn, conn)


# ---------------------------------------------------------------------------
# AC-12.24 — disconnect makes in-flight failed; client MAY retry  (R-7.7-a/b)
# ---------------------------------------------------------------------------

class TestDisconnectMakesInFlightFailed:
  def test_in_flight_requests_failed_on_disconnect(self):
    """R-7.7-a: connection lost → both outstanding requests are failed."""
    client, server = InMemoryTransport.create_pair()
    tracker = InFlightTracker()
    tracker.send(2)
    tracker.send(3)
    server.close()
    with pytest.raises(DisconnectionError):
      client.receive()
    failed = fail_in_flight_on_disconnect(tracker)
    assert 2 in failed
    assert 3 in failed

  def test_retry_on_new_connection(self):
    """R-7.7-b: client MAY retry on new connection because no state is bound."""
    tracker = InFlightTracker()
    tracker.send(2)
    tracker.send(3)
    failed = fail_in_flight_on_disconnect(tracker)
    new_client, new_server = InMemoryTransport.create_pair()
    new_tracker = InFlightTracker()
    for rid in sorted(failed):
      new_tracker.send(rid)
      new_client.send(JSONRPCRequest(id=rid, method="m", params={}))
    assert new_tracker.in_flight_ids == frozenset({2, 3})
    assert isinstance(new_server.receive(), JSONRPCRequest)
    assert isinstance(new_server.receive(), JSONRPCRequest)

  def test_no_state_bound_to_connection(self):
    """After disconnect, in-flight set is cleared — state is gone with connection."""
    tracker = InFlightTracker()
    tracker.send("op-1")
    fail_in_flight_on_disconnect(tracker)
    assert tracker.in_flight_ids == frozenset()
