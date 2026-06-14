"""Tests for S13 — The stdio Transport (§8).

AC → test coverage map:
  AC-13.1  (UTF-8, one line, no embedded newline, single \\n terminator)
             → TestFramingEncoding
  AC-13.2  (accept \\n and \\r\\n; strip trailing \\r before parsing)
             → TestLineTerminators
  AC-13.3  (empty / whitespace-only line ignored, not malformed)
             → TestBlankLines
  AC-13.4  (client stdin: no responses, no non-MCP content)
             → TestClientStdinDirection
  AC-13.5  (server stdout: no requests, no non-MCP content)
             → TestServerStdoutDirection
  AC-13.6  (forward-referenced to S16; subscription notif is one of three kinds)
             → TestSubscriptionNotificationForwardReference
  AC-13.7  (server reply-requiring interaction carried inside the response)
             → TestServerNoInitiatedRequest
  AC-13.8  (cancellation via notifications/cancelled; post-cancel silence)
             → TestCancellation
  AC-13.9  (server stderr logging is valid, not protocol, never parsed)
             → TestStderrNotProtocol
  AC-13.10 (client may capture/forward/ignore stderr; never JSON-RPC; not an error)
             → TestStderrClientHandling
  AC-13.11 (malformed line: no crash, discard, optional diagnostic, resync)
             → TestMalformedLineNonFatal
  AC-13.12 (malformed request with recoverable id MAY get -32700/-32600; else silent)
             → TestMalformedLineErrorResponse
  AC-13.13 (startup: no handshake; every request carries _meta; any first message)
             → TestStartupNoHandshake
  AC-13.14 (graceful shutdown: close stdin, wait, then force; server exits on EOF)
             → TestGracefulShutdown
  AC-13.15 (server-initiated shutdown: close stdout and exit)
             → TestServerInitiatedShutdown
  AC-13.16 (forced termination: OS-appropriate SIGTERM→SIGKILL escalation)
             → TestForcedTermination
  AC-13.17 (unexpected exit: restart, retry lost in-flight; streams re-established per S16)
             → TestUnexpectedExitRestart
  AC-13.18 (every request carries revision/identity/caps; protocolVersion string; -32004)
             → TestRequestEnvelopeAndUnsupported
  AC-13.19 (server/discover as first message permitted; probing RECOMMENDED)
             → TestDiscoverProbeFirst
  AC-13.20 (probe outcomes: -32004 no-handshake select; other/timeout MAY handshake; not keyed)
             → TestDiscoverProbeOutcomes
  AC-13.21 (custom reliable byte-stream reuses framing/message rules; supplies subprocess aspects)
             → TestCustomByteStreamReuse
  AC-13.22 (subprocess stderr carries only diagnostics; never protocol)
             → TestStderrStreamRole
"""

from __future__ import annotations

import json

import pytest

from mcp_sdk_py.jsonrpc import (
  JSONRPCErrorResponse,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResultResponse,
)
from mcp_sdk_py.meta_object import (
  CURRENT_PROTOCOL_VERSION,
  KEY_CLIENT_CAPABILITIES,
  KEY_CLIENT_INFO,
  KEY_PROTOCOL_VERSION,
)
from mcp_sdk_py.negotiation import (
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
  build_unsupported_protocol_version_error,
)
from mcp_sdk_py.progress import CANCELLED_NOTIFICATION_METHOD
from mcp_sdk_py.stdio import (
  CARRIAGE_RETURN,
  CODE_INVALID_REQUEST,
  CODE_PARSE_ERROR,
  LINE_FEED,
  POSIX_FORCED_TERMINATION_ESCALATION,
  STDERR_IS_PROTOCOL,
  STDIO_NEWLINE,
  STDIO_REUSABLE_RULES,
  SUBPROCESS_SPECIFIC_ASPECTS,
  CustomByteStreamReuse,
  DiscoverProbeReaction,
  LifecycleState,
  MalformedLineOutcome,
  MessageDirection,
  ProcessHandle,
  StderrSink,
  StdioDirectionError,
  StdioLineReader,
  StreamRole,
  SubprocessController,
  assert_client_stdin_allowed,
  assert_server_stdout_allowed,
  build_cancellation,
  build_discover_probe,
  build_enveloped_request,
  build_request_envelope,
  correlates_to_cancelled,
  decode_line,
  encode_line,
  handle_inbound_line,
  is_blank_line,
  react_to_discover_probe,
  select_revision_from_unsupported,
  serialize_message,
)


CLIENT_INFO = {"name": "ExampleClient", "version": "1.0.0"}


# ===========================================================================
# AC-13.1 — UTF-8, one line, no embedded newline, single \n terminator
# ===========================================================================

class TestFramingEncoding:
  def test_serialized_message_is_single_line_no_newline(self):
    req = JSONRPCRequest(id=1, method="tools/call", params={"city": "Paris"})
    text = serialize_message(req)
    assert LINE_FEED not in text
    assert CARRIAGE_RETURN not in text
    assert "\n" not in text

  def test_encode_line_is_utf8_and_terminated_by_single_newline(self):
    req = JSONRPCRequest(id=1, method="m", params={"text": "18°C sunny"})
    wire = encode_line(req)
    assert isinstance(wire, bytes)
    # UTF-8 round-trips the non-ASCII degree sign rather than \u escaping it.
    assert "°C".encode("utf-8") in wire
    # Exactly one terminator, at the very end.
    assert wire.endswith(STDIO_NEWLINE)
    assert wire.count(b"\n") == 1

  def test_in_string_newline_is_escaped_not_embedded(self):
    # A genuine newline inside a string value must be escaped as \n, never literal.
    req = JSONRPCRequest(id=1, method="m", params={"text": "line1\nline2"})
    wire = encode_line(req)
    assert wire.count(b"\n") == 1  # only the terminator
    decoded = json.loads(wire[:-1].decode("utf-8"))
    assert decoded["params"]["text"] == "line1\nline2"

  def test_embedded_newline_in_any_field_is_escaped_to_single_line(self):
    # A sender MUST serialize so the message contains no literal newline (R-8.2-b/c):
    # newlines inside ANY string value are escaped, keeping the output single-line.
    bad = {"jsonrpc": "2.0", "id": 1, "method": "m\nx", "params": {"k": "a\nb"}}
    text = serialize_message(bad)
    assert "\n" not in text
    assert "\r" not in text
    # The escaped values survive a round-trip unchanged.
    decoded = json.loads(text)
    assert decoded["method"] == "m\nx"
    assert decoded["params"]["k"] == "a\nb"


# ===========================================================================
# AC-13.2 — accept \n and \r\n; strip trailing \r before parsing
# ===========================================================================

class TestLineTerminators:
  def _line_bytes(self) -> bytes:
    return json.dumps(
      {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}, separators=(",", ":")
    ).encode("utf-8")

  def test_lf_terminated_line_parses(self):
    raw = self._line_bytes()  # framer already removed the \n
    value = decode_line(raw)
    assert value["id"] == 1

  def test_crlf_trailing_cr_is_stripped_before_parsing(self):
    raw = self._line_bytes() + CARRIAGE_RETURN.encode("ascii")
    value = decode_line(raw)
    assert value["result"] == {"ok": True}

  def test_line_reader_accepts_both_lf_and_crlf(self):
    reader = StdioLineReader()
    body1 = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}, separators=(",", ":"))
    body2 = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {}}, separators=(",", ":"))
    chunk = (body1 + "\n" + body2 + "\r\n").encode("utf-8")
    outcomes = reader.feed(chunk)
    msgs = [o.message for o in outcomes if o.message is not None]
    assert [m.id for m in msgs] == [1, 2]


# ===========================================================================
# AC-13.3 — empty / whitespace-only line ignored, not malformed
# ===========================================================================

class TestBlankLines:
  def test_is_blank_line_detects_empty_and_whitespace(self):
    assert is_blank_line(b"")
    assert is_blank_line(b"   ")
    assert is_blank_line(b"\t \r")
    assert not is_blank_line(b'{"a":1}')

  def test_blank_line_ignored_not_malformed(self):
    outcome = handle_inbound_line(b"   ")
    assert outcome.ignored_blank is True
    assert outcome.malformed is False
    assert outcome.message is None

  def test_line_reader_skips_blank_lines_between_messages(self):
    reader = StdioLineReader()
    body = json.dumps({"jsonrpc": "2.0", "id": 9, "result": {}}, separators=(",", ":"))
    chunk = ("\n   \n" + body + "\n").encode("utf-8")
    outcomes = reader.feed(chunk)
    blanks = [o for o in outcomes if o.ignored_blank]
    msgs = [o.message for o in outcomes if o.message is not None]
    assert len(blanks) == 2
    assert [m.id for m in msgs] == [9]


# ===========================================================================
# AC-13.4 — client stdin: no responses, no non-MCP content
# ===========================================================================

class TestClientStdinDirection:
  def test_request_and_notification_allowed_on_stdin(self):
    assert_client_stdin_allowed(JSONRPCRequest(id=1, method="tools/list"))
    assert_client_stdin_allowed(JSONRPCNotification(method="notifications/cancelled"))

  def test_result_response_rejected_on_stdin(self):
    with pytest.raises(StdioDirectionError) as exc:
      assert_client_stdin_allowed(JSONRPCResultResponse(id=1, result={}))
    assert exc.value.role is StreamRole.STDIN

  def test_error_response_rejected_on_stdin(self):
    with pytest.raises(StdioDirectionError):
      assert_client_stdin_allowed(JSONRPCErrorResponse(id=1, error={"code": -1, "message": "x"}))


# ===========================================================================
# AC-13.5 — server stdout: no requests, no non-MCP content
# ===========================================================================

class TestServerStdoutDirection:
  def test_response_and_notification_allowed_on_stdout(self):
    assert_server_stdout_allowed(JSONRPCResultResponse(id=1, result={}))
    assert_server_stdout_allowed(JSONRPCErrorResponse(id=1, error={"code": -1, "message": "x"}))
    assert_server_stdout_allowed(JSONRPCNotification(method="notifications/progress"))

  def test_request_rejected_on_stdout(self):
    with pytest.raises(StdioDirectionError) as exc:
      assert_server_stdout_allowed(JSONRPCRequest(id=1, method="anything"))
    assert exc.value.role is StreamRole.STDOUT

  def test_three_kinds_of_stdout_messages_are_responses_and_notifications(self):
    # The only allowed stdout messages are responses and notifications.
    response = JSONRPCResultResponse(id=1, result={})
    progress = JSONRPCNotification(method="notifications/progress", params={"progressToken": "t", "progress": 1})
    subscription = JSONRPCNotification(
      method="notifications/resource",
      params={"_meta": {"io.modelcontextprotocol/subscriptionId": "s1"}},
    )
    for m in (response, progress, subscription):
      assert_server_stdout_allowed(m)


# ===========================================================================
# AC-13.6 — subscription notif forward-referenced to S16 (one of three kinds)
# ===========================================================================

class TestSubscriptionNotificationForwardReference:
  def test_subscription_notification_carried_on_stdout_as_notification(self):
    # This story only establishes that subscription notifications travel on the
    # shared stdout channel as one of the three kinds; correlation is owned by S16.
    sub = JSONRPCNotification(
      method="notifications/resourceUpdated",
      params={"_meta": {"io.modelcontextprotocol/subscriptionId": "abc"}},
    )
    assert_server_stdout_allowed(sub)  # permitted on stdout
    # It is a notification, not a request, and not a response.
    assert isinstance(sub, JSONRPCNotification)


# ===========================================================================
# AC-13.7 — server reply-requiring interaction carried inside the response
# ===========================================================================

class TestServerNoInitiatedRequest:
  def test_server_cannot_initiate_request_on_stdout(self):
    # Any reply-requiring interaction must be carried inside the response, not as
    # a separate stdout request (R-8.3-b/d).
    with pytest.raises(StdioDirectionError):
      assert_server_stdout_allowed(JSONRPCRequest(id=99, method="elicit/input"))

  def test_reply_requiring_interaction_is_carried_inside_response(self):
    # The interaction lives inside the response object the server writes to stdout.
    response = JSONRPCResultResponse(
      id=1, result={"needsInput": True, "inputRequest": {"prompt": "name?"}}
    )
    assert_server_stdout_allowed(response)  # allowed: it is a response, not a request


# ===========================================================================
# AC-13.8 — cancellation via notifications/cancelled; post-cancel silence
# ===========================================================================

class TestCancellation:
  def test_build_cancellation_references_request_id(self):
    notif = build_cancellation(1)
    assert isinstance(notif, JSONRPCNotification)
    assert notif.method == CANCELLED_NOTIFICATION_METHOD
    assert notif.params == {"requestId": 1}

  def test_cancellation_with_reason(self):
    notif = build_cancellation("req-7", reason="user aborted")
    assert notif.params["requestId"] == "req-7"
    assert notif.params["reason"] == "user aborted"

  def test_cancellation_is_a_valid_client_to_server_notification(self):
    notif = build_cancellation(1)
    assert_client_stdin_allowed(notif)  # client writes it to stdin

  def test_response_for_cancelled_id_must_be_withheld(self):
    # After cancellation the server MUST NOT send the response for that id.
    response = JSONRPCResultResponse(id=1, result={"ok": True})
    assert correlates_to_cancelled(response, 1) is True
    other = JSONRPCResultResponse(id=2, result={})
    assert correlates_to_cancelled(other, 1) is False

  def test_related_notification_for_cancelled_request_must_be_withheld(self):
    progress = JSONRPCNotification(
      method="notifications/progress", params={"requestId": 1, "progress": 5}
    )
    assert correlates_to_cancelled(progress, 1) is True
    progress_token = JSONRPCNotification(
      method="notifications/progress", params={"progressToken": 1, "progress": 5}
    )
    assert correlates_to_cancelled(progress_token, 1) is True

  def test_unrelated_messages_not_withheld(self):
    unrelated = JSONRPCNotification(method="notifications/message", params={"data": "x"})
    assert correlates_to_cancelled(unrelated, 1) is False


# ===========================================================================
# AC-13.9 / AC-13.22 — stderr is valid logging, not protocol, never parsed
# ===========================================================================

class TestStderrNotProtocol:
  def test_stderr_stream_role_does_not_carry_protocol(self):
    assert StreamRole.STDERR.carries_protocol is False
    assert StreamRole.STDIN.carries_protocol is True
    assert StreamRole.STDOUT.carries_protocol is True

  def test_stderr_is_protocol_constant_is_false(self):
    assert STDERR_IS_PROTOCOL is False
    assert StderrSink.is_protocol() is False

  def test_stderr_text_is_not_parsed_as_protocol(self):
    # Even a line that looks like JSON-RPC, when arriving on stderr, is treated
    # as free-form text and never classified.
    sink = StderrSink(capture=True)
    sink.feed(b'{"jsonrpc":"2.0","id":1,"method":"x"}\n')
    sink.feed(b"[server] handling tools/call\n")
    # Captured verbatim as text; no JSON-RPC objects produced.
    assert any("handling tools/call" in c for c in sink.captured)
    assert all(isinstance(c, str) for c in sink.captured)


class TestStderrStreamRole:
  def test_stderr_carries_only_diagnostic_text(self):
    sink = StderrSink(capture=True)
    sink.feed(b"info: starting\ndebug: ready\n")
    joined = "".join(sink.captured)
    assert "starting" in joined and "ready" in joined

  def test_stderr_role_value(self):
    assert StreamRole.STDERR.value == "stderr"


# ===========================================================================
# AC-13.10 — client may capture/forward/ignore stderr; never JSON-RPC; not error
# ===========================================================================

class TestStderrClientHandling:
  def test_client_may_ignore_stderr(self):
    sink = StderrSink()  # neither capture nor forward
    sink.feed(b"some diagnostic\n")
    assert sink.captured == []

  def test_client_may_capture_stderr(self):
    sink = StderrSink(capture=True)
    sink.feed(b"captured line\n")
    assert sink.captured == ["captured line\n"]

  def test_client_may_forward_stderr(self):
    forwarded: list[str] = []
    sink = StderrSink(forward=forwarded.append)
    sink.feed(b"forward me\n")
    assert forwarded == ["forward me\n"]

  def test_presence_of_stderr_is_not_treated_as_error(self):
    sink = StderrSink(capture=True)
    sink.feed(b"ERROR: something bad happened\n")
    # SHOULD NOT assume presence indicates an error condition (R-8.4-e).
    assert sink.saw_error is False


# ===========================================================================
# AC-13.11 — malformed line: no crash, discard, optional diagnostic, resync
# ===========================================================================

class TestMalformedLineNonFatal:
  def test_invalid_json_line_does_not_raise(self):
    outcome = handle_inbound_line(b"this is not json")
    assert outcome.malformed is True
    assert outcome.message is None
    assert outcome.diagnostic is not None  # optional diagnostic recorded

  def test_valid_json_but_not_jsonrpc_is_malformed(self):
    outcome = handle_inbound_line(b'{"not":"a jsonrpc message"}')
    assert outcome.malformed is True
    assert outcome.message is None

  def test_receiver_resynchronizes_at_next_newline(self):
    # A malformed line followed by a valid line: the valid one is still read.
    reader = StdioLineReader()
    good = json.dumps({"jsonrpc": "2.0", "id": 5, "result": {}}, separators=(",", ":"))
    chunk = (b"garbage not json\n" + good.encode("utf-8") + b"\n")
    outcomes = reader.feed(chunk)
    assert outcomes[0].malformed is True
    assert outcomes[0].resynchronize is True  # connection continues
    msgs = [o.message for o in outcomes if o.message is not None]
    assert [m.id for m in msgs] == [5]

  def test_malformed_outcome_always_resynchronizes(self):
    assert MalformedLineOutcome(malformed=True).resynchronize is True
    assert MalformedLineOutcome(ignored_blank=True).resynchronize is True


# ===========================================================================
# AC-13.12 — malformed request with recoverable id MAY get -32700/-32600; else silent
# ===========================================================================

class TestMalformedLineErrorResponse:
  def test_recoverable_request_id_yields_error_response_when_opted_in(self):
    # A JSON object recognizable as a request (has method + id) but invalid as a
    # JSON-RPC message (bad jsonrpc) → MAY return -32600.
    line = b'{"jsonrpc":"1.0","id":7,"method":"tools/call"}'
    outcome = handle_inbound_line(line, respond_to_malformed=True)
    assert outcome.malformed is True
    assert outcome.error_response is not None
    assert outcome.error_response.id == 7
    assert outcome.error_response.error["code"] in (CODE_PARSE_ERROR, CODE_INVALID_REQUEST)

  def test_no_error_response_when_not_opted_in(self):
    line = b'{"jsonrpc":"1.0","id":7,"method":"tools/call"}'
    outcome = handle_inbound_line(line, respond_to_malformed=False)
    assert outcome.malformed is True
    assert outcome.error_response is None

  def test_unparseable_line_has_no_recoverable_id_and_is_silent(self):
    # No id can be recovered from non-JSON → no response, silently discarded.
    outcome = handle_inbound_line(b"<<<not json>>>", respond_to_malformed=True)
    assert outcome.malformed is True
    assert outcome.error_response is None

  def test_malformed_without_method_is_not_a_request_so_no_response(self):
    # Valid JSON, has id, but no method → not recognizable as a request → silent.
    outcome = handle_inbound_line(b'{"jsonrpc":"1.0","id":3}', respond_to_malformed=True)
    assert outcome.malformed is True
    assert outcome.error_response is None


# ===========================================================================
# AC-13.13 — startup: no handshake; every request carries _meta; any first msg
# ===========================================================================

class TestStartupNoHandshake:
  def _handle(self) -> ProcessHandle:
    return ProcessHandle(
      close_stdin=lambda: None,
      poll=lambda: 0,
      terminate=lambda: None,
      kill=lambda: None,
    )

  def test_controller_starts_connected_without_handshake(self):
    ctrl = SubprocessController(self._handle())
    assert ctrl.state is LifecycleState.CONNECTED
    assert ctrl.requires_handshake is False

  def test_every_request_carries_full_meta_envelope(self):
    req = build_enveloped_request(1, "tools/call", client_info=CLIENT_INFO)
    meta = req.params["_meta"]
    assert KEY_PROTOCOL_VERSION in meta
    assert KEY_CLIENT_INFO in meta
    assert KEY_CLIENT_CAPABILITIES in meta

  def test_first_message_may_be_any_enveloped_request(self):
    # A tools/list request as the first message is valid (no required first msg).
    req = build_enveloped_request(1, "tools/list", client_info=CLIENT_INFO)
    assert_client_stdin_allowed(req)
    assert req.params["_meta"][KEY_PROTOCOL_VERSION] == CURRENT_PROTOCOL_VERSION

  def test_first_message_may_be_server_discover(self):
    probe = build_discover_probe(0, client_info=CLIENT_INFO)
    assert probe.method == "server/discover"
    assert_client_stdin_allowed(probe)


# ===========================================================================
# Lifecycle test helpers
# ===========================================================================

class _FakeProcess:
  """A scripted fake process driving ProcessHandle for deterministic tests."""

  def __init__(self, exit_after_close: bool = True, exit_on_terminate: bool = True):
    self.exit_code: int | None = None
    self.stdin_closed = False
    self.terminated = False
    self.killed = False
    self.signals: list[int] = []
    self._exit_after_close = exit_after_close
    self._exit_on_terminate = exit_on_terminate

  def close_stdin(self):
    self.stdin_closed = True
    if self._exit_after_close:
      self.exit_code = 0  # server exits promptly on EOF (R-8.6.2-b)

  def poll(self):
    return self.exit_code

  def terminate(self):
    self.terminated = True
    import signal as _s
    self.signals.append(int(_s.SIGTERM))
    if self._exit_on_terminate:
      self.exit_code = -15

  def kill(self):
    self.killed = True
    import signal as _s
    self.signals.append(int(_s.SIGKILL))
    self.exit_code = -9

  def handle(self) -> ProcessHandle:
    return ProcessHandle(
      close_stdin=self.close_stdin,
      poll=self.poll,
      terminate=self.terminate,
      kill=self.kill,
    )


# ===========================================================================
# AC-13.14 — graceful shutdown: close stdin first, wait, then force; server exits on EOF
# ===========================================================================

class TestGracefulShutdown:
  def test_shutdown_closes_stdin_first(self):
    fake = _FakeProcess(exit_after_close=True)
    ctrl = SubprocessController(fake.handle(), grace_period=0.5, poll_interval=0.001)
    graceful = ctrl.shutdown()
    assert fake.stdin_closed is True
    assert graceful is True
    assert ctrl.state is LifecycleState.EXITED
    assert ctrl.was_forced is False

  def test_server_exits_promptly_on_eof_avoids_forced_termination(self):
    fake = _FakeProcess(exit_after_close=True)
    ctrl = SubprocessController(fake.handle(), grace_period=0.5, poll_interval=0.001)
    ctrl.shutdown()
    assert fake.terminated is False
    assert fake.killed is False


# ===========================================================================
# AC-13.15 — server-initiated shutdown: close stdout and exit
# ===========================================================================

class TestServerInitiatedShutdown:
  def test_server_initiated_exit_transitions_to_exited(self):
    fake = _FakeProcess()
    ctrl = SubprocessController(fake.handle())
    assert ctrl.state is LifecycleState.CONNECTED
    ctrl.note_server_initiated_exit()
    assert ctrl.state is LifecycleState.EXITED


# ===========================================================================
# AC-13.16 — forced termination: OS-appropriate SIGTERM→SIGKILL escalation
# ===========================================================================

class TestForcedTermination:
  def test_force_escalates_sigterm_then_sigkill(self):
    # Server never exits on EOF nor on SIGTERM → escalate to SIGKILL.
    fake = _FakeProcess(exit_after_close=False, exit_on_terminate=False)
    ctrl = SubprocessController(fake.handle(), grace_period=0.02, poll_interval=0.001)
    graceful = ctrl.shutdown()
    assert graceful is False
    assert ctrl.was_forced is True
    assert fake.terminated is True
    assert fake.killed is True
    # POSIX example escalation order: SIGTERM then SIGKILL.
    assert fake.signals[0] == POSIX_FORCED_TERMINATION_ESCALATION[0]
    assert POSIX_FORCED_TERMINATION_ESCALATION[1] in fake.signals
    assert ctrl.state is LifecycleState.EXITED

  def test_sigterm_alone_suffices_when_server_responds(self):
    fake = _FakeProcess(exit_after_close=False, exit_on_terminate=True)
    ctrl = SubprocessController(fake.handle(), grace_period=0.02, poll_interval=0.001)
    graceful = ctrl.shutdown()
    assert graceful is False  # required forcing, but...
    assert fake.terminated is True
    assert fake.killed is False  # SIGKILL not needed

  def test_posix_escalation_constant(self):
    import signal
    assert POSIX_FORCED_TERMINATION_ESCALATION == (int(signal.SIGTERM), int(signal.SIGKILL))


# ===========================================================================
# AC-13.17 — unexpected exit: restart, retry lost in-flight; streams per S16
# ===========================================================================

class TestUnexpectedExitRestart:
  def test_unexpected_exit_reports_lost_in_flight_ids(self):
    fake = _FakeProcess()
    ctrl = SubprocessController(fake.handle())
    ctrl.register_in_flight(1)
    ctrl.register_in_flight(2)
    lost = ctrl.detect_unexpected_exit()
    assert ctrl.state is LifecycleState.UNEXPECTED_EXIT
    assert lost == frozenset({1, 2})

  def test_restart_returns_retryable_ids_and_reconnects(self):
    fake = _FakeProcess()
    ctrl = SubprocessController(fake.handle())
    ctrl.register_in_flight(1)
    ctrl.register_in_flight(2)
    ctrl.detect_unexpected_exit()
    fresh = _FakeProcess()
    retryable = ctrl.restart(fresh.handle())
    assert retryable == frozenset({1, 2})
    assert ctrl.state is LifecycleState.CONNECTED

  def test_restart_clears_state_streams_do_not_survive(self):
    # Stateless: after restart, nothing carries over; server-to-client streams
    # must be re-established per S16 (not preserved by this controller).
    fake = _FakeProcess()
    ctrl = SubprocessController(fake.handle())
    ctrl.register_in_flight(1)
    ctrl.detect_unexpected_exit()
    ctrl.restart(_FakeProcess().handle())
    # A second unexpected exit now reports nothing in-flight (cleared on restart).
    assert ctrl.detect_unexpected_exit() == frozenset()


# ===========================================================================
# AC-13.18 — every request carries revision/identity/caps; protocolVersion string; -32004
# ===========================================================================

class TestRequestEnvelopeAndUnsupported:
  def test_envelope_carries_all_three_required_keys(self):
    meta = build_request_envelope(client_info=CLIENT_INFO, client_capabilities={})
    assert isinstance(meta[KEY_PROTOCOL_VERSION], str)
    assert meta[KEY_PROTOCOL_VERSION] == CURRENT_PROTOCOL_VERSION
    assert meta[KEY_CLIENT_INFO] == CLIENT_INFO
    assert meta[KEY_CLIENT_CAPABILITIES] == {}

  def test_protocol_version_is_a_revision_string(self):
    meta = build_request_envelope(client_info=CLIENT_INFO, protocol_version="2026-07-28")
    assert meta[KEY_PROTOCOL_VERSION] == "2026-07-28"

  def test_unsupported_revision_uses_code_minus_32004(self):
    err = build_unsupported_protocol_version_error(["2026-07-28"], requested="1999-01-01")
    assert err.code == UNSUPPORTED_PROTOCOL_VERSION_CODE == -32004

  def test_enveloped_request_round_trips_on_the_wire(self):
    req = build_enveloped_request(
      1, "tools/call", client_info=CLIENT_INFO,
      extra_params={"name": "get_weather", "arguments": {"city": "Paris"}},
    )
    wire = encode_line(req)
    decoded = json.loads(wire[:-1].decode("utf-8"))
    assert decoded["params"]["name"] == "get_weather"
    assert decoded["params"]["_meta"][KEY_PROTOCOL_VERSION] == CURRENT_PROTOCOL_VERSION


# ===========================================================================
# AC-13.19 — server/discover as first message permitted; probing RECOMMENDED
# ===========================================================================

class TestDiscoverProbeFirst:
  def test_discover_probe_is_a_valid_first_request(self):
    probe = build_discover_probe(0, client_info=CLIENT_INFO)
    assert probe.method == "server/discover"
    # carries the client's preferred revision in _meta
    assert probe.params["_meta"][KEY_PROTOCOL_VERSION] == CURRENT_PROTOCOL_VERSION
    assert_client_stdin_allowed(probe)

  def test_probe_can_be_sent_before_any_other_request(self):
    # No ordering constraint: a probe at id 0 then a request at id 1.
    probe = build_discover_probe(0, client_info=CLIENT_INFO)
    follow = build_enveloped_request(1, "tools/list", client_info=CLIENT_INFO)
    assert probe.id == 0 and follow.id == 1


# ===========================================================================
# AC-13.20 — probe outcomes: -32004 no-handshake select; other/timeout MAY handshake; not keyed
# ===========================================================================

class TestDiscoverProbeOutcomes:
  def test_discover_result_outcome_continue_with_discovered(self):
    response = {
      "jsonrpc": "2.0",
      "id": 0,
      "result": {
        "resultType": "complete",
        "supportedVersions": ["2026-07-28"],
        "capabilities": {},
        "serverInfo": {"name": "S", "version": "1.0"},
      },
    }
    result = react_to_discover_probe(response)
    assert result.reaction is DiscoverProbeReaction.CONTINUE_WITH_DISCOVERED
    assert result.supported_versions == ["2026-07-28"]
    assert result.handshake_allowed is False

  def test_minus_32004_outcome_selects_revision_no_handshake(self):
    err = build_unsupported_protocol_version_error(["2026-07-28"], requested="1999-01-01")
    response = {"jsonrpc": "2.0", "id": 0, "error": err.to_dict()}
    result = react_to_discover_probe(response)
    assert result.reaction is DiscoverProbeReaction.CONTINUE_FROM_UNSUPPORTED
    # MUST NOT fall back to a session-establishing handshake on this outcome.
    assert result.handshake_allowed is False
    # The client selects a revision from the advertised data and continues.
    chosen = select_revision_from_unsupported(err.to_dict(), ["2026-07-28"])
    assert chosen == "2026-07-28"

  def test_select_revision_from_unsupported_raises_when_no_overlap(self):
    err = build_unsupported_protocol_version_error(["2030-01-01"], requested="x")
    with pytest.raises(ValueError):
      select_revision_from_unsupported(err.to_dict(), ["2026-07-28"])

  def test_method_not_found_outcome_may_fall_back_not_keyed(self):
    response = {"jsonrpc": "2.0", "id": 0, "error": {"code": -32601, "message": "Method not found"}}
    result = react_to_discover_probe(response)
    assert result.reaction is DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE
    assert result.handshake_allowed is True
    assert result.keyed_to_error_code is False

  def test_invalid_params_outcome_also_may_fall_back(self):
    # A DIFFERENT error code lands in the SAME fallback bucket → not keyed to one code.
    response = {"jsonrpc": "2.0", "id": 0, "error": {"code": -32602, "message": "Invalid params"}}
    result = react_to_discover_probe(response)
    assert result.reaction is DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE

  def test_no_response_timeout_may_fall_back(self):
    result = react_to_discover_probe(None)
    assert result.reaction is DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE
    assert result.handshake_allowed is True

  def test_fallback_is_not_keyed_to_a_single_code(self):
    # Confirm two distinct non-32004 codes and a timeout all route identically.
    codes = [
      {"jsonrpc": "2.0", "id": 0, "error": {"code": -32601, "message": "x"}},
      {"jsonrpc": "2.0", "id": 0, "error": {"code": -32602, "message": "y"}},
      None,
    ]
    reactions = {react_to_discover_probe(c).reaction for c in codes}
    assert reactions == {DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE}


# ===========================================================================
# AC-13.21 — custom reliable byte-stream reuses framing/message rules
# ===========================================================================

class TestCustomByteStreamReuse:
  def test_reusable_rule_set_covers_framing_and_message_rules(self):
    # The framing (§8.2) and message (§8.3/§8.5/§8.7-envelope) rules are reusable.
    for rid in ("R-8.2-a", "R-8.2-d", "R-8.3-a", "R-8.5-e", "R-8.7-a"):
      assert rid in STDIO_REUSABLE_RULES

  def test_subprocess_specific_aspects_named(self):
    assert SUBPROCESS_SPECIFIC_ASPECTS == frozenset({"launch", "stderr", "shutdown", "restart"})

  def test_conformant_custom_transport_reuses_rules_and_supplies_aspects(self):
    reuse = CustomByteStreamReuse(transport_name="unix-domain-socket")
    assert reuse.is_conformant() is True

  def test_non_conformant_when_missing_a_subprocess_aspect(self):
    reuse = CustomByteStreamReuse(
      transport_name="incomplete",
      supplies_own=frozenset({"launch", "stderr"}),  # missing shutdown + restart
    )
    assert reuse.is_conformant() is False

  def test_non_conformant_when_framing_rules_not_reused(self):
    reuse = CustomByteStreamReuse(
      transport_name="no-framing",
      reuses_rules=frozenset({"R-8.2-a"}),  # does not reuse the full framing rule set
    )
    assert reuse.is_conformant() is False


# ===========================================================================
# Cross-cutting: MessageDirection enum
# ===========================================================================

class TestMessageDirection:
  def test_two_directions_only(self):
    assert {d.value for d in MessageDirection} == {"client_to_server", "server_to_client"}
