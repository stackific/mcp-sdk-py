"""The stdio Transport — S13.

Delivers the **stdio** transport binding (§8): a concrete realization of the
transport-agnostic contract (S12) that carries Model Context Protocol messages
over the standard input/output streams of a client-launched subprocess. The
protocol semantics are identical to every other transport; this binding supplies
only the *wire framing* (one newline-delimited JSON-RPC message per line over a
reliable bidirectional byte stream) and the *subprocess-lifecycle* rules.

This module deliberately reuses the framing/UTF-8 primitives from
``transport.py`` (``frame_message``/``split_frames``/``validate_utf8_json_unit``),
the message classification from ``jsonrpc.py`` (``classify_message``), the
per-request envelope keys from ``meta_object.py``, the discovery probe and the
``-32004`` machinery from ``negotiation.py``, and the cancellation method name
from ``progress.py`` — rather than re-implementing any of them.

Public surface:

Constants & stream roles (§8.1/§8.2/§8.4):
  - LINE_FEED / CARRIAGE_RETURN / STDIO_NEWLINE: the framing characters (R-8.2-d/e/f/g).
  - StreamRole: enum naming the three OS streams and what each carries (§6.2).
  - STDERR_IS_PROTOCOL: always False — stderr is never protocol (R-8.1-a/R-8.4-b).

Framing (§8.2):
  - serialize_message(): compact, newline-free, single-line UTF-8 JSON + terminator (R-8.2-a/b/c/d).
  - encode_line()/decode_line(): the wire codec; strips a tolerated leading \\r (R-8.2-e/f/g).
  - is_blank_line(): whitespace-only / empty line detection (R-8.2-h).

Direction of messages (§8.3):
  - MessageDirection: enum (CLIENT_TO_SERVER / SERVER_TO_CLIENT).
  - StdioDirectionError: a prohibited write was attempted on stdin/stdout.
  - assert_client_stdin_allowed()/assert_server_stdout_allowed(): direction guards
    (R-8.3-a/b/d, R-8.5-a/b/c).
  - build_cancellation()/correlates_to_cancelled(): cancellation + post-cancel silence
    (R-8.3-e/f/g).

Standard error (§8.4):
  - StderrSink: a client-side sink that may capture/forward/ignore stderr and
    never parses it as protocol; presence is not treated as an error (R-8.4-a–e).

Malformed lines (§8.5):
  - MalformedLineOutcome / handle_inbound_line(): non-fatal malformed-line handling,
    resynchronization at the next newline, optional -32700/-32600 by recoverable id
    (R-8.5-d/e/f/g/h).
  - StdioLineReader: a stateful, resynchronizing line reader over a byte stream.

Subprocess lifecycle (§8.6):
  - LifecycleState / SubprocessController: startup-without-handshake, graceful
    shutdown by closing stdin (EOF), prompt-exit wait, OS-appropriate forced
    termination, unexpected-exit detection and restart (R-8.6.1-a/b, R-8.6.2-a/b/c,
    R-8.6.3-a, R-8.6.4-a/b/c).

Protocol-revision selection & discovery (§8.7):
  - build_request_envelope(): the inline _meta carried by every request (R-8.7-a/b).
  - build_enveloped_request(): a JSONRPCRequest whose params carry that envelope.
  - select_revision_from_unsupported(): pick a revision from a -32004 outcome
    WITHOUT any handshake fallback (R-8.7-e).
  - DiscoverProbeReaction / react_to_discover_probe(): the three §8.7 probe
    outcomes, including the handshake fallback that is NOT keyed to one code
    (R-8.7-d/f/g/h).

Custom byte-stream reuse note (§8.1):
  - STDIO_REUSABLE_RULES: the rule-ids a non-subprocess reliable byte-stream
    transport SHOULD reuse, and SUBPROCESS_SPECIFIC_ASPECTS it must supply
    itself (R-8.1-b).

Spec: §8 (lines 1497–1641)
Depends on: S12 (transport model), S09 (negotiation), S08 (discovery),
  S05/S06/S07 (envelope), S03 (JSON-RPC base), S22 (cancellation method)
"""

from __future__ import annotations

import json
import signal
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_sdk_py.discovery import DISCOVER_METHOD_NAME, validate_discover_result
from mcp_sdk_py.jsonrpc import (
  FramingError,
  JSONRPCErrorResponse,
  JSONRPCMessage,
  JSONRPCNotification,
  JSONRPCRequest,
  RequestId,
  classify_message,
)
from mcp_sdk_py.meta_object import (
  CURRENT_PROTOCOL_VERSION,
  KEY_CLIENT_CAPABILITIES,
  KEY_CLIENT_INFO,
  KEY_PROTOCOL_VERSION,
)
from mcp_sdk_py.negotiation import (
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
  parse_unsupported_protocol_version_error,
  select_revision,
)
from mcp_sdk_py.progress import CANCELLED_NOTIFICATION_METHOD
from mcp_sdk_py.transport import (
  STDIO_FRAME_DELIMITER,
  MalformedMessageError,
  frame_message,
  validate_utf8_json_unit,
)


# ---------------------------------------------------------------------------
# §8.2  Framing characters  [R-8.2-d/e/f/g]
# ---------------------------------------------------------------------------

#: The line feed character (U+000A) — the message terminator on this transport (R-8.2-d/e).
LINE_FEED: str = "\n"

#: The carriage return character (U+000D) — tolerated before LF, stripped before parsing (R-8.2-f/g).
CARRIAGE_RETURN: str = "\r"

#: The single newline a sender MUST write to terminate each message (R-8.2-d).
STDIO_NEWLINE: bytes = STDIO_FRAME_DELIMITER  # b"\n" — reuse the S12 delimiter.

#: JSON-RPC parse-error code (§22; referenced here only as a wire code) (R-8.5-g).
CODE_PARSE_ERROR: int = -32700

#: JSON-RPC invalid-request code (§22; referenced here only as a wire code) (R-8.5-g).
CODE_INVALID_REQUEST: int = -32600


# ---------------------------------------------------------------------------
# §6.2 / §8.1 / §8.4  Stream roles  [R-8.1-a, R-8.4-b]
# ---------------------------------------------------------------------------

class StreamRole(Enum):
  """The three OS streams of the subprocess and what each carries (§6.2/§8.1).

  STDIN carries client-originated requests and notifications only (never
  responses, never non-MCP content); closing it is the graceful-shutdown
  signal (EOF).  STDOUT carries server-originated responses and notifications
  only (never requests, never non-MCP content).  STDERR is free-form UTF-8
  diagnostic text that is NOT part of the protocol and is never parsed as a
  protocol message (R-8.1-a, R-8.4-b).
  """

  STDIN = "stdin"
  STDOUT = "stdout"
  STDERR = "stderr"

  @property
  def carries_protocol(self) -> bool:
    """True for stdin/stdout, False for stderr (R-8.1-a, R-8.4-b)."""
    return self is not StreamRole.STDERR


#: stderr is never protocol; this constant exists so callers can assert the rule
#: explicitly (R-8.1-a, R-8.4-b).  A receiver MUST NOT treat stderr as protocol.
STDERR_IS_PROTOCOL: bool = False


# ---------------------------------------------------------------------------
# §8.3  Message direction
# ---------------------------------------------------------------------------

class MessageDirection(Enum):
  """The two message directions on this single shared channel (§8.3).

  CLIENT_TO_SERVER messages are written by the client to the server's stdin;
  SERVER_TO_CLIENT messages are written by the server to its stdout.  There are
  no per-request streams and no other channels (§8.1).
  """

  CLIENT_TO_SERVER = "client_to_server"
  SERVER_TO_CLIENT = "server_to_client"


# ---------------------------------------------------------------------------
# §8.2  Message framing  [R-8.2-a–h]
# ---------------------------------------------------------------------------

def serialize_message(message: JSONRPCMessage | dict[str, Any]) -> str:
  """Serialize one JSON-RPC message to a single-line, newline-free UTF-8 JSON string (R-8.2-a/b/c).

  Produces compact JSON (no spaces, ``ensure_ascii=False`` so genuine UTF-8 is
  emitted, R-8.2-a) with any in-string newline escaped as the two-character
  sequence ``\\n`` (R-8.2-b/c) so the serialized message contains no literal
  newline characters.  ``json.dumps`` already escapes control characters inside
  strings, so the result is guaranteed single-line; this function additionally
  asserts that invariant.

  Args:
    message: a typed JSON-RPC message (with ``to_dict``) or an already-built dict.

  Returns:
    The compact JSON text of the message — exactly one line, no terminator.
  """
  payload = message.to_dict() if hasattr(message, "to_dict") else message
  text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
  # R-8.2-b/c: a sender MUST NOT emit a message containing a literal newline.
  # json.dumps escapes in-string LF as "\\n", so this never fires in practice;
  # it guards against a hand-built dict slipping a raw newline through.
  if LINE_FEED in text or CARRIAGE_RETURN in text:
    raise ValueError(
      "Serialized JSON-RPC message MUST NOT contain a literal newline (R-8.2-b/c)"
    )
  return text


def encode_line(message: JSONRPCMessage | dict[str, Any]) -> bytes:
  """Encode one message as a framed wire line: UTF-8 JSON + single ``\\n`` (R-8.2-a/d).

  This is the sender-side codec.  It serializes the message to a single
  newline-free line (R-8.2-b/c), UTF-8 encodes it (R-8.2-a), and appends exactly
  one line feed terminator (R-8.2-d) via the shared S12 ``frame_message``
  primitive.

  Returns:
    The framed bytes ready to write to the channel.
  """
  text = serialize_message(message)
  return frame_message(text.encode("utf-8"), delimiter=STDIO_NEWLINE)


def is_blank_line(line: str | bytes) -> bool:
  """Return True if a line is empty or whitespace-only (R-8.2-h).

  Such a line is not a JSON-RPC message; a receiver SHOULD ignore it rather than
  treat it as malformed (R-8.2-h).
  """
  text = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line
  return text.strip() == ""


def decode_line(line: bytes) -> Any:
  """Decode one framed line into a JSON value, tolerating a trailing/leading ``\\r`` (R-8.2-e/f/g).

  The terminating newline has already been removed by the framing layer.  This
  function accepts the line feed as the terminator (R-8.2-e), tolerates an
  optional preceding carriage return so a ``\\r\\n`` sequence is also accepted
  (R-8.2-f), strips that carriage return before parsing (R-8.2-g), and validates
  the remaining bytes as a well-formed UTF-8 JSON value via the shared S12
  primitive (R-8.2-a).

  Args:
    line: the raw bytes of one line, newline already stripped by the framer.

  Returns:
    The JSON-decoded Python value.

  Raises:
    MalformedMessageError: the line is not well-formed UTF-8 or not valid JSON.
  """
  # R-8.2-g: strip a single tolerated trailing CR (the \r of a \r\n sequence).
  if line.endswith(CARRIAGE_RETURN.encode("ascii")):
    line = line[: -len(CARRIAGE_RETURN.encode("ascii"))]
  return validate_utf8_json_unit(line)


# ---------------------------------------------------------------------------
# §8.3  Direction guards  [R-8.3-a/b/d, R-8.5-a/b/c]
# ---------------------------------------------------------------------------

class StdioDirectionError(Exception):
  """A prohibited write was attempted on stdin or stdout (§8.3/§8.5).

  Raised when:
    - the client tries to write a response (or any non-MCP content) to stdin
      (R-8.3-a, R-8.5-c);
    - the server tries to write a request (or any non-MCP content) to stdout
      (R-8.3-b/d, R-8.5-a/b).

  Attributes:
    role: the StreamRole on which the prohibited write was attempted.
  """

  def __init__(self, detail: str, *, role: StreamRole) -> None:
    super().__init__(detail)
    self.role: StreamRole = role


def _is_response(message: JSONRPCMessage) -> bool:
  """True if message is a JSON-RPC response (success or error)."""
  return isinstance(message, (JSONRPCErrorResponse,)) or (
    hasattr(message, "result") and not hasattr(message, "method")
  )


def assert_client_stdin_allowed(message: JSONRPCMessage) -> None:
  """Guard the client's stdin writer: only requests/notifications are allowed (R-8.3-a, R-8.5-c).

  The client MUST NOT write JSON-RPC responses to the server's stdin (R-8.3-a),
  and MUST NOT write anything that is not a valid MCP message there (R-8.5-c).
  Only ``JSONRPCRequest`` and ``JSONRPCNotification`` are permitted.

  Raises:
    StdioDirectionError: message is a response, or not a valid MCP message.
  """
  if isinstance(message, (JSONRPCRequest, JSONRPCNotification)):
    return
  raise StdioDirectionError(
    "The client MUST NOT write a JSON-RPC response (or any non-request/"
    "non-notification) to the server's stdin (R-8.3-a, R-8.5-c)",
    role=StreamRole.STDIN,
  )


def assert_server_stdout_allowed(message: JSONRPCMessage) -> None:
  """Guard the server's stdout writer: only responses/notifications are allowed (R-8.3-b/d, R-8.5-a/b).

  The server MUST NOT write JSON-RPC requests to its stdout (R-8.3-b) and MUST
  NOT initiate a request at all (R-8.3-d); any reply-requiring interaction is
  carried inside the response to the client's request (see §11).  Non-message
  output (diagnostics, banners, prompts) MUST go to stderr or be suppressed,
  never to stdout (R-8.5-a/b).  Only ``JSONRPCResultResponse``,
  ``JSONRPCErrorResponse``, and ``JSONRPCNotification`` are permitted.

  Raises:
    StdioDirectionError: message is a request, or not a valid MCP message.
  """
  if isinstance(message, JSONRPCRequest):
    raise StdioDirectionError(
      "The server MUST NOT write a JSON-RPC request to its stdout; any "
      "reply-requiring interaction is carried inside the response, not as a "
      "separate stdout request (R-8.3-b/d)",
      role=StreamRole.STDOUT,
    )
  if isinstance(message, JSONRPCNotification) or _is_response(message):
    return
  raise StdioDirectionError(
    "The server MUST NOT write anything to stdout that is not a valid MCP "
    "response or notification (R-8.5-a/b)",
    role=StreamRole.STDOUT,
  )


# ---------------------------------------------------------------------------
# §8.3  Cancellation + post-cancellation silence  [R-8.3-e/f/g]
# ---------------------------------------------------------------------------

def build_cancellation(
  request_id: RequestId,
  *,
  reason: str | None = None,
) -> JSONRPCNotification:
  """Build the ``notifications/cancelled`` notification for an in-flight request (R-8.3-e).

  To cancel an in-flight request on this single shared channel, the client MUST
  send a ``notifications/cancelled`` notification referencing the target
  request's ``id`` (there is no per-request stream to close, R-8.3-e).

  Args:
    request_id: the ``id`` of the request being cancelled.
    reason: optional human-readable cancellation explanation.

  Returns:
    A ``JSONRPCNotification`` with method ``notifications/cancelled`` whose
    params carry ``requestId``.
  """
  params: dict[str, Any] = {"requestId": request_id}
  if reason is not None:
    params["reason"] = reason
  return JSONRPCNotification(method=CANCELLED_NOTIFICATION_METHOD, params=params)


def correlates_to_cancelled(
  message: JSONRPCMessage,
  cancelled_id: RequestId,
) -> bool:
  """Return True if ``message`` relates to ``cancelled_id`` and so MUST NOT be sent (R-8.3-g).

  After cancellation, the server MUST NOT send any further messages — neither
  the response correlated by ``id`` nor any related notification — for the
  cancelled request (R-8.3-g).  This predicate identifies such a message so a
  server can suppress it: a response whose ``id`` equals ``cancelled_id``, or a
  notification whose params reference that request (``requestId`` or
  ``progressToken`` equal to it).

  Args:
    message: a server-originated message about to be written to stdout.
    cancelled_id: the id of the request that was cancelled.

  Returns:
    True if the message belongs to the cancelled request and must be withheld.
  """
  rid = getattr(message, "id", None)
  if rid is not None and rid == cancelled_id and not isinstance(message, JSONRPCRequest):
    return True
  if isinstance(message, JSONRPCNotification) and isinstance(message.params, dict):
    for key in ("requestId", "progressToken"):
      if message.params.get(key) == cancelled_id:
        return True
  return False


# ---------------------------------------------------------------------------
# §8.4  Standard error sink  [R-8.4-a–e]
# ---------------------------------------------------------------------------

class StderrSink:
  """Client-side handler for the server's stderr stream (§8.4, R-8.4-a–e).

  The server MAY write UTF-8 text to stderr for any logging purpose (R-8.4-a);
  such text is not part of the protocol and MUST NOT be parsed as a protocol
  message (R-8.4-b).  This sink lets the client capture, forward, or ignore that
  output (R-8.4-c); it NEVER interprets the content as JSON-RPC (R-8.4-d); and
  it does not treat the presence of stderr output as an error condition
  (R-8.4-e — ``saw_error`` stays False no matter what arrives).

  Args:
    capture: when True, retains received lines in ``captured`` (R-8.4-c).
    forward: optional callback invoked with each decoded line for forwarding
      (e.g. to the client's own logger) (R-8.4-c).
  """

  def __init__(
    self,
    *,
    capture: bool = False,
    forward: Callable[[str], None] | None = None,
  ) -> None:
    self._capture: bool = capture
    self._forward: Callable[[str], None] | None = forward
    self.captured: list[str] = []

  def feed(self, data: bytes) -> None:
    """Consume a chunk of stderr bytes; never parse it as protocol (R-8.4-b/c/d).

    Decodes the bytes as UTF-8 free-form text (replacement on bad bytes, since
    stderr need not be valid JSON) and routes it to the configured destinations.
    It does NOT attempt JSON-RPC classification of any kind (R-8.4-d).
    """
    text = data.decode("utf-8", errors="replace")
    if self._capture:
      self.captured.append(text)
    if self._forward is not None:
      self._forward(text)

  @property
  def saw_error(self) -> bool:
    """Always False — stderr presence is not assumed to indicate an error (R-8.4-e)."""
    return False

  @staticmethod
  def is_protocol() -> bool:
    """Return False — stderr is never interpreted as JSON-RPC (R-8.4-b/d)."""
    return STDERR_IS_PROTOCOL


# ---------------------------------------------------------------------------
# §8.5  Malformed-line handling  [R-8.5-d/e/f/g/h]
# ---------------------------------------------------------------------------

@dataclass
class MalformedLineOutcome:
  """Result of handling one inbound line (§8.5).

  Fields:
    message: the classified JSON-RPC message when the line was a valid MCP
      message; None for blank or malformed lines.
    ignored_blank: True when the line was empty/whitespace-only and ignored
      (R-8.2-h) — not malformed.
    malformed: True when the line was non-blank but not a valid MCP message
      (R-8.5-e) — discarded, connection continues.
    error_response: an optional JSON-RPC error response (-32700 or -32600) the
      receiver MAY return when an ``id`` was recoverable from a malformed
      request line (R-8.5-g); None otherwise.
    diagnostic: an optional human-readable diagnostic the receiver MAY record
      (server via stderr; client via its own logging) (R-8.5-f).
  """

  message: JSONRPCMessage | None = None
  ignored_blank: bool = False
  malformed: bool = False
  error_response: JSONRPCErrorResponse | None = None
  diagnostic: str | None = None

  @property
  def resynchronize(self) -> bool:
    """Always True — after any line the receiver continues at the next newline (R-8.5-h)."""
    return True


def _recover_request_id(raw: Any) -> RequestId | None:
  """Try to recover a JSON-RPC request id from a partially-valid object (R-8.5-g).

  Returns the id only when it is present, is a non-bool string/number, and the
  object is recognizable as a request (has a ``method``).  Otherwise None.
  """
  if not isinstance(raw, dict):
    return None
  if "method" not in raw:
    return None
  rid = raw.get("id")
  if rid is None or isinstance(rid, bool):
    return None
  if isinstance(rid, (str, int, float)):
    return rid
  return None


def handle_inbound_line(
  line: bytes,
  *,
  respond_to_malformed: bool = False,
) -> MalformedLineOutcome:
  """Handle one inbound line without ever crashing the connection (§8.5, R-8.5-d–h).

  Implements the §8.5 receiver algorithm for a single line whose terminating
  newline has already been removed by the framer:

  - A blank/whitespace-only line is ignored (R-8.2-h) — ``ignored_blank``.
  - A non-blank line that is not well-formed JSON, or is JSON but not a valid
    JSON-RPC message object, is **malformed**: it is discarded, the connection
    is NOT torn down (R-8.5-d/e), an optional diagnostic is recorded (R-8.5-f),
    and the receiver resynchronizes at the next newline (R-8.5-h, always True
    via ``MalformedLineOutcome.resynchronize``).
  - If ``respond_to_malformed`` is True and a request ``id`` can be recovered
    from a malformed request line, an error response with code -32700 (parse
    error) or -32600 (invalid request) is produced; with no recoverable id, no
    response is produced and the line is silently discarded (R-8.5-g).

  This function NEVER raises for a malformed line — that is the whole point of
  R-8.5-d (do not crash or terminate the connection).

  Args:
    line: the raw bytes of one inbound line (newline already stripped).
    respond_to_malformed: when True, MAY return a -32700/-32600 error response
      for a malformed *request* line with a recoverable id (R-8.5-g).

  Returns:
    A MalformedLineOutcome describing what happened.
  """
  if is_blank_line(line):
    return MalformedLineOutcome(ignored_blank=True)

  # First: is it even well-formed UTF-8 JSON?  (R-8.5-e first clause)
  try:
    raw = decode_line(line)
  except MalformedMessageError as exc:
    # Not well-formed JSON → malformed; no id is recoverable from unparseable
    # bytes, so per R-8.5-g no response is sent (unless caller opted in AND a
    # request id were recoverable, which it is not here).
    return MalformedLineOutcome(
      malformed=True,
      diagnostic=f"Discarded malformed line (not valid JSON): {exc}",
    )

  # Second: well-formed JSON but a valid JSON-RPC message object? (R-8.5-e second clause)
  try:
    message = classify_message(raw)
  except FramingError as exc:
    diagnostic = f"Discarded malformed line (not a valid JSON-RPC message): {exc}"
    error_response: JSONRPCErrorResponse | None = None
    if respond_to_malformed:
      rid = _recover_request_id(raw)
      if rid is not None:
        # R-8.5-g: recoverable request id → MAY return -32600 (the JSON parsed,
        # so it is an Invalid Request rather than a Parse error).
        error_response = JSONRPCErrorResponse(
          id=rid,
          error={"code": CODE_INVALID_REQUEST, "message": "Invalid Request"},
        )
      # else: no recoverable id → no response; silently discarded (R-8.5-g).
    return MalformedLineOutcome(
      malformed=True,
      error_response=error_response,
      diagnostic=diagnostic,
    )

  return MalformedLineOutcome(message=message)


class StdioLineReader:
  """Stateful, resynchronizing line reader over a byte stream (§8.2/§8.5).

  Feed it arbitrary byte chunks via ``feed``; it accumulates them, splits on the
  line feed terminator (R-8.2-d/e), and yields one ``MalformedLineOutcome`` per
  completed line.  Because framing is line-based, a single malformed line never
  desynchronizes the stream — the next newline still begins the next message —
  so the reader resynchronizes automatically rather than abandoning the
  connection (R-8.5-h).  Blank lines are ignored (R-8.2-h); malformed lines are
  discarded without raising (R-8.5-d/e).

  Args:
    respond_to_malformed: forwarded to ``handle_inbound_line`` so a receiver MAY
      emit a -32700/-32600 error for a malformed request with a recoverable id
      (R-8.5-g).
  """

  def __init__(self, *, respond_to_malformed: bool = False) -> None:
    self._buffer: bytearray = bytearray()
    self._respond_to_malformed: bool = respond_to_malformed

  def feed(self, data: bytes) -> list[MalformedLineOutcome]:
    """Append ``data`` and return outcomes for every newly completed line.

    Only complete lines (terminated by a line feed) are processed; a trailing
    partial line is retained in the buffer until its terminator arrives.
    """
    self._buffer.extend(data)
    outcomes: list[MalformedLineOutcome] = []
    while True:
      idx = self._buffer.find(STDIO_NEWLINE)
      if idx == -1:
        break
      raw_line = bytes(self._buffer[:idx])
      del self._buffer[: idx + len(STDIO_NEWLINE)]
      outcomes.append(
        handle_inbound_line(
          raw_line,
          respond_to_malformed=self._respond_to_malformed,
        )
      )
    return outcomes

  def pending_bytes(self) -> bytes:
    """Return the buffered, not-yet-terminated trailing bytes (for diagnostics)."""
    return bytes(self._buffer)


# ---------------------------------------------------------------------------
# §8.6  Subprocess lifecycle  [R-8.6.1 – R-8.6.4]
# ---------------------------------------------------------------------------

class LifecycleState(Enum):
  """States of the subprocess-lifecycle state machine (§8.6).

  CONNECTED: streams are wired up; no handshake occurred; each request carries
    full _meta (R-8.6.1-a).
  DRAINING: stdin has been closed (EOF) and the client is waiting for the
    server to exit promptly (R-8.6.2-a/b).
  FORCED_TERMINATING: the server did not exit in time; the client is forcibly
    terminating it (R-8.6.3-a).
  UNEXPECTED_EXIT: the server exited unexpectedly; in-flight requests are lost
    (R-8.6.4-a/b).
  EXITED: the process has fully exited.
  """

  CONNECTED = "connected"
  DRAINING = "draining"
  FORCED_TERMINATING = "forced_terminating"
  UNEXPECTED_EXIT = "unexpected_exit"
  EXITED = "exited"


@dataclass
class ProcessHandle:
  """Minimal abstraction of a launched subprocess for lifecycle control (§8.6).

  This is a thin protocol the controller drives; in production it wraps a real
  ``subprocess.Popen`` (or platform equivalent), but it is defined structurally
  so the lifecycle logic is testable without launching a process.  Callbacks may
  be supplied to observe each lifecycle action.

  Fields:
    close_stdin: closes the server's stdin (sends EOF) — the primary, only
      portable graceful-shutdown signal (R-8.6.2-a step 1).
    poll: returns the process exit code, or None if still running.
    terminate: sends the OS-appropriate "polite" termination (SIGTERM on POSIX).
    kill: sends the OS-appropriate forceful termination (SIGKILL on POSIX).
    stdin_closed: tracks whether close_stdin has been called.
  """

  close_stdin: Callable[[], None]
  poll: Callable[[], int | None]
  terminate: Callable[[], None]
  kill: Callable[[], None]
  stdin_closed: bool = False


#: The OS-appropriate forced-termination escalation on POSIX systems: SIGTERM
#: then SIGKILL (R-8.6.3-a).  On non-POSIX systems clients use the
#: platform-appropriate equivalent (a terminate-process call or job-object kill).
POSIX_FORCED_TERMINATION_ESCALATION: tuple[int, int] = (
  int(signal.SIGTERM),
  int(signal.SIGKILL),
)


class SubprocessController:
  """Drives the stdio subprocess lifecycle (§8.6).

  Encapsulates the §8.6 state machine over a ``ProcessHandle``:

  - **Startup** (§8.6.1): construction places the controller in CONNECTED with
    no handshake; the connection exists as soon as streams are wired up
    (R-8.6.1-a).  ``requires_handshake`` is always False (R-8.6.1-a).
  - **Graceful shutdown** (§8.6.2): ``shutdown`` closes stdin first (EOF),
    waits for prompt exit, and only forcibly terminates if the server does not
    exit within ``grace_period`` (R-8.6.2-a, R-8.6.3-a).
  - **Server-initiated shutdown** (§8.6.2): ``note_server_initiated_exit``
    records that the server closed stdout and exited on its own (R-8.6.2-c).
  - **Unexpected termination & restart** (§8.6.4): ``detect_unexpected_exit``
    transitions to UNEXPECTED_EXIT and reports lost in-flight ids; ``restart``
    re-establishes a fresh process and returns the ids the client MAY retry
    (R-8.6.4-a/b).  Active server-to-client streams do NOT survive and MUST be
    re-established by their owning feature, S16/§10 (R-8.6.4-c).

  Args:
    handle: the ProcessHandle to drive.
    grace_period: seconds to wait for prompt exit before forcing (R-8.6.2-a/3).
    poll_interval: how often to poll ``handle.poll`` while waiting.
    clock: monotonic clock function (injectable for deterministic tests).
    sleep: sleep function (injectable for deterministic tests).
  """

  def __init__(
    self,
    handle: ProcessHandle,
    *,
    grace_period: float = 5.0,
    poll_interval: float = 0.05,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
  ) -> None:
    self._handle: ProcessHandle = handle
    self._grace_period: float = grace_period
    self._poll_interval: float = poll_interval
    self._clock: Callable[[], float] = clock
    self._sleep: Callable[[float], None] = sleep
    # R-8.6.1-a: the connection exists as soon as streams are wired up — no
    # handshake, registration, or session id.
    self._state: LifecycleState = LifecycleState.CONNECTED
    self._in_flight: set[RequestId] = set()
    self._forced: bool = False

  @property
  def state(self) -> LifecycleState:
    """The current lifecycle state."""
    return self._state

  @property
  def requires_handshake(self) -> bool:
    """Always False — there is no connection handshake on stdio (R-8.6.1-a)."""
    return False

  @property
  def was_forced(self) -> bool:
    """True if the last shutdown escalated to forced termination (R-8.6.3-a)."""
    return self._forced

  def register_in_flight(self, request_id: RequestId) -> None:
    """Record an outstanding request id (so it can be reported lost on exit)."""
    self._in_flight.add(request_id)

  def complete_in_flight(self, request_id: RequestId) -> None:
    """Mark an outstanding request id as completed (response received)."""
    self._in_flight.discard(request_id)

  def shutdown(self) -> bool:
    """Gracefully shut down, escalating to forced termination if needed (R-8.6.2-a, R-8.6.3-a).

    Performs the §8.6.2 steps in order:
      1. Close the server's stdin (EOF — the primary, only portable graceful
         signal) (R-8.6.2-a step 1).
      2. Wait up to ``grace_period`` for the process to exit (R-8.6.2-a step 2),
         relying on the server's obligation to exit promptly on EOF (R-8.6.2-b).
      3. If it has not exited, forcibly terminate it with the OS-appropriate
         mechanism — SIGTERM escalating to SIGKILL on POSIX (R-8.6.2-a step 3,
         R-8.6.3-a).

    Returns:
      True if the process exited gracefully within the grace period; False if
      forced termination was required.
    """
    self._state = LifecycleState.DRAINING
    self._handle.close_stdin()
    self._handle.stdin_closed = True

    if self._wait_for_exit(self._grace_period):
      self._state = LifecycleState.EXITED
      self._forced = False
      return True

    # Step 3 / §8.6.3: forced termination, OS-appropriate escalation.
    self._force_terminate()
    self._state = LifecycleState.EXITED
    self._forced = True
    return False

  def _wait_for_exit(self, timeout: float) -> bool:
    """Poll ``handle.poll`` until it reports an exit or ``timeout`` elapses."""
    deadline = self._clock() + timeout
    while True:
      if self._handle.poll() is not None:
        return True
      if self._clock() >= deadline:
        return False
      self._sleep(self._poll_interval)

  def _force_terminate(self) -> None:
    """Escalate SIGTERM → SIGKILL (POSIX) / platform equivalent (R-8.6.3-a)."""
    self._state = LifecycleState.FORCED_TERMINATING
    # Polite first (SIGTERM on POSIX), then forceful (SIGKILL) if still alive.
    self._handle.terminate()
    if self._wait_for_exit(self._grace_period):
      return
    self._handle.kill()
    self._wait_for_exit(self._grace_period)

  def note_server_initiated_exit(self) -> None:
    """Record a server-initiated shutdown: it closed stdout and exited (R-8.6.2-c).

    The server MAY initiate shutdown on its own by closing its stdout and
    exiting; this is a permitted, non-error transition to EXITED.
    """
    self._state = LifecycleState.EXITED

  def detect_unexpected_exit(self) -> frozenset[RequestId]:
    """Transition to UNEXPECTED_EXIT and report the lost in-flight ids (R-8.6.4-a/b).

    When the server process exits unexpectedly, any in-flight requests are
    simply lost because the protocol is stateless (R-8.6.4-b).  This records the
    transition and returns the ids that were outstanding, so the caller can
    surface their loss; the client SHOULD restart the process (R-8.6.4-a) via
    ``restart``.

    Returns:
      The set of request ids that were in-flight and are now lost.
    """
    self._state = LifecycleState.UNEXPECTED_EXIT
    lost = frozenset(self._in_flight)
    return lost

  def restart(self, new_handle: ProcessHandle) -> frozenset[RequestId]:
    """Restart the server against a fresh process and return retryable ids (R-8.6.4-a/b/c).

    Because the protocol is stateless, the client SHOULD restart on unexpected
    exit (R-8.6.4-a) and MAY retry the lost in-flight requests against the fresh
    process (R-8.6.4-b).  Any active server-to-client streams do NOT survive the
    exit and MUST be re-established by their owning feature — S16/§10 — which is
    out of scope here (R-8.6.4-c); this controller therefore drops them and only
    returns the request ids the client may retry.

    Args:
      new_handle: a freshly launched ProcessHandle.

    Returns:
      The set of request ids the client MAY retry against the new process.
    """
    retryable = frozenset(self._in_flight)
    self._handle = new_handle
    self._in_flight = set()  # stateless: nothing carries over (R-8.6.4-b/c).
    self._state = LifecycleState.CONNECTED
    self._forced = False
    return retryable


# ---------------------------------------------------------------------------
# §8.7  Protocol-revision selection and discovery  [R-8.7-a – R-8.7-h]
# ---------------------------------------------------------------------------

def build_request_envelope(
  *,
  client_info: dict[str, Any],
  client_capabilities: dict[str, Any] | None = None,
  protocol_version: str = CURRENT_PROTOCOL_VERSION,
) -> dict[str, Any]:
  """Build the inline per-request ``_meta`` envelope every request MUST carry (R-8.7-a/b).

  This transport has no header layer, so every request MUST carry, in its
  ``_meta`` object, the protocol revision, the client identity, and the client's
  per-request capabilities (R-8.7-a).  The revision is declared in the required
  ``io.modelcontextprotocol/protocolVersion`` string (R-8.7-b); the body is the
  sole source of truth.  The key names are reused verbatim from S05.

  Args:
    client_info: the client identity object (``io.modelcontextprotocol/clientInfo``).
    client_capabilities: the client's per-request capabilities; ``{}`` is valid.
    protocol_version: the revision identifier (e.g. ``"2026-07-28"``).

  Returns:
    A ``_meta`` dict carrying the three required keys.
  """
  return {
    KEY_PROTOCOL_VERSION: protocol_version,
    KEY_CLIENT_INFO: dict(client_info),
    KEY_CLIENT_CAPABILITIES: dict(client_capabilities or {}),
  }


def build_enveloped_request(
  request_id: RequestId,
  method: str,
  *,
  client_info: dict[str, Any],
  client_capabilities: dict[str, Any] | None = None,
  protocol_version: str = CURRENT_PROTOCOL_VERSION,
  extra_params: dict[str, Any] | None = None,
) -> JSONRPCRequest:
  """Build a request whose ``params._meta`` carries the full §8.7 envelope (R-8.7-a/b).

  The first message the client sends — and every subsequent request — stands
  alone and carries its full envelope (R-8.6.1-a/R-8.7-a).  The first message
  MAY be any enveloped request (e.g. ``tools/call``) or a ``server/discover``
  probe; there is no required first message or ordering (R-8.6.1-b).

  Args:
    request_id: the JSON-RPC ``id``.
    method: the request method (e.g. ``tools/call`` or ``server/discover``).
    client_info / client_capabilities / protocol_version: forwarded to
      ``build_request_envelope``.
    extra_params: any additional params (e.g. ``name``/``arguments``) merged
      alongside ``_meta``.

  Returns:
    A ``JSONRPCRequest`` ready to serialize and write to stdin.
  """
  params: dict[str, Any] = dict(extra_params or {})
  params["_meta"] = build_request_envelope(
    client_info=client_info,
    client_capabilities=client_capabilities,
    protocol_version=protocol_version,
  )
  return JSONRPCRequest(id=request_id, method=method, params=params)


def build_discover_probe(
  request_id: RequestId,
  *,
  client_info: dict[str, Any],
  client_capabilities: dict[str, Any] | None = None,
  protocol_version: str = CURRENT_PROTOCOL_VERSION,
) -> JSONRPCRequest:
  """Build a ``server/discover`` probe carrying the client's preferred revision (R-8.7-d/h).

  A client MAY probe the server's supported revisions by sending
  ``server/discover`` before sending any other request; the probe carries the
  client's preferred revision in ``_meta`` (R-8.7-d).  Probing before any other
  request is RECOMMENDED even for a client that supports only the current
  revision (R-8.7-h).

  Returns:
    A ``server/discover`` ``JSONRPCRequest`` with the full §8.7 envelope.
  """
  return build_enveloped_request(
    request_id,
    DISCOVER_METHOD_NAME,
    client_info=client_info,
    client_capabilities=client_capabilities,
    protocol_version=protocol_version,
  )


def select_revision_from_unsupported(
  error: dict[str, Any],
  client_preferences: Sequence[str],
) -> str:
  """Select a revision from a ``-32004`` outcome WITHOUT any handshake fallback (R-8.7-e).

  On the Unsupported-Protocol-Version outcome of a discover probe, the client
  selects one of the revisions advertised in that error's ``data.supported`` and
  continues; it MUST NOT, on this outcome, fall back to any session-establishing
  handshake (R-8.7-e).  Selection reuses the S09 rule (client preference order
  over the server's advertised set).

  Args:
    error: the ``error`` member of the -32004 response.
    client_preferences: the client's revisions, most-preferred first.

  Returns:
    The selected revision string.

  Raises:
    ValueError: the error is not a valid -32004 error, or no advertised revision
      is mutually supported.
  """
  supported, _requested = parse_unsupported_protocol_version_error(error)
  chosen = select_revision(client_preferences, supported)
  if chosen is None:
    raise ValueError(
      "No mutually supported revision among the server's advertised set "
      f"{supported!r}; the client MUST NOT fall back to a handshake here (R-8.7-e)"
    )
  return chosen


class DiscoverProbeReaction(Enum):
  """The three §8.7 outcomes of a ``server/discover`` probe.

  CONTINUE_WITH_DISCOVERED: the server returned a ``DiscoverResult``; select a
    mutually supported revision from ``supportedVersions`` and continue
    (R-8.7-d, first bullet).
  CONTINUE_FROM_UNSUPPORTED: the server returned ``-32004``; select a revision
    from the error's advertised data and continue.  The client MUST NOT fall
    back to a session-establishing handshake on this outcome (R-8.7-e).
  MAY_FALL_BACK_TO_HANDSHAKE: the server returned any *other* JSON-RPC error or
    did not respond within the timeout; a client with a handshake-based
    counterpart MAY fall back to its handshake.  That fallback MUST NOT be keyed
    to one specific error code (R-8.7-f/g).
  """

  CONTINUE_WITH_DISCOVERED = "continue_with_discovered"
  CONTINUE_FROM_UNSUPPORTED = "continue_from_unsupported"
  MAY_FALL_BACK_TO_HANDSHAKE = "may_fall_back_to_handshake"


@dataclass
class DiscoverProbeResult:
  """The interpreted outcome of a discover probe (§8.7).

  Fields:
    reaction: which of the three §8.7 outcomes occurred.
    supported_versions: the revisions the server advertised — populated for the
      first two outcomes (from ``DiscoverResult.supportedVersions`` or from the
      -32004 error's ``data.supported``); empty for the fallback outcome.
    handshake_allowed: True ONLY for MAY_FALL_BACK_TO_HANDSHAKE; a guard so a
      caller cannot mistakenly invoke a handshake on the -32004 outcome
      (R-8.7-e/f).
    keyed_to_error_code: always False — the fallback decision is NOT keyed to any
      one specific error code (R-8.7-g).
  """

  reaction: DiscoverProbeReaction
  supported_versions: list[str] = field(default_factory=list)

  @property
  def handshake_allowed(self) -> bool:
    """True only for the catch-all fallback outcome (R-8.7-e/f)."""
    return self.reaction is DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE

  @property
  def keyed_to_error_code(self) -> bool:
    """Always False — the fallback is not keyed to one specific code (R-8.7-g)."""
    return False


def react_to_discover_probe(response: dict[str, Any] | None) -> DiscoverProbeResult:
  """Interpret a discover-probe response into one of the three §8.7 reactions (R-8.7-d/e/f/g).

  Outcomes:
    - A valid ``DiscoverResult`` → CONTINUE_WITH_DISCOVERED with its
      ``supportedVersions`` (R-8.7-d, first bullet).
    - A recognized ``-32004`` error → CONTINUE_FROM_UNSUPPORTED with the error's
      advertised ``data.supported``; the client MUST NOT fall back to a
      handshake here (R-8.7-e).
    - Any other JSON-RPC error, an unclassifiable result, or ``None`` (no
      response within the timeout) → MAY_FALL_BACK_TO_HANDSHAKE.  A client with a
      handshake-based counterpart MAY fall back; the decision is NOT keyed to any
      one error code (R-8.7-f/g) — note that a ``-32601``/`-32602`` lands here,
      exactly like a timeout.

  Args:
    response: the decoded JSON response, or ``None`` to signal no response
      within a reasonable timeout (R-8.7-f).

  Returns:
    A DiscoverProbeResult describing the reaction.
  """
  # No response within the timeout → the catch-all fallback bucket (R-8.7-f).
  if response is None or not isinstance(response, dict):
    return DiscoverProbeResult(DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE)

  # A successful DiscoverResult → first outcome (R-8.7-d, first bullet).
  if "result" in response and "error" not in response:
    try:
      discover = validate_discover_result(response["result"])
    except (TypeError, ValueError):
      # A result that does not validate as a DiscoverResult is not a recognized
      # success of this revision → catch-all fallback (R-8.7-f).
      return DiscoverProbeResult(DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE)
    return DiscoverProbeResult(
      DiscoverProbeReaction.CONTINUE_WITH_DISCOVERED,
      supported_versions=list(discover.supported_versions),
    )

  error = response.get("error")
  if isinstance(error, dict):
    # A recognized -32004 → second outcome; NO handshake fallback (R-8.7-e).
    if error.get("code") == UNSUPPORTED_PROTOCOL_VERSION_CODE:
      try:
        supported, _requested = parse_unsupported_protocol_version_error(error)
      except ValueError:
        return DiscoverProbeResult(DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE)
      return DiscoverProbeResult(
        DiscoverProbeReaction.CONTINUE_FROM_UNSUPPORTED,
        supported_versions=supported,
      )
    # Any OTHER error code (e.g. -32601 / -32602) → catch-all fallback, NOT keyed
    # to one specific code (R-8.7-f/g).
    return DiscoverProbeResult(DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE)

  return DiscoverProbeResult(DiscoverProbeReaction.MAY_FALL_BACK_TO_HANDSHAKE)


# ---------------------------------------------------------------------------
# §8.1  Custom reliable-byte-stream reuse note  [R-8.1-b]
# ---------------------------------------------------------------------------

#: The rule-ids a custom transport over a reliable bidirectional byte stream
#: (e.g. a Unix domain socket or TCP connection) SHOULD reuse from this story —
#: the framing and message rules are self-contained (R-8.1-b).
STDIO_REUSABLE_RULES: frozenset[str] = frozenset({
  # §8.2 message framing
  "R-8.2-a", "R-8.2-b", "R-8.2-c", "R-8.2-d", "R-8.2-e", "R-8.2-f", "R-8.2-g", "R-8.2-h",
  # §8.3 direction of messages
  "R-8.3-a", "R-8.3-b", "R-8.3-d", "R-8.3-e", "R-8.3-f", "R-8.3-g",
  # §8.5 prohibited content & malformed lines
  "R-8.5-a", "R-8.5-c", "R-8.5-d", "R-8.5-e", "R-8.5-g", "R-8.5-h",
  # §8.7 inline-envelope revision selection
  "R-8.7-a", "R-8.7-b", "R-8.7-c",
})

#: The subprocess-specific aspects a custom byte-stream transport must supply its
#: OWN equivalents for, rather than reusing the stdio mechanics (R-8.1-b).
SUBPROCESS_SPECIFIC_ASPECTS: frozenset[str] = frozenset({
  "launch",            # how the peer is started (a subprocess vs. a socket connect)
  "stderr",            # the free-form diagnostic side channel
  "shutdown",          # closing the stream vs. closing the subprocess's stdin
  "restart",           # re-establishing the connection after loss
})


@dataclass(frozen=True)
class CustomByteStreamReuse:
  """Record asserting a custom byte-stream transport reuses the stdio rules (R-8.1-b).

  A custom transport that runs over a reliable bidirectional byte stream (Unix
  domain socket, TCP, …) SHOULD reuse this story's framing and message rules and
  supply channel-specific equivalents only for the subprocess-specific aspects:
  launch, stderr, shutdown-by-closing-the-stream, and restart (R-8.1-b).

  Fields:
    transport_name: a human-readable name for the custom transport.
    reuses_rules: the rule-ids it reuses (SHOULD equal ``STDIO_REUSABLE_RULES``).
    supplies_own: the subprocess-specific aspects it implements itself (SHOULD
      cover ``SUBPROCESS_SPECIFIC_ASPECTS``).
  """

  transport_name: str
  reuses_rules: frozenset[str] = STDIO_REUSABLE_RULES
  supplies_own: frozenset[str] = SUBPROCESS_SPECIFIC_ASPECTS

  def is_conformant(self) -> bool:
    """True when the framing rules are reused and every subprocess aspect is supplied (R-8.1-b)."""
    return STDIO_REUSABLE_RULES <= self.reuses_rules and (
      SUBPROCESS_SPECIFIC_ASPECTS <= self.supplies_own
    )
