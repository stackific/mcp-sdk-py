"""Transport Model & Transport-Agnostic Guarantees — S12.

Delivers the abstract transport contract (§7.1–§7.2) and a working reference
implementation so the protocol can be exercised bidirectionally before any
concrete wire (stdio / HTTP) is added.

Public surface:

Transport contract (abstract interface — §7.1/§7.2):
  - Transport: Protocol/structural interface; every conforming transport implements
    send(JSONRPCMessage), receive() -> JSONRPCMessage, close(), is_closed.

Reference implementation (§7.2 guarantees exercised in-memory):
  - InMemoryTransport: paired-queue transport used for testing and integration;
    raises MessageDeliveryError on closed peer (R-7.2-r) and
    DisconnectionError on peer close (R-7.5-a/b).
  - InMemoryTransport.create_pair(): factory for a connected client+server pair.

Framing (§7.2-b/c/d — body-independent boundary finding):
  - split_frames(data, delimiter): split a byte stream into messages without
    parsing JSON; production code, usable by any newline-framed transport.
  - frame_message(data, delimiter): append the delimiter to a message bytes object.

Transport-level errors:
  - TransportError: base class for all channel-layer failures.
  - DisconnectionError: abrupt channel loss; MUST be observable (R-7.5-a/b).
  - MessageDeliveryError: message accepted but cannot be delivered (R-7.2-r/s).
  - MalformedMessageError: unit is not well-formed UTF-8 or not a JSON value (R-7.6-b/c).
  - ConnectionScopedStateError: connection identity used as a session key (R-7.6-d–j).

Encoding validation:
  - validate_utf8_json_unit(bytes): parse-level UTF-8 + JSON check; rejects and
    raises rather than silently dropping (R-7.6-a/b/c).

Statelessness enforcement:
  - is_connection_scoped(state_key, connection_id): predicate — True when the
    caller is using a connection object as a state key (R-7.6-i/j).
  - assert_no_connection_scoped_state(state_key, connection_id): guard; raises
    ConnectionScopedStateError only when state_key IS the connection_id.

Disconnection handling:
  - fail_in_flight_on_disconnect(tracker): snapshots all in-flight ids, clears
    the tracker, returns the failed set so callers can surface errors (R-7.5-c/d/e).

Defined transports & compliance checklist:
  - TRANSPORT_STDIO / TRANSPORT_STREAMABLE_HTTP / DEFINED_TRANSPORTS.
  - CustomTransportChecklist: typed §7.2 obligation record for implementers (R-7.3-b/c/d).

Spec: §7
Depends on: S03, S06
"""

from __future__ import annotations

import json
import queue
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from mcp_sdk_py.jsonrpc import (
  InFlightTracker,
  JSONRPCMessage,
  RequestId,
)


# ---------------------------------------------------------------------------
# §7.3  Defined transport identifiers
# ---------------------------------------------------------------------------

#: The stdio transport defined by this document (§7 / S13).
TRANSPORT_STDIO: str = "stdio"

#: The Streamable HTTP transport defined by this document (§7 / S14/S15).
TRANSPORT_STREAMABLE_HTTP: str = "streamable-http"

#: The set of transports formally defined by this specification.
DEFINED_TRANSPORTS: frozenset[str] = frozenset({TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP})


# ---------------------------------------------------------------------------
# Transport-layer exception hierarchy
# ---------------------------------------------------------------------------

class TransportError(Exception):
  """Base class for all transport-layer failures (§7 — channel failure, not JSON-RPC error).

  A transport error signals that the channel itself failed, as opposed to a
  JSON-RPC error response (which is a normal, fully delivered protocol message).
  Callers MUST surface this error rather than swallowing it (R-7.2-r, R-7.5-i).
  """


class DisconnectionError(TransportError):
  """The transport channel was lost or closed; each side MUST observe this (R-7.5-a/b).

  When raised by receive(), callers MUST NOT retry on the same connection.  Use
  fail_in_flight_on_disconnect() to resolve all outstanding requests as failures
  before retrying on a fresh connection (R-7.5-c/d/e).

  Attributes:
    connection_id: optional opaque identifier for diagnostics.  MUST NOT be
      used as a session key (R-7.6-i).
  """

  def __init__(
    self,
    message: str = "Transport connection lost",
    *,
    connection_id: Any = None,
  ) -> None:
    super().__init__(message)
    self.connection_id: Any = connection_id


class MessageDeliveryError(TransportError):
  """A message was accepted from a sender but could not be delivered (R-7.2-r/s).

  Silently dropping a message is forbidden (R-7.2-q/s).  Raising this error
  surfaces the failure to the caller so it can observe and react (R-7.5-j).

  Attributes:
    message_summary: brief human-readable description of the undeliverable
      message (for diagnostics only; never used for id-correlation).
  """

  def __init__(self, detail: str, *, message_summary: str = "") -> None:
    super().__init__(detail)
    self.message_summary: str = message_summary


class MalformedMessageError(TransportError):
  """A received unit is not well-formed UTF-8 or does not parse as a JSON value (R-7.6-b).

  The receiver MUST reject and MUST NOT silently substitute or drop such a unit
  (R-7.6-c).  The failure is surfaced as a transport/parse error.

  Attributes:
    raw_excerpt: a byte excerpt of the offending unit, for diagnostics.
  """

  def __init__(self, detail: str, *, raw_excerpt: bytes = b"") -> None:
    super().__init__(detail)
    self.raw_excerpt: bytes = raw_excerpt


class ConnectionScopedStateError(Exception):
  """Connection identity is being used as a session or conversation key (R-7.6-d–j).

  R-7.6-i: The connection or process identity MUST NOT be treated as a proxy
  for conversation or session continuity.
  R-7.6-j: State that must span multiple requests MUST be referenced by an
  explicit client-supplied identifier passed on each request.

  Raised by assert_no_connection_scoped_state() when state_key IS the
  connection_id, so the violation is caught at the call site.
  """

  def __init__(self, detail: str = "") -> None:
    msg = (
      "Connection identity MUST NOT be used as a proxy for session/conversation "
      "state (R-7.6-i).  Use an explicit client-supplied identifier instead (R-7.6-j)."
    )
    if detail:
      msg = f"{msg}  Detail: {detail}"
    super().__init__(msg)


# ---------------------------------------------------------------------------
# §7.1  Abstract Transport Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class Transport(Protocol):
  """Abstract transport contract (§7.1 / §7.2).

  Every conforming transport — defined (stdio, Streamable HTTP) or custom —
  MUST implement this interface.  The protocol carries the JSONRPCMessage
  union bidirectionally without interpreting method names, params, or results.

  Guarantees (§7.2) a conforming implementation MUST uphold:
    - Framing (R-7.2-b/c/d): unambiguous body-independent message boundaries.
    - Id-correlation (R-7.2-e/f/g): responses carry the originating request id.
    - Multiplexing (R-7.2-i/j/k/l): concurrent outstanding requests allowed.
    - Order-independence (R-7.2-m/n/p): no FIFO delivery precondition.
    - No silent loss (R-7.2-q/r/s): every message delivered or raises.
    - Clean close (R-7.2-t): close() defines graceful shutdown; is_closed observable.
    - Observable disconnection (R-7.5-a/b): abrupt loss raises DisconnectionError.
    - UTF-8 encoding (R-7.6-a): all messages are UTF-8 JSON.
    - Statelessness (R-7.6-d–j): no conversational state bound to connection.
  """

  @property
  def is_closed(self) -> bool:
    """True once close() has been called on this side of the connection."""
    ...

  def send(self, message: JSONRPCMessage) -> None:
    """Send message to the remote peer (R-7.1-a/d).

    Raises:
      MessageDeliveryError: this transport or the peer is closed, or the
        message cannot be delivered (R-7.2-q/r — never silently dropped).
    """
    ...

  def receive(self) -> JSONRPCMessage:
    """Return the next inbound message, blocking until one is available.

    MUST surface disconnection rather than blocking indefinitely (R-7.5-b).

    Raises:
      DisconnectionError: this transport is closed or the peer disconnected
        and no more messages are queued (R-7.5-a/b).
    """
    ...

  def close(self) -> None:
    """Close this side of the connection cleanly (R-7.2-t).

    After close(), is_closed is True; send() raises MessageDeliveryError;
    the peer observes DisconnectionError on its next receive() call.
    """
    ...


# ---------------------------------------------------------------------------
# §7.2  In-memory reference transport implementation
# ---------------------------------------------------------------------------

#: Maximum time (seconds) receive() waits for a message before raising DisconnectionError.
#: The intent is to surface disconnection rather than block indefinitely (R-7.5-b).
_RECEIVE_TIMEOUT_S: float = 2.0
_RECEIVE_POLL_S: float = 0.001


class InMemoryTransport:
  """Reference transport implemented with paired in-memory queues (§7.1–§7.2).

  Satisfies all §7.2 guarantees:
  - Bidirectional: send() delivers to the peer's receive() queue (R-7.4-a).
  - No silent loss: send() raises MessageDeliveryError on a closed peer (R-7.2-r).
  - Clean close: close() sets is_closed; peer observes DisconnectionError (R-7.2-t).
  - Observable disconnection: receive() raises instead of blocking indefinitely
    when the peer is gone (R-7.5-a/b).
  - Multiplexing: the queue accepts concurrent puts from any number of threads.
  - Order-independence: the queue delivers in FIFO order but callers MUST
    correlate responses by id, not by order.

  Usage::

      client_t, server_t = InMemoryTransport.create_pair()
      client_t.send(JSONRPCRequest(id=1, method="tools/list"))
      msg = server_t.receive()  # → the request
  """

  def __init__(self) -> None:
    #: Inbound queue; peers call send() to put messages here.
    self._inbound: queue.SimpleQueue[JSONRPCMessage] = queue.SimpleQueue()
    self._peer: InMemoryTransport | None = None
    self._closed: bool = False

  @classmethod
  def create_pair(cls) -> tuple[InMemoryTransport, InMemoryTransport]:
    """Create a connected (client, server) pair of in-memory transports.

    Messages sent on one side arrive on the other's receive() queue.
    """
    client = cls()
    server = cls()
    client._peer = server
    server._peer = client
    return client, server

  @property
  def is_closed(self) -> bool:
    """True once close() has been called on this side."""
    return self._closed

  def send(self, message: JSONRPCMessage) -> None:
    """Deliver message to the peer's inbound queue (R-7.1-a/d, R-7.4-b/c).

    Raises:
      MessageDeliveryError: this transport is closed (R-7.2-q), the peer is
        closed (R-7.2-r), or no peer is connected.
    """
    if self._closed:
      raise MessageDeliveryError(
        "Cannot send: this transport is closed (R-7.2-q/s)",
        message_summary=type(message).__name__,
      )
    if self._peer is None:
      raise MessageDeliveryError("Cannot send: transport has no connected peer")
    if self._peer._closed:
      raise MessageDeliveryError(
        "Cannot send: peer transport is closed; message cannot be delivered (R-7.2-r)",
        message_summary=type(message).__name__,
      )
    self._peer._inbound.put(message)

  def receive(self) -> JSONRPCMessage:
    """Return the next inbound message; block briefly, then raise DisconnectionError (R-7.5-b).

    MUST NOT block indefinitely — surfaces disconnection as soon as the peer is
    closed and no further messages are queued (R-7.5-a/b).

    Raises:
      DisconnectionError: this transport is closed, the peer disconnected, or
        no message arrived within _RECEIVE_TIMEOUT_S seconds.
    """
    if self._closed:
      raise DisconnectionError(
        "This transport is closed (R-7.5-a)",
        connection_id=id(self),
      )
    deadline = time.monotonic() + _RECEIVE_TIMEOUT_S
    while True:
      try:
        return self._inbound.get(block=False)
      except queue.Empty:
        pass
      if self._closed:
        raise DisconnectionError("Transport closed during receive")
      if self._peer is not None and self._peer._closed and self._inbound.empty():
        raise DisconnectionError(
          "Peer has disconnected — no further messages will arrive (R-7.5-a)",
          connection_id=id(self._peer),
        )
      if self._peer is None:
        raise DisconnectionError("Transport has no connected peer")
      if time.monotonic() >= deadline:
        raise DisconnectionError(
          f"Receive timed out after {_RECEIVE_TIMEOUT_S}s without a message — "
          "surfacing as disconnection instead of blocking indefinitely (R-7.5-b)"
        )
      time.sleep(_RECEIVE_POLL_S)

  def close(self) -> None:
    """Close this side of the connection (R-7.2-t).

    After close():
    - is_closed is True.
    - send() raises MessageDeliveryError.
    - The peer's receive() raises DisconnectionError once its queue is drained.
    """
    self._closed = True


# ---------------------------------------------------------------------------
# §7.2  Framing primitive (body-independent, production code)
# ---------------------------------------------------------------------------

#: The default frame delimiter used by the stdio transport (S13): newline byte.
STDIO_FRAME_DELIMITER: bytes = b"\n"


def split_frames(data: bytes, *, delimiter: bytes = STDIO_FRAME_DELIMITER) -> list[bytes]:
  """Split a byte stream into message frames by delimiter — body-independent (R-7.2-b/c/d).

  A receiver MUST be able to determine the exact byte boundaries of one message
  without parsing the JSON body; the framing alone MUST delimit messages (R-7.2-d).
  This function implements that guarantee: it splits solely on the delimiter and
  returns only non-empty frame bytes.

  Args:
    data: the raw bytes received from the channel (may contain multiple frames).
    delimiter: the byte sequence that marks the end of one frame (default: b"\\n").

  Returns:
    A list of non-empty byte objects, each representing one message frame
    (delimiter stripped; empty frames from trailing delimiters are excluded).
  """
  return [frame for frame in data.split(delimiter) if frame]


def frame_message(message_bytes: bytes, *, delimiter: bytes = STDIO_FRAME_DELIMITER) -> bytes:
  """Append the frame delimiter to a serialised message (R-7.2-b).

  Used by senders to produce a properly framed unit before writing to the wire.

  Args:
    message_bytes: the UTF-8-encoded JSON of one JSONRPCMessage.
    delimiter: the frame terminator (default: b"\\n").

  Returns:
    message_bytes + delimiter.
  """
  return message_bytes + delimiter


# ---------------------------------------------------------------------------
# §7.6  Character encoding validation  (R-7.6-a/b/c)
# ---------------------------------------------------------------------------

def validate_utf8_json_unit(data: bytes) -> Any:
  """Validate that data is a well-formed UTF-8 JSON value (R-7.6-a/b/c).

  Every message carried by any transport MUST be UTF-8 encoded (R-7.6-a).
  A receiver MUST reject, as a transport/parse error, any unit that is not
  well-formed UTF-8 or does not parse as a single JSON value (R-7.6-b).
  It MUST NOT silently substitute or drop such a unit (R-7.6-c).

  Args:
    data: raw bytes of one framed transport unit (framing already removed).

  Returns:
    The JSON-decoded Python value (dict, list, str, number, bool, None).

  Raises:
    MalformedMessageError: data is not well-formed UTF-8 or not valid JSON.
  """
  excerpt = data[:120] if len(data) > 120 else data
  try:
    text = data.decode("utf-8")
  except UnicodeDecodeError as exc:
    raise MalformedMessageError(
      f"Transport unit is not well-formed UTF-8 (R-7.6-a/b): {exc}",
      raw_excerpt=excerpt,
    ) from exc
  try:
    return json.loads(text)
  except json.JSONDecodeError as exc:
    raise MalformedMessageError(
      f"Transport unit is not a valid JSON value (R-7.6-b): {exc}",
      raw_excerpt=excerpt,
    ) from exc


# ---------------------------------------------------------------------------
# §7.6  Statelessness enforcement  (R-7.6-d–j)
# ---------------------------------------------------------------------------

def is_connection_scoped(state_key: Any, connection_id: Any) -> bool:
  """Return True if state_key IS the connection identity (R-7.6-i/j).

  Detects the forbidden pattern of using a connection or process object
  directly as a session or conversation key.  Uses identity comparison (``is``)
  so that a string connection-id that happens to equal an explicit identifier
  is not falsely flagged — only the literal same object is detected.

  Args:
    state_key: the key being used to look up or store per-request state.
    connection_id: the connection or process object whose identity MUST NOT
      be used as a state proxy (R-7.6-i).

  Returns:
    True only when state_key is the exact same object as connection_id.
  """
  return state_key is connection_id


def assert_no_connection_scoped_state(
  state_key: Any,
  connection_id: Any,
  *,
  context: str = "",
) -> None:
  """Guard: raise ConnectionScopedStateError if state_key IS connection_id (R-7.6-i/j).

  Place this at any call site where connection identity might otherwise be used
  as a lookup key.  If state_key is a distinct, explicitly supplied identifier
  (the correct pattern), the function is a no-op.  If it IS the connection
  object, it raises immediately so the violation is caught at the source.

  Args:
    state_key: the key used to look up or store state (MUST be an explicit
      client-supplied identifier, not the connection object itself).
    connection_id: the connection or process object to guard against.
    context: optional call-site description for the error message.

  Raises:
    ConnectionScopedStateError: state_key is the same object as connection_id.
  """
  if is_connection_scoped(state_key, connection_id):
    detail = context or (
      f"state_key {state_key!r} is the connection identity — "
      "use an explicit client-supplied identifier instead (R-7.6-j)"
    )
    raise ConnectionScopedStateError(detail)


# ---------------------------------------------------------------------------
# §7.5  Disconnect handling  (R-7.5-a–e)
# ---------------------------------------------------------------------------

def fail_in_flight_on_disconnect(tracker: InFlightTracker) -> frozenset[RequestId]:
  """Resolve all outstanding requests as failed on connection loss (R-7.5-c/d/e).

  When a connection is lost, the sender MUST NOT wait indefinitely for
  responses that can never arrive (R-7.5-d).  Every in-flight request MUST be
  considered failed (R-7.5-c) and resolved so callers can observe the error
  and retry on a fresh connection (R-7.5-e/f).

  Args:
    tracker: the InFlightTracker for the lost connection.

  Returns:
    frozenset of RequestId values that were in-flight and are now considered
    failed; callers SHOULD raise or surface DisconnectionError for each.
  """
  failed_ids: frozenset[RequestId] = tracker.in_flight_ids
  for rid in failed_ids:
    tracker.receive(rid)
  return failed_ids


# ---------------------------------------------------------------------------
# §7.3  Custom transport compliance checklist  (R-7.3-b/c/d/e)
# ---------------------------------------------------------------------------

@dataclass
class CustomTransportChecklist:
  """Typed record of §7.2 obligations that every custom transport MUST uphold (R-7.3-b/c).

  Instantiate this, fill in the fields, and call is_conformant() to check
  whether the transport satisfies the MUST-level guarantees from §7.2.

  Note: satisfying the Transport Protocol (send/receive/close/is_closed) is
  what provides actual enforcement; this checklist documents what properties
  must hold and records implementer attestations for audit purposes.

  Fields default to False — set to True when the property is verified:
    preserves_json_rpc_format: JSON-RPC message format is carried unchanged (R-7.3-b).
    preserves_exchange_patterns: request/response/notification patterns are preserved (R-7.3-b).
    preserves_per_request_meta: every request carries its _meta envelope (R-7.3-b, R-7.4-d).
    provides_framing: unambiguous body-independent message boundaries (R-7.2-b/c/d).
    provides_id_correlation: responses carry the originating request id (R-7.2-e/f/g).
    supports_multiplexing: concurrent outstanding requests are permitted (R-7.2-i/j/k/l).
    allows_out_of_order_responses: no FIFO ordering precondition (R-7.2-m/n/p).
    no_silent_loss: every message delivered or produces observable failure (R-7.2-q/r/s).
    defines_clean_close: close mechanics defined; each side can observe channel unusability (R-7.2-t).
    observable_disconnection: abrupt disconnection surfaces DisconnectionError (R-7.5-a/b).
    utf8_encoded: all messages are UTF-8 encoded (R-7.6-a).
    bidirectional: carries messages in both directions over one connection (R-7.4-a/b/c).
    documented: connection establishment, framing, and cancellation are documented (R-7.3-d).
    uses_stdio_framing_if_stream: reuses stdio newline framing over reliable byte streams (R-7.3-e).
    name: human-readable identifier for this custom transport.
  """

  preserves_json_rpc_format: bool = False
  preserves_exchange_patterns: bool = False
  preserves_per_request_meta: bool = False
  provides_framing: bool = False
  provides_id_correlation: bool = False
  supports_multiplexing: bool = False
  allows_out_of_order_responses: bool = False
  no_silent_loss: bool = False
  defines_clean_close: bool = False
  observable_disconnection: bool = False
  utf8_encoded: bool = False
  bidirectional: bool = False
  documented: bool = False
  uses_stdio_framing_if_stream: bool = False
  name: str = ""

  def is_conformant(self) -> bool:
    """Return True only when all MUST-level §7.2 obligations are satisfied (R-7.3-c).

    ``documented`` and ``uses_stdio_framing_if_stream`` are SHOULD-level
    recommendations and do not block conformance.
    """
    return all([
      self.preserves_json_rpc_format,
      self.preserves_exchange_patterns,
      self.preserves_per_request_meta,
      self.provides_framing,
      self.provides_id_correlation,
      self.supports_multiplexing,
      self.allows_out_of_order_responses,
      self.no_silent_loss,
      self.defines_clean_close,
      self.observable_disconnection,
      self.utf8_encoded,
      self.bidirectional,
    ])

  def missing_obligations(self) -> list[str]:
    """Return names of MUST-level obligations not yet satisfied."""
    mandatory = [
      "preserves_json_rpc_format",
      "preserves_exchange_patterns",
      "preserves_per_request_meta",
      "provides_framing",
      "provides_id_correlation",
      "supports_multiplexing",
      "allows_out_of_order_responses",
      "no_silent_loss",
      "defines_clean_close",
      "observable_disconnection",
      "utf8_encoded",
      "bidirectional",
    ]
    return [attr for attr in mandatory if not getattr(self, attr)]
