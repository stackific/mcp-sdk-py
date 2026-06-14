"""Transport Model & Transport-Agnostic Guarantees — S12.

Delivers:
  - TRANSPORT_STDIO / TRANSPORT_STREAMABLE_HTTP: identifiers for the two defined transports
  - TransportError: base for all transport-layer errors
  - DisconnectionError: abrupt channel loss, MUST be observable (R-7.5-a/b)
  - MessageDeliveryError: message accepted but cannot be delivered (R-7.2-r/s, R-7.5-i/j)
  - MalformedMessageError: unit is not well-formed UTF-8 or not a single JSON value (R-7.6-b/c)
  - ConnectionScopedStateError: raised when code attempts to bind state to a connection id (R-7.6-d–j)
  - validate_utf8_json_unit(): parse-level UTF-8 + JSON validation, must reject and not silently drop (R-7.6-a/b/c)
  - assert_no_connection_scoped_state(): defensive marker for the statelessness rule (R-7.6-d–j)
  - fail_in_flight_on_disconnect(): resolves all outstanding request ids as failed on disconnect (R-7.5-c/d/e)
  - CustomTransportChecklist: typed record of §7.2 obligations every custom transport must uphold (R-7.3-b/c/d/e)

Spec: §7
Depends on: S03, S06
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.jsonrpc import InFlightTracker, RequestId


# ---------------------------------------------------------------------------
# §7.3  Defined transport identifiers
# ---------------------------------------------------------------------------

#: The stdio transport defined by this document (§7, S13).
TRANSPORT_STDIO: str = "stdio"

#: The Streamable HTTP transport defined by this document (§7, S14/S15).
TRANSPORT_STREAMABLE_HTTP: str = "streamable-http"

#: The set of transports formally defined by this specification.
DEFINED_TRANSPORTS: frozenset[str] = frozenset({TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP})


# ---------------------------------------------------------------------------
# Transport-layer exception hierarchy
# ---------------------------------------------------------------------------

class TransportError(Exception):
  """Base class for all transport-layer failures (§7 — not a JSON-RPC error).

  A transport error signals a failure of the channel itself, as opposed to a
  JSON-RPC error response which is a normal, fully delivered protocol message.
  Callers catching TransportError MUST surface it rather than silently swallowing
  it (R-7.2-r, R-7.5-i).
  """


class DisconnectionError(TransportError):
  """The transport channel was lost abruptly; MUST be observable (R-7.5-a/b).

  When a connection is lost, all in-flight requests for which no response has
  been received MUST be considered failed (R-7.5-c).  Callers MUST use
  fail_in_flight_on_disconnect() to surface those failures (R-7.5-d/e).

  Attributes:
    connection_id: optional opaque identifier for the lost connection, for
      logging/diagnostics; MUST NOT be used as session or conversation state
      (R-7.6-i).
  """

  def __init__(self, message: str = "Transport connection lost", *, connection_id: Any = None) -> None:
    super().__init__(message)
    self.connection_id: Any = connection_id


class MessageDeliveryError(TransportError):
  """A message was accepted from a sender but could not be delivered (R-7.2-r/s).

  Silently dropping a message is forbidden (R-7.2-q/s).  Raising this error
  makes the failure observable on the affected side (R-7.5-j).

  Attributes:
    message_summary: a brief human-readable description of the undeliverable
      message (for diagnostics only; never used for correlation).
  """

  def __init__(self, detail: str, *, message_summary: str = "") -> None:
    super().__init__(detail)
    self.message_summary: str = message_summary


class MalformedMessageError(TransportError):
  """A received unit is not well-formed UTF-8 or does not parse as a single JSON value (R-7.6-b).

  The receiver MUST reject and MUST NOT silently substitute or drop such a unit
  (R-7.6-c).  The unit is surfaced as a transport/parse error, not silently ignored.

  Attributes:
    raw_excerpt: a byte-level excerpt of the offending unit, for diagnostics.
  """

  def __init__(self, detail: str, *, raw_excerpt: bytes = b"") -> None:
    super().__init__(detail)
    self.raw_excerpt: bytes = raw_excerpt


class ConnectionScopedStateError(Exception):
  """Code attempted to treat connection identity as conversation or session state (R-7.6-d–j).

  The connection or process identity MUST NOT be used as a proxy for
  conversation continuity (R-7.6-i).  State that spans multiple requests MUST
  be referenced by an explicit client-supplied identifier (R-7.6-j).
  """

  def __init__(self, detail: str = "") -> None:
    msg = (
      "Connection identity MUST NOT be used as a proxy for session/conversation "
      "state (R-7.6-d–j).  Use an explicit client-supplied identifier instead."
    )
    if detail:
      msg = f"{msg}  Detail: {detail}"
    super().__init__(msg)


# ---------------------------------------------------------------------------
# §7.6  Character encoding validation  (R-7.6-a/b/c)
# ---------------------------------------------------------------------------

def validate_utf8_json_unit(data: bytes) -> Any:
  """Validate that data is a well-formed UTF-8 JSON value (R-7.6-a/b/c).

  Every message carried by any transport MUST be UTF-8 encoded (R-7.6-a) and
  MUST parse as a single JSON value (R-7.6-b).  A receiver MUST NOT silently
  substitute or drop a malformed unit (R-7.6-c); this function raises
  MalformedMessageError instead.

  Args:
    data: the raw bytes of one framed transport unit (framing already removed).

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

def assert_no_connection_scoped_state(detail: str = "") -> None:
  """Defensive marker: raise ConnectionScopedStateError unconditionally.

  Call this at any site where connection identity would otherwise be used to
  look up per-session state, to make the violation immediately visible.

  R-7.6-d: A single transport connection MUST NOT be required to carry
  conversational state across requests.
  R-7.6-i: The connection or process identity MUST NOT be treated as a proxy
  for conversation or session continuity.
  R-7.6-j: State that must span requests MUST be referenced by an explicit
  client-supplied identifier.

  Raises:
    ConnectionScopedStateError: always.
  """
  raise ConnectionScopedStateError(detail)


# ---------------------------------------------------------------------------
# §7.5  Disconnect handling  (R-7.5-a–e)
# ---------------------------------------------------------------------------

def fail_in_flight_on_disconnect(tracker: InFlightTracker) -> frozenset[RequestId]:
  """Resolve all outstanding requests as failed on connection loss (R-7.5-c/d/e).

  When a connection is lost, the sender MUST NOT wait indefinitely for
  responses that can never arrive (R-7.5-d).  Every in-flight request MUST be
  considered failed and resolved so callers can observe the error (R-7.5-e).

  This function:
  1. Snapshots all in-flight request ids.
  2. Calls tracker.receive() for each to clear the in-flight set (connection is dead).
  3. Returns the snapshot so callers can surface individual errors.

  Args:
    tracker: the InFlightTracker for the lost connection.

  Returns:
    frozenset of RequestId values that were in-flight and are now considered failed.
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

  Implementers of a custom transport SHOULD instantiate this checklist and confirm
  each flag before declaring conformance (R-7.3-d).

  Fields (all default False — set to True when the property is satisfied):
    preserves_json_rpc_format: JSON-RPC message format is preserved unchanged (R-7.3-b).
    preserves_exchange_patterns: request/response/notification patterns are preserved (R-7.3-b).
    preserves_per_request_meta: every request carries its _meta envelope (R-7.3-b, R-7.4-d).
    provides_framing: unambiguous byte boundaries for each message, body-independent (R-7.2-b/c/d).
    provides_id_correlation: responses carry the originating request id (R-7.2-e/f/g).
    supports_multiplexing: concurrent outstanding requests are permitted (R-7.2-i/j/k/l).
    allows_out_of_order_responses: no FIFO ordering precondition (R-7.2-m/n/p).
    no_silent_loss: every message is delivered or produces an observable failure (R-7.2-q/r/s).
    defines_clean_close: close mechanics are defined; each side observes channel loss (R-7.2-t).
    observable_disconnection: abrupt disconnection is surfaced, not silently ignored (R-7.5-a/b).
    utf8_encoded: all messages are UTF-8 encoded (R-7.6-a).
    bidirectional: carries messages in both directions over one connection (R-7.4-a/b/c).
    documented: connection establishment, framing, and cancellation are documented (R-7.3-d).
    uses_stdio_framing_if_stream: reuses stdio newline framing over reliable byte streams (R-7.3-e).
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

  #: Human-readable name of this custom transport, for documentation purposes.
  name: str = ""

  def is_conformant(self) -> bool:
    """Return True only if all mandatory §7.2 obligations are satisfied (R-7.3-c).

    ``documented`` and ``uses_stdio_framing_if_stream`` are SHOULD-level
    recommendations; they do not block conformance but SHOULD be True.
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
    """Return the names of mandatory obligations that are not yet satisfied."""
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
    return [name for name in mandatory if not getattr(self, name)]
