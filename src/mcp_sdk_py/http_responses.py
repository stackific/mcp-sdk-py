"""Streamable HTTP: Responses, Status Mapping & HeaderMismatch — S15.

The *response half* of the Streamable HTTP transport, completing what S14
started: once a well-formed POST has arrived, this module defines how the
server answers a JSON-RPC *request* (a single JSON object or a request-scoped
Server-Sent Events stream), how every protocol/transport condition maps onto an
HTTP status code, the full ``-32001`` ``HeaderMismatch`` error *object* (S14 only
referenced the code), the statelessness rules of the HTTP layer, the security
rules for ``Origin`` validation and endpoint binding, and the
backward-compatibility probing that lets a client tell a modern server from a
legacy (HTTP+SSE / ``initialize``-handshake) one.

Public surface:

Response shapes (§9.6):
  - ResponseShape: SINGLE_JSON vs. EVENT_STREAM (R-9.6-a).
  - choose_response_shape(): pick a shape from whether request-scoped
    notifications will be emitted (R-9.6-a).
  - build_single_json_response(): 200 + application/json + one JSON-RPC response
    whose id equals the request id (R-9.6.1-a).
  - EventStreamResponse: the SSE response shape — headers (incl. X-Accel-Buffering),
    request-scoped framing, allowed/forbidden kinds, termination, non-resumability,
    and stream-close-as-cancellation (R-9.6.2-a..k, R-9.9-g).
  - encode_sse_event() / sse_data_line(): text/event-stream framing (R-9.6.2-a).

HTTP status mapping (§9.7):
  - HTTP_OK / HTTP_ACCEPTED / HTTP_BAD_REQUEST / HTTP_FORBIDDEN /
    HTTP_NOT_FOUND / HTTP_METHOD_NOT_ALLOWED.
  - StatusMapping / map_condition_to_status(): the fixed condition→status table.
  - build_method_not_found_response() / method_not_found_http(): 404 + -32601 with a
    JSON-RPC body that always carries the code (R-9.7-b).
  - build_invalid_params_response / parse_error / invalid_request response builders
    (codes owned by S04/S34; mapped to 400 here).

HeaderMismatch -32001 (§9.8):
  - HEADER_MISMATCH_CODE (re-exported from streamable_http), HeaderMismatch name.
  - build_header_mismatch_error() / build_header_mismatch_response(): the full
    -32001 error object + JSON-RPC response (R-9.8-a..d).
  - header_mismatch_http(): (400, response) pair (R-9.8-a).
  - intermediary_rejection(): an intermediary's status-only rejection that MAY omit
    a body (R-9.8-e/f).
  - intermediary_should_trust_headers(): trust only when MCP-Protocol-Version is
    present and indicates a validating revision; reject when absent (R-9.8-g/h).

Statelessness (§9.9):
  - SESSION_ID_HEADER_CANDIDATES / strip_session_identifier_headers(): a server
    MUST ignore any client session-id header (R-9.9-b/c/d).
  - strip_last_event_id(): a Last-Event-ID header MUST be ignored (R-9.6.2-h, R-9.9-g).
  - is_stateless_endpoint(): the endpoint needs no handshake/affinity (R-9.9-a/e).
  - get_only_transport_status() / handle_get_or_delete(): 405 for GET/DELETE on a
    this-transport-only server (R-9.9-f).

Security & binding (§9.11):
  - OriginValidator: validates Origin on every connection; 403 on a present,
    non-accepted Origin, with an optional id-less JSON-RPC body (R-9.11-a/b/c, R-9.7-a).
  - LOOPBACK_INTERFACE / ALL_INTERFACES / recommended_bind_interface(): bind to
    loopback when local (R-9.11-d).
  - authentication recommendation / §23 deferral documented (R-9.11-e/f).

Backward compatibility (§9.12):
  - is_recognized_revision_error(): does a 400 body carry a recognized JSON-RPC
    error of this revision? (R-9.12-b/c/e).
  - react_to_modern_post_400() / FallbackDecision: inspect a 400 body, never fall
    back on a recognized error, retry on data.supported (R-9.12-a..e).
  - should_probe_legacy_get(): a 400/404/405 with an unrecognized body SHOULD
    trigger a GET probe (R-9.12-g).
  - is_legacy_endpoint_event() / interpret_legacy_get(): an SSE stream whose first
    event is an ``endpoint`` event is the deprecated HTTP+SSE transport (R-9.12-h).
  - DUAL_HOSTING_RECOMMENDED: servers SHOULD also host the deprecated transport
    (R-9.12-f).

Spec: §9.6–§9.12
Depends on: S14 (request half: HeaderMismatchError, HEADER_MISMATCH_CODE, get_header),
  S09 (-32004/-32003 builders, http_status_for_negotiation_error)
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_sdk_py.jsonrpc import (
  JSONRPCErrorResponse,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResultResponse,
  RequestId,
)
from mcp_sdk_py.negotiation import (
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
  parse_unsupported_protocol_version_error,
)
from mcp_sdk_py.result_error import ErrorObject
from mcp_sdk_py.revision import SUPPORTED_REVISIONS
from mcp_sdk_py.streamable_http import (
  HEADER_MISMATCH_CODE,
  MCP_PROTOCOL_VERSION_HEADER,
  get_header,
)


# ---------------------------------------------------------------------------
# HTTP status codes (§9.7 — the fixed condition→status table)
# ---------------------------------------------------------------------------

#: Request handled successfully (single JSON or event stream) (§9.7, R-9.6-a).
HTTP_OK: int = 200
#: Notification accepted; empty body (§9.7).
HTTP_ACCEPTED: int = 202
#: Every transport/protocol-boundary rejection in §9.7/§9.8.
HTTP_BAD_REQUEST: int = 400
#: Origin present and invalid (§9.7, §9.11, R-9.11-b).
HTTP_FORBIDDEN: int = 403
#: Requested RPC method not implemented (§9.7, R-9.7-b).
HTTP_NOT_FOUND: int = 404
#: GET/DELETE at the MCP endpoint on a this-transport-only server (§9.9, R-9.9-f).
HTTP_METHOD_NOT_ALLOWED: int = 405


# ---------------------------------------------------------------------------
# JSON-RPC error codes mapped onto HTTP here (defined in S04/S09/S34)
# ---------------------------------------------------------------------------

#: Parse error — malformed JSON body (§22/S34; mapped to 400 here, §9.7).
PARSE_ERROR_CODE: int = -32700
#: Invalid request — body is not a valid JSON-RPC request object (mapped to 400).
INVALID_REQUEST_CODE: int = -32600
#: Method not found — requested RPC method not implemented (mapped to 404, R-9.7-b).
METHOD_NOT_FOUND_CODE: int = -32601
#: Invalid params — parameter-validation error (mapped to 400, §9.7).
INVALID_PARAMS_CODE: int = -32602

#: The set of JSON-RPC error codes that, when carried in a 400/403/404 body, are
#: "recognized errors of this revision" for the §9.12 backward-compat probe. The
#: §5 negotiation codes and the §9.8 HeaderMismatch code are what a *modern*
#: server returns with HTTP 400 (R-9.12-b); a recognized one MUST NOT trigger an
#: initialize fallback (R-9.12-d).
RECOGNIZED_REVISION_ERROR_CODES: frozenset[int] = frozenset({
  HEADER_MISMATCH_CODE,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  PARSE_ERROR_CODE,
  INVALID_REQUEST_CODE,
  METHOD_NOT_FOUND_CODE,
  INVALID_PARAMS_CODE,
})


# ---------------------------------------------------------------------------
# §9.6  Response shapes
# ---------------------------------------------------------------------------

class ResponseShape(Enum):
  """The two ways a server MAY answer a JSON-RPC *request* body (§9.6, R-9.6-a).

  SINGLE_JSON: one HTTP 200 + ``application/json`` carrying exactly one JSON-RPC
    response (§9.6.1). Used when no request-scoped notifications are emitted.
  EVENT_STREAM: HTTP 200 + ``text/event-stream``, an SSE stream scoped to the one
    request (§9.6.2). Used when the server emits request-scoped notifications
    (progress, logging) before the final response.

  Both shapes deliver successfully with HTTP 200 OK; the server MUST select
  exactly one per request (R-9.6-a).
  """

  SINGLE_JSON = "single_json"
  EVENT_STREAM = "event_stream"


def choose_response_shape(*, will_emit_request_scoped_notifications: bool) -> ResponseShape:
  """Pick exactly one of the two response shapes for a request body (§9.6, R-9.6-a).

  The single-JSON shape is used when the server produces the response without
  any request-scoped notifications (§9.6.1); the event-stream shape is used when
  it emits request-scoped notifications before the final response (§9.6.2). Either
  way, successful HTTP delivery is HTTP 200 OK.

  Args:
    will_emit_request_scoped_notifications: True iff the server will emit progress
      or logging notifications for this request before the final response.

  Returns:
    EVENT_STREAM when notifications will be emitted, else SINGLE_JSON.
  """
  return (
    ResponseShape.EVENT_STREAM
    if will_emit_request_scoped_notifications
    else ResponseShape.SINGLE_JSON
  )


# §9.6.1  Single JSON response

#: The Content-Type header field name (shared with streamable_http; redefined
#: here so callers building responses need only this module).
CONTENT_TYPE_HEADER: str = "Content-Type"
#: Content-Type for the single-JSON response shape (§9.6.1, R-9.6.1-a).
CONTENT_TYPE_JSON: str = "application/json"
#: Content-Type for the event-stream response shape (§9.6.2, R-9.6.2-a).
CONTENT_TYPE_EVENT_STREAM: str = "text/event-stream"


@dataclass(frozen=True)
class HTTPResponse:
  """A fully-formed HTTP response: status, headers, and a body string.

  A small transport-agnostic value used by the response builders so callers can
  inspect the status, the headers (e.g. ``Content-Type``), and the serialized
  body without committing to a particular HTTP server library.

  Fields:
    status: the HTTP status code (§9.7).
    headers: the response headers (e.g. ``Content-Type``, ``X-Accel-Buffering``).
    body: the serialized response body; empty string when the body is empty.
  """

  status: int
  headers: dict[str, str] = field(default_factory=dict)
  body: str = ""


def build_single_json_response(
  response: JSONRPCResultResponse | JSONRPCErrorResponse,
  request_id: RequestId,
) -> HTTPResponse:
  """Build the §9.6.1 single-JSON response (R-9.6.1-a).

  Produces HTTP 200 OK with ``Content-Type: application/json`` and a body that is
  exactly one JSON-RPC response (a result or error response) whose ``id`` equals
  the originating request ``id`` (R-9.6.1-a). Used when the server resolves the
  request without emitting any request-scoped notifications.

  Args:
    response: the single JSON-RPC response to deliver.
    request_id: the originating request's id — the response id MUST equal it.

  Returns:
    The 200 OK / application/json HTTPResponse.

  Raises:
    ValueError: the response id does not equal the request id (R-9.6.1-a).
  """
  if response.id != request_id:
    raise ValueError(
      f"single-JSON response id {response.id!r} MUST equal the request id "
      f"{request_id!r} (R-9.6.1-a)"
    )
  return HTTPResponse(
    status=HTTP_OK,
    headers={CONTENT_TYPE_HEADER: CONTENT_TYPE_JSON},
    body=json.dumps(response.to_dict(), separators=(",", ":")),
  )


# §9.6.2  Event-stream response framing

#: The reverse-proxy buffering hint a server SHOULD send when opening an SSE
#: stream so events are delivered immediately (R-9.6.2-g).
X_ACCEL_BUFFERING_HEADER: str = "X-Accel-Buffering"
X_ACCEL_BUFFERING_VALUE: str = "no"
#: Header field name a server MUST ignore — streams are not resumable (R-9.6.2-h, R-9.9-g).
LAST_EVENT_ID_HEADER: str = "Last-Event-ID"


def sse_data_line(message: dict[str, Any]) -> str:
  """Serialize one JSON-RPC message as a single SSE ``data:`` field (R-9.6.2-a).

  Each event's ``data`` field carries exactly one JSON-RPC message serialized as
  compact JSON, on one ``data:`` line (§9.6.2 / §9.10.3).
  """
  return "data: " + json.dumps(message, separators=(",", ":"))


def encode_sse_event(message: dict[str, Any]) -> str:
  """Encode one JSON-RPC message as a complete ``text/event-stream`` event (R-9.6.2-a).

  The event is one ``data:`` line carrying the JSON-RPC message, terminated by a
  blank line (a line containing only a line feed) per the SSE framing rules
  (§9.6.2 / §9.10.3). The returned string therefore ends in ``\\n\\n``.
  """
  return sse_data_line(message) + "\n\n"


class EventStreamError(Exception):
  """A write to an event stream violates the §9.6.2 framing rules.

  Raised when a caller attempts to send an independent JSON-RPC *request* on the
  stream (R-9.6.2-d), a notification unrelated to the originating request
  (R-9.6.2-c), or any message after the final response / after cancellation
  (R-9.6.2-f/k).
  """


def _notification_relates_to_request(
  notification: JSONRPCNotification,
  request: JSONRPCRequest,
) -> bool:
  """True iff a notification belongs to ``request`` (R-9.6.2-c).

  A request-scoped notification either references the request's progressToken
  (a ``notifications/progress`` whose ``params.progressToken`` equals the
  request's ``params._meta.progressToken``) or is a per-request log entry
  (``notifications/message``) flagged with the same progressToken when the
  caller correlates it. A notification carrying no progressToken at all is
  accepted as a per-request log entry only when the request defines no token to
  contradict it.
  """
  params = notification.params or {}
  note_token = params.get("progressToken")
  req_token = ((request.params or {}).get("_meta") or {}).get("progressToken")
  if note_token is not None:
    return note_token == req_token
  # No token on the notification (e.g. a notifications/message log entry): it is
  # request-scoped by virtue of flowing on this request's stream (§9.6.2).
  return True


class EventStreamResponse:
  """The §9.6.2 event-stream (SSE) response shape, scoped to one request.

  Models a ``text/event-stream`` response opened for exactly one JSON-RPC
  request. The server MAY emit request-scoped notifications before the final
  response (R-9.6.2-b); every notification MUST relate to the originating request
  (R-9.6.2-c); the server MUST NOT send an independent JSON-RPC *request* on the
  stream (R-9.6.2-d); the final response SHOULD terminate the stream (R-9.6.2-e)
  and no further messages may follow it (R-9.6.2-f). Closing the stream is
  cancellation of the request (R-9.6.2-i): the server SHOULD stop work
  (R-9.6.2-j) and MUST NOT send any further messages (R-9.6.2-k). A
  ``Last-Event-ID`` header has no effect — streams are not resumable
  (R-9.6.2-h, R-9.9-g).

  Use ``response_headers`` for the 200 OK headers, ``send_notification`` for each
  request-scoped notification, ``send_final_response`` to deliver and terminate,
  and ``cancel`` when the client closes the stream. ``events`` accumulates the
  encoded wire bytes for inspection/testing.
  """

  def __init__(self, request: JSONRPCRequest, *, x_accel_buffering: bool = True) -> None:
    self.request: JSONRPCRequest = request
    self._x_accel_buffering = x_accel_buffering
    self._events: list[str] = []
    self._closed: bool = False
    self._cancelled: bool = False

  @property
  def status(self) -> int:
    """The HTTP status — always 200 OK for either response shape (R-9.6.2-a)."""
    return HTTP_OK

  def response_headers(self) -> dict[str, str]:
    """Return the 200 OK response headers for the SSE stream (R-9.6.2-a/g).

    Always ``Content-Type: text/event-stream``; ``X-Accel-Buffering: no`` is
    included by default so reverse proxies do not buffer events (R-9.6.2-g).
    """
    headers = {CONTENT_TYPE_HEADER: CONTENT_TYPE_EVENT_STREAM}
    if self._x_accel_buffering:
      headers[X_ACCEL_BUFFERING_HEADER] = X_ACCEL_BUFFERING_VALUE
    return headers

  @property
  def events(self) -> list[str]:
    """Snapshot of the encoded SSE events written so far (one string per event)."""
    return list(self._events)

  @property
  def closed(self) -> bool:
    """True once the final response was sent or the stream was cancelled."""
    return self._closed

  @property
  def cancelled(self) -> bool:
    """True once the client closed the stream (treated as cancellation, R-9.6.2-i)."""
    return self._cancelled

  def send_notification(self, notification: JSONRPCNotification) -> str:
    """Emit a request-scoped notification before the final response (R-9.6.2-b/c/d/f).

    The server MAY send notifications on the stream (R-9.6.2-b); each MUST relate
    to the originating request (R-9.6.2-c). A JSONRPCRequest is never a valid
    argument here — the server MUST NOT send independent requests (R-9.6.2-d) —
    and nothing may be written after the final response or after cancellation
    (R-9.6.2-f/k).

    Returns:
      The encoded SSE event string that was appended to the stream.

    Raises:
      EventStreamError: the stream is closed/cancelled, the argument is not a
        notification, or the notification does not relate to this request.
    """
    self._ensure_open()
    if not isinstance(notification, JSONRPCNotification):
      raise EventStreamError(
        "the server MUST NOT send an independent JSON-RPC request on the "
        "response stream; only request-scoped notifications and the final "
        "response are allowed (R-9.6.2-d)"
      )
    if not _notification_relates_to_request(notification, self.request):
      raise EventStreamError(
        "every notification on the response stream MUST relate to the "
        "originating request (R-9.6.2-c)"
      )
    event = encode_sse_event(notification.to_dict())
    self._events.append(event)
    return event

  def send_final_response(
    self,
    response: JSONRPCResultResponse | JSONRPCErrorResponse,
  ) -> str:
    """Deliver the final response and terminate the stream (R-9.6.2-e/f).

    The final JSON-RPC response SHOULD terminate the stream (R-9.6.2-e); after it
    the server MUST NOT send any further messages for the request (R-9.6.2-f).
    The response id MUST equal the request id.

    Returns:
      The encoded SSE event string for the final response.

    Raises:
      EventStreamError: the stream is already closed or cancelled.
      ValueError: the response id does not equal the request id.
    """
    self._ensure_open()
    if response.id != self.request.id:
      raise ValueError(
        f"final response id {response.id!r} MUST equal the request id "
        f"{self.request.id!r} (R-9.6.1-a)"
      )
    event = encode_sse_event(response.to_dict())
    self._events.append(event)
    self._closed = True  # R-9.6.2-e/f: terminate; no further messages.
    return event

  def cancel(self) -> None:
    """Record a client stream-close as cancellation of the request (R-9.6.2-i/j/k).

    Closing the response stream MUST be treated as cancellation (R-9.6.2-i); the
    server SHOULD stop work as soon as practical (R-9.6.2-j) and MUST NOT send any
    further messages for the request (R-9.6.2-k). Idempotent.
    """
    self._cancelled = True
    self._closed = True

  def _ensure_open(self) -> None:
    if self._cancelled:
      raise EventStreamError(
        "the response stream was closed by the client (cancellation); the "
        "server MUST NOT send any further messages for this request (R-9.6.2-k)"
      )
    if self._closed:
      raise EventStreamError(
        "the final response already terminated the stream; the server MUST NOT "
        "send any further messages for this request (R-9.6.2-f)"
      )


# ---------------------------------------------------------------------------
# §9.7  HTTP status-code mapping
# ---------------------------------------------------------------------------

class Condition(Enum):
  """The protocol/transport conditions the §9.7 table maps onto HTTP status.

  Each member names a row of the §9.7 mapping table; ``map_condition_to_status``
  returns the HTTP status the spec assigns it.
  """

  REQUEST_HANDLED = "request_handled"
  NOTIFICATION_ACCEPTED = "notification_accepted"
  REQUIRED_HEADER_MISSING = "required_header_missing"
  HEADER_DISAGREES_OR_MALFORMED = "header_disagrees_or_malformed"
  UNSUPPORTED_PROTOCOL_VERSION = "unsupported_protocol_version"
  MISSING_REQUIRED_CLIENT_CAPABILITY = "missing_required_client_capability"
  INVALID_PARAMS = "invalid_params"
  MALFORMED_JSON = "malformed_json"
  NOT_A_REQUEST_OBJECT = "not_a_request_object"
  METHOD_NOT_IMPLEMENTED = "method_not_implemented"
  ORIGIN_INVALID = "origin_invalid"
  GET_OR_DELETE_ON_ENDPOINT = "get_or_delete_on_endpoint"


#: The fixed §9.7 condition→HTTP-status mapping (and the JSON-RPC code, when one
#: is defined by the table). A None code means the body is empty / has no fixed
#: JSON-RPC code (e.g. 202, 405, or the optional 403 body).
_STATUS_MAPPING: dict[Condition, tuple[int, int | None]] = {
  Condition.REQUEST_HANDLED: (HTTP_OK, None),
  Condition.NOTIFICATION_ACCEPTED: (HTTP_ACCEPTED, None),
  Condition.REQUIRED_HEADER_MISSING: (HTTP_BAD_REQUEST, HEADER_MISMATCH_CODE),
  Condition.HEADER_DISAGREES_OR_MALFORMED: (HTTP_BAD_REQUEST, HEADER_MISMATCH_CODE),
  Condition.UNSUPPORTED_PROTOCOL_VERSION: (HTTP_BAD_REQUEST, UNSUPPORTED_PROTOCOL_VERSION_CODE),
  Condition.MISSING_REQUIRED_CLIENT_CAPABILITY: (
    HTTP_BAD_REQUEST,
    MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  ),
  Condition.INVALID_PARAMS: (HTTP_BAD_REQUEST, INVALID_PARAMS_CODE),
  Condition.MALFORMED_JSON: (HTTP_BAD_REQUEST, PARSE_ERROR_CODE),
  Condition.NOT_A_REQUEST_OBJECT: (HTTP_BAD_REQUEST, INVALID_REQUEST_CODE),
  Condition.METHOD_NOT_IMPLEMENTED: (HTTP_NOT_FOUND, METHOD_NOT_FOUND_CODE),
  Condition.ORIGIN_INVALID: (HTTP_FORBIDDEN, None),
  Condition.GET_OR_DELETE_ON_ENDPOINT: (HTTP_METHOD_NOT_ALLOWED, None),
}


@dataclass(frozen=True)
class StatusMapping:
  """A resolved §9.7 mapping row: the HTTP status and the body's JSON-RPC code.

  Fields:
    status: the HTTP status code the condition maps to.
    json_rpc_code: the JSON-RPC error code the body carries, or None when the
      body is empty or has no fixed code (202, 405, or an optional 403 body).
  """

  status: int
  json_rpc_code: int | None


def map_condition_to_status(condition: Condition) -> StatusMapping:
  """Return the §9.7 HTTP status (and body code) for a condition (§9.7).

  Implements the fixed status-code mapping table: success shapes → 200,
  accepted notification → 202, the various boundary rejections → 400 with their
  JSON-RPC codes, unknown method → 404 / -32601 (R-9.7-b), invalid Origin → 403
  (R-9.7-a), and GET/DELETE at the endpoint → 405 (R-9.9-f).
  """
  status, code = _STATUS_MAPPING[condition]
  return StatusMapping(status=status, json_rpc_code=code)


def build_error_response(
  code: int,
  message: str,
  request_id: RequestId | None = None,
  *,
  data: Any = None,
) -> JSONRPCErrorResponse:
  """Build a §9.7 JSONRPCErrorResponse body for a 400/403/404 rejection (§9.7).

  The body is the standard JSON-RPC error response of §3 Base Message Format:
  ``jsonrpc`` const ``"2.0"``, an optional ``id`` (omitted when no request id can
  be determined), and the canonical ``error`` object (§3.8).

  Args:
    code: the JSON-RPC error code.
    message: the human-readable error message.
    request_id: the originating request id, or None when it cannot be determined.
    data: optional structured error data (omitted when None).

  Returns:
    The JSONRPCErrorResponse to deliver in the body.
  """
  error = ErrorObject(code=code, message=message) if data is None else ErrorObject(
    code=code, message=message, data=data
  )
  return JSONRPCErrorResponse(id=request_id, error=error.to_dict())


def build_method_not_found_response(
  method: str,
  request_id: RequestId,
  *,
  message: str | None = None,
) -> JSONRPCErrorResponse:
  """Build the §9.7 404 body for an unimplemented method (R-9.7-b).

  A 404 for an unknown method MUST always carry a JSON-RPC error body with code
  ``-32601`` so an MCP endpoint is distinguishable from a 404 returned by a host
  that does not serve the MCP endpoint at all (R-9.7-b).

  Args:
    method: the requested method that is not implemented.
    request_id: the originating request id (echoed in the body).
    message: optional override for the human-readable message.

  Returns:
    The JSONRPCErrorResponse carrying code -32601.
  """
  return build_error_response(
    METHOD_NOT_FOUND_CODE,
    message or f"Method not found: {method}",
    request_id,
  )


def method_not_found_http(
  method: str,
  request_id: RequestId,
) -> tuple[int, JSONRPCErrorResponse]:
  """Return the (404, body) pair for an unimplemented method (R-9.7-b).

  The body always carries code -32601 (R-9.7-b); see
  build_method_not_found_response.
  """
  return HTTP_NOT_FOUND, build_method_not_found_response(method, request_id)


def build_invalid_params_response(
  request_id: RequestId,
  *,
  message: str = "Invalid params",
) -> JSONRPCErrorResponse:
  """Build the §9.7 400 body for a parameter-validation error (-32602)."""
  return build_error_response(INVALID_PARAMS_CODE, message, request_id)


def build_parse_error_response(
  request_id: RequestId | None = None,
  *,
  message: str = "Parse error",
) -> JSONRPCErrorResponse:
  """Build the §9.7 400 body for a malformed JSON body (-32700).

  The request id is typically None because an unparseable body yields no id.
  """
  return build_error_response(PARSE_ERROR_CODE, message, request_id)


def build_invalid_request_response(
  request_id: RequestId | None = None,
  *,
  message: str = "Invalid request",
) -> JSONRPCErrorResponse:
  """Build the §9.7 400 body for a body that is not a valid request object (-32600)."""
  return build_error_response(INVALID_REQUEST_CODE, message, request_id)


# ---------------------------------------------------------------------------
# §9.8  The -32001 HeaderMismatch error (full object — S14 only referenced the code)
# ---------------------------------------------------------------------------

#: The error name carried in the §9.8 table for code -32001.
HEADER_MISMATCH_NAME: str = "HeaderMismatch"
#: The implementation-defined JSON-RPC server-error range [-32099, -32000] that
#: -32001 lies within (§9.8). Used to assert the code is in range.
SERVER_ERROR_RANGE_MIN: int = -32099
SERVER_ERROR_RANGE_MAX: int = -32000


def header_mismatch_code_in_server_range() -> bool:
  """True iff -32001 lies in the implementation-defined server-error range (§9.8)."""
  return SERVER_ERROR_RANGE_MIN <= HEADER_MISMATCH_CODE <= SERVER_ERROR_RANGE_MAX


def build_header_mismatch_error(
  message: str = "Header does not match request body",
) -> ErrorObject:
  """Build the §9.8 -32001 HeaderMismatch error *object* (R-9.8-a).

  This is the full -32001 error object S14 only referenced by code: code
  ``-32001`` (HeaderMismatch, in the server-error range -32000…-32099) and a
  human-readable message (exact text not normative). It is produced whenever the
  HTTP headers do not match the request body or a REQUIRED header is missing or
  malformed (R-9.8-a..d).

  Args:
    message: human-readable description of the mismatch.

  Returns:
    An ErrorObject with code -32001.
  """
  return ErrorObject(code=HEADER_MISMATCH_CODE, message=message)


def build_header_mismatch_response(
  request_id: RequestId | None = None,
  *,
  message: str = "Header does not match request body",
) -> JSONRPCErrorResponse:
  """Build the full §9.8 -32001 JSON-RPC error response (R-9.8-a).

  The response carries the §9.8 error object (build_header_mismatch_error) and
  echoes the originating request id when known. On the HTTP transport this
  response MUST be delivered with HTTP 400 Bad Request (R-9.8-a) — see
  header_mismatch_http.

  Args:
    request_id: the originating request id, or None when it cannot be determined.
    message: human-readable description of the mismatch.
  """
  return JSONRPCErrorResponse(
    id=request_id,
    error=build_header_mismatch_error(message).to_dict(),
  )


def header_mismatch_http(
  request_id: RequestId | None = None,
  *,
  message: str = "Header does not match request body",
) -> tuple[int, JSONRPCErrorResponse]:
  """Return the (400, -32001 body) pair for a header mismatch (R-9.8-a..d).

  A receiver that rejects a request because a REQUIRED header is missing
  (R-9.8-b), a header value disagrees with the body (R-9.8-c), or an
  ``Mcp-Param-*`` value contains invalid characters (R-9.8-d) MUST return HTTP
  400 Bad Request and the -32001 JSON-RPC error response (R-9.8-a).
  """
  return HTTP_BAD_REQUEST, build_header_mismatch_response(request_id, message=message)


def intermediary_rejection(
  *,
  status: int = HTTP_BAD_REQUEST,
  include_body: bool = False,
  request_id: RequestId | None = None,
  message: str = "Header validation failed",
) -> tuple[int, JSONRPCErrorResponse | None]:
  """Build an intermediary's status-only rejection on header-validation failure (R-9.8-e/f).

  An intermediary that enforces policy by inspecting mirrored headers MUST return
  an appropriate HTTP error status (for example 400) on a validation failure
  (R-9.8-e) but is NOT REQUIRED to return a JSON-RPC error body (R-9.8-f). By
  default this returns ``(400, None)`` — a status-only rejection; set
  ``include_body=True`` to attach the -32001 body.

  Args:
    status: the HTTP error status (defaults to 400 Bad Request).
    include_body: True to attach a -32001 JSON-RPC error body (optional, R-9.8-f).
    request_id: the originating request id when a body is included.
    message: the body message when a body is included.

  Returns:
    ``(status, None)`` by default, or ``(status, error_response)`` when
    ``include_body`` is set.
  """
  if not include_body:
    return status, None
  return status, build_header_mismatch_response(request_id, message=message)


def intermediary_should_trust_headers(headers: dict[str, Any]) -> bool:
  """Decide whether an intermediary MAY trust mirrored headers (R-9.8-g/h).

  Before trusting any mirrored header, an intermediary SHOULD verify that the
  ``MCP-Protocol-Version`` header indicates a version that requires header-body
  validation (R-9.8-g); if the header is absent it SHOULD reject the request
  rather than trust unvalidated headers (R-9.8-h). This SDK speaks only revisions
  that require header-body validation, so a present and supported
  ``MCP-Protocol-Version`` permits trust; an absent (or unsupported) header does
  not.

  Returns:
    True iff the request carries a present, supported ``MCP-Protocol-Version``
    header — meaning the intermediary MAY trust the mirrored headers; False when
    the header is absent (or names an unvalidating version), meaning it SHOULD
    reject (R-9.8-h).
  """
  version = get_header(headers, MCP_PROTOCOL_VERSION_HEADER)
  if version is None:
    return False  # R-9.8-h: absent header → SHOULD reject, do not trust.
  return version in SUPPORTED_REVISIONS  # R-9.8-g: validating revision → MAY trust.


# ---------------------------------------------------------------------------
# §9.9  Statelessness at the HTTP layer
# ---------------------------------------------------------------------------

#: Header names a server MUST ignore if a client sends them — this transport
#: uses no session identifier (R-9.9-b/c/d). Compared case-insensitively.
SESSION_ID_HEADER_CANDIDATES: frozenset[str] = frozenset({
  "Mcp-Session-Id",
  "MCP-Session-Id",
  "Session-Id",
  "X-Session-Id",
})


def strip_session_identifier_headers(headers: dict[str, Any]) -> dict[str, Any]:
  """Return a copy of ``headers`` with any session-identifier header removed (R-9.9-b/c/d).

  The transport MUST NOT use a session-identifier header (R-9.9-b); a server MUST
  NOT mint, require, or echo one (R-9.9-c); and if a client sends one the server
  MUST ignore it (R-9.9-d). This drops every candidate session header (matched
  case-insensitively) so the rest of the pipeline never observes session state.
  """
  drop = {name.lower() for name in SESSION_ID_HEADER_CANDIDATES}
  return {k: v for k, v in headers.items() if k.lower() not in drop}


def strip_last_event_id(headers: dict[str, Any]) -> dict[str, Any]:
  """Return a copy of ``headers`` with ``Last-Event-ID`` removed (R-9.6.2-h, R-9.9-g).

  Streams are not resumable; a ``Last-Event-ID`` request header has no effect and
  MUST be ignored. Dropping it here guarantees no downstream code can act on it.
  """
  target = LAST_EVENT_ID_HEADER.lower()
  return {k: v for k, v in headers.items() if k.lower() != target}


def is_stateless_endpoint() -> bool:
  """Return True: the MCP endpoint requires no handshake and no affinity (R-9.9-a/e).

  There is no session-establishment request and no session-bound state
  (R-9.9-a), and the endpoint requires no server affinity or sticky routing —
  every request carries its full protocol metadata in body ``_meta`` and mirrored
  routing headers, so any instance can serve any request (R-9.9-e). This SDK's
  HTTP layer is unconditionally stateless, so this is always True.
  """
  return True


def requires_handshake() -> bool:
  """Return False: this transport MUST NOT require any handshake (R-9.9-a)."""
  return False


def get_only_transport_status(http_method: str) -> int:
  """Return the HTTP status for a non-POST method on a this-transport-only server (R-9.9-f).

  A server that supports only this transport SHOULD respond with HTTP 405 Method
  Not Allowed to a ``GET`` or ``DELETE`` at the MCP endpoint (R-9.9-f); a ``POST``
  is the normal request method and is not rejected here.

  Args:
    http_method: the HTTP method of the incoming request.

  Returns:
    405 for GET/DELETE; 200 (the success status) for POST so callers can treat
    a non-405 result as "proceed to body handling".
  """
  if http_method.upper() in {"GET", "DELETE"}:
    return HTTP_METHOD_NOT_ALLOWED
  return HTTP_OK


def handle_get_or_delete(http_method: str) -> HTTPResponse | None:
  """Reject GET/DELETE at the endpoint on a this-transport-only server (R-9.9-f).

  Returns a 405 Method Not Allowed HTTPResponse with an empty body for a ``GET``
  or ``DELETE`` (R-9.9-f); returns None for any other method so the caller
  proceeds with normal POST handling.
  """
  if http_method.upper() in {"GET", "DELETE"}:
    return HTTPResponse(status=HTTP_METHOD_NOT_ALLOWED)
  return None


# ---------------------------------------------------------------------------
# §9.11  Security and endpoint binding
# ---------------------------------------------------------------------------

#: The loopback interface a locally-run server SHOULD bind to (R-9.11-d).
LOOPBACK_INTERFACE: str = "127.0.0.1"
#: The all-interfaces address a locally-run server SHOULD avoid (R-9.11-d).
ALL_INTERFACES: str = "0.0.0.0"
#: Header naming the requesting web origin, validated on every connection (R-9.11-a).
ORIGIN_HEADER: str = "Origin"


class OriginValidator:
  """Validates the ``Origin`` header on every connection (§9.11, R-9.11-a/b/c).

  A server MUST validate the ``Origin`` header on every incoming connection to
  prevent DNS-rebinding attacks (R-9.11-a). If ``Origin`` is present and is not
  an origin the server is configured to accept, the server MUST reject with HTTP
  403 Forbidden (R-9.11-b); the 403 body MAY contain a JSON-RPC error response
  with no ``id`` (R-9.11-c, R-9.7-a).

  Construct with the set of accepted origins. ``is_accepted`` reports whether a
  request's ``Origin`` is acceptable; ``reject_response`` builds the 403 (with an
  optional id-less body). An *absent* ``Origin`` is not rejected by this rule —
  the rejection applies only when ``Origin`` is *present* and not accepted.
  """

  def __init__(self, accepted_origins: Iterable[str]) -> None:
    self.accepted_origins: frozenset[str] = frozenset(accepted_origins)

  def origin_of(self, headers: dict[str, Any]) -> str | None:
    """Return the request's ``Origin`` header value, or None if absent."""
    return get_header(headers, ORIGIN_HEADER)

  def is_accepted(self, headers: dict[str, Any]) -> bool:
    """Return True iff the request's ``Origin`` is acceptable (R-9.11-a/b).

    True when ``Origin`` is absent (this rule rejects only a *present*,
    non-accepted origin) or present and in the configured accepted set; False
    only when ``Origin`` is present and not accepted (→ 403, R-9.11-b).
    """
    origin = self.origin_of(headers)
    if origin is None:
      return True
    return origin in self.accepted_origins

  def reject_response(
    self,
    *,
    include_body: bool = True,
    message: str = "Origin not permitted",
  ) -> HTTPResponse:
    """Build the 403 Forbidden rejection for an invalid ``Origin`` (R-9.11-b/c, R-9.7-a).

    The 403 body MAY contain a JSON-RPC error response with no ``id`` (R-9.11-c,
    R-9.7-a); set ``include_body=False`` to omit it entirely.

    Args:
      include_body: True (default) to attach an id-less JSON-RPC error body.
      message: the body message when a body is attached.

    Returns:
      A 403 Forbidden HTTPResponse; the body, when present, carries no ``id``.
    """
    if not include_body:
      return HTTPResponse(status=HTTP_FORBIDDEN)
    body = build_error_response(INVALID_REQUEST_CODE, message, request_id=None)
    return HTTPResponse(
      status=HTTP_FORBIDDEN,
      headers={CONTENT_TYPE_HEADER: CONTENT_TYPE_JSON},
      body=json.dumps(body.to_dict(), separators=(",", ":")),
    )


def recommended_bind_interface(*, is_local: bool) -> str:
  """Return the interface a server SHOULD bind its MCP endpoint to (R-9.11-d).

  When a server runs locally it SHOULD bind only to the loopback interface
  ``127.0.0.1`` rather than to all interfaces ``0.0.0.0``, so the endpoint is not
  reachable from other hosts (R-9.11-d).

  Args:
    is_local: True when the server is running locally.

  Returns:
    ``127.0.0.1`` for a local server, else ``0.0.0.0``.
  """
  return LOOPBACK_INTERFACE if is_local else ALL_INTERFACES


def should_implement_authentication() -> bool:
  """Return True: a Streamable HTTP endpoint SHOULD authenticate connections (R-9.11-e).

  A server exposing a Streamable HTTP endpoint SHOULD implement proper
  authentication for all connections (R-9.11-e); where authorization is used it
  MUST satisfy §23 Authorization (R-9.11-f), defined in S35–S37 and out of scope
  here. This advisory flag records the SHOULD so callers can surface it.
  """
  return True


# ---------------------------------------------------------------------------
# §9.12  Backward compatibility
# ---------------------------------------------------------------------------

#: A server wishing to support older clients SHOULD also host the deprecated
#: HTTP+SSE transport's SSE and POST endpoints alongside this endpoint (R-9.12-f).
DUAL_HOSTING_RECOMMENDED: bool = True

#: The SSE event name a deprecated HTTP+SSE server emits first on its GET stream;
#: seeing it means the server runs the legacy transport (R-9.12-h).
LEGACY_ENDPOINT_EVENT: str = "endpoint"


def is_recognized_revision_error(body: Any) -> bool:
  """True iff a response body is a recognized JSON-RPC error of this revision (§9.12).

  Used by the §9.12 probe: a modern server returns HTTP 400 not only for legacy
  reasons but also for ``-32004``, ``-32003``, and ``-32001`` (R-9.12-b). A body
  is "recognized" when it is a JSON-RPC error response (``jsonrpc`` ``"2.0"`` with
  an ``error`` object) whose code is one this revision defines
  (RECOGNIZED_REVISION_ERROR_CODES). An empty or non-error body is not recognized
  (R-9.12-e). Accepts either a decoded dict or a raw JSON string.

  Returns:
    True iff the body parses as a recognized JSON-RPC error of this revision.
  """
  if body is None:
    return False
  if isinstance(body, str):
    if body.strip() == "":
      return False
    try:
      body = json.loads(body)
    except (ValueError, TypeError):
      return False
  if not isinstance(body, dict):
    return False
  if body.get("jsonrpc") != "2.0":
    return False
  error = body.get("error")
  if not isinstance(error, dict):
    return False
  return error.get("code") in RECOGNIZED_REVISION_ERROR_CODES


class FallbackAction(Enum):
  """The client's reaction to a modern-POST 400 response (§9.12).

  RETRY_THIS_REVISION: the body is a recognized error of this revision; retry
    using ``error.data.supported`` (or correct the request) and MUST NOT fall
    back to an ``initialize`` handshake (R-9.12-c/d).
  FALL_BACK_TO_INITIALIZE: the body is empty or not a recognized error of this
    revision; the client MAY fall back to ``initialize`` (R-9.12-e).
  """

  RETRY_THIS_REVISION = "retry_this_revision"
  FALL_BACK_TO_INITIALIZE = "fall_back_to_initialize"


@dataclass(frozen=True)
class FallbackDecision:
  """A client's decision after inspecting a modern-POST 400 body (§9.12).

  Fields:
    action: RETRY_THIS_REVISION or FALL_BACK_TO_INITIALIZE.
    supported_versions: when ``action`` is RETRY_THIS_REVISION and the body was a
      ``-32004`` error, the revisions advertised in ``error.data.supported`` to
      retry with (R-9.12-c); empty otherwise.
    may_fall_back: True iff the client MAY fall back to ``initialize`` (R-9.12-e);
      always False for a recognized error of this revision (R-9.12-d).
  """

  action: FallbackAction
  supported_versions: list[str] = field(default_factory=list)
  may_fall_back: bool = False


def react_to_modern_post_400(body: Any) -> FallbackDecision:
  """Decide how a dual-revision client reacts to a modern-POST 400 (R-9.12-a..e).

  On an HTTP 400, the client SHOULD inspect the body before falling back, because
  a modern server also returns 400 for ``-32004``/``-32003``/``-32001``
  (R-9.12-b). If the body is a recognized JSON-RPC error of this revision, the
  client MUST retry using ``error.data.supported`` (or correct the request) and
  MUST NOT fall back to an ``initialize`` handshake (R-9.12-c/d). If the body is
  empty or not a recognized error of this revision, the client MAY fall back to
  ``initialize`` (R-9.12-e).

  Args:
    body: the 400 response body (decoded dict or raw JSON string).

  Returns:
    A FallbackDecision describing the reaction.
  """
  if not is_recognized_revision_error(body):
    return FallbackDecision(
      action=FallbackAction.FALL_BACK_TO_INITIALIZE,
      may_fall_back=True,
    )
  # Recognized error of this revision: retry, never fall back (R-9.12-c/d).
  decoded = json.loads(body) if isinstance(body, str) else body
  error = decoded.get("error", {})
  supported: list[str] = []
  if error.get("code") == UNSUPPORTED_PROTOCOL_VERSION_CODE:
    try:
      supported, _requested = parse_unsupported_protocol_version_error(error)
    except ValueError:
      supported = []
  return FallbackDecision(
    action=FallbackAction.RETRY_THIS_REVISION,
    supported_versions=supported,
    may_fall_back=False,
  )


def should_probe_legacy_get(status: int, body: Any) -> bool:
  """True iff a failed POST SHOULD trigger a legacy GET probe (R-9.12-g).

  A client wishing to support older servers SHOULD, if a POST fails with HTTP
  400, 404, or 405 AND the body is not a recognized JSON-RPC error of this
  revision, issue an HTTP ``GET`` to the URL (R-9.12-g). A recognized error of
  this revision means the server is modern and no legacy probe is warranted
  (R-9.12-d).

  Args:
    status: the HTTP status of the failed POST.
    body: the POST response body (decoded dict or raw JSON string).

  Returns:
    True iff status is one of {400, 404, 405} and the body is not recognized.
  """
  if status not in {HTTP_BAD_REQUEST, HTTP_NOT_FOUND, HTTP_METHOD_NOT_ALLOWED}:
    return False
  return not is_recognized_revision_error(body)


def is_legacy_endpoint_event(first_event_name: str | None) -> bool:
  """True iff a GET-probe SSE stream's first event is an ``endpoint`` event (R-9.12-h).

  If an HTTP ``GET`` to the URL opens an SSE stream whose first event is an
  ``endpoint`` event, the client SHOULD treat the server as running the
  deprecated HTTP+SSE transport (R-9.12-h).
  """
  return first_event_name == LEGACY_ENDPOINT_EVENT


def interpret_legacy_get(first_event_name: str | None) -> bool:
  """Decide whether to use the deprecated HTTP+SSE transport after a GET probe (R-9.12-h).

  Returns True (use the legacy transport for subsequent communication) iff the
  GET opened an SSE stream whose first event is an ``endpoint`` event; False
  otherwise (the server is not the deprecated transport).
  """
  return is_legacy_endpoint_event(first_event_name)
