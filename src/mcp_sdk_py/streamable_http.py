"""Streamable HTTP: Request, Headers & Routing — S14.

The *request half* of the Streamable HTTP transport: how a client frames each
JSON-RPC message as an HTTP POST to the single MCP endpoint, the required
request headers, the routing headers that mirror body fields, and the optional
``x-mcp-header`` mechanism that surfaces tool parameters as ``Mcp-Param-*``
headers (declaration, client emission, value encoding, receiver validation).

The body is the single source of truth (§9.1); headers mirror selected body
fields for routing/observability, and any header that disagrees is rejected with
``-32001`` (``HeaderMismatch``). The ``-32001`` error *object* is defined in S15;
this story only references the code as the rejection signal.

Public surface (selected):

Endpoint & POST framing (§9.1/§9.2):
  - parse_post_body_bytes(): UTF-8 decode + JSON parse (R-9.1-a).
  - validate_post_body(): exactly one request/notification, never a batch, never
    a response, method POST (R-9.1-b, R-9.2-b/c/d/e).
  - notification_response(): 202 + empty body on accept; HTTP error otherwise
    (R-9.2-g/h/i).

Required request headers (§9.3):
  - CONTENT_TYPE_HEADER / ACCEPT_HEADER / required values; get_header()
    case-insensitive lookup (R-9.3-b); validate_required_request_headers().
  - validate_protocol_version_header(): absent / mismatch / unsupported
    (R-9.3.3-a..e) → HeaderMismatchError (-32001) or UnsupportedRevisionError
    (-32004).

Routing headers (§9.4):
  - build_routing_headers(); validate_routing_headers() (R-9.4-a/b, R-9.4.1/2/3).

Tool parameters as headers (§9.5):
  - is_valid_tchar_token(); validate_x_mcp_header_value(); collect_header_
    annotations() (R-9.5.1); filter_valid_tools() (R-9.5.1-i/j/k).
  - encode_param_value() / decode_param_value() incl. the =?base64?…?= sentinel
    (R-9.5.3); build_param_headers() (R-9.5.2); validate_param_headers()
    (R-9.5.4).

Errors:
  - HeaderMismatchError: the -32001 rejection signal (code referenced; full
    object in S15). http_status is 400.

Spec: §9.1–§9.5
Depends on: S12 (transport model), S05 (_meta / protocolVersion), S07 (revision),
  S09 (UnsupportedProtocolVersion -32004 builders)
"""

from __future__ import annotations

import base64
import logging
import string
from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.jsonrpc import (
  JSONRPCErrorResponse,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResponse,
  RequestId,
  classify_message,
)
from mcp_sdk_py.json_value import (
  SAFE_INTEGER_MAX,
  SAFE_INTEGER_MIN,
  is_within_safe_range,
)
from mcp_sdk_py.meta_object import KEY_PROTOCOL_VERSION
from mcp_sdk_py.negotiation import build_unsupported_protocol_version_response
from mcp_sdk_py.revision import HTTP_PROTOCOL_VERSION_HEADER, UnsupportedRevisionError
from mcp_sdk_py.transport import validate_utf8_json_unit

_log = logging.getLogger("mcp_sdk_py.streamable_http")


# ---------------------------------------------------------------------------
# Header names & values (§9.3, §9.4, §9.5)
# ---------------------------------------------------------------------------

CONTENT_TYPE_HEADER: str = "Content-Type"
ACCEPT_HEADER: str = "Accept"
#: Mirrors S07's MCP-Protocol-Version header (the value mirrors _meta, R-9.3.3-a).
MCP_PROTOCOL_VERSION_HEADER: str = HTTP_PROTOCOL_VERSION_HEADER
MCP_METHOD_HEADER: str = "Mcp-Method"
MCP_NAME_HEADER: str = "Mcp-Name"
MCP_PARAM_PREFIX: str = "Mcp-Param-"

CONTENT_TYPE_VALUE: str = "application/json"
#: The two media types a conforming client MUST advertise (R-9.3.2-b).
ACCEPT_MEDIA_JSON: str = "application/json"
ACCEPT_MEDIA_EVENT_STREAM: str = "text/event-stream"
ACCEPT_VALUE: str = "application/json, text/event-stream"

#: HTTP status for an accepted notification (R-9.2-g).
NOTIFICATION_ACCEPTED_STATUS: int = 202
#: HTTP status used for every header-related rejection in this story (R-9.4.3-a etc.).
HTTP_BAD_REQUEST: int = 400

#: The -32001 HeaderMismatch code (object owned by S15; referenced here, §6.4).
HEADER_MISMATCH_CODE: int = -32001

#: Methods that carry an Mcp-Name routing header and the body field it mirrors
#: (R-9.4.2-b/c/d). All other methods MUST NOT send Mcp-Name (R-9.4.2-e).
MCP_NAME_METHODS: dict[str, str] = {
  "tools/call": "name",
  "prompts/get": "name",
  "resources/read": "uri",
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class HeaderMismatchError(Exception):
  """A required header is missing, malformed, or disagrees with the body (-32001).

  The rejection signal for every header problem in §9.3.3/§9.4.3/§9.5.4: the
  receiver responds with HTTP 400 Bad Request and JSON-RPC error code -32001
  (``HeaderMismatch``). The full -32001 error *object* is defined in S15; this
  exception only references the code and the 400 status.

  Attributes:
    json_rpc_code: -32001.
    http_status: 400.
    request_id: the originating request id when known (echoed in the response).
  """

  json_rpc_code: int = HEADER_MISMATCH_CODE
  http_status: int = HTTP_BAD_REQUEST

  def __init__(self, detail: str, *, request_id: RequestId | None = None) -> None:
    super().__init__(f"{detail} — reject with HTTP 400 and JSON-RPC -32001 (HeaderMismatch)")
    self.detail: str = detail
    self.request_id: RequestId | None = request_id

  def to_response(self, *, message: str = "Header does not match request body") -> JSONRPCErrorResponse:
    """Build the JSON-RPC error response carrying code -32001 (message-only, §9.8/S15)."""
    return JSONRPCErrorResponse(
      id=self.request_id,
      error={"code": HEADER_MISMATCH_CODE, "message": message},
    )


class XMcpHeaderError(Exception):
  """An ``x-mcp-header`` annotation violates the §9.5.1 constraints (R-9.5.1-a..g).

  A client using this transport MUST reject the offending tool and exclude it
  from the ``tools/list`` result it returns (R-9.5.1-i), while leaving other
  valid tools usable (R-9.5.1-j).

  Attributes:
    reason: human-readable description of the violated constraint.
    value: the offending x-mcp-header value (when applicable).
  """

  def __init__(self, reason: str, *, value: Any = None) -> None:
    super().__init__(reason)
    self.reason: str = reason
    self.value: Any = value


class NotASingleMessageError(Exception):
  """A POST body is not exactly one JSON-RPC request or notification (R-9.1-b, R-9.2-c/d/e).

  Covers a batch array (R-9.2-e), a JSON-RPC response sent by a client
  (R-9.2-d), or any body that is not a single request/notification.
  """


# ---------------------------------------------------------------------------
# Case-insensitive header access (§9.3 — field names compare case-insensitively)
# ---------------------------------------------------------------------------

def get_header(headers: dict[str, Any], name: str) -> str | None:
  """Return the value of header ``name`` using case-insensitive name matching (R-9.3-b).

  Header field *names* compare case-insensitively; the returned *value* is
  unchanged (values that mirror body fields are compared case-sensitively by the
  caller, R-9.3-c). Returns None when no header with that name is present.
  """
  target = name.lower()
  for key, value in headers.items():
    if key.lower() == target:
      return value
  return None


# ---------------------------------------------------------------------------
# §9.1/§9.2  Endpoint & POST framing
# ---------------------------------------------------------------------------

def parse_post_body_bytes(data: bytes) -> Any:
  """Decode a POST body that MUST be UTF-8 JSON (R-9.1-a).

  Reuses the transport-layer UTF-8 + JSON validation (S12): a body that is not
  well-formed UTF-8 or not valid JSON is rejected rather than silently dropped.

  Raises:
    MalformedMessageError: data is not well-formed UTF-8 or not valid JSON.
  """
  return validate_utf8_json_unit(data)


def validate_post_body(
  raw: Any,
  *,
  http_method: str = "POST",
) -> JSONRPCRequest | JSONRPCNotification:
  """Validate that a POST body is exactly one request or notification (§9.2).

  Enforces:
    - HTTP method MUST be POST (R-9.2-b).
    - body MUST NOT be a batch array (R-9.2-e).
    - body MUST be exactly one JSON-RPC request or notification per §3 framing
      (R-9.1-b, R-9.2-c).
    - a client MUST NOT send a JSON-RPC response to the server (R-9.2-d).

  Args:
    raw: the JSON-decoded POST body.
    http_method: the HTTP method used (defaults to POST).

  Returns:
    The classified JSONRPCRequest or JSONRPCNotification.

  Raises:
    NotASingleMessageError: method is not POST, body is a batch, body is a
      JSON-RPC response, or it cannot be classified as a single request/
      notification.
  """
  if http_method.upper() != "POST":
    raise NotASingleMessageError(
      f"Streamable HTTP requires the HTTP method POST; got {http_method!r} (R-9.2-b)"
    )
  if isinstance(raw, list):
    raise NotASingleMessageError(
      "POST body MUST NOT be a batch (array of messages); each message is its own POST (R-9.2-e)"
    )
  message = classify_message(raw)
  if isinstance(message, JSONRPCResponse.__args__):  # result or error response
    raise NotASingleMessageError(
      "A client MUST NOT send a JSON-RPC response to the server; servers do not "
      "initiate JSON-RPC requests (R-9.2-d)"
    )
  return message


def notification_response(
  accepted: bool,
  *,
  reject_message: str = "Notification could not be accepted",
) -> tuple[int, JSONRPCErrorResponse | None]:
  """Build the server's HTTP response to a posted notification (§9.2, R-9.2-g/h/i).

  Args:
    accepted: whether the server accepts the notification.
    reject_message: human-readable message for the rejection error body.

  Returns:
    On accept: ``(202, None)`` — HTTP 202 Accepted with no response body
    (R-9.2-g). On reject: ``(400, error_response)`` — an HTTP error status whose
    JSON-RPC error response omits ``id`` (R-9.2-h/i).
  """
  if accepted:
    return NOTIFICATION_ACCEPTED_STATUS, None
  rejection = JSONRPCErrorResponse(
    id=None,  # id omitted for a rejected notification (R-9.2-i)
    error={"code": HEADER_MISMATCH_CODE, "message": reject_message},
  )
  return HTTP_BAD_REQUEST, rejection


# ---------------------------------------------------------------------------
# §9.3  Required request headers
# ---------------------------------------------------------------------------

def content_type_is_valid(headers: dict[str, Any]) -> bool:
  """Return True if Content-Type is exactly ``application/json`` (R-9.3.1-a)."""
  return get_header(headers, CONTENT_TYPE_HEADER) == CONTENT_TYPE_VALUE


def accept_is_valid(headers: dict[str, Any]) -> bool:
  """Return True if Accept lists both required media types (R-9.3.2-a/b).

  The client MUST advertise both ``application/json`` and ``text/event-stream``
  so it can accept whichever response shape the server selects (§9.6).
  """
  accept = get_header(headers, ACCEPT_HEADER)
  if not isinstance(accept, str):
    return False
  media = {part.split(";")[0].strip().lower() for part in accept.split(",")}
  return ACCEPT_MEDIA_JSON in media and ACCEPT_MEDIA_EVENT_STREAM in media


def validate_required_request_headers(headers: dict[str, Any]) -> None:
  """Validate the §9.3 Content-Type and Accept headers on a POST (R-9.3.1-a, R-9.3.2-a/b).

  A POST missing either, or with a wrong Content-Type, is non-conforming.
  (The MCP-Protocol-Version header is validated by
  validate_protocol_version_header, which carries its own -32001/-32004 rules.)

  Raises:
    ValueError: Content-Type is not ``application/json`` or Accept does not list
      both required media types.
  """
  if not content_type_is_valid(headers):
    raise ValueError(
      f"Content-Type MUST be {CONTENT_TYPE_VALUE!r} (R-9.3.1-a); "
      f"got {get_header(headers, CONTENT_TYPE_HEADER)!r}"
    )
  if not accept_is_valid(headers):
    raise ValueError(
      f"Accept MUST list both {ACCEPT_MEDIA_JSON!r} and {ACCEPT_MEDIA_EVENT_STREAM!r} "
      f"(R-9.3.2-b); got {get_header(headers, ACCEPT_HEADER)!r}"
    )


def validate_protocol_version_header(
  headers: dict[str, Any],
  body_meta: dict[str, Any],
  *,
  supported_versions: frozenset[str],
  request_id: RequestId | None = None,
  supports_pre_header_clients: bool = False,
) -> str:
  """Validate the MCP-Protocol-Version header against the body and support set (§9.3.3).

  Rules:
    - The header value MUST equal the body ``_meta`` protocolVersion (R-9.3.3-a).
    - If the header is absent: a server that does not support pre-header clients
      MUST reject with -32001 (R-9.3.3-b); one that does MAY treat the request as
      the earliest revision that did not define it (R-9.3.3-c) — signalled by
      ``supports_pre_header_clients=True``, in which case the body ``_meta``
      version is used.
    - If header ≠ body, reject with -32001 (R-9.3.3-d).
    - If the (matching) version is not implemented by the server, reject with
      -32004 (R-9.3.3-e).

  Returns:
    The validated protocol-revision string.

  Raises:
    HeaderMismatchError: header absent (no pre-header support) or header ≠ body
      (-32001, HTTP 400).
    UnsupportedRevisionError: the requested version is not supported (-32004,
      HTTP 400) — map to a response via build_unsupported_protocol_version_response.
  """
  header_val = get_header(headers, MCP_PROTOCOL_VERSION_HEADER)
  meta_version = body_meta.get(KEY_PROTOCOL_VERSION)

  if header_val is None:
    if supports_pre_header_clients:
      # R-9.3.3-c: MAY treat omission as the earliest revision; defer to the body.
      if not isinstance(meta_version, str):
        raise HeaderMismatchError(
          "MCP-Protocol-Version header absent and body _meta has no protocolVersion",
          request_id=request_id,
        )
      candidate = meta_version
    else:
      raise HeaderMismatchError(
        "MCP-Protocol-Version header is absent (R-9.3.3-b)",
        request_id=request_id,
      )
  else:
    # R-9.3.3-d: header MUST equal the body _meta protocolVersion (case-sensitive).
    if not isinstance(meta_version, str) or header_val != meta_version:
      raise HeaderMismatchError(
        f"MCP-Protocol-Version header {header_val!r} does not equal body _meta "
        f"protocolVersion {meta_version!r} (R-9.3.3-d)",
        request_id=request_id,
      )
    candidate = header_val

  # R-9.3.3-e: unsupported version → -32004 (UnsupportedProtocolVersionError).
  if candidate not in supported_versions:
    raise UnsupportedRevisionError(candidate, supported_versions)
  return candidate


# ---------------------------------------------------------------------------
# §9.4  Routing headers
# ---------------------------------------------------------------------------

def mcp_name_for(method: str, params: dict[str, Any] | None) -> str | None:
  """Return the Mcp-Name value for ``method``, or None if the method carries none.

  For ``tools/call``/``prompts/get`` it is ``params.name``; for
  ``resources/read`` it is ``params.uri`` (R-9.4.2-b/c/d). Other methods carry
  no Mcp-Name (R-9.4.2-e).
  """
  body_field = MCP_NAME_METHODS.get(method)
  if body_field is None:
    return None
  return (params or {}).get(body_field)


def build_routing_headers(method: str, params: dict[str, Any] | None) -> dict[str, str]:
  """Build the §9.4 routing headers for a POST (R-9.4-a/b).

  Always includes ``Mcp-Method`` (mirrors ``method`` verbatim, R-9.4.1-a) and
  includes ``Mcp-Name`` only for the targeted methods (R-9.4.2-a..e).
  """
  headers: dict[str, str] = {MCP_METHOD_HEADER: method}
  name = mcp_name_for(method, params)
  if name is not None:
    headers[MCP_NAME_HEADER] = name
  return headers


def validate_routing_headers(
  headers: dict[str, Any],
  method: str,
  params: dict[str, Any] | None,
  *,
  request_id: RequestId | None = None,
) -> None:
  """Validate routing headers against the body (server side, §9.4.3, R-9.4.3-a).

  Rejects (HeaderMismatchError, -32001) any request whose routing-header value
  disagrees with the body, and any request that omits a REQUIRED routing header.
  Also rejects an Mcp-Name sent for a method that defines no targeted name/URI
  (R-9.4.2-e), since the body provides no matching value.

  Raises:
    HeaderMismatchError: a routing header is missing or disagrees with the body.
  """
  # Mcp-Method REQUIRED on every POST, exact (case-sensitive) match (R-9.4-a, R-9.4.1-a).
  mcp_method = get_header(headers, MCP_METHOD_HEADER)
  if mcp_method is None:
    raise HeaderMismatchError(
      f"required routing header {MCP_METHOD_HEADER!r} is missing (R-9.4-a)",
      request_id=request_id,
    )
  if mcp_method != method:
    raise HeaderMismatchError(
      f"{MCP_METHOD_HEADER} {mcp_method!r} does not equal body method {method!r} "
      f"(verbatim, case-sensitive) (R-9.4.1-a, R-9.4.3-a)",
      request_id=request_id,
    )

  mcp_name = get_header(headers, MCP_NAME_HEADER)
  body_field = MCP_NAME_METHODS.get(method)
  if body_field is None:
    # R-9.4.2-e: Mcp-Name MUST NOT be sent for non-targeted methods.
    if mcp_name is not None:
      raise HeaderMismatchError(
        f"{MCP_NAME_HEADER} sent for method {method!r}, which defines no targeted "
        f"name or URI (R-9.4.2-e)",
        request_id=request_id,
      )
    return

  # Mcp-Name REQUIRED for tools/call, resources/read, prompts/get (R-9.4.2-a).
  if mcp_name is None:
    raise HeaderMismatchError(
      f"required routing header {MCP_NAME_HEADER!r} is missing for {method!r} (R-9.4.2-a)",
      request_id=request_id,
    )
  body_value = (params or {}).get(body_field)
  if mcp_name != body_value:
    raise HeaderMismatchError(
      f"{MCP_NAME_HEADER} {mcp_name!r} does not equal body params.{body_field} "
      f"{body_value!r} (R-9.4.2-b/c/d, R-9.4.3-a)",
      request_id=request_id,
    )


# ---------------------------------------------------------------------------
# §9.5.1  The x-mcp-header annotation
# ---------------------------------------------------------------------------

#: RFC 9110 tchar set for an HTTP field-name token (1*tchar).
_TCHAR: frozenset[str] = frozenset(
  "!#$%&'*+-.^_`|~" + string.ascii_letters + string.digits
)

#: JSON primitive types an x-mcp-header annotation may target (R-9.5.1-e).
_PRIMITIVE_TYPES: frozenset[str] = frozenset({"integer", "string", "boolean"})


def is_valid_tchar_token(value: Any) -> bool:
  """Return True if value is a non-empty HTTP field-name token (1*tchar) (R-9.5.1-b).

  A tchar token contains only the RFC 9110 token characters and therefore can
  contain no control characters, including CR/LF (R-9.5.1-c).
  """
  return isinstance(value, str) and len(value) >= 1 and all(c in _TCHAR for c in value)


def validate_x_mcp_header_value(value: Any, json_type: Any) -> None:
  """Validate a single ``x-mcp-header`` value and its parameter type (R-9.5.1-a/b/c/e/f).

  Checks (uniqueness, R-9.5.1-d, is enforced across the whole schema by
  collect_header_annotations):
    - non-empty (R-9.5.1-a);
    - matches ``1*tchar`` with no control chars incl. CR/LF (R-9.5.1-b/c);
    - the annotated parameter's JSON type is a primitive integer/string/boolean
      (R-9.5.1-e), and is NOT ``number`` (R-9.5.1-f).

  Raises:
    XMcpHeaderError: any constraint is violated.
  """
  if not isinstance(value, str) or value == "":
    raise XMcpHeaderError("x-mcp-header value MUST NOT be empty (R-9.5.1-a)", value=value)
  if not is_valid_tchar_token(value):
    raise XMcpHeaderError(
      "x-mcp-header value MUST match the HTTP field-name token syntax 1*tchar with "
      "no control characters incl. CR/LF (R-9.5.1-b/c)",
      value=value,
    )
  if json_type == "number":
    raise XMcpHeaderError(
      "x-mcp-header MUST NOT be applied to a parameter of JSON type 'number' (R-9.5.1-f)",
      value=value,
    )
  if json_type not in _PRIMITIVE_TYPES:
    raise XMcpHeaderError(
      f"x-mcp-header may only annotate a primitive integer/string/boolean parameter; "
      f"got type {json_type!r} (R-9.5.1-e)",
      value=value,
    )


@dataclass(frozen=True)
class HeaderAnnotation:
  """A resolved ``x-mcp-header`` annotation found in an inputSchema.

  Fields:
    path: the property-name path into ``params.arguments`` where the value lives
      (length > 1 for nested properties, R-9.5.1-h).
    header_name: the name portion; the emitted header is ``Mcp-Param-{name}``.
    json_type: the annotated parameter's JSON primitive type.
  """

  path: tuple[str, ...]
  header_name: str
  json_type: str


def collect_header_annotations(input_schema: dict[str, Any]) -> list[HeaderAnnotation]:
  """Collect & validate every ``x-mcp-header`` annotation in an inputSchema (§9.5.1).

  Walks ``properties`` at any nesting depth (R-9.5.1-h), validating each
  annotation (R-9.5.1-a/b/c/e/f) and enforcing case-insensitive uniqueness of
  the header names across the whole schema (R-9.5.1-d).

  Returns:
    A list of HeaderAnnotation in document order.

  Raises:
    XMcpHeaderError: any annotation is invalid or two names collide
      case-insensitively.
  """
  results: list[HeaderAnnotation] = []
  seen_ci: dict[str, str] = {}

  def walk(schema: Any, path: tuple[str, ...]) -> None:
    if not isinstance(schema, dict):
      return
    props = schema.get("properties")
    if isinstance(props, dict):
      for name, subschema in props.items():
        if not isinstance(subschema, dict):
          continue
        child_path = path + (name,)
        if "x-mcp-header" in subschema:
          header_name = subschema["x-mcp-header"]
          json_type = subschema.get("type")
          validate_x_mcp_header_value(header_name, json_type)
          low = header_name.lower()
          if low in seen_ci:
            raise XMcpHeaderError(
              f"x-mcp-header value {header_name!r} collides case-insensitively with "
              f"{seen_ci[low]!r} in the same inputSchema (R-9.5.1-d)",
              value=header_name,
            )
          seen_ci[low] = header_name
          results.append(HeaderAnnotation(child_path, header_name, json_type))
        # Recurse into nested object properties (R-9.5.1-h).
        walk(subschema, child_path)

  walk(input_schema, ())
  return results


@dataclass
class RejectedTool:
  """A tool excluded from tools/list because its annotation was invalid (R-9.5.1-i)."""

  name: str
  reason: str


def filter_valid_tools(
  tools: list[dict[str, Any]],
  *,
  logger: logging.Logger | None = None,
) -> tuple[list[dict[str, Any]], list[RejectedTool]]:
  """Partition tools into (valid, rejected) by their x-mcp-header validity (§9.5.1).

  A client using this transport MUST reject any tool with an invalid annotation
  and exclude only that tool from the ``tools/list`` result (R-9.5.1-i); a single
  malformed tool MUST NOT prevent other valid tools from being used (R-9.5.1-j).
  Each rejection SHOULD log a warning naming the tool and reason (R-9.5.1-k).

  Args:
    tools: the raw tool definitions returned by the server.
    logger: where to emit warnings (defaults to the module logger).

  Returns:
    ``(valid_tools, rejected)`` — rejected carries the tool name and reason.
  """
  use_logger = logger or _log
  valid: list[dict[str, Any]] = []
  rejected: list[RejectedTool] = []
  for tool in tools:
    name = tool.get("name", "<unnamed>")
    schema = tool.get("inputSchema")
    try:
      if isinstance(schema, dict):
        collect_header_annotations(schema)
      valid.append(tool)
    except XMcpHeaderError as exc:
      rejected.append(RejectedTool(name=name, reason=exc.reason))
      use_logger.warning("Rejected tool %r: %s (R-9.5.1-i/k)", name, exc.reason)
  return valid, rejected


# ---------------------------------------------------------------------------
# §9.5.3  Value encoding (plain form / =?base64?…?= sentinel)
# ---------------------------------------------------------------------------

_SENTINEL_PREFIX: str = "=?base64?"
_SENTINEL_SUFFIX: str = "?="
#: Header whitespace that MUST NOT lead/trail a plain value (R-9.5.3-b).
_HEADER_WHITESPACE: frozenset[str] = frozenset({" ", "\t"})


def _matches_sentinel_shape(s: str) -> bool:
  """True if s begins with the sentinel prefix and ends with the suffix (R-9.5.3-e)."""
  return (
    s.startswith(_SENTINEL_PREFIX)
    and s.endswith(_SENTINEL_SUFFIX)
    and len(s) >= len(_SENTINEL_PREFIX) + len(_SENTINEL_SUFFIX)
  )


def _is_header_value_safe_char(ch: str) -> bool:
  """True if ch is permitted unencoded in a header value: 0x09, 0x20, 0x21–0x7E."""
  o = ord(ch)
  return o == 0x09 or o == 0x20 or 0x21 <= o <= 0x7E


def is_valid_header_value_chars(s: str) -> bool:
  """True if every character of s is permitted in an HTTP header value (R-9.5.4-b)."""
  return all(_is_header_value_safe_char(ch) for ch in s)


def _needs_sentinel(s: str) -> bool:
  """True if s cannot be carried as a plain ASCII header value (R-9.5.3-b/e)."""
  if _matches_sentinel_shape(s):
    return True  # R-9.5.3-e: avoid ambiguity with the sentinel form.
  if s and (s[0] in _HEADER_WHITESPACE or s[-1] in _HEADER_WHITESPACE):
    return True  # leading/trailing whitespace
  return not is_valid_header_value_chars(s)  # non-ASCII or control characters


def _stringify_param_value(value: Any, json_type: str | None) -> str:
  """Convert a parameter value to its per-type string representation (R-9.5.3-a).

  ``string`` as-is; ``integer`` as its decimal string (validated in safe range,
  R-9.5.1-g); ``boolean`` as the lowercase literal ``true``/``false``.
  """
  effective = json_type
  if effective is None:
    # Infer from the Python type (bool before int — bool subclasses int).
    if isinstance(value, bool):
      effective = "boolean"
    elif isinstance(value, int):
      effective = "integer"
    elif isinstance(value, str):
      effective = "string"

  if effective == "boolean":
    if not isinstance(value, bool):
      raise TypeError(f"boolean parameter expected; got {type(value).__name__}")
    return "true" if value else "false"
  if effective == "integer":
    if isinstance(value, bool) or not isinstance(value, int):
      raise TypeError(f"integer parameter expected; got {type(value).__name__}")
    if not is_within_safe_range(value):
      raise ValueError(
        f"annotated integer {value!r} is outside the safe range "
        f"[{SAFE_INTEGER_MIN}, {SAFE_INTEGER_MAX}] (R-9.5.1-g)"
      )
    return str(value)
  if effective == "string":
    if not isinstance(value, str):
      raise TypeError(f"string parameter expected; got {type(value).__name__}")
    return value
  raise TypeError(
    f"x-mcp-header parameter must be integer/string/boolean; got type {json_type!r} (R-9.5.1-e)"
  )


def encode_param_value(value: Any, json_type: str | None = None) -> str:
  """Encode a parameter value for safe placement in a header (R-9.5.3-a/b/c/e).

  Produces the plain string form when it is safe ASCII with no leading/trailing
  whitespace and does not itself match the sentinel pattern; otherwise Base64-
  encodes the UTF-8 bytes and wraps them as ``=?base64?{payload}?=`` (lowercase,
  exact prefix/suffix).

  Args:
    value: the parameter value (string/integer/boolean).
    json_type: the declared JSON type, or None to infer from the Python type.

  Returns:
    The encoded header value.
  """
  s = _stringify_param_value(value, json_type)
  if _needs_sentinel(s):
    payload = base64.b64encode(s.encode("utf-8")).decode("ascii")
    return f"{_SENTINEL_PREFIX}{payload}{_SENTINEL_SUFFIX}"
  return s


def decode_param_value(encoded: str) -> str:
  """Decode a header value, unwrapping the sentinel form when present (R-9.5.3-d).

  Detects the ``=?base64?…?=`` sentinel and decodes the Base64 payload as UTF-8;
  otherwise returns the value unchanged.
  """
  if _matches_sentinel_shape(encoded):
    payload = encoded[len(_SENTINEL_PREFIX):-len(_SENTINEL_SUFFIX)]
    return base64.b64decode(payload).decode("utf-8")
  return encoded


# ---------------------------------------------------------------------------
# §9.5.2  Client emission of Mcp-Param-{name} headers
# ---------------------------------------------------------------------------

def _resolve_path(arguments: Any, path: tuple[str, ...]) -> tuple[bool, Any]:
  """Resolve a property path into arguments. Returns (present, value)."""
  current = arguments
  for segment in path:
    if not isinstance(current, dict) or segment not in current:
      return False, None
    current = current[segment]
  return True, current


def build_param_headers(
  input_schema: dict[str, Any] | None,
  arguments: dict[str, Any],
) -> dict[str, str]:
  """Build the ``Mcp-Param-{name}`` headers for a tools/call POST (§9.5.2).

  For each annotated parameter present (and non-null) in ``arguments``, emits one
  encoded ``Mcp-Param-{name}`` header (R-9.5.2-b/c/d/e). A parameter that is
  ``null`` or absent yields no header (R-9.5.2-g/i). When ``input_schema`` is None
  (schema unknown or stale), no custom headers are emitted (R-9.5.2-l).

  Returns:
    A mapping of header name → encoded value.
  """
  if input_schema is None:
    return {}
  headers: dict[str, str] = {}
  for annotation in collect_header_annotations(input_schema):
    present, value = _resolve_path(arguments, annotation.path)
    if not present or value is None:
      continue  # omit header for null/absent values (R-9.5.2-g/i)
    headers[MCP_PARAM_PREFIX + annotation.header_name] = encode_param_value(
      value, annotation.json_type
    )
  return headers


def build_post_headers(
  method: str,
  params: dict[str, Any] | None,
  protocol_version: str,
  *,
  input_schema: dict[str, Any] | None = None,
) -> dict[str, str]:
  """Build the full header set for a client POST (§9.3–§9.5).

  Includes the required request headers (Content-Type, Accept,
  MCP-Protocol-Version), the routing headers (Mcp-Method, and Mcp-Name where
  applicable), and — for ``tools/call`` with a known ``input_schema`` — the
  ``Mcp-Param-*`` headers (R-9.2-f, R-9.5.2-a/d).

  Args:
    method: the JSON-RPC method.
    params: the request params (for Mcp-Name and argument values).
    protocol_version: the negotiated revision (mirrors _meta protocolVersion).
    input_schema: the tool's inputSchema, for Mcp-Param-* emission on tools/call.

  Returns:
    The complete header mapping for the POST.
  """
  headers: dict[str, str] = {
    CONTENT_TYPE_HEADER: CONTENT_TYPE_VALUE,
    ACCEPT_HEADER: ACCEPT_VALUE,
    MCP_PROTOCOL_VERSION_HEADER: protocol_version,
  }
  headers.update(build_routing_headers(method, params))
  if method == "tools/call" and input_schema is not None:
    arguments = (params or {}).get("arguments", {})
    headers.update(build_param_headers(input_schema, arguments))
  return headers


def send_without_param_headers(*, schema_known: bool, schema_stale: bool = False) -> bool:
  """Return True when a tools/call SHOULD be sent without custom Mcp-Param-* headers.

  When the client lacks the tool's inputSchema or the cached schema is stale, it
  SHOULD send the request without custom headers; if the server then rejects for
  missing required headers, the client SHOULD call ``tools/list`` to refresh and
  retry (R-9.5.2-l/m). A client MAY pre-load schemas to emit headers without a
  prior ``tools/list`` (R-9.5.2-n).
  """
  return (not schema_known) or schema_stale


# ---------------------------------------------------------------------------
# §9.5.4  Receiver validation of parameter headers
# ---------------------------------------------------------------------------

def _param_values_match(decoded: str, body_value: Any, json_type: str) -> bool:
  """Compare a decoded header value to the body value by JSON type (R-9.5.4-c/d)."""
  if json_type == "integer":
    # R-9.5.4-d: compare numerically (e.g. header "42.0" equals body 42).
    try:
      return float(decoded) == float(body_value)
    except (TypeError, ValueError):
      return False
  if json_type == "boolean":
    return decoded == ("true" if body_value else "false")
  # string (and any other primitive): exact comparison.
  return decoded == body_value


def validate_param_headers(
  headers: dict[str, Any],
  input_schema: dict[str, Any],
  arguments: dict[str, Any],
  *,
  request_id: RequestId | None = None,
) -> None:
  """Validate recognized Mcp-Param-{name} headers against the body (server side, §9.5.4).

  For each annotated parameter:
    - if the body value is null or absent, the header MUST be omitted; a present
      header is a mismatch (R-9.5.2-h/j);
    - if the body value is present, the header MUST be present (R-9.5.2-k);
    - the (raw) header value MUST contain only permitted characters (R-9.5.4-b);
    - the decoded value MUST match the body value, integers compared numerically
      (R-9.5.4-c/d).

  An intermediary that does not recognize a header forwards and ignores it
  (R-9.5.4-a) — this body-processing receiver validates only recognized
  (schema-declared) parameter headers.

  Raises:
    HeaderMismatchError: any header is missing-while-required, present-while-
      omitted, malformed, or disagrees with the body (-32001, HTTP 400).
  """
  for annotation in collect_header_annotations(input_schema):
    header_name = MCP_PARAM_PREFIX + annotation.header_name
    header_val = get_header(headers, header_name)
    present, body_value = _resolve_path(arguments, annotation.path)

    if not present or body_value is None:
      # Body value null/absent → header MUST NOT be present (R-9.5.2-h/j).
      if header_val is not None:
        raise HeaderMismatchError(
          f"{header_name} present but the body value is null/absent (R-9.5.2-h/j)",
          request_id=request_id,
        )
      continue

    # Body value present → header MUST be present (R-9.5.2-k).
    if header_val is None:
      raise HeaderMismatchError(
        f"required parameter header {header_name!r} is missing while the body "
        f"carries the value (R-9.5.2-k)",
        request_id=request_id,
      )

    # Raw header value character validity (R-9.5.4-b).
    if not is_valid_header_value_chars(header_val):
      raise HeaderMismatchError(
        f"{header_name} contains characters not permitted in a header value (R-9.5.4-b)",
        request_id=request_id,
      )

    # Decode and compare to the body (R-9.5.4-c/d).
    try:
      decoded = decode_param_value(header_val)
    except (ValueError, UnicodeDecodeError) as exc:
      raise HeaderMismatchError(
        f"{header_name} sentinel payload could not be decoded: {exc} (R-9.5.4-c)",
        request_id=request_id,
      ) from exc
    if not _param_values_match(decoded, body_value, annotation.json_type):
      raise HeaderMismatchError(
        f"{header_name} decoded value {decoded!r} does not match body value "
        f"{body_value!r} (R-9.5.4-c)",
        request_id=request_id,
      )


def unsupported_protocol_version_response(
  request_id: RequestId | None,
  error: UnsupportedRevisionError,
) -> JSONRPCErrorResponse:
  """Map an UnsupportedRevisionError to its -32004 JSON-RPC response (R-9.3.3-e).

  Convenience bridge: builds the §5.5 ``UnsupportedProtocolVersion`` response
  (HTTP 400) whose ``data.supported`` lists the server's versions and
  ``data.requested`` echoes the rejected version.
  """
  return build_unsupported_protocol_version_response(
    request_id,
    sorted(error.supported),
    error.requested,
  )
