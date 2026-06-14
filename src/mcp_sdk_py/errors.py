"""Error Handling & the Consolidated Error-Code Registry — S34.

This module is the single, authoritative model of how MCP failures appear on
the wire (§22). Every earlier feature can now fail, so this story centralizes:

  - the consolidated error-code registry (standard JSON-RPC codes, MCP
    protocol-specific codes, and the Streamable HTTP transport code), assembled
    here by *referencing* — never re-defining — the codes other modules own;
  - the cross-cutting error semantics: the exactly-one-of result/error rule, the
    `code`-is-authoritative rule, the normative `data` shapes for §22.3 codes,
    the canonical mapping of validation failures to -32602, the protocol-error
    vs. feature-level-error-result boundary, the transport status mapping, the
    `id`-omission and no-response-to-notifications rules, and the extensibility
    rules for extension-defined and unknown codes.

Code ownership (reused, not redefined):
  - Standard codes -32700/-32600/-32601/-32602/-32603 and the canonical
    `ErrorObject` come from S04 (`result_error.py`, §3.8).
  - -32004 UnsupportedProtocolVersion and -32003 MissingRequiredClientCapability
    come from S09 (`negotiation.py`, §5.5/§5.6); this module re-exports their
    code constants and reuses their builders.
  - -32001 HeaderMismatch is owned by S14/S15 (`streamable_http.py` /
    `http_responses.py`, §9.8); this module references the code constant.
  - The HTTP status mapping is owned by S15 (`http_responses.py`, §9.7); this
    module references it via the §9.7 condition table.

Public surface:

Registry (§22.2/§22.3/§22.5):
  - PARSE_ERROR_CODE / INVALID_REQUEST_CODE / METHOD_NOT_FOUND_CODE /
    INVALID_PARAMS_CODE / INTERNAL_ERROR_CODE — the five standard codes (S04).
  - UNSUPPORTED_PROTOCOL_VERSION_CODE / MISSING_REQUIRED_CLIENT_CAPABILITY_CODE —
    the protocol-specific codes (re-exported from S09).
  - HEADER_MISMATCH_CODE — the transport code (re-exported from S14).
  - STANDARD_ERROR_CODES / PROTOCOL_SPECIFIC_ERROR_CODES / RESERVED_ERROR_CODES.
  - ErrorCodeEntry / ERROR_CODE_REGISTRY / error_code_entry() / error_code_name().
  - SERVER_ERROR_RANGE_MIN / SERVER_ERROR_RANGE_MAX — the JSON-RPC server-error
    range that -32001 lies within.

Envelope & object validation (§22.1):
  - validate_error_response(): the exactly-one-of result/error envelope rule.
  - is_error_response() / is_success_response().
  - classify_by_code(): code is authoritative, never `message` (R-22.1-j).

Protocol-specific data (§22.3):
  - validate_missing_required_client_capability_data() — normative -32003 data.
  - validate_unsupported_protocol_version_data() — normative -32004 data.
  - build_missing_required_client_capability_error /
    build_unsupported_protocol_version_error (re-exported from S09).

Canonical -32602 conditions (§22.4):
  - Reason / INVALID_PARAMS_REASONS.
  - build_invalid_params_error() / build_resource_not_found_error().
  - is_resource_not_found_signalled_by_empty_contents() — the forbidden signal.

Protocol error vs. feature-level error result (§22.5):
  - ToolFailureMode / classify_tool_failure(): protocol -32602 vs. isError result.
  - build_tool_execution_error_result(): the isError-true success result.
  - assert_tool_dispatch_failure_is_protocol_error /
    assert_tool_execution_failure_is_result.

Transport mapping & malformed input (§22.6):
  - TransportCondition / map_transport_condition(): code (+ HTTP status).
  - code_for_unparseable_input() / code_for_invalid_request_object().
  - error_id_for_request() / response_id_for_undeterminable_request().
  - should_respond_to_message(): no response to notifications.

Extensibility & unknown codes (§22.7):
  - validate_extension_error_code(): integer, non-colliding (R-22.7-a/b/c).
  - is_reserved_error_code() / is_known_error_code().
  - surface_unknown_error(): tolerate & surface an unrecognized code (R-22.7-e).
  - SurfacedError.

Spec: §22 (lines 6014–6227)
Depends on: S04 (ErrorObject, standard codes), S09 (-32003/-32004), S15 (-32001,
  HTTP status mapping)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from mcp_sdk_py.http_responses import Condition, map_condition_to_status
from mcp_sdk_py.jsonrpc import JSONRPCErrorResponse, RequestId
from mcp_sdk_py.negotiation import (
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
  build_missing_required_client_capability_error,
  build_unsupported_protocol_version_error,
  parse_unsupported_protocol_version_error,
)
from mcp_sdk_py.result_error import ErrorObject, validate_error_object
from mcp_sdk_py.streamable_http import HEADER_MISMATCH_CODE


# ---------------------------------------------------------------------------
# §22.2  Standard JSON-RPC error codes (defined in S04; named & gathered here)
# ---------------------------------------------------------------------------
#
# These five integers are the standard JSON-RPC codes the protocol reuses
# verbatim (§22.2). The numeric values are fixed by JSON-RPC 2.0; this module
# is the consolidated registry that names them and records the condition each
# signals (R-22.2-a..f).

#: -32700 Parse error: the byte stream could not be parsed as JSON (R-22.2-b).
PARSE_ERROR_CODE: int = -32700
#: -32600 Invalid Request: valid JSON but not a valid request object (R-22.2-c).
INVALID_REQUEST_CODE: int = -32600
#: -32601 Method not found: method unknown/unavailable on the receiver (R-22.2-d).
METHOD_NOT_FOUND_CODE: int = -32601
#: -32602 Invalid params: parameters invalid or malformed; see §22.4 (R-22.2-e).
INVALID_PARAMS_CODE: int = -32602
#: -32603 Internal error: an unexpected server-side condition (R-22.2-f).
INTERNAL_ERROR_CODE: int = -32603


# ---------------------------------------------------------------------------
# §22.3 / §9.8  Protocol-specific & transport codes (owned elsewhere; re-exported)
# ---------------------------------------------------------------------------
#
# -32003 and -32004 are owned by S09 (negotiation.py); -32001 by S14/S15. This
# registry re-exports the constants (imported above) so callers can reach the
# entire authoritative code set through `mcp_sdk_py.errors` without re-defining
# any value (consolidation goal). The names below are re-bound from the imports.

#: -32004 UnsupportedProtocolVersion (owned by S09 §5.5; re-exported, §22.3.2).
UNSUPPORTED_PROTOCOL_VERSION_CODE = UNSUPPORTED_PROTOCOL_VERSION_CODE
#: -32003 MissingRequiredClientCapability (owned by S09 §5.6; re-exported, §22.3.1).
MISSING_REQUIRED_CLIENT_CAPABILITY_CODE = MISSING_REQUIRED_CLIENT_CAPABILITY_CODE
#: -32001 HeaderMismatch (owned by S14/S15 §9.8; re-exported, referenced by §22.6/§22.7).
HEADER_MISMATCH_CODE = HEADER_MISMATCH_CODE

#: The implementation-defined JSON-RPC server-error range -32000..-32099 that
#: -32001 (HeaderMismatch) lies within (§22.6, §22.7, §9.8).
SERVER_ERROR_RANGE_MIN: int = -32099
SERVER_ERROR_RANGE_MAX: int = -32000


# ---------------------------------------------------------------------------
# §22.2 / §22.3 / §22.7  Consolidated registry tables
# ---------------------------------------------------------------------------

#: The five standard JSON-RPC codes (§22.2), in registry order.
STANDARD_ERROR_CODES: frozenset[int] = frozenset({
  PARSE_ERROR_CODE,
  INVALID_REQUEST_CODE,
  METHOD_NOT_FOUND_CODE,
  INVALID_PARAMS_CODE,
  INTERNAL_ERROR_CODE,
})

#: The MCP protocol-specific codes (§22.3); their `data` shape is normative.
PROTOCOL_SPECIFIC_ERROR_CODES: frozenset[int] = frozenset({
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
})

#: Every code reserved by this specification: the standard codes, the
#: protocol-specific codes, and the Streamable HTTP transport code -32001. An
#: extension-defined code MUST NOT collide with any of these (R-22.7-c).
RESERVED_ERROR_CODES: frozenset[int] = (
  STANDARD_ERROR_CODES
  | PROTOCOL_SPECIFIC_ERROR_CODES
  | frozenset({HEADER_MISMATCH_CODE})
)


@dataclass(frozen=True)
class ErrorCodeEntry:
  """One row of the consolidated §22 error-code registry.

  Fields:
    code: the numeric error code (authoritative; never inferred from message).
    name: the registry name for the code (e.g. "Parse error", "HeaderMismatch").
    owner: the story/section that defines the code (this story references it).
    data_normative: True iff the §22.3 `data` shape is normative for this code
      (true only for -32003 and -32004); False when `data` is sender-defined.
  """

  code: int
  name: str
  owner: str
  data_normative: bool = False


#: The authoritative, consolidated §22 registry, keyed by code (R-22.2-a, §22.3,
#: §22.6). Each entry records the registry name and the owning story/section;
#: codes whose definition lives in another module are referenced, not redefined.
ERROR_CODE_REGISTRY: dict[int, ErrorCodeEntry] = {
  PARSE_ERROR_CODE: ErrorCodeEntry(
    PARSE_ERROR_CODE, "Parse error", "S04/§22.2"
  ),
  INVALID_REQUEST_CODE: ErrorCodeEntry(
    INVALID_REQUEST_CODE, "Invalid Request", "S04/§22.2"
  ),
  METHOD_NOT_FOUND_CODE: ErrorCodeEntry(
    METHOD_NOT_FOUND_CODE, "Method not found", "S04/§22.2"
  ),
  INVALID_PARAMS_CODE: ErrorCodeEntry(
    INVALID_PARAMS_CODE, "Invalid params", "S04/§22.2, §22.4"
  ),
  INTERNAL_ERROR_CODE: ErrorCodeEntry(
    INTERNAL_ERROR_CODE, "Internal error", "S04/§22.2"
  ),
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE: ErrorCodeEntry(
    MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
    "MissingRequiredClientCapability",
    "S09/§22.3.1",
    data_normative=True,
  ),
  UNSUPPORTED_PROTOCOL_VERSION_CODE: ErrorCodeEntry(
    UNSUPPORTED_PROTOCOL_VERSION_CODE,
    "UnsupportedProtocolVersion",
    "S09/§22.3.2",
    data_normative=True,
  ),
  HEADER_MISMATCH_CODE: ErrorCodeEntry(
    HEADER_MISMATCH_CODE, "HeaderMismatch", "S15/§9.8"
  ),
}


def error_code_entry(code: int) -> ErrorCodeEntry | None:
  """Return the registry entry for ``code``, or None when it is not reserved (§22.2/§22.3).

  A None result means the code is not one this specification reserves; it may be
  an extension-defined code (§22.7) and MUST still be tolerated by receivers
  (R-22.7-e). The lookup is by exact integer code; `message` is never consulted
  (R-22.1-j).
  """
  return ERROR_CODE_REGISTRY.get(code)


def error_code_name(code: int) -> str | None:
  """Return the registry name for ``code``, or None when it is not reserved (§22.2/§22.3)."""
  entry = ERROR_CODE_REGISTRY.get(code)
  return entry.name if entry is not None else None


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class MalformedErrorResponseError(Exception):
  """A response object violates the §22.1 exactly-one-of result/error rule.

  Raised by validate_error_response() / validate_success_response() when a
  response carries both ``result`` and ``error`` or neither (R-22.1-a), or when
  the envelope's ``jsonrpc`` is not the exact string "2.0" (R-22.1-d).
  """


class ReservedErrorCodeCollisionError(Exception):
  """An extension-defined error code collides with a reserved code (§22.7).

  Raised by validate_extension_error_code() when the proposed code equals one of
  the standard codes, the protocol-specific codes, or the transport code -32001
  (R-22.7-c).

  Attributes:
    code: the colliding code.
    collides_with: the registry name of the reserved code it collides with.
  """

  def __init__(self, code: int, collides_with: str) -> None:
    super().__init__(
      f"extension-defined error code {code} collides with the reserved code "
      f"{collides_with} ({code}); extension codes MUST NOT collide with any "
      f"code defined in this specification (R-22.7-c)"
    )
    self.code: int = code
    self.collides_with: str = collides_with


class ProtocolErrorMisuseError(Exception):
  """The wrong §22.5 mechanism was chosen for reporting a failure.

  Raised when a tool *dispatch* failure (unknown tool / schema-invalid
  arguments) is reported as a feature-level ``isError`` result (R-22.5-f), or a
  tool *execution* failure is reported as a JSON-RPC error (R-22.5-e). Senders
  MUST choose the correct mechanism (R-22.5-a).
  """


# ---------------------------------------------------------------------------
# §22.1  The error response envelope: exactly one of result / error
# ---------------------------------------------------------------------------

#: The exact, case-sensitive JSON-RPC version marker every message carries
#: (R-22.1-d, R-22-a). Reproduced verbatim on the wire.
JSONRPC_VERSION: str = "2.0"


def is_error_response(response: dict[str, Any]) -> bool:
  """Return True iff ``response`` is an error response (carries ``error``, not ``result``).

  A response is an error response when it has an ``error`` member and no
  ``result`` member (§22.1). A response with both or neither is non-conformant
  and is neither an error nor a success response (R-22.1-a) — use
  validate_error_response() to reject it.
  """
  return "error" in response and "result" not in response


def is_success_response(response: dict[str, Any]) -> bool:
  """Return True iff ``response`` is a success response (carries ``result``, not ``error``).

  A response is a success response when it has a ``result`` member and no
  ``error`` member (§22.1, R-22.1-a).
  """
  return "result" in response and "error" not in response


def validate_error_response(response: dict[str, Any]) -> ErrorObject:
  """Validate an error-response envelope and return its parsed ``error`` (§22.1).

  Enforces, for the *error* form of a response:
    - exactly one of ``result``/``error`` — an error response MUST carry
      ``error`` and MUST NOT carry ``result`` (R-22.1-a);
    - ``jsonrpc`` is exactly the string "2.0" (R-22.1-d);
    - the ``error`` object is the canonical §3.8 Error with a REQUIRED integer
      ``code`` (MAY be negative) and a REQUIRED string ``message`` (R-22.1-c/h/i),
      validated by S04's validate_error_object();
    - ``data`` is treated as OPTIONAL; for -32003/-32004 the normative shape is
      checked (R-22.1-k, R-22.3-a).

  The ``id`` member is intentionally not constrained here: it is REQUIRED in the
  normal case but MAY be omitted/null when the request id could not be determined
  (R-22.1-f, §22.6) — see error_id_for_request() / response_id_for_undeterminable_request().

  Args:
    response: the decoded response object.

  Returns:
    The validated ErrorObject from the ``error`` member.

  Raises:
    TypeError: response is not a dict.
    MalformedErrorResponseError: both/neither result and error, or jsonrpc wrong.
    ValueError / TypeError: the ``error`` object itself is malformed (from S04),
      or a §22.3 normative ``data`` shape is violated.
  """
  if not isinstance(response, dict):
    raise TypeError(
      f"response must be a JSON object; got {type(response).__name__}"
    )
  _assert_exactly_one_response_member(response)
  if "error" not in response:
    raise MalformedErrorResponseError(
      "an error response MUST contain an `error` member, never a `result` "
      "(R-22.1-a)"
    )
  _assert_jsonrpc_version(response)

  error = validate_error_object(response["error"])
  # For the §22.3 codes the data shape is normative (R-22.3-a, R-22.1-k).
  if error.code == MISSING_REQUIRED_CLIENT_CAPABILITY_CODE and error.has_data:
    validate_missing_required_client_capability_data(error.data)
  elif error.code == UNSUPPORTED_PROTOCOL_VERSION_CODE and error.has_data:
    validate_unsupported_protocol_version_data(error.data)
  return error


def validate_success_response(response: dict[str, Any]) -> dict[str, Any]:
  """Validate a success-response envelope and return its ``result`` (§22.1).

  Enforces the converse of validate_error_response(): a success response MUST
  carry ``result`` and MUST NOT carry ``error`` (R-22.1-a), and ``jsonrpc`` MUST
  be exactly "2.0" (R-22.1-d). The ``result`` shape itself is owned by S04 and
  not re-validated here.

  Raises:
    TypeError: response is not a dict, or ``result`` is not an object.
    MalformedErrorResponseError: both/neither member present, or jsonrpc wrong.
  """
  if not isinstance(response, dict):
    raise TypeError(
      f"response must be a JSON object; got {type(response).__name__}"
    )
  _assert_exactly_one_response_member(response)
  if "result" not in response:
    raise MalformedErrorResponseError(
      "a success response MUST contain a `result` member, never an `error` "
      "(R-22.1-a)"
    )
  _assert_jsonrpc_version(response)
  result = response["result"]
  if not isinstance(result, dict):
    raise TypeError(
      f"result must be a JSON object; got {type(result).__name__}"
    )
  return result


def _assert_exactly_one_response_member(response: dict[str, Any]) -> None:
  """Assert exactly one of ``result``/``error`` is present (R-22.1-a)."""
  has_result = "result" in response
  has_error = "error" in response
  if has_result and has_error:
    raise MalformedErrorResponseError(
      "a response object MUST contain exactly one of `result` or `error`, never "
      "both (R-22.1-a)"
    )
  if not has_result and not has_error:
    raise MalformedErrorResponseError(
      "a response object MUST contain exactly one of `result` or `error`, never "
      "neither (R-22.1-a)"
    )


def _assert_jsonrpc_version(response: dict[str, Any]) -> None:
  """Assert ``jsonrpc`` is exactly the string "2.0" (R-22.1-d, R-22-a)."""
  jsonrpc = response.get("jsonrpc")
  if jsonrpc != JSONRPC_VERSION:
    raise MalformedErrorResponseError(
      f"`jsonrpc` MUST be exactly the string {JSONRPC_VERSION!r}; got "
      f"{jsonrpc!r} (R-22.1-d)"
    )


def classify_by_code(error: ErrorObject | dict[str, Any]) -> int:
  """Return the authoritative condition for an error: its ``code`` (R-22.1-j).

  The condition is identified by the numeric ``code`` alone. The ``message`` is
  informational and MUST NOT be parsed to determine the condition — two errors
  differing only in ``message`` classify identically. This function deliberately
  ignores ``message`` entirely and returns the integer ``code``.

  Args:
    error: an ErrorObject or its raw ``error`` wire dict.

  Returns:
    The integer ``code``.

  Raises:
    TypeError: the error has no integer ``code``.
    ValueError: ``code`` is absent.
  """
  if isinstance(error, ErrorObject):
    return error.code
  validated = validate_error_object(error)
  return validated.code


# ---------------------------------------------------------------------------
# §22.3  Normative `data` shapes for the protocol-specific codes
# ---------------------------------------------------------------------------

def validate_missing_required_client_capability_data(data: Any) -> dict[str, Any]:
  """Validate the normative `data` for -32003 and return ``requiredCapabilities`` (§22.3.1).

  The `data` member of a MissingRequiredClientCapability error MUST be an object
  carrying ``requiredCapabilities`` — a ClientCapabilities object enumerating the
  capabilities the server requires from the client to process the request
  (R-22.3-a, R-22.3.1-b). The actual capability shape is owned by S10.

  Returns:
    The ``requiredCapabilities`` object.

  Raises:
    TypeError: ``data`` is not an object, or ``requiredCapabilities`` is not one.
    ValueError: ``requiredCapabilities`` is absent.
  """
  if not isinstance(data, dict):
    raise TypeError(
      f"-32003 data MUST be a JSON object; got {type(data).__name__} (R-22.3-a)"
    )
  if "requiredCapabilities" not in data:
    raise ValueError(
      "-32003 data MUST carry `requiredCapabilities` listing the capabilities "
      "the server requires from the client (R-22.3.1-b)"
    )
  required = data["requiredCapabilities"]
  if not isinstance(required, dict):
    raise TypeError(
      "-32003 data.requiredCapabilities MUST be a ClientCapabilities object; "
      f"got {type(required).__name__} (R-22.3.1-b)"
    )
  return required


def validate_unsupported_protocol_version_data(data: Any) -> tuple[list[str], str]:
  """Validate the normative `data` for -32004 and return ``(supported, requested)`` (§22.3.2).

  The `data` member of an UnsupportedProtocolVersion error MUST be an object
  carrying ``supported`` (a non-empty array of revision strings the server
  supports, from which the client SHOULD pick one and retry) and ``requested``
  (the echoed requested revision string) (R-22.3-a, R-22.3.2-a).

  Returns:
    A ``(supported, requested)`` tuple.

  Raises:
    TypeError: ``data`` is not an object.
    ValueError: ``supported`` is absent/empty/non-array, or ``requested`` absent
      or not a string.
  """
  if not isinstance(data, dict):
    raise TypeError(
      f"-32004 data MUST be a JSON object; got {type(data).__name__} (R-22.3-a)"
    )
  supported = data.get("supported")
  if not isinstance(supported, list) or not supported:
    raise ValueError(
      "-32004 data.supported MUST be a non-empty array of supported revisions "
      "(R-22.3.2-a)"
    )
  for v in supported:
    if not isinstance(v, str):
      raise ValueError(
        "-32004 data.supported entries MUST be revision strings (R-22.3.2-a)"
      )
  requested = data.get("requested")
  if not isinstance(requested, str):
    raise ValueError(
      "-32004 data.requested MUST echo the requested revision string "
      "(R-22.3.2-a)"
    )
  return list(supported), requested


def client_should_retry_on_unsupported_version(
  error: ErrorObject | dict[str, Any],
) -> list[str]:
  """Return the revisions a client SHOULD retry from after a -32004 (R-22.3.2-b).

  On receiving an UnsupportedProtocolVersion error, the client SHOULD choose a
  mutually supported revision from ``data.supported`` and retry. This returns the
  ``supported`` list (the candidate revisions to pick from); the actual
  preference-ordered selection is owned by S09's RevisionNegotiator.

  Raises:
    ValueError: the error is not a well-formed -32004 (wrong code or bad data).
  """
  supported, _requested = parse_unsupported_protocol_version_error(error)
  return supported


# ---------------------------------------------------------------------------
# §22.4  Canonical uses of -32602 (Invalid params)
# ---------------------------------------------------------------------------

class Reason(Enum):
  """The §22.4 conditions of a well-formed request that map to -32602.

  Each member names a validation failure of an otherwise well-formed request
  that MUST be reported with -32602 (R-22.4-a..g). The listed set is a *minimum*,
  not exhaustive: other well-formed-parameter validation failures (e.g. an
  invalid logging level) likewise use -32602 (R-22.4-a) and are covered by the
  catch-all OTHER_PARAM_VALIDATION member.
  """

  UNKNOWN_TOOL_NAME = "unknown_tool_name"
  INVALID_TOOL_ARGUMENTS = "invalid_tool_arguments"
  UNKNOWN_PROMPT_NAME = "unknown_prompt_name"
  MISSING_REQUIRED_PROMPT_ARGUMENT = "missing_required_prompt_argument"
  UNKNOWN_RESOURCE_TEMPLATE = "unknown_resource_template"
  INVALID_OR_EXPIRED_CURSOR = "invalid_or_expired_cursor"
  RESOURCE_NOT_FOUND = "resource_not_found"
  OTHER_PARAM_VALIDATION = "other_param_validation"


#: The explicit minimum set of §22.4 conditions that MUST map to -32602
#: (R-22.4-b..g). Every member of Reason maps to INVALID_PARAMS_CODE; this frozen
#: set is the enumerated minimum the spec lists by name.
INVALID_PARAMS_REASONS: frozenset[Reason] = frozenset({
  Reason.UNKNOWN_TOOL_NAME,
  Reason.INVALID_TOOL_ARGUMENTS,
  Reason.UNKNOWN_PROMPT_NAME,
  Reason.MISSING_REQUIRED_PROMPT_ARGUMENT,
  Reason.UNKNOWN_RESOURCE_TEMPLATE,
  Reason.INVALID_OR_EXPIRED_CURSOR,
  Reason.RESOURCE_NOT_FOUND,
})


def code_for_invalid_params_reason(reason: Reason) -> int:
  """Return the code for a §22.4 condition: always -32602 (R-22.4-a..g).

  Every well-formed-request parameter-validation failure in §22.4 — and any
  other such failure (R-22.4-a) — maps to -32602 (Invalid params). An unexpected
  server-side condition is *not* a §22.4 reason and SHOULD use -32603 instead;
  see code_for_unexpected_server_condition() (R-22.4-j).
  """
  if not isinstance(reason, Reason):
    raise TypeError(
      f"reason must be a Reason; got {type(reason).__name__}"
    )
  return INVALID_PARAMS_CODE


def code_for_unexpected_server_condition() -> int:
  """Return -32603 for an unexpected server-side condition (R-22.4-j).

  When a well-formed request fails not on parameter validation but on an
  unexpected server-side condition, the server SHOULD return -32603 (Internal
  error) rather than -32602.
  """
  return INTERNAL_ERROR_CODE


def build_invalid_params_error(
  message: str,
  *,
  data: Any = None,
) -> ErrorObject:
  """Build a -32602 Invalid params error object (§22.4).

  Args:
    message: human-readable description (informational; not parsed, R-22.1-j).
    data: OPTIONAL sender-defined structured data (e.g. ``{"toolName": ...}``);
      omitted from the wire when None (R-22.1-k).

  Returns:
    An ErrorObject with code -32602.
  """
  if data is None:
    return ErrorObject(code=INVALID_PARAMS_CODE, message=message)
  return ErrorObject(code=INVALID_PARAMS_CODE, message=message, data=data)


def build_resource_not_found_error(
  uri: str,
  *,
  message: str = "Resource not found",
) -> ErrorObject:
  """Build the -32602 resource-not-found error with ``data.uri`` (§22.4, R-22.4-g/h).

  A ``resources/read`` for a URI that does not exist MUST return -32602
  (R-22.4-g); the ``error.data`` SHOULD include a ``uri`` member identifying the
  requested resource (R-22.4-h). A server MUST NOT instead signal non-existence
  by returning an empty ``contents`` array (R-22.4-i) — see
  is_resource_not_found_signalled_by_empty_contents().

  Args:
    uri: the requested resource URI to echo in ``data.uri``.
    message: human-readable description.

  Returns:
    An ErrorObject with code -32602 and ``data = {"uri": uri}``.

  Raises:
    TypeError: uri is not a string.
  """
  if not isinstance(uri, str):
    raise TypeError(f"uri must be a string; got {type(uri).__name__} (R-22.4-h)")
  return ErrorObject(
    code=INVALID_PARAMS_CODE,
    message=message,
    data={"uri": uri},
  )


def is_resource_not_found_signalled_by_empty_contents(result: dict[str, Any]) -> bool:
  """True iff a result tries to signal not-found via an empty ``contents`` array (R-22.4-i).

  A server MUST NOT signal a non-existent resource by returning a successful
  result whose ``contents`` is an empty array, because an empty array is
  ambiguous — it could mean the resource exists but is empty. Non-existence MUST
  instead be a -32602 error (R-22.4-g). This predicate detects the forbidden
  shape (``contents == []``) so callers can reject it.

  Returns:
    True iff ``result`` has a ``contents`` key whose value is an empty list.
  """
  return result.get("contents") == []


# ---------------------------------------------------------------------------
# §22.5  Protocol errors vs. feature-level error results
# ---------------------------------------------------------------------------

class ToolFailureMode(Enum):
  """How a ``tools/call`` failure MUST be reported (§22.5).

  PROTOCOL_ERROR: the request could not be dispatched/processed — an unknown
    tool or arguments that fail schema validation — and MUST be a JSON-RPC error
    with -32602 (R-22.5-c). It is NEVER reported via ``isError`` (R-22.5-f).
  EXECUTION_ERROR_RESULT: the tool was dispatched and ran but its work failed;
    this MUST be a *successful* response whose ``result`` has ``isError: true``,
    NOT a JSON-RPC error (R-22.5-b/d/e).
  """

  PROTOCOL_ERROR = "protocol_error"
  EXECUTION_ERROR_RESULT = "execution_error_result"


def classify_tool_failure(*, tool_dispatched_and_ran: bool) -> ToolFailureMode:
  """Pick the §22.5 reporting mechanism for a tool failure (R-22.5-a..f).

  The single discriminator is whether the tool was actually dispatched and ran:
    - if it never ran (unknown tool, or arguments failing schema validation), the
      failure is a protocol error reported with -32602 (R-22.5-c) — PROTOCOL_ERROR;
    - if it ran but its work failed, the failure is a feature-level error result
      with ``isError: true`` (R-22.5-b/d) — EXECUTION_ERROR_RESULT.

  Senders MUST choose correctly and MUST NOT conflate the two (R-22.5-a/e/f).

  Args:
    tool_dispatched_and_ran: True iff the named tool was found and executed.

  Returns:
    EXECUTION_ERROR_RESULT when the tool ran, else PROTOCOL_ERROR.
  """
  return (
    ToolFailureMode.EXECUTION_ERROR_RESULT
    if tool_dispatched_and_ran
    else ToolFailureMode.PROTOCOL_ERROR
  )


def build_tool_execution_error_result(
  content: list[dict[str, Any]],
) -> dict[str, Any]:
  """Build the §22.5 feature-level error *result* for a tool that ran but failed (R-22.5-b/d).

  When a tool runs but its execution fails, the server MUST return a normal
  successful response whose ``result`` carries ``isError: true`` and content
  describing the failure — NOT a JSON-RPC error (R-22.5-b). The full tool-result
  shape is owned by S25; this builds the minimal ``{content, isError: true}``
  body. The caller wraps it in a success response (carrying ``result``, never
  ``error``), so it can never be mistaken for a protocol error (R-22.5-e).

  Args:
    content: the content blocks describing the failure (shape owned by S21/S25).

  Returns:
    A result dict ``{"content": content, "isError": True}``.
  """
  return {"content": list(content), "isError": True}


def assert_tool_dispatch_failure_is_protocol_error(
  *,
  reported_as_is_error_result: bool,
) -> None:
  """Assert a tool-*dispatch* failure is NOT reported via ``isError`` (R-22.5-f).

  A ``tools/call`` that could not be dispatched at all (unknown tool, or
  schema-invalid arguments) MUST be a JSON-RPC -32602 error and MUST NOT be a
  result with ``isError: true`` (R-22.5-c/f).

  Raises:
    ProtocolErrorMisuseError: the dispatch failure was reported via ``isError``.
  """
  if reported_as_is_error_result:
    raise ProtocolErrorMisuseError(
      "a `tools/call` that could not be dispatched (unknown tool / schema-invalid "
      "arguments) MUST be reported as a JSON-RPC -32602 error, never as a result "
      "with isError: true (R-22.5-c, R-22.5-f)"
    )


def assert_tool_execution_failure_is_result(
  *,
  reported_as_json_rpc_error: bool,
) -> None:
  """Assert a tool-*execution* failure is NOT reported as a JSON-RPC error (R-22.5-e).

  A ``tools/call`` that reached and ran the tool but whose work failed MUST be a
  successful result with ``isError: true`` and MUST NOT be a JSON-RPC ``error``
  (R-22.5-d/e).

  Raises:
    ProtocolErrorMisuseError: the execution failure was reported as a JSON-RPC error.
  """
  if reported_as_json_rpc_error:
    raise ProtocolErrorMisuseError(
      "an ordinary tool-execution failure MUST be reported as a successful result "
      "with isError: true, never as a JSON-RPC error (R-22.5-d, R-22.5-e)"
    )


# ---------------------------------------------------------------------------
# §22.6  Transport error mapping and malformed messages
# ---------------------------------------------------------------------------

class TransportCondition(Enum):
  """The §22.6 conditions that classify an inbound message into a code + status.

  Each member names a row of the §22.6 mapping. map_transport_condition() returns
  the authoritative JSON-RPC code (the same on every transport) plus the
  Streamable HTTP status the §9.7 table (owned by S15) assigns.
  """

  MISSING_REQUIRED_CLIENT_CAPABILITY = "missing_required_client_capability"
  UNSUPPORTED_PROTOCOL_VERSION = "unsupported_protocol_version"
  ROUTING_HEADER_INVALID = "routing_header_invalid"
  STRUCTURALLY_INVALID_REQUEST = "structurally_invalid_request"
  INVALID_PER_REQUEST_METADATA = "invalid_per_request_metadata"
  UNPARSEABLE_JSON = "unparseable_json"
  NOT_A_REQUEST_OBJECT = "not_a_request_object"


#: Maps each §22.6 transport condition to (JSON-RPC code, §9.7 Condition). The
#: code is authoritative on every transport (R-22.6); the §9.7 Condition is used
#: to derive the Streamable-HTTP status from S15's owning table (not re-defined
#: here), keeping S15 the single source of truth for the status mapping.
_TRANSPORT_CONDITION_MAP: dict[TransportCondition, tuple[int, Condition]] = {
  TransportCondition.MISSING_REQUIRED_CLIENT_CAPABILITY: (
    MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
    Condition.MISSING_REQUIRED_CLIENT_CAPABILITY,
  ),
  TransportCondition.UNSUPPORTED_PROTOCOL_VERSION: (
    UNSUPPORTED_PROTOCOL_VERSION_CODE,
    Condition.UNSUPPORTED_PROTOCOL_VERSION,
  ),
  TransportCondition.ROUTING_HEADER_INVALID: (
    HEADER_MISMATCH_CODE,
    Condition.HEADER_DISAGREES_OR_MALFORMED,
  ),
  TransportCondition.STRUCTURALLY_INVALID_REQUEST: (
    INVALID_REQUEST_CODE,
    Condition.NOT_A_REQUEST_OBJECT,
  ),
  TransportCondition.INVALID_PER_REQUEST_METADATA: (
    INVALID_PARAMS_CODE,
    Condition.INVALID_PARAMS,
  ),
  TransportCondition.UNPARSEABLE_JSON: (
    PARSE_ERROR_CODE,
    Condition.MALFORMED_JSON,
  ),
  TransportCondition.NOT_A_REQUEST_OBJECT: (
    INVALID_REQUEST_CODE,
    Condition.NOT_A_REQUEST_OBJECT,
  ),
}


@dataclass(frozen=True)
class TransportMapping:
  """A resolved §22.6 mapping: the JSON-RPC code and the Streamable HTTP status.

  Fields:
    code: the authoritative JSON-RPC error code, identical on every transport.
    http_status: the Streamable HTTP status the §9.7 table (S15) assigns this
      condition — 400 for every §22.6 rejection here.
  """

  code: int
  http_status: int


def map_transport_condition(condition: TransportCondition) -> TransportMapping:
  """Map a §22.6 transport condition to its code and Streamable HTTP status (§22.6).

  Implements the §22.6 mapping while deferring the HTTP status to S15's §9.7
  table (the authoritative source this story cites, not overrides):
    - -32003 / -32004 ⇒ HTTP 400 (R-22.6-a);
    - a missing/malformed/mismatched routing header ⇒ -32001 HeaderMismatch +
      HTTP 400 (R-22.6-b);
    - a structurally invalid (non-routing) request ⇒ -32600 (R-22.6-c);
    - a well-formed request with missing/invalid per-request metadata ⇒ -32602
      (R-22.6-d);
    - unparseable bytes ⇒ -32700 (R-22.6-e);
    - parseable-but-not-a-request ⇒ -32600 (R-22.6-f).

  Returns:
    A TransportMapping carrying the JSON-RPC code and the HTTP status.
  """
  code, http_condition = _TRANSPORT_CONDITION_MAP[condition]
  status = map_condition_to_status(http_condition).status
  return TransportMapping(code=code, http_status=status)


def code_for_unparseable_input() -> int:
  """Return -32700 for an incoming byte stream that cannot be parsed as JSON (R-22.6-e)."""
  return PARSE_ERROR_CODE


def code_for_invalid_request_object() -> int:
  """Return -32600 for parseable JSON that is not a valid request object (R-22.6-f)."""
  return INVALID_REQUEST_CODE


def error_id_for_request(request_id: RequestId) -> RequestId:
  """Return the ``id`` an error response MUST carry for a known request (R-22.6-g).

  An error response normally MUST carry the same ``id`` as the request it
  answers (R-22.1-b, R-22.6-g). This echoes the request id unchanged.

  Raises:
    ValueError: request_id is None — use response_id_for_undeterminable_request()
      for the unparseable/idless case instead (R-22.6-h).
  """
  if request_id is None:
    raise ValueError(
      "request_id is None; an error answering a known request MUST echo its id "
      "(R-22.6-g). Use response_id_for_undeterminable_request() when the id "
      "cannot be determined (R-22.6-h)."
    )
  return request_id


def response_id_for_undeterminable_request(
  *,
  transport_requires_value: bool = False,
) -> RequestId | None:
  """Return the ``id`` for an error whose request id could not be determined (R-22.6-h).

  When the request ``id`` cannot be determined — the payload was unparseable or
  lacked a usable ``id`` — the error response MAY omit ``id`` (returns None), or
  send ``id`` as ``null`` where the transport structurally requires a value
  (returns None as well, which serializes to JSON ``null``). This is the ONLY
  circumstance in which an error response's ``id`` need not match a request id
  (R-22.1-f, R-22.6-h).

  Args:
    transport_requires_value: True when the transport structurally requires an
      ``id`` value; the caller then serializes the returned None as JSON ``null``.

  Returns:
    None — meaning "omit ``id``" when ``transport_requires_value`` is False, or
    "send ``id`` as ``null``" when True. Both render the absence of a known id.
  """
  return None


def build_undeterminable_id_error_response(error: ErrorObject) -> JSONRPCErrorResponse:
  """Build an id-less error response for input whose request id is undeterminable (R-22.6-h).

  Used for parse errors (-32700) and other cases where no usable ``id`` exists.
  The resulting JSONRPCErrorResponse omits ``id`` on the wire (S03 serializes a
  None id as absent); a transport that structurally requires a value sends
  ``null`` (the §22.6 wire example).
  """
  return JSONRPCErrorResponse(id=None, error=error.to_dict())


def should_respond_to_message(*, has_id: bool) -> bool:
  """Return False for a notification (no ``id``): never respond to it (R-22.1-g, R-22.6-i).

  A notification is a message without an ``id``. A receiver MUST NOT emit any
  response — error or otherwise — to a notification, even when processing it
  would otherwise produce an error (R-22.1-g, R-22.6-i). A request (has an
  ``id``) is answered normally.

  Args:
    has_id: True iff the inbound message carries an ``id`` (i.e. is a request).

  Returns:
    True iff the message is a request and so MUST receive a response.
  """
  return has_id


# ---------------------------------------------------------------------------
# §22.7  Extensibility and unknown codes
# ---------------------------------------------------------------------------

def is_reserved_error_code(code: int) -> bool:
  """Return True iff ``code`` is reserved by this specification (R-22.7-c).

  The reserved codes are the five standard codes, the two protocol-specific
  codes, and the transport code -32001 (RESERVED_ERROR_CODES). An
  extension-defined code MUST NOT equal any of these.
  """
  return code in RESERVED_ERROR_CODES


def is_known_error_code(code: int) -> bool:
  """Return True iff ``code`` appears in the consolidated §22 registry (§22.2/§22.3).

  Equivalent to membership in RESERVED_ERROR_CODES — a "known" code is one this
  specification defines. A code outside this set is unknown and, when received,
  MUST still be tolerated and surfaced (R-22.7-e); see surface_unknown_error().
  """
  return code in ERROR_CODE_REGISTRY


def validate_extension_error_code(code: Any) -> int:
  """Validate an extension-defined error code (§22.7, R-22.7-a/b/c).

  An extension MAY define additional error codes (R-22.7-a). Each MUST be an
  integer (R-22.7-b) and MUST NOT collide with any code reserved by this
  specification — the standard codes, the protocol-specific codes, or -32001
  (R-22.7-c). Extension codes SHOULD additionally carry structured ``data``
  (R-22.7-d); that advisory is enforced by build/inspection callers, not by this
  type/collision check.

  Args:
    code: the proposed extension-defined code.

  Returns:
    The validated integer code.

  Raises:
    TypeError: ``code`` is not an integer (bool is rejected) (R-22.7-b).
    ReservedErrorCodeCollisionError: ``code`` collides with a reserved code
      (R-22.7-c).
  """
  if isinstance(code, bool) or not isinstance(code, int):
    raise TypeError(
      f"extension-defined error code MUST be an integer; got "
      f"{type(code).__name__} (R-22.7-b)"
    )
  if code in RESERVED_ERROR_CODES:
    name = error_code_name(code) or "reserved"
    raise ReservedErrorCodeCollisionError(code, name)
  return code


def build_extension_error(
  code: int,
  message: str,
  data: Any,
) -> ErrorObject:
  """Build a validated extension-defined error object (§22.7, R-22.7-a/b/c/d).

  Validates the code is an integer and does not collide with a reserved code
  (R-22.7-b/c) via validate_extension_error_code, and requires structured
  ``data`` so receivers can act on the condition programmatically (R-22.7-d).

  Args:
    code: the extension-defined integer code (non-reserved).
    message: human-readable description.
    data: structured data describing the condition (R-22.7-d); MUST be provided.

  Returns:
    An ErrorObject with the validated extension code and structured data.

  Raises:
    TypeError / ReservedErrorCodeCollisionError: from validate_extension_error_code.
    ValueError: ``data`` is None (extension errors SHOULD carry structured data,
      R-22.7-d).
  """
  validated = validate_extension_error_code(code)
  if data is None:
    raise ValueError(
      "extension-defined errors SHOULD carry descriptive structured `data` so "
      "receivers can act on the condition programmatically (R-22.7-d)"
    )
  return ErrorObject(code=validated, message=message, data=data)


@dataclass(frozen=True)
class SurfacedError:
  """An unrecognized-code error surfaced as a failed request (§22.7, R-22.7-e).

  When a receiver gets an error response whose ``code`` it does not recognize, it
  MUST treat the response as a failed request and surface it (e.g. log it or
  propagate it to the caller) using ``message`` and ``data`` — it MUST NOT reject
  the response as malformed. This captures exactly that surfaced view.

  Fields:
    code: the unrecognized error code (preserved verbatim; still authoritative).
    message: the human-readable ``error.message`` to surface (R-22.7-e).
    data: the ``error.data`` to surface, or None when absent (R-22.7-e).
    recognized: whether the code is in the §22 registry — False here means the
      caller surfaced an unknown code rather than rejecting it.
  """

  code: int
  message: str
  data: Any = None
  recognized: bool = False


def surface_unknown_error(error: ErrorObject | dict[str, Any]) -> SurfacedError:
  """Surface an error with an unrecognized ``code`` as a failed request (R-22.7-e).

  Receivers MUST tolerate unknown error codes: an error response whose ``code``
  is not recognized MUST be treated as a failed request and surfaced using
  ``error.message`` and ``error.data``, NOT rejected as malformed. This validates
  the canonical Error shape (a REQUIRED integer ``code`` and string ``message``,
  via S04), then returns a SurfacedError carrying the code, message, and data so
  the caller can log or propagate it. A recognized code is surfaced too (with
  ``recognized=True``); the point of R-22.7-e is that an *unknown* code is never
  a reason to reject.

  Args:
    error: an ErrorObject or its raw ``error`` wire dict.

  Returns:
    A SurfacedError view; ``recognized`` flags whether the code is in the registry.

  Raises:
    TypeError / ValueError: only when the Error object itself is structurally
      malformed (missing/wrong-typed ``code``/``message``) — an *unknown code* is
      never such a failure (R-22.7-e).
  """
  obj = error if isinstance(error, ErrorObject) else validate_error_object(error)
  return SurfacedError(
    code=obj.code,
    message=obj.message,
    data=obj.data if obj.has_data else None,
    recognized=is_known_error_code(obj.code),
  )
