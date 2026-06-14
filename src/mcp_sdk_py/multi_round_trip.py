"""Multi-Round-Trip Requests — S17.

The single, protocol-wide mechanism by which a server obtains additional
information from a client *while processing* a client request. Instead of
opening an independent server-to-client request, the server returns an
"input_required" result; the client fulfills the input requests locally
and retries the original method with the gathered responses plus an opaque
continuation token (requestState).

Spec: §11
Depends on: S04, S05
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac_module
import json
from dataclasses import dataclass
from typing import Any

from mcp_sdk_py.result_error import RESULT_TYPE_INPUT_REQUIRED


# ---------------------------------------------------------------------------
# §11.2  Recognized input-request kinds  [R-11.2-k]
# ---------------------------------------------------------------------------

#: Exact, case-sensitive recognized input-request method strings (§11.2).
#: A received kind not in this set MUST be treated as an error (R-11.2-k/l).
INPUT_REQUEST_SAMPLING: str = "sampling/createMessage"
INPUT_REQUEST_ELICITATION: str = "elicitation/create"
INPUT_REQUEST_ROOTS: str = "roots/list"

RECOGNIZED_INPUT_REQUEST_METHODS: frozenset[str] = frozenset({
  INPUT_REQUEST_SAMPLING,
  INPUT_REQUEST_ELICITATION,
  INPUT_REQUEST_ROOTS,
})

#: The two deprecated kinds that servers SHOULD prefer to avoid (R-11.2-i).
DEPRECATED_INPUT_REQUEST_METHODS: frozenset[str] = frozenset({
  INPUT_REQUEST_SAMPLING,
  INPUT_REQUEST_ROOTS,
})


# ---------------------------------------------------------------------------
# §11.6  Methods that participate in MRTR  [R-11.6-a, R-11.6-b]
# ---------------------------------------------------------------------------

#: Methods from which a server MAY return "input_required" results.
#: Clients MUST be prepared to receive "input_required" from any of these.
MRTR_METHODS: frozenset[str] = frozenset({
  "tools/call",
  "prompts/get",
  "resources/read",
})


# ---------------------------------------------------------------------------
# Data structures  (§11.2–§11.4)
# ---------------------------------------------------------------------------

@dataclass
class InputRequest:
  """A single input request the server asks the client to fulfill (§11.2).

  Discriminated by method; recognized values are in RECOGNIZED_INPUT_REQUEST_METHODS.
  An unrecognized method MUST cause the whole InputRequiredResult to be treated
  as an error by the client (R-11.2-k, R-11.2-l).

  Fields:
    method: Exact input-request kind string (case-sensitive).
    params: Kind-specific parameters. May be None when the kind has no params.
  """

  method: str
  params: dict[str, Any] | None = None

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire-compatible dict."""
    out: dict[str, Any] = {"method": self.method}
    if self.params is not None:
      out["params"] = self.params
    return out


@dataclass
class InputRequiredResult:
  """A result returned in place of a method's normal "complete" result (§11.2).

  Signals the server needs client input to finish processing. The client MUST
  branch on resultType to detect this (R-11.5-c); resultType is always
  "input_required".

  At least one of input_requests or request_state MUST be present (R-11.2-b).
  A result missing both is malformed (R-11.2-c).

  Fields:
    input_requests: Map of server-chosen key → InputRequest. Keys MUST be
      unique and non-empty (R-11.2-d/e). Absent/empty ⇒ load-shedding signal.
    request_state: Opaque continuation token — treat as uninterpreted blob
      (R-11.3-a/b). Echo verbatim on retry (R-11.3-c).
    meta: Optional result-level _meta.
  """

  input_requests: dict[str, InputRequest] | None = None
  request_state: str | None = None
  meta: dict[str, Any] | None = None

  @property
  def result_type(self) -> str:
    """The resultType discriminator; always "input_required"."""
    return RESULT_TYPE_INPUT_REQUIRED

  @property
  def is_load_shedding(self) -> bool:
    """True when this is a retry-later signal: no input requests, only requestState.

    R-11.5-l: A server MAY return such a result to shed load temporarily.
    The client MUST NOT treat this as an error (R-11.5-p).
    """
    return not bool(self.input_requests) and self.request_state is not None

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire-compatible dict."""
    out: dict[str, Any] = {"resultType": RESULT_TYPE_INPUT_REQUIRED}
    if self.meta is not None:
      out["_meta"] = self.meta
    if self.input_requests:
      out["inputRequests"] = {k: v.to_dict() for k, v in self.input_requests.items()}
    if self.request_state is not None:
      out["requestState"] = self.request_state
    return out


@dataclass
class InputResponseRequestParams:
  """Extra params carried on a retry request to fulfill an InputRequiredResult (§11.4).

  Any client-initiated request MAY carry these alongside its regular params
  (R-11.4-a). The retry MUST use the same method with the same original
  arguments, and is a new JSON-RPC request with a new id (R-11.4-b).

  Fields:
    meta: Required per-request _meta.
    input_responses: Map of key → response, keyed identically to the answered
      inputRequests (R-11.4-c/d). Absent on load-shedding retries.
    request_state: The requestState echoed verbatim from InputRequiredResult
      (R-11.3-c, R-11.4-g). Absent only if no requestState was received.
  """

  meta: dict[str, Any]
  input_responses: dict[str, Any] | None = None
  request_state: str | None = None

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire-compatible dict."""
    out: dict[str, Any] = {"_meta": self.meta}
    if self.input_responses is not None:
      out["inputResponses"] = self.input_responses
    if self.request_state is not None:
      out["requestState"] = self.request_state
    return out


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class MalformedInputRequiredResultError(Exception):
  """Raised when an InputRequiredResult is structurally invalid.

  R-11.2-c: Both inputRequests and requestState absent → malformed.
  R-11.2-g: Duplicate keys in inputRequests → malformed.

  json_rpc_code: -32600 (general protocol-error code; §22).
  """

  json_rpc_code: int = -32600


class DuplicateInputRequestKeyError(MalformedInputRequiredResultError):
  """Raised when a duplicate key is encountered while decoding an InputRequiredResult.

  R-11.2-e: Keys in inputRequests MUST be unique.
  R-11.2-g: A receiver encountering duplicate keys MUST treat the result as malformed.

  Python's json.loads() silently collapses duplicates (last-wins), so detection
  requires object_pairs_hook at decode time. Use decode_input_required_result_from_json()
  instead of validate_input_required_result() on raw JSON text.

  json_rpc_code: -32600 (inherited from MalformedInputRequiredResultError).
  """

  def __init__(self, key: str) -> None:
    super().__init__(
      f"Duplicate key {key!r} in inputRequests; keys MUST be unique (R-11.2-e, R-11.2-g)"
    )
    self.key: str = key


class InputResponseKindMismatchError(Exception):
  """Raised when an inputResponse value does not match the expected kind shape.

  R-11.4-e: The InputResponse MUST be the result counterpart of the InputRequest kind
    (ElicitResult↔elicitation/create, ListRootsResult↔roots/list,
    CreateMessageResult↔sampling/createMessage).
  R-11.4-f: A client MUST NOT answer with a mismatched kind.
  R-11.5-s: A malformed retry value is a protocol error; the server MUST return a
    JSON-RPC error rather than an InputRequiredResult.

  json_rpc_code: -32600.
  """

  json_rpc_code: int = -32600

  def __init__(self, key: str, kind: str, detail: str) -> None:
    super().__init__(
      f"inputResponses[{key!r}] is not a valid {kind!r} response: {detail} "
      f"(R-11.4-e, R-11.4-f, R-11.5-s)"
    )
    self.key: str = key
    self.kind: str = kind


class UndeclaredInputKindError(Exception):
  """Raised when a client receives an input-request kind it did not declare support for.

  R-11.5-k: A client receiving an input-request kind it did not declare MUST treat
    the result as an error, even if the kind is otherwise recognized.

  json_rpc_code: -32600.
  """

  json_rpc_code: int = -32600

  def __init__(self, kind: str) -> None:
    super().__init__(
      f"Received input-request kind {kind!r} which was not declared in client "
      f"capabilities; the whole InputRequiredResult must be treated as an error (R-11.5-k)"
    )
    self.kind: str = kind


class UnrecognizedInputRequestKindError(Exception):
  """Raised when an InputRequest carries an unrecognized method string.

  R-11.2-k: Treat as an unrecognized kind.
  R-11.2-l: The client MUST treat the whole InputRequiredResult as an error
    and MUST NOT attempt to fulfill an unrecognized kind.

  Attributes:
    unrecognized_method: The unknown method string.
  """

  def __init__(self, method: str) -> None:
    super().__init__(
      f"Unrecognized input-request kind {method!r}; recognized kinds are "
      f"{sorted(RECOGNIZED_INPUT_REQUEST_METHODS)!r}. Treat the whole "
      f"InputRequiredResult as an error (R-11.2-k, R-11.2-l)"
    )
    self.unrecognized_method: str = method


class InvalidRequestStateError(Exception):
  """Raised by a server when requestState on a retry is invalid or tampered.

  R-11.3-h: The server MUST validate requestState on each retry.
  R-11.3-i: The server MUST reject a value it did not mint or that was altered.

  json_rpc_code: -32600.
  """

  json_rpc_code: int = -32600


# ---------------------------------------------------------------------------
# §11.2  Parsing & validation
# ---------------------------------------------------------------------------

def parse_input_request(raw: dict[str, Any]) -> InputRequest:
  """Parse and validate a single InputRequest from a wire dict (§11.2).

  Raises:
    TypeError: raw is not a dict, or method is not a string.
    ValueError: method is absent.
    UnrecognizedInputRequestKindError: method is not one of the recognized kinds
      (R-11.2-k). Caller MUST treat the whole InputRequiredResult as an error
      (R-11.2-l).
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"InputRequest must be a JSON object; got {type(raw).__name__}"
    )
  if "method" not in raw:
    raise ValueError("InputRequest.method is REQUIRED")
  method = raw["method"]
  if not isinstance(method, str):
    raise TypeError(
      f"InputRequest.method must be a string; got {type(method).__name__}"
    )
  if method not in RECOGNIZED_INPUT_REQUEST_METHODS:
    raise UnrecognizedInputRequestKindError(method)
  params = raw.get("params")
  if params is not None and not isinstance(params, dict):
    raise TypeError(
      f"InputRequest.params must be a JSON object if present; "
      f"got {type(params).__name__}"
    )
  return InputRequest(method=method, params=params)


def validate_input_required_result(raw: dict[str, Any]) -> InputRequiredResult:
  """Parse and validate an InputRequiredResult from a wire dict (§11.2).

  Raises:
    TypeError: raw is not a dict, or fields have wrong types.
    ValueError: resultType is wrong; both inputRequests and requestState absent.
    MalformedInputRequiredResultError: both inputRequests and requestState absent
      (R-11.2-b/c).
    UnrecognizedInputRequestKindError: any InputRequest has an unrecognized method
      (R-11.2-k) — the whole result is an error (R-11.2-l).
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"InputRequiredResult must be a JSON object; got {type(raw).__name__}"
    )

  # resultType MUST be exactly "input_required" (R-11.2-a, case-sensitive).
  rt = raw.get("resultType")
  if rt != RESULT_TYPE_INPUT_REQUIRED:
    raise ValueError(
      f"resultType must be exactly {RESULT_TYPE_INPUT_REQUIRED!r} (case-sensitive); "
      f"got {rt!r} (R-11.2-a)"
    )

  # Parse inputRequests (R-11.2-d/e).
  input_requests: dict[str, InputRequest] | None = None
  raw_ir = raw.get("inputRequests")
  if raw_ir is not None and raw_ir:
    if not isinstance(raw_ir, dict):
      raise TypeError(
        f"inputRequests must be a JSON object; got {type(raw_ir).__name__}"
      )
    input_requests = {}
    for key, val in raw_ir.items():
      if not key:
        raise ValueError(
          "inputRequests keys must be non-empty strings (R-11.2-d)"
        )
      input_requests[key] = parse_input_request(val)

  # requestState: opaque string (R-11.3-a).
  request_state: str | None = None
  if "requestState" in raw:
    rs = raw["requestState"]
    if rs is not None:
      if not isinstance(rs, str):
        raise TypeError(
          f"requestState must be a string; got {type(rs).__name__}"
        )
      request_state = rs

  # At least one of inputRequests or requestState MUST be present (R-11.2-b/c).
  if not input_requests and request_state is None:
    raise MalformedInputRequiredResultError(
      "InputRequiredResult must have at least one of inputRequests or requestState; "
      "both are absent (R-11.2-b, R-11.2-c)"
    )

  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )

  return InputRequiredResult(
    input_requests=input_requests,
    request_state=request_state,
    meta=meta,
  )


def parse_input_response_params(raw: dict[str, Any]) -> InputResponseRequestParams:
  """Parse retry request params carrying inputResponses and/or requestState (§11.4).

  Raises:
    TypeError: raw is not a dict, or a field has the wrong type.
    ValueError: _meta is absent (R-3.7-a).
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"InputResponseRequestParams must be a JSON object; got {type(raw).__name__}"
    )
  if "_meta" not in raw:
    raise ValueError("_meta is REQUIRED on retry request params (R-3.7-a)")
  meta = raw["_meta"]
  if not isinstance(meta, dict):
    raise TypeError(f"_meta must be a JSON object; got {type(meta).__name__}")

  input_responses = raw.get("inputResponses")
  if input_responses is not None and not isinstance(input_responses, dict):
    raise TypeError(
      f"inputResponses must be a JSON object if present; "
      f"got {type(input_responses).__name__}"
    )
  if input_responses is not None:
    for resp_key, resp_val in input_responses.items():
      if not isinstance(resp_val, dict):
        raise MalformedInputRequiredResultError(
          f"inputResponses[{resp_key!r}] must be a JSON object (InputResponse); "
          f"got {type(resp_val).__name__} — protocol-malformed retry (R-11.5-s)"
        )

  request_state = raw.get("requestState")
  if request_state is not None and not isinstance(request_state, str):
    raise TypeError(
      f"requestState must be a string if present; got {type(request_state).__name__}"
    )

  return InputResponseRequestParams(
    meta=meta,
    input_responses=input_responses,
    request_state=request_state,
  )


# ---------------------------------------------------------------------------
# §11.5  Client exchange algorithm helpers  [R-11.5-c–f]
# ---------------------------------------------------------------------------

class ResultTypeClassification:
  """Classification constants returned by classify_result_type (§11.5)."""

  #: Final result — inspect the body.
  COMPLETE = "complete"
  #: Needs fulfillment — build retry with inputResponses + requestState.
  INPUT_REQUIRED = "input_required"
  #: No resultType field — treat as "complete" (R-11.5-f).
  ABSENT = "absent"
  #: Unrecognized value — treat as error, MUST NOT inspect body (R-11.5-d/e).
  UNKNOWN = "unknown"


def classify_result_type(raw: dict[str, Any]) -> str:
  """Classify a result's type for the client exchange algorithm (§11.5).

  The client MUST branch on resultType (R-11.5-c):
  - "complete"       → COMPLETE  — final result.
  - "input_required" → INPUT_REQUIRED — fulfill and retry.
  - absent           → ABSENT    — treat as "complete" (R-11.5-f).
  - anything else    → UNKNOWN   — error; MUST NOT inspect body (R-11.5-d/e).

  Returns one of the ResultTypeClassification string constants.
  """
  if "resultType" not in raw:
    return ResultTypeClassification.ABSENT
  rt = raw["resultType"]
  if rt == "complete":
    return ResultTypeClassification.COMPLETE
  if rt == RESULT_TYPE_INPUT_REQUIRED:
    return ResultTypeClassification.INPUT_REQUIRED
  return ResultTypeClassification.UNKNOWN


def validate_response_keys_match(
  input_requests: dict[str, InputRequest],
  input_responses: dict[str, Any],
) -> None:
  """Validate inputResponses keys are all present in inputRequests (R-11.2-h, R-11.4-c).

  Raises:
    ValueError: inputResponses contains a key not present in inputRequests.
  """
  extra = set(input_responses) - set(input_requests)
  if extra:
    raise ValueError(
      f"inputResponses contains keys not present in inputRequests: "
      f"{sorted(extra)!r} (R-11.2-h, R-11.4-c)"
    )


def is_load_shedding_result(raw: dict[str, Any]) -> bool:
  """Return True if raw is a load-shedding InputRequiredResult.

  A load-shedding result (R-11.5-l) has:
  - resultType = "input_required"
  - inputRequests absent or empty
  - requestState present and non-empty

  The client MUST NOT treat this as an error (R-11.5-p).
  """
  if raw.get("resultType") != RESULT_TYPE_INPUT_REQUIRED:
    return False
  return not bool(raw.get("inputRequests")) and bool(raw.get("requestState"))


def client_supports_input_kind(meta: dict[str, Any], kind: str) -> bool:
  """Return True if the client's declared capabilities include the given input kind.

  R-11.2-j / R-11.5-g: A server MUST NOT emit an input-request kind the client
  has not declared support for. The capability key is the first path segment of
  the method (e.g. "elicitation" for "elicitation/create").

  Args:
    meta: The _meta from the current client request.
    kind: One of the RECOGNIZED_INPUT_REQUEST_METHODS strings.
  """
  from mcp_sdk_py.meta_object import KEY_CLIENT_CAPABILITIES
  caps: dict[str, Any] = meta.get(KEY_CLIENT_CAPABILITIES, {})
  cap_name = kind.split("/")[0]  # "elicitation", "sampling", "roots"
  return cap_name in caps


# ---------------------------------------------------------------------------
# §11.3  requestState HMAC signing  [R-11.3-g, R-11.3-h, R-11.3-i]
# ---------------------------------------------------------------------------

def make_hmac_request_state(payload: str, secret_key: bytes) -> str:
  """Create a signed requestState token (HMAC-SHA256, base64url-encoded).

  Encodes payload into a token that detects tampering. The client echoes it
  back verbatim (R-11.3-c); the server verifies it on retry (R-11.3-h/i).

  R-11.3-g: Servers that encode trust-bearing context MUST protect the token;
  this function provides authentication (tamper detection) by HMAC.

  Token format: "<base64url-payload>.<base64url-hmac>" (no padding).

  Args:
    payload: Arbitrary server-defined continuation context string.
    secret_key: Server secret; must be kept confidential.
  """
  payload_b64 = base64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()
  sig = _hmac_module.new(
    secret_key, payload_b64.encode(), hashlib.sha256
  ).digest()
  sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
  return f"{payload_b64}.{sig_b64}"


def verify_hmac_request_state(token: str, secret_key: bytes) -> str:
  """Verify a signed requestState token and return the payload.

  R-11.3-h: Server MUST validate requestState on retry.
  R-11.3-i: MUST reject values not minted by this server or that were altered.
  Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.

  Args:
    token: The requestState string echoed from the client.
    secret_key: The server secret used at mint time.

  Returns:
    The original payload string.

  Raises:
    InvalidRequestStateError: Token is malformed, has invalid structure, or
      the HMAC does not match (R-11.3-i).
  """
  parts = token.split(".", 1)
  if len(parts) != 2:
    raise InvalidRequestStateError(
      "requestState token is malformed: expected '<payload>.<hmac>' format "
      "(R-11.3-i)"
    )
  payload_b64, received_sig_b64 = parts
  try:
    expected_sig = _hmac_module.new(
      secret_key, payload_b64.encode(), hashlib.sha256
    ).digest()
    # Re-add stripped padding for urlsafe_b64decode.
    padding = (4 - len(received_sig_b64) % 4) % 4
    received_sig = base64.urlsafe_b64decode(received_sig_b64 + "=" * padding)
  except Exception as exc:
    raise InvalidRequestStateError(
      f"requestState token has invalid base64 format: {exc} (R-11.3-i)"
    ) from exc

  if not _hmac_module.compare_digest(expected_sig, received_sig):
    raise InvalidRequestStateError(
      "requestState HMAC verification failed; token was not minted by this "
      "server or has been altered (R-11.3-i)"
    )

  try:
    padding = (4 - len(payload_b64) % 4) % 4
    return base64.urlsafe_b64decode(payload_b64 + "=" * padding).decode()
  except Exception as exc:
    raise InvalidRequestStateError(
      f"requestState payload could not be decoded: {exc} (R-11.3-i)"
    ) from exc


# ---------------------------------------------------------------------------
# §11.2  Duplicate-key detection  [R-11.2-e, R-11.2-g]
# ---------------------------------------------------------------------------

def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
  """object_pairs_hook: raise DuplicateInputRequestKeyError on any duplicate JSON key.

  Python's json.loads() is last-wins for duplicate keys, so duplicates are
  silently collapsed before reaching validate_input_required_result(). Using
  this hook at decode time detects them before any information is lost.
  """
  result: dict[str, Any] = {}
  for key, value in pairs:
    if key in result:
      raise DuplicateInputRequestKeyError(key)
    result[key] = value
  return result


def decode_input_required_result_from_json(json_text: str) -> InputRequiredResult:
  """Decode and validate an InputRequiredResult from a JSON string (R-11.2-g).

  Uses object_pairs_hook to detect duplicate keys before they are collapsed
  by Python's last-wins JSON decoder. Callers who receive raw JSON text MUST
  use this function rather than json.loads() + validate_input_required_result()
  to satisfy R-11.2-g.

  Raises:
    DuplicateInputRequestKeyError: A duplicate key was encountered anywhere in
      the JSON object tree (inherits MalformedInputRequiredResultError, json_rpc_code -32600).
    MalformedInputRequiredResultError: The result is otherwise structurally invalid.
    json.JSONDecodeError: json_text is not valid JSON.
  """
  raw = json.loads(json_text, object_pairs_hook=_no_duplicate_pairs)
  return validate_input_required_result(raw)


# ---------------------------------------------------------------------------
# §11.4  InputResponse kind-shape validation  [R-11.4-e, R-11.4-f, R-11.5-s]
# ---------------------------------------------------------------------------

#: Valid actions for an ElicitResult (elicitation/create response).
_ELICIT_ACTIONS: frozenset[str] = frozenset({"accept", "decline", "cancel"})


def validate_input_response_for_kind(key: str, kind: str, response: Any) -> None:
  """Validate that response matches the expected shape for the given input-request kind.

  R-11.4-e: The InputResponse MUST be the result counterpart of the InputRequest kind.
  R-11.4-f: A client MUST NOT answer with a mismatched kind.
  R-11.5-s: A malformed retry value is a protocol error.

  Expected shapes:
    elicitation/create  → ElicitResult: {action: "accept"|"decline"|"cancel", content?: ...}
    sampling/createMessage → CreateMessageResult: {model: str, role: "assistant", content: {...}}
    roots/list  → ListRootsResult: {roots: [...]}

  Raises:
    InputResponseKindMismatchError: response does not match the expected kind shape.
  """
  if not isinstance(response, dict):
    raise InputResponseKindMismatchError(
      key, kind,
      f"must be a JSON object; got {type(response).__name__}"
    )
  if kind == INPUT_REQUEST_ELICITATION:
    action = response.get("action")
    if action not in _ELICIT_ACTIONS:
      raise InputResponseKindMismatchError(
        key, kind,
        f"ElicitResult.action must be one of {sorted(_ELICIT_ACTIONS)!r}; got {action!r}"
      )
  elif kind == INPUT_REQUEST_SAMPLING:
    model = response.get("model")
    if not isinstance(model, str) or not model:
      raise InputResponseKindMismatchError(
        key, kind,
        "CreateMessageResult must have a non-empty string 'model'"
      )
    if response.get("role") != "assistant":
      raise InputResponseKindMismatchError(
        key, kind,
        f"CreateMessageResult 'role' must be 'assistant'; got {response.get('role')!r}"
      )
    if not isinstance(response.get("content"), dict):
      raise InputResponseKindMismatchError(
        key, kind,
        "CreateMessageResult must have a 'content' object"
      )
  elif kind == INPUT_REQUEST_ROOTS:
    if not isinstance(response.get("roots"), list):
      raise InputResponseKindMismatchError(
        key, kind,
        "ListRootsResult must have a 'roots' array"
      )


def validate_input_responses_match_kinds(
  input_requests: dict[str, InputRequest],
  input_responses: dict[str, Any],
) -> None:
  """Validate each inputResponse value matches the shape for its request kind.

  For each key in input_responses that has a corresponding entry in input_requests,
  calls validate_input_response_for_kind to check the structural shape.

  Used by:
  - Clients before sending a retry (R-11.4-e, R-11.4-f, AC-17.19).
  - Servers when processing a retry (R-11.5-s, AC-17.30).

  Raises:
    InputResponseKindMismatchError: response does not match kind (json_rpc_code -32600).
  """
  for resp_key, resp_val in input_responses.items():
    if resp_key in input_requests:
      validate_input_response_for_kind(resp_key, input_requests[resp_key].method, resp_val)


# ---------------------------------------------------------------------------
# §11.5  Client validation: undeclared kind  [R-11.5-k]
# ---------------------------------------------------------------------------

def validate_client_can_fulfill_input_requests(
  meta: dict[str, Any],
  input_requests: dict[str, InputRequest],
) -> None:
  """Raise if any input request kind was not declared by the client (R-11.5-k).

  A client MUST treat an InputRequiredResult containing an input-request kind it
  did not declare as an error, even when the kind is otherwise recognized
  (R-11.5-k). This is stricter than the unrecognized-kind check (R-11.2-k): a
  recognized-but-undeclared kind also causes an error.

  Args:
    meta: The _meta from the client's current request.
    input_requests: The inputRequests map from the server's InputRequiredResult.

  Raises:
    UndeclaredInputKindError: Any input request kind is not in client capabilities
      (json_rpc_code -32600).
  """
  for _, ir in input_requests.items():
    if not client_supports_input_kind(meta, ir.method):
      raise UndeclaredInputKindError(ir.method)
