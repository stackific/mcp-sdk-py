"""JSON-RPC Base Message Framing — S03.

Delivers RequestId, the three message kinds (JSONRPCRequest,
JSONRPCNotification, JSONRPCResultResponse, JSONRPCErrorResponse),
structural classification, framing validation, in-flight id tracking,
and the RequestDispatcher that enforces the method-recognition and
params-validity obligations (R-3.3-i, R-3.3-j, R-3.3-k).

Spec: §3.1–§3.5
Depends on: S01, S02
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Union


# ---------------------------------------------------------------------------
# §3.2  RequestId  [R-3.2-a, R-3.2-b]
# ---------------------------------------------------------------------------

#: Wire type for request identifiers: JSON string or number, never null.
RequestId = Union[str, int, float]

JSONRPC_VERSION: str = "2.0"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class FramingError(Exception):
  """Raised when a message violates JSON-RPC 2.0 framing rules (§3.1–§3.5).

  Attributes:
    is_notification: True when the frame was structurally identified as a
      notification.  Callers MUST NOT send any response in that case (R-3.4-f).
    originating_id: The request id if it could be determined; None otherwise.
      Used to populate the id on an error response (R-3.5.2-c/d).
  """

  def __init__(
    self,
    message: str,
    *,
    is_notification: bool = False,
    originating_id: RequestId | None = None,
  ) -> None:
    super().__init__(message)
    self.is_notification = is_notification
    self.originating_id: RequestId | None = originating_id


# ---------------------------------------------------------------------------
# §3.3  JSONRPCRequest  [R-3.3-a–k]
# ---------------------------------------------------------------------------

@dataclass
class JSONRPCRequest:
  """JSON-RPC 2.0 request: carries id + method, expects exactly one response (§3.3)."""

  id: RequestId
  method: str
  params: dict[str, Any] | None = None
  jsonrpc: str = field(default=JSONRPC_VERSION, init=False)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {
      "jsonrpc": self.jsonrpc,
      "id": self.id,
      "method": self.method,
    }
    if self.params is not None:
      result["params"] = self.params
    return result


# ---------------------------------------------------------------------------
# §3.4  JSONRPCNotification  [R-3.4-a–f]
# ---------------------------------------------------------------------------

@dataclass
class JSONRPCNotification:
  """JSON-RPC 2.0 notification: one-way, no id, no response ever (§3.4)."""

  method: str
  params: dict[str, Any] | None = None
  jsonrpc: str = field(default=JSONRPC_VERSION, init=False)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {
      "jsonrpc": self.jsonrpc,
      "method": self.method,
    }
    if self.params is not None:
      result["params"] = self.params
    return result


# ---------------------------------------------------------------------------
# §3.5.1  JSONRPCResultResponse  [R-3.5.1-a–c]
# ---------------------------------------------------------------------------

@dataclass
class JSONRPCResultResponse:
  """JSON-RPC 2.0 success response: echoes request id, carries result object (§3.5.1).

  The Result shape is defined in S04; only structural presence is checked here.
  """

  id: RequestId
  result: dict[str, Any]
  jsonrpc: str = field(default=JSONRPC_VERSION, init=False)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict."""
    return {
      "jsonrpc": self.jsonrpc,
      "id": self.id,
      "result": self.result,
    }


# ---------------------------------------------------------------------------
# §3.5.2  JSONRPCErrorResponse  [R-3.5.2-a–f]
# ---------------------------------------------------------------------------

@dataclass
class JSONRPCErrorResponse:
  """JSON-RPC 2.0 error response: id is optional, error object is required (§3.5.2).

  id MUST be set when the originating request's id is known (R-3.5.2-c);
  MAY be omitted only when it cannot be determined (R-3.5.2-d).
  The Error shape is defined in S04.
  """

  error: dict[str, Any]
  id: RequestId | None = None
  jsonrpc: str = field(default=JSONRPC_VERSION, init=False)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits id when absent."""
    result: dict[str, Any] = {
      "jsonrpc": self.jsonrpc,
      "error": self.error,
    }
    if self.id is not None:
      result["id"] = self.id
    return result


# ---------------------------------------------------------------------------
# Union types
# ---------------------------------------------------------------------------

#: Success or error response.
JSONRPCResponse = Union[JSONRPCResultResponse, JSONRPCErrorResponse]

#: Any well-formed JSON-RPC 2.0 message.
JSONRPCMessage = Union[JSONRPCRequest, JSONRPCNotification, JSONRPCResponse]


# ---------------------------------------------------------------------------
# §3.2  RequestId validation  [R-3.2-a, R-3.2-b]
# ---------------------------------------------------------------------------

def validate_request_id(rid: Any, field_name: str = "id") -> RequestId:
  """Validate rid as a RequestId (string or number, never null) (R-3.2-a, b).

  Returns rid unchanged when valid; raises TypeError otherwise.
  """
  if rid is None:
    raise TypeError(
      f"{field_name}: RequestId MUST NOT be null (R-3.2-b)"
    )
  if isinstance(rid, bool):
    raise TypeError(
      f"{field_name}: RequestId must be a string or number, not bool (R-3.2-a)"
    )
  if not isinstance(rid, (str, int, float)):
    raise TypeError(
      f"{field_name}: RequestId must be a string or number, "
      f"got {type(rid).__name__} (R-3.2-a)"
    )
  return rid


def ids_are_equal(a: RequestId, b: RequestId) -> bool:
  """Return True iff two RequestIds are equal in both JSON type and value (R-3.2-e–g).

  JSON has a single 'number' type, so int and float with the same numeric
  value are equal.  A string id and a numeric id are never equal (R-3.2-g).
  """
  a_is_num = isinstance(a, (int, float)) and not isinstance(a, bool)
  b_is_num = isinstance(b, (int, float)) and not isinstance(b, bool)
  if a_is_num != b_is_num:
    return False  # one is string, one is number — forbidden coercion
  return a == b


# ---------------------------------------------------------------------------
# §3.1  Message classification  [R-3.1-a–f]
# ---------------------------------------------------------------------------

def _try_extract_id(raw: dict[str, Any]) -> RequestId | None:
  """Extract the id from a raw dict as a RequestId, or None if absent/invalid."""
  rid = raw.get("id")
  if rid is None or isinstance(rid, bool):
    return None
  if isinstance(rid, (str, int, float)):
    return rid
  return None


def classify_message(raw: Any) -> JSONRPCMessage:
  """Classify and validate an incoming JSON-decoded message (§3.1–§3.5).

  Returns a typed message dataclass on success.  Raises FramingError for any
  framing violation.  Callers should inspect err.is_notification (R-3.4-f) to
  decide whether to send an error response, and err.originating_id (R-3.5.2-c/d)
  to populate the response id.

  Classification:
    batch array     → FramingError (R-3.1-b/c)
    non-dict        → FramingError (R-3.1-a)
    jsonrpc ≠ "2.0" → FramingError (R-3.1-d/e)
    method+result|error or result+error → FramingError (R-3.1-f)
    method + id     → JSONRPCRequest
    method − id     → JSONRPCNotification
    id + result     → JSONRPCResultResponse
    error (± id)    → JSONRPCErrorResponse
  """
  if isinstance(raw, list):
    raise FramingError(
      "Top-level JSON array (batch) is forbidden (R-3.1-b/c)"
    )
  if not isinstance(raw, dict):
    raise FramingError(
      f"Message must be a single JSON object; got {type(raw).__name__} (R-3.1-a)"
    )

  originating_id = _try_extract_id(raw)
  has_method = "method" in raw
  has_result = "result" in raw
  has_error = "error" in raw
  has_id = "id" in raw

  jsonrpc = raw.get("jsonrpc")
  if jsonrpc != JSONRPC_VERSION:
    raise FramingError(
      f"jsonrpc must be exactly '2.0'; got {jsonrpc!r} (R-3.1-d/e)",
      is_notification=has_method and not has_id,
      originating_id=originating_id,
    )

  if has_method and (has_result or has_error):
    raise FramingError(
      "method cannot coexist with result or error (R-3.1-f)",
      is_notification=not has_id,
      originating_id=originating_id,
    )
  if has_result and has_error:
    raise FramingError(
      "result and error cannot both be present (R-3.1-f)",
      originating_id=originating_id,
    )

  if has_method and has_id:
    return _parse_request(raw, originating_id)
  if has_method:
    return _parse_notification(raw)
  if has_result:
    return _parse_result_response(raw, originating_id)
  if has_error:
    return _parse_error_response(raw, originating_id)

  raise FramingError(
    "Cannot classify message: no valid combination of id/method/result/error",
    originating_id=originating_id,
  )


def _parse_request(
  raw: dict[str, Any],
  originating_id: RequestId | None,
) -> JSONRPCRequest:
  """Parse and validate a request (R-3.3-a–k)."""
  try:
    rid = validate_request_id(raw.get("id"), "id")
  except TypeError as exc:
    raise FramingError(str(exc), originating_id=originating_id) from exc

  method = raw.get("method")
  if not isinstance(method, str):
    raise FramingError(
      f"method must be a string (R-3.3-c); got {type(method).__name__}",
      originating_id=rid,
    )

  params = raw.get("params")
  if params is not None and not isinstance(params, dict):
    raise FramingError(
      f"params must be a JSON object, not a positional array or other type "
      f"(R-3.3-f/g); got {type(params).__name__}",
      originating_id=rid,
    )

  return JSONRPCRequest(id=rid, method=method, params=params)


def _parse_notification(raw: dict[str, Any]) -> JSONRPCNotification:
  """Parse and validate a notification (R-3.4-a–f).

  FramingError.is_notification is always True here so callers never respond.
  """
  method = raw.get("method")
  if not isinstance(method, str):
    raise FramingError(
      f"notification method must be a string (R-3.4-c); got {type(method).__name__}",
      is_notification=True,
    )

  params = raw.get("params")
  if params is not None and not isinstance(params, dict):
    raise FramingError(
      f"notification params must be a JSON object (R-3.4-d); "
      f"got {type(params).__name__}",
      is_notification=True,
    )

  return JSONRPCNotification(method=method, params=params)


def _parse_result_response(
  raw: dict[str, Any],
  originating_id: RequestId | None,
) -> JSONRPCResultResponse:
  """Parse and validate a success response (R-3.5.1-a–c)."""
  try:
    rid = validate_request_id(raw.get("id"), "id")
  except TypeError as exc:
    raise FramingError(str(exc), originating_id=originating_id) from exc

  result = raw.get("result")
  if not isinstance(result, dict):
    raise FramingError(
      f"result must be a JSON object (R-3.5.1-c); got {type(result).__name__}",
      originating_id=rid,
    )

  return JSONRPCResultResponse(id=rid, result=result)


def _parse_error_response(
  raw: dict[str, Any],
  originating_id: RequestId | None,
) -> JSONRPCErrorResponse:
  """Parse and validate an error response (R-3.5.2-a–f)."""
  rid: RequestId | None = None
  rid_raw = raw.get("id")
  if rid_raw is not None:
    try:
      rid = validate_request_id(rid_raw, "id")
    except TypeError as exc:
      raise FramingError(str(exc), originating_id=originating_id) from exc

  error = raw.get("error")
  if not isinstance(error, dict):
    raise FramingError(
      f"error must be a JSON object (R-3.5.2-f); got {type(error).__name__}",
      originating_id=rid,
    )

  return JSONRPCErrorResponse(error=error, id=rid)


# ---------------------------------------------------------------------------
# §3.2  In-flight identifier tracker  [R-3.2-c, R-3.2-d]
# ---------------------------------------------------------------------------

class InFlightTracker:
  """Tracks in-flight request ids for a single sender on a single connection.

  Enforces that an id is not reused while the original request is outstanding
  (R-3.2-c) and all in-flight ids are unique (R-3.2-d).
  """

  def __init__(self) -> None:
    # Key is (type, value) to distinguish str "1" from int 1.
    self._in_flight: set[tuple[type, Any]] = set()

  def _key(self, rid: RequestId) -> tuple[type, Any]:
    return (type(rid), rid)

  def send(self, rid: RequestId) -> None:
    """Record rid as in-flight; raises ValueError if already in-flight (R-3.2-c/d)."""
    validate_request_id(rid)
    key = self._key(rid)
    if key in self._in_flight:
      raise ValueError(
        f"RequestId {rid!r} is already in-flight; MUST be unique per sender "
        f"per connection (R-3.2-c/d)"
      )
    self._in_flight.add(key)

  def receive(self, rid: RequestId) -> None:
    """Mark rid's response as received; removes it from the in-flight set."""
    self._in_flight.discard(self._key(rid))

  def is_in_flight(self, rid: RequestId) -> bool:
    """Return True if rid currently has an outstanding request."""
    return self._key(rid) in self._in_flight

  @property
  def in_flight_ids(self) -> frozenset[RequestId]:
    """Snapshot of all currently in-flight identifiers."""
    return frozenset(v for _, v in self._in_flight)


# ---------------------------------------------------------------------------
# §3.3  Request dispatch: method-not-found & invalid-params  [R-3.3-i/j/k]
# ---------------------------------------------------------------------------

# Placeholder codes used here; formally defined in S04.
_CODE_METHOD_NOT_FOUND: int = -32601
_CODE_INVALID_PARAMS: int = -32602


@dataclass
class MethodDescriptor:
  """Registration metadata for a single method in RequestDispatcher (§3.3).

  name: case-sensitive method name (R-3.3-d).
  requires_meta: True when per-request _meta is REQUIRED, meaning params
    MUST be present on every request for this method (R-3.3-i).
  params_validator: optional callable that validates the params dict content;
    raises ValueError or TypeError for invalid params (R-3.3-k).
    Called only when params is present (not None).
  """

  name: str
  requires_meta: bool = False
  params_validator: Callable[[dict[str, Any]], None] | None = None


class RequestDispatcher:
  """Enforces method-recognition and params-validity obligations on requests (§3.3).

  R-3.3-j: A receiver MUST respond with a method-not-found error when the
    requested method is not recognized.
  R-3.3-i: Where a method's per-request _meta is REQUIRED, params MUST be
    present; absent params on such a method triggers an invalid-params error.
  R-3.3-k: A receiver MUST respond with an invalid-params error when params
    do not satisfy the method's schema.

  The concrete error codes are formalized in S04; this class uses the
  standard JSON-RPC values as placeholders (-32601, -32602).
  """

  def __init__(self) -> None:
    self._methods: dict[str, MethodDescriptor] = {}

  def register(
    self,
    method: str,
    *,
    requires_meta: bool = False,
    params_validator: Callable[[dict[str, Any]], None] | None = None,
  ) -> None:
    """Register a recognized method and its validation rules.

    method: case-sensitive name (R-3.3-d).
    requires_meta: True when per-request _meta is REQUIRED for this method (R-3.3-i).
    params_validator: callable called with the params dict (when present);
      raises ValueError/TypeError for invalid params (R-3.3-k).
    """
    self._methods[method] = MethodDescriptor(
      name=method,
      requires_meta=requires_meta,
      params_validator=params_validator,
    )

  def dispatch(self, request: JSONRPCRequest) -> JSONRPCErrorResponse | None:
    """Check a request against registered methods and return an error response on violation.

    Returns None when the request passes all checks (caller may proceed to handle it).
    Returns a JSONRPCErrorResponse — never raises — for:
      - unrecognized method (R-3.3-j)
      - _meta-REQUIRED method with absent params (R-3.3-i)
      - params failing the registered validator (R-3.3-k)

    The returned error response's id equals the request id (R-3.5.2-c).
    """
    descriptor = self._methods.get(request.method)
    if descriptor is None:
      return JSONRPCErrorResponse(
        id=request.id,
        error={
          "code": _CODE_METHOD_NOT_FOUND,
          "message": f"Method not found: {request.method!r}",
        },
      )

    # R-3.3-i: params MUST be present when _meta is REQUIRED for this method
    if descriptor.requires_meta and request.params is None:
      return JSONRPCErrorResponse(
        id=request.id,
        error={
          "code": _CODE_INVALID_PARAMS,
          "message": "params is REQUIRED to carry _meta for this method (R-3.3-i)",
        },
      )

    # R-3.3-k: validate params content against the method's schema
    if descriptor.params_validator is not None and request.params is not None:
      try:
        descriptor.params_validator(request.params)
      except (ValueError, TypeError) as exc:
        return JSONRPCErrorResponse(
          id=request.id,
          error={
            "code": _CODE_INVALID_PARAMS,
            "message": f"Invalid params: {exc}",
          },
        )

    return None
