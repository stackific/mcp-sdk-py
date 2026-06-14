"""Result base, base params, error object, and empty result — S04.

Defines the payload shapes that ride inside JSON-RPC envelopes from S03:
  - Result: the success payload with resultType discriminator (§3.6)
  - RequestParams / NotificationParams: common param bases (§3.7)
  - ProgressToken, Cursor: opaque value types (§3.7)
  - ErrorObject: the error payload (§3.8)
  - EmptyResult: a Result carrying only base members (§3.9)

Spec: §3.6–§3.10
Depends on: S03
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Union


# ---------------------------------------------------------------------------
# §3.6  ResultType — open string enum  [R-3.6-e]
# ---------------------------------------------------------------------------

#: Open string enum type for the resultType discriminator.
ResultType = str

#: The two resultType values defined by this protocol revision (§3.6).
RESULT_TYPE_COMPLETE: ResultType = "complete"
RESULT_TYPE_INPUT_REQUIRED: ResultType = "input_required"

#: Protocol-defined set; additional values require the extension mechanism (§24/S38).
_KNOWN_RESULT_TYPES: frozenset[str] = frozenset({
  RESULT_TYPE_COMPLETE,
  RESULT_TYPE_INPUT_REQUIRED,
})


# ---------------------------------------------------------------------------
# §3.7  Opaque token types  [R-3.7-c, R-3.7-d]
# ---------------------------------------------------------------------------

#: Opaque value placed in request _meta to correlate out-of-band progress
#: notifications to the originating request (§3.7). Placement and flow
#: are defined in §15/S22.
ProgressToken = Union[str, int, float]

#: Opaque pagination string; receivers MUST NOT parse or infer structure (R-3.7-d).
#: Its use in list operations is defined in §12/S18.
Cursor = str


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class UnknownResultTypeError(Exception):
  """Raised when a result carries an unrecognized resultType value.

  Per R-3.6-f the receiver MUST treat the whole response as an error.
  Per R-3.6-g the receiver MUST NOT attempt to interpret other result members.

  Attributes:
    result_type: The unrecognized resultType string.
  """

  def __init__(self, result_type: str) -> None:
    super().__init__(
      f"Unrecognized resultType {result_type!r}; treat whole response as an "
      f"error and do not read remaining result members (R-3.6-f, R-3.6-g)"
    )
    self.result_type: str = result_type


# ---------------------------------------------------------------------------
# §3.6  Result  [R-3.6-a–i]
# ---------------------------------------------------------------------------

@dataclass
class Result:
  """Base object for the `result` member of every success response (§3.6).

  All method-specific results extend this by adding further members.

  Fields:
    result_type: Discriminator telling the receiver how to interpret the
      result (R-3.6-c/h). Wire key: "resultType".
    meta: Optional metadata map; keys follow §4 naming rules (R-3.6-a).
      Wire key: "_meta".
    extra: Method-defined members beyond the base (R-3.6-d). Serialised
      directly into the wire dict alongside resultType and _meta.
  """

  result_type: ResultType
  meta: dict[str, Any] | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict."""
    out: dict[str, Any] = {"resultType": self.result_type}
    if self.meta is not None:
      out["_meta"] = self.meta
    out.update(self.extra)
    return out


# ---------------------------------------------------------------------------
# §3.9  EmptyResult  [R-3.9-a, R-3.9-b]
# ---------------------------------------------------------------------------

@dataclass
class EmptyResult:
  """A Result carrying only base members, for methods with no output data (§3.9).

  resultType MUST be set, normally to "complete" (R-3.9-a).
  MAY carry _meta; carries no additional method-specific members (R-3.9-b).
  """

  result_type: ResultType = RESULT_TYPE_COMPLETE
  meta: dict[str, Any] | None = None

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict."""
    out: dict[str, Any] = {"resultType": self.result_type}
    if self.meta is not None:
      out["_meta"] = self.meta
    return out

  def to_result(self) -> Result:
    """Convert to a base Result with no extra members."""
    return Result(result_type=self.result_type, meta=self.meta, extra={})


# ---------------------------------------------------------------------------
# §3.7  RequestParams  [R-3.7-a, R-3.7-c]
# ---------------------------------------------------------------------------

@dataclass
class RequestParams:
  """Base params shape for every request (§3.7).

  _meta is REQUIRED on requests because it conveys per-request protocol
  state (protocol revision, client info, capabilities, etc.) defined in
  §4/S05 (R-3.7-a). Wire key: "_meta".

  Fields:
    meta: Required RequestMetaObject (structure in §4/S05).
    extra: Method-specific members beyond _meta.
  """

  meta: dict[str, Any]
  extra: dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict."""
    out: dict[str, Any] = {"_meta": self.meta}
    out.update(self.extra)
    return out


# ---------------------------------------------------------------------------
# §3.7  NotificationParams  [R-3.7-b]
# ---------------------------------------------------------------------------

@dataclass
class NotificationParams:
  """Base params shape for every notification (§3.7).

  _meta is OPTIONAL on notifications (R-3.7-b). When present its keys
  follow the same reserved-key naming rules as other _meta objects (§4/S05).
  Wire key: "_meta".

  Fields:
    meta: Optional metadata map; None means _meta is absent on the wire.
    extra: Method-specific members beyond _meta.
  """

  meta: dict[str, Any] | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits _meta when None."""
    out: dict[str, Any] = {}
    if self.meta is not None:
      out["_meta"] = self.meta
    out.update(self.extra)
    return out


# ---------------------------------------------------------------------------
# §3.8  ErrorObject  [R-3.8-a–f]
# ---------------------------------------------------------------------------

_UNSET: object = object()


@dataclass
class ErrorObject:
  """Object carried in the `error` member of every error response (§3.8).

  Fields:
    code: REQUIRED integer identifying the error condition (R-3.8-a).
      Legal values and conditions are defined in §22/S34; implementations
      MUST NOT assign codes outside those rules (R-3.8-b).
    message: REQUIRED human-readable description (R-3.8-c). SHOULD be a
      single concise sentence (R-3.8-d).
    data: OPTIONAL additional info; structure is sender-defined (R-3.8-e).
      Receivers MUST NOT assume structure unless the specific code defines
      one in §22/S34 (R-3.8-f). Omitted from the wire when unset.
  """

  code: int
  message: str
  data: Any = field(default=_UNSET)

  @property
  def has_data(self) -> bool:
    """True when the data field was explicitly provided (including None/null)."""
    return self.data is not _UNSET

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits data when not set."""
    out: dict[str, Any] = {"code": self.code, "message": self.message}
    if self.has_data:
      out["data"] = self.data
    return out


# ---------------------------------------------------------------------------
# Parsing / validation helpers
# ---------------------------------------------------------------------------

def parse_result(
  raw: dict[str, Any],
  *,
  interop_fallback: bool = False,
  known_extensions: frozenset[str] | None = None,
) -> Result:
  """Parse and validate a result object from a wire dict (§3.6).

  Args:
    raw: The raw wire dict from the `result` member of a success response.
    interop_fallback: When True, a missing `resultType` is treated as
      "complete" to allow interoperation with non-conformant servers
      (R-3.6-i). Default False (conformant strict mode).
    known_extensions: Additional resultType values introduced via the
      extension mechanism (§24/S38). Any value absent from the protocol-
      defined set and this set is unrecognized (R-3.6-f/g).

  Raises:
    TypeError: raw is not a dict, or a field has the wrong JSON type.
    ValueError: resultType absent in strict mode (R-3.6-c/h).
    UnknownResultTypeError: resultType present but not recognized (R-3.6-f).
      Caller MUST treat the whole response as an error and MUST NOT inspect
      any other result members (R-3.6-g).
  """
  if not isinstance(raw, dict):
    raise TypeError(f"result must be a JSON object; got {type(raw).__name__}")

  # Read resultType first; raise before touching any other member on unknown
  # values so the no-read-other-members rule (R-3.6-g) is structurally enforced.
  rt_raw = raw.get("resultType")
  if rt_raw is None:
    if interop_fallback:
      # R-3.6-i: treat absent resultType as "complete" when interoperating.
      result_type: ResultType = RESULT_TYPE_COMPLETE
    else:
      raise ValueError(
        "resultType is REQUIRED on every result (R-3.6-c, R-3.6-h)"
      )
  elif not isinstance(rt_raw, str):
    raise TypeError(
      f"resultType must be a string; got {type(rt_raw).__name__}"
    )
  else:
    result_type = rt_raw

  # Reject unrecognized resultType BEFORE reading other members (R-3.6-f/g).
  all_known = _KNOWN_RESULT_TYPES | (known_extensions or frozenset())
  if result_type not in all_known:
    raise UnknownResultTypeError(result_type)

  # _meta: OPTIONAL object (R-3.6-a).
  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )

  # Remaining keys are method-defined additional members (R-3.6-d).
  reserved = {"resultType", "_meta"}
  extra = {k: v for k, v in raw.items() if k not in reserved}

  return Result(result_type=result_type, meta=meta, extra=extra)


def parse_empty_result(
  raw: dict[str, Any],
  *,
  interop_fallback: bool = False,
) -> EmptyResult:
  """Parse and validate an EmptyResult from a wire dict (§3.9).

  An EmptyResult MUST set resultType (R-3.9-a) and MUST NOT carry any
  members beyond _meta and resultType (R-3.9-b).

  Raises:
    TypeError: raw is not a dict or a field has the wrong type.
    ValueError: resultType absent in strict mode, or unexpected extra members.
    UnknownResultTypeError: resultType is present but unrecognized.
  """
  result = parse_result(raw, interop_fallback=interop_fallback)
  if result.extra:
    raise ValueError(
      f"EmptyResult must not carry method-specific members; "
      f"extra keys found: {sorted(result.extra)!r} (R-3.9-b)"
    )
  return EmptyResult(result_type=result.result_type, meta=result.meta)


def parse_request_params(raw: dict[str, Any]) -> RequestParams:
  """Parse and validate request params; _meta is REQUIRED (R-3.7-a).

  Raises:
    TypeError: raw is not a dict, or _meta is not an object.
    ValueError: _meta is absent.
  """
  if not isinstance(raw, dict):
    raise TypeError(f"params must be a JSON object; got {type(raw).__name__}")

  meta = raw.get("_meta")
  if "_meta" not in raw:
    raise ValueError(
      "_meta is REQUIRED on request params to convey per-request protocol "
      "state (R-3.7-a)"
    )
  if not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object; got {type(meta).__name__}"
    )

  extra = {k: v for k, v in raw.items() if k != "_meta"}
  return RequestParams(meta=meta, extra=extra)


def parse_notification_params(raw: dict[str, Any]) -> NotificationParams:
  """Parse and validate notification params; _meta is OPTIONAL (R-3.7-b).

  Raises:
    TypeError: raw is not a dict, or _meta is present but not an object.
  """
  if not isinstance(raw, dict):
    raise TypeError(f"params must be a JSON object; got {type(raw).__name__}")

  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )

  extra = {k: v for k, v in raw.items() if k != "_meta"}
  return NotificationParams(meta=meta, extra=extra)


def validate_error_object(raw: dict[str, Any]) -> ErrorObject:
  """Parse and validate an error object from a wire dict (§3.8).

  Validates that code is a required integer (R-3.8-a) and message is a
  required string (R-3.8-c). Accepts any integer code without range-checking;
  legal code values and their conditions are defined in §22/S34 (R-3.8-b).
  Accepts any sender-defined data value without assuming structure (R-3.8-f).

  Raises:
    TypeError: raw is not a dict, code is not an int, or message is not a str.
    ValueError: code or message is absent.
  """
  if not isinstance(raw, dict):
    raise TypeError(f"error must be a JSON object; got {type(raw).__name__}")

  # code: REQUIRED integer (R-3.8-a); legal values deferred to §22/S34.
  if "code" not in raw:
    raise ValueError("error.code is REQUIRED (R-3.8-a)")
  code = raw["code"]
  if isinstance(code, bool) or not isinstance(code, int):
    raise TypeError(
      f"error.code must be an integer (R-3.8-a); got {type(code).__name__}"
    )

  # message: REQUIRED string, SHOULD be a single concise sentence (R-3.8-c/d).
  if "message" not in raw:
    raise ValueError("error.message is REQUIRED (R-3.8-c)")
  message = raw["message"]
  if not isinstance(message, str):
    raise TypeError(
      f"error.message must be a string (R-3.8-c); got {type(message).__name__}"
    )

  # data: OPTIONAL, any sender-defined value (R-3.8-e); accept without assuming
  # structure unless a specific code defines one in §22/S34 (R-3.8-f).
  if "data" in raw:
    return ErrorObject(code=code, message=message, data=raw["data"])
  return ErrorObject(code=code, message=message)


def validate_progress_token(value: Any) -> ProgressToken:
  """Validate that value is a ProgressToken (string or number) (§3.7).

  ProgressToken is opaque; its placement in request _meta and the progress
  notification flow are defined in §15/S22.

  Raises:
    TypeError: value is not a string or number.
  """
  if isinstance(value, bool):
    raise TypeError("ProgressToken must be str or number, not bool")
  if not isinstance(value, (str, int, float)):
    raise TypeError(
      f"ProgressToken must be str or number; got {type(value).__name__}"
    )
  return value


def validate_cursor(value: Any) -> Cursor:
  """Validate that value is a Cursor (opaque string) (§3.7, R-3.7-d).

  Receivers MUST NOT parse or infer structure from a cursor; treat it as
  opaque. Its use in list operations is defined in §12/S18.

  Raises:
    TypeError: value is not a string.
  """
  if not isinstance(value, str):
    raise TypeError(f"Cursor must be a string; got {type(value).__name__}")
  return value
