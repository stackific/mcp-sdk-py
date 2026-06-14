"""Utilities: Progress & Cancellation — S22.

Delivers out-of-band progress reporting (notifications/progress) and request
cancellation (notifications/cancelled). Both are optional, opt-in mechanisms
that apply to any request regardless of feature. A peer that does not implement
either continues to operate correctly (R-15-a).

Spec: §15.1–§15.2
Depends on: S05, S04
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp_sdk_py.jsonrpc import InFlightTracker, RequestId
from mcp_sdk_py.result_error import validate_progress_token, ProgressToken


# ---------------------------------------------------------------------------
# §15  Notification method names
# ---------------------------------------------------------------------------

#: Method name of the progress notification (§15.1).
PROGRESS_NOTIFICATION_METHOD: str = "notifications/progress"

#: Method name of the cancellation notification (§15.2).
CANCELLED_NOTIFICATION_METHOD: str = "notifications/cancelled"

#: The server/discover exchange MUST NOT be cancelled by a client (R-15.2.2-b).
DISCOVER_METHOD: str = "server/discover"


# ---------------------------------------------------------------------------
# §15.1  Data structures  [R-15.1.1-a, R-15.1.3-a–k]
# ---------------------------------------------------------------------------

@dataclass
class ProgressNotificationParams:
  """Params of a notifications/progress notification (§15.1.3).

  Fields:
    progress_token: REQUIRED. Correlates this notification to the originating
      request that opted in via _meta.progressToken (R-15.1.3-a/b).
      Wire key: "progressToken".
    progress: REQUIRED. Progress so far. Must strictly increase across
      successive notifications for the same token (R-15.1.3-d/e).
      Wire key: "progress".
    total: OPTIONAL. Total progress expected when known (R-15.1.3-g/h).
      Wire key: "total".
    message: OPTIONAL. Human-readable progress description (R-15.1.3-j/k).
      Wire key: "message".
    meta: OPTIONAL. Notification metadata.
      Wire key: "_meta".
  """

  progress_token: ProgressToken
  progress: float | int
  total: float | int | None = None
  message: str | None = None
  meta: dict[str, Any] | None = None

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire-compatible dict."""
    out: dict[str, Any] = {
      "progressToken": self.progress_token,
      "progress": self.progress,
    }
    if self.total is not None:
      out["total"] = self.total
    if self.message is not None:
      out["message"] = self.message
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


@dataclass
class CancelledNotificationParams:
  """Params of a notifications/cancelled notification (§15.2.1).

  Fields:
    request_id: The JSON-RPC id of the request being cancelled.
      MUST reference a request the sender issued in the same direction
      (R-15.2.1-a/b).
      Wire key: "requestId".
    reason: OPTIONAL. Human-readable cancellation explanation (R-15.2.1-c/d).
      Wire key: "reason".
    meta: OPTIONAL. Notification metadata.
      Wire key: "_meta".
  """

  request_id: str | int
  reason: str | None = None
  meta: dict[str, Any] | None = None

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire-compatible dict."""
    out: dict[str, Any] = {"requestId": self.request_id}
    if self.reason is not None:
      out["reason"] = self.reason
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


# ---------------------------------------------------------------------------
# §15.1  Parsing & validation
# ---------------------------------------------------------------------------

def validate_progress_notification_params(
  raw: dict[str, Any],
) -> ProgressNotificationParams:
  """Parse and validate params of notifications/progress (§15.1.3).

  Raises:
    TypeError: raw is not a dict, or a field has the wrong type.
    ValueError: progressToken or progress is absent (R-15.1.3-a/d).
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"ProgressNotificationParams must be a JSON object; got {type(raw).__name__}"
    )
  if "progressToken" not in raw:
    raise ValueError(
      "progressToken is REQUIRED in progress notifications (R-15.1.3-a)"
    )
  token = validate_progress_token(raw["progressToken"])

  if "progress" not in raw:
    raise ValueError(
      "progress is REQUIRED in progress notifications (R-15.1.3-d)"
    )
  progress = raw["progress"]
  if isinstance(progress, bool) or not isinstance(progress, (int, float)):
    raise TypeError(
      f"progress must be a number; got {type(progress).__name__}"
    )

  total = raw.get("total")
  if total is not None:
    if isinstance(total, bool) or not isinstance(total, (int, float)):
      raise TypeError(
        f"total must be a number if present; got {type(total).__name__}"
      )

  message = raw.get("message")
  if message is not None and not isinstance(message, str):
    raise TypeError(
      f"message must be a string if present; got {type(message).__name__}"
    )

  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )

  return ProgressNotificationParams(
    progress_token=token,
    progress=progress,
    total=total,
    message=message,
    meta=meta,
  )


def validate_cancelled_notification_params(
  raw: dict[str, Any],
) -> CancelledNotificationParams:
  """Parse and validate params of notifications/cancelled (§15.2.1).

  Raises:
    TypeError: raw is not a dict, or a field has the wrong type.
    ValueError: requestId is absent.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"CancelledNotificationParams must be a JSON object; "
      f"got {type(raw).__name__}"
    )
  if "requestId" not in raw:
    raise ValueError(
      "requestId is REQUIRED in cancellation notifications (R-15.2.1-a)"
    )
  request_id = raw["requestId"]
  if isinstance(request_id, bool):
    raise TypeError("requestId must be a string or number, not bool")
  if not isinstance(request_id, (str, int)):
    raise TypeError(
      f"requestId must be a string or number; got {type(request_id).__name__}"
    )

  reason = raw.get("reason")
  if reason is not None and not isinstance(reason, str):
    raise TypeError(
      f"reason must be a string if present; got {type(reason).__name__}"
    )

  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )

  return CancelledNotificationParams(
    request_id=request_id,
    reason=reason,
    meta=meta,
  )


# ---------------------------------------------------------------------------
# §15.2  Cancellation semantics  [R-15.2.2-b, R-15.2.2-c]
# ---------------------------------------------------------------------------

def is_cancellable_method(method: str) -> bool:
  """Return True if a request of this method may be cancelled via notifications/cancelled.

  R-15.2.2-b: Clients MUST NOT cancel the server/discover exchange.
  R-15.2.2-c: Requests with dedicated cancellation mechanisms (e.g. tasks/cancel
    for task-augmented requests) MUST use those instead.
  """
  if method == DISCOVER_METHOD:
    return False
  return True


# ---------------------------------------------------------------------------
# §15.1  ProgressTracker  [R-15.1.1-c, R-15.1.3-b/c/e, R-15.1.4-e/g]
# ---------------------------------------------------------------------------

class ProgressTracker:
  """Tracks active progress tokens for one connection direction (§15.1).

  Both parties SHOULD maintain a tracker (R-15.1.4-e). Enforces:
  - Token uniqueness across concurrent requests (R-15.1.1-c).
  - Referential validity: only registered tokens are valid emit targets
    (R-15.1.3-b/c).
  - Strict monotonic increase of progress values (R-15.1.3-e).
  - Terminal state: emit() raises after complete() (R-15.1.4-g).
  """

  def __init__(self) -> None:
    # token → (last_progress_or_sentinel, is_complete)
    self._active: dict[str | int | float, tuple[float | int | None, bool]] = {}

  def register(self, token: ProgressToken) -> None:
    """Register a new active progress token (R-15.1.1-c).

    Raises:
      ValueError: token is already registered as active.
      TypeError: token is not a valid ProgressToken type.
    """
    validate_progress_token(token)
    if token in self._active and not self._active[token][1]:
      raise ValueError(
        f"Progress token {token!r} is already active; tokens must be unique "
        f"across the sender's currently active requests (R-15.1.1-c)"
      )
    self._active[token] = (None, False)  # None sentinel: no emission yet

  def emit(self, token: ProgressToken, progress: float | int) -> None:
    """Record a progress emission for token; raise if invalid.

    R-15.1.3-b: token must correspond to an active registered request.
    R-15.1.3-e: progress must strictly increase from the previous value.
    R-15.1.4-g: MUST stop emitting after terminal state.

    Raises:
      ValueError: token not registered, already completed, or progress not
        strictly greater than the last emitted value.
    """
    validate_progress_token(token)
    if token not in self._active:
      raise ValueError(
        f"Progress token {token!r} is not registered; MUST NOT emit progress "
        f"for tokens not supplied by the peer (R-15.1.3-b/c)"
      )
    last, is_complete = self._active[token]
    if is_complete:
      raise ValueError(
        f"Progress token {token!r} is already in terminal state; "
        f"MUST stop emitting after completion (R-15.1.4-g)"
      )
    if last is not None and progress <= last:
      raise ValueError(
        f"Progress {progress!r} must strictly increase; previous was {last!r} "
        f"(R-15.1.3-e)"
      )
    self._active[token] = (progress, False)

  def complete(self, token: ProgressToken) -> None:
    """Mark token as having reached terminal state.

    After calling complete(), emit() for this token raises (R-15.1.4-g).

    Raises:
      ValueError: token was not registered.
    """
    validate_progress_token(token)
    if token not in self._active:
      raise ValueError(f"Progress token {token!r} is not registered")
    last, _ = self._active[token]
    self._active[token] = (last, True)

  def is_active(self, token: ProgressToken) -> bool:
    """Return True if token is registered and not yet completed."""
    if token not in self._active:
      return False
    _, is_complete = self._active[token]
    return not is_complete

  def unregister(self, token: ProgressToken) -> None:
    """Remove token from the active set after the request is fully done."""
    self._active.pop(token, None)

  @property
  def active_tokens(self) -> frozenset:
    """Frozenset of currently registered, non-completed tokens."""
    return frozenset(
      token
      for token, (_, is_complete) in self._active.items()
      if not is_complete
    )


# ---------------------------------------------------------------------------
# §15.1.2  Progress opt-in enforcement  [R-15.1.2-a, R-15.1.3-b/c]
# ---------------------------------------------------------------------------

class ProgressNotOptedInError(Exception):
  """Raised when progress would be emitted for a request that did not opt in.

  R-15.1.2-a: A request that omits progressToken from its _meta MUST NOT receive
    any progress notifications. Progress is delivered only when the issuer opted in.
  R-15.1.3-b/c: A progress notification MUST NOT reference a token not supplied
    by the peer or not corresponding to an active in-progress request.
  """


def validate_progress_opt_in(
  request_meta: dict[str, Any],
  token: ProgressToken,
) -> None:
  """Assert that the request opted in to progress by placing token in _meta.

  R-15.1.2-a: Progress MUST NOT be emitted when the request omitted progressToken.
  R-15.1.3-b/c: The token MUST equal one supplied by the peer in an active request.

  The bare "progressToken" key is the reserved opt-in sentinel (§15.1, §4.1).
  Call this before registering a token in ProgressTracker to enforce opt-in.

  Args:
    request_meta: The _meta dict from the originating request params.
    token: The ProgressToken the emitter intends to use.

  Raises:
    ProgressNotOptedInError: progressToken is absent from request_meta, or the
      value in _meta does not match token.
  """
  actual = request_meta.get("progressToken")
  if actual != token:
    raise ProgressNotOptedInError(
      f"Progress token {token!r} not found in request _meta.progressToken "
      f"(found {actual!r}); progress MUST NOT be emitted when the request did "
      f"not opt in (R-15.1.2-a, R-15.1.3-b, R-15.1.3-c)"
    )


# ---------------------------------------------------------------------------
# §15.2.1  Cancellation: in-flight guard  [R-15.2.1-a, R-15.2.1-b]
# ---------------------------------------------------------------------------

class CancellationTargetNotInFlightError(Exception):
  """Raised when trying to cancel a request not tracked as in-flight by the sender.

  R-15.2.1-a: requestId MUST correspond to a request the sender issued earlier
    in the same direction and that the sender believes is still in-flight.
  R-15.2.1-b: The cancellation MUST reference an in-flight request.

  Callers should catch this and not emit the notification; they SHOULD NOT
  return a JSON-RPC error to a remote party for this (it is a local guard).

  json_rpc_code: -32600 (returned to callers that need an error code).
  """

  json_rpc_code: int = -32600

  def __init__(self, request_id: RequestId) -> None:
    super().__init__(
      f"Request id {request_id!r} is not in the sender's in-flight set; "
      f"cancellation MUST target only requests the sender issued and believes "
      f"in-flight (R-15.2.1-a, R-15.2.1-b)"
    )
    self.request_id: RequestId = request_id


def build_cancel_notification(
  tracker: InFlightTracker,
  request_id: RequestId,
  reason: str | None = None,
) -> CancelledNotificationParams:
  """Build a CancelledNotificationParams only if request_id is in the sender's in-flight set.

  R-15.2.1-a: requestId MUST correspond to a request the sender issued earlier
    in the same direction and that the sender believes is still in-flight.
  R-15.2.1-b: The cancellation MUST reference an in-flight request.

  Args:
    tracker: The sender's InFlightTracker (tracks ids of requests it issued).
    request_id: The JSON-RPC id of the request to cancel.
    reason: Optional human-readable explanation (R-15.2.1-c).

  Returns:
    CancelledNotificationParams ready to be sent.

  Raises:
    CancellationTargetNotInFlightError: request_id is not in tracker's in-flight set.
  """
  if not tracker.is_in_flight(request_id):
    raise CancellationTargetNotInFlightError(request_id)
  return CancelledNotificationParams(request_id=request_id, reason=reason)


# ---------------------------------------------------------------------------
# §15.2.3  Cancellation race-condition handling  [R-15.2.2-e/f, R-15.2.3-a–e]
# ---------------------------------------------------------------------------

class CancellationRegistry:
  """Registry of request ids the local party has cancelled (R-15.2.3-e).

  When a party sends notifications/cancelled for a request it records the id
  so that any late response arriving after the cancellation can be identified
  and ignored. This is the pure-logic affordance for cancellation race
  tolerance; the physical late-response race only manifests once S16 streaming
  lands, but the logic belongs here.

  Usage:
    registry = CancellationRegistry()
    note = build_cancel_notification(tracker, request_id)
    registry.cancel(request_id)       # record the cancellation
    ...
    if registry.should_ignore_response(incoming_id):
      return                          # tolerate & ignore (R-15.2.3-d/e)
  """

  def __init__(self) -> None:
    # Key is (type, value) so int 1 and str "1" are distinct (mirrors InFlightTracker).
    self._cancelled: set[tuple[type, Any]] = set()

  def _key(self, rid: RequestId) -> tuple[type, Any]:
    return (type(rid), rid)

  def cancel(self, request_id: RequestId) -> None:
    """Record that the local party sent a cancellation for request_id."""
    self._cancelled.add(self._key(request_id))

  def should_ignore_response(self, request_id: RequestId) -> bool:
    """Return True if a response for request_id should be gracefully ignored.

    R-15.2.3-d: A response arriving after cancellation MUST be tolerated.
    R-15.2.3-e: The cancelling party SHOULD ignore any such late response.
    """
    return self._key(request_id) in self._cancelled

  def forget(self, request_id: RequestId) -> None:
    """Remove a cancelled id once it no longer requires tracking (cleanup)."""
    self._cancelled.discard(self._key(request_id))

  @property
  def cancelled_ids(self) -> frozenset[RequestId]:
    """Frozenset snapshot of all currently tracked cancelled request ids."""
    return frozenset(v for _, v in self._cancelled)


def receive_cancellation(
  tracker: InFlightTracker | None,
  request_id: RequestId,
  method: str | None = None,
) -> bool:
  """Determine if a received notifications/cancelled notification is actionable.

  R-15.2.2-e: A receiver MAY ignore a cancellation when the referenced request
    is unknown, when processing has already completed, or when the request cannot
    be cancelled. This function returns False for all such cases.
  R-15.2.2-f: Malformed cancellation notifications SHOULD be ignored (False).
  R-15.2.3-a: The notification MAY arrive after the request has already finished.
  R-15.2.3-b: MUST handle gracefully — no crash, no protocol violation.

  Args:
    tracker: The receiver's InFlightTracker for requests it is currently
      processing. Pass None to treat all ids as unknown (always returns False).
    request_id: The requestId from the notifications/cancelled params.
    method: Optional method name of the original request; when provided and
      non-cancellable (e.g. server/discover), returns False immediately.

  Returns:
    True: the cancellation is actionable — request_id is actively in-flight
      and the method (if given) is cancellable. The receiver SHOULD stop.
    False: the receiver MAY ignore this notification gracefully; covers:
      tracker is None, id not in-flight, or method is non-cancellable.
  """
  if method is not None and not is_cancellable_method(method):
    return False
  if tracker is None:
    return False
  return tracker.is_in_flight(request_id)
