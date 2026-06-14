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
