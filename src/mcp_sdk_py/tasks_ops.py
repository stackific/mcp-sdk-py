"""The Tasks Extension II — get/update/cancel, Notifications & Cleanup — S40 (spec §25.7–§25.12).

This module delivers the client-facing **operations** that drive a task created
under S39 (:mod:`mcp_sdk_py.tasks`) through its lifecycle: retrieving a task's
current state (``tasks/get``), supplying input to a task that is waiting for it
(``tasks/update``), requesting cooperative cancellation (``tasks/cancel``),
receiving optional push status updates (``notifications/tasks``), and the rules
governing task expiry, removal, and protocol-vs-application error reporting
(§25.7–§25.12). Together with S39 (which owns the task model, capability, and
object types) it completes the Tasks extension's wire surface.

It REUSES, rather than re-implements, its dependencies:

  - S39 (:mod:`mcp_sdk_py.tasks`) owns the extension identifier, the negotiation
    /gating predicates, the ``-32003`` missing-capability and ``-32602``
    not-found error conditions, the :class:`~mcp_sdk_py.tasks.Task` /
    :class:`~mcp_sdk_py.tasks.DetailedTask` object types, the five-state
    :class:`~mcp_sdk_py.tasks.TaskStatus` lifecycle, and the
    :class:`~mcp_sdk_py.tasks.CreateTaskResult` task handle. This story consumes
    those without redefining them; ``tasks/get`` returns a ``DetailedTask`` and
    every operation gates on :func:`~mcp_sdk_py.tasks.tasks_active`.
  - S16 (:mod:`mcp_sdk_py.subscriptions`) owns the subscription mechanism
    (``subscriptions/listen`` and ``notifications/subscriptions/acknowledged``);
    this story only ADDS the ``taskIds`` filter member as the opt-in carrier for
    ``notifications/tasks`` (§25.10), reusing S16's
    :data:`~mcp_sdk_py.subscriptions.SUBSCRIPTION_ID_META_KEY` correlation.
  - S17 (:mod:`mcp_sdk_py.multi_round_trip`) owns the ``InputResponses`` /
    ``InputResponse`` shapes; ``tasks/update``'s ``inputResponses`` reuses them
    verbatim. The only task-specific binding S40 adds is that each response key
    MUST match a currently-outstanding ``inputRequests`` key (§25.8).
  - S03 (:mod:`mcp_sdk_py.jsonrpc`) owns the JSON-RPC envelopes used to build the
    requests, the acknowledgement responses, the error responses, and the
    notification.
  - S04 (:mod:`mcp_sdk_py.result_error`) owns the ``resultType`` discriminator;
    every result here carries :data:`~mcp_sdk_py.result_error.RESULT_TYPE_COMPLETE`
    (``"complete"``).

Spec: §25.7–§25.12 (lines 7371–7761)
Depends on: S39 (task model, capability, types), S16 (subscription mechanism),
  S17 (InputResponses), S03 (JSON-RPC envelopes), S04 (resultType)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp_sdk_py.jsonrpc import (
  JSONRPCErrorResponse,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResultResponse,
  RequestId,
  validate_request_id,
)
from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE, ResultType
from mcp_sdk_py.subscriptions import SUBSCRIPTIONS_LISTEN_METHOD
from mcp_sdk_py.tasks import (
  DetailedTask,
  Task,
  TaskNotFoundError,
  TaskStatus,
  TasksExtensionNotActiveError,
  parse_detailed_task,
  tasks_active,
)


# ---------------------------------------------------------------------------
# §25.7–§25.10  Method & notification names  [R-25.7-a, R-25.8-a, R-25.9-b, R-25.10-a]
# ---------------------------------------------------------------------------

#: The literal request method that retrieves a task's current state (§25.7, R-25.7-a).
TASKS_GET_METHOD: str = "tasks/get"

#: The literal request method that supplies responses to a task's outstanding
#: input requests (§25.8, R-25.8-a).
TASKS_UPDATE_METHOD: str = "tasks/update"

#: The literal request method that requests cooperative cancellation (§25.9, R-25.9-b).
TASKS_CANCEL_METHOD: str = "tasks/cancel"

#: The literal notification method that pushes a task's current state (§25.10, R-25.10-a).
TASKS_NOTIFICATION_METHOD: str = "notifications/tasks"

#: The three request methods this story adds. Each is gated on the negotiated
#: ``io.modelcontextprotocol/tasks`` extension (§25.7/§25.8/§25.9).
TASKS_OPERATION_METHODS: frozenset[str] = frozenset({
  TASKS_GET_METHOD,
  TASKS_UPDATE_METHOD,
  TASKS_CANCEL_METHOD,
})

#: The ``subscriptions/listen`` ``params.notifications`` member by which a client
#: opts in to ``notifications/tasks`` for the listed task ids (§25.10, R-25.10-b/c).
TASK_IDS_FILTER_KEY: str = "taskIds"

#: The notification methods that MUST NOT be sent for a task; task state is
#: conveyed ONLY via ``tasks/get`` and ``notifications/tasks`` (§25.10, R-25.10-g).
FORBIDDEN_TASK_NOTIFICATION_METHODS: frozenset[str] = frozenset({
  "notifications/progress",
  "notifications/message",
})

#: The general-purpose cancellation notification that MUST NOT be used to cancel a
#: task; ``tasks/cancel`` is the only mechanism (§25.9, R-25.9-a).
GENERAL_CANCELLED_NOTIFICATION_METHOD: str = "notifications/cancelled"


# ---------------------------------------------------------------------------
# §25.7  tasks/get — request params & builder  [R-25.7-a, R-25.7-b, R-25.7-c]
# ---------------------------------------------------------------------------

@dataclass
class GetTaskRequestParams:
  """Params of a ``tasks/get`` request: the single REQUIRED ``taskId`` (§25.7).

  The params object carries exactly one member, ``taskId`` — the server-generated
  identifier of the task to query (R-25.7-a). A client MUST send the value
  verbatim, exactly as obtained from the originating ``CreateTaskResult``
  (R-25.7-b); this type takes the value opaquely and never interprets it.

  Fields:
    task_id (``taskId``): the opaque server-generated identifier. REQUIRED.
  """

  task_id: str

  def __post_init__(self) -> None:
    """Validate ``taskId`` is a non-empty opaque string (R-25.7-a/b).

    Raises:
      TypeError: ``task_id`` is not a string.
      ValueError: ``task_id`` is empty.
    """
    _validate_task_id(self.task_id)

  def to_dict(self) -> dict[str, Any]:
    """Serialize to the wire ``params`` object (§25.7, R-25.7-a)."""
    return {"taskId": self.task_id}


def parse_get_task_request_params(raw: Any) -> GetTaskRequestParams:
  """Parse and validate ``tasks/get`` params (§25.7, R-25.7-a/b).

  ``taskId`` is REQUIRED; the value is taken verbatim as an opaque string
  (R-25.7-a/b).

  Raises:
    TypeError: ``raw`` is not a dict or ``taskId`` is not a string.
    ValueError: ``taskId`` is absent or empty.
  """
  task_id = _require_task_id(raw, TASKS_GET_METHOD)
  return GetTaskRequestParams(task_id=task_id)


def build_get_task_request(request_id: RequestId, task_id: str) -> JSONRPCRequest:
  """Build the ``tasks/get`` JSON-RPC request that retrieves a task's state (§25.7).

  This is the polling primitive: a client repeatedly issues ``tasks/get`` to
  observe progress until the task is terminal (R-25.7-p). The ``taskId`` is sent
  verbatim from the originating ``CreateTaskResult`` (R-25.7-b). The caller MUST
  have negotiated the Tasks extension before sending (R-25.7-c); gating is the
  caller's responsibility (see :func:`assert_tasks_method_allowed`).

  Args:
    request_id: the JSON-RPC id.
    task_id: the opaque task identifier, verbatim from ``CreateTaskResult``.

  Returns:
    A :class:`~mcp_sdk_py.jsonrpc.JSONRPCRequest` for ``tasks/get``.
  """
  validate_request_id(request_id)
  params = GetTaskRequestParams(task_id=task_id)
  return JSONRPCRequest(
    id=request_id, method=TASKS_GET_METHOD, params=params.to_dict()
  )


# ---------------------------------------------------------------------------
# §25.7  GetTaskResult — Result merged with DetailedTask  [R-25.7-e..l]
# ---------------------------------------------------------------------------

@dataclass
class GetTaskResult:
  """The ``tasks/get`` result: a base ``Result`` merged with a ``DetailedTask`` (§25.7).

  The ``resultType`` member MUST be the literal string ``"complete"`` (R-25.7-e),
  and the body is the current :class:`~mcp_sdk_py.tasks.DetailedTask` variant —
  selected by the task's status (R-25.7-f). The variant discipline (which
  status-specific payload field is present) is enforced by ``DetailedTask`` from
  S39: ``working`` / ``cancelled`` carry none, ``input_required`` carries
  ``inputRequests``, ``completed`` carries ``result``, ``failed`` carries
  ``error`` (R-25.7-g..l).

  Fields:
    detailed_task: the current :class:`~mcp_sdk_py.tasks.DetailedTask`.
    meta: OPTIONAL result-level ``_meta`` (wire key ``_meta``).
  """

  detailed_task: DetailedTask
  meta: dict[str, Any] | None = None

  @property
  def result_type(self) -> ResultType:
    """The ``resultType`` discriminator; always ``"complete"`` (R-25.7-e)."""
    return RESULT_TYPE_COMPLETE

  @property
  def status(self) -> TaskStatus:
    """The status of the carried detailed task (the discriminator of the variant)."""
    return self.detailed_task.status

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire ``Result``: ``resultType: "complete"`` + the DetailedTask (§25.7).

    ``resultType`` is emitted first, then every flattened ``DetailedTask`` field
    (the base ``Task`` fields plus the single status-specific payload member),
    and ``_meta`` is appended when present (R-25.7-e/f).
    """
    out: dict[str, Any] = {"resultType": RESULT_TYPE_COMPLETE}
    out.update(self.detailed_task.to_dict())
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def parse_get_task_result(raw: dict[str, Any]) -> GetTaskResult:
  """Parse and validate a ``tasks/get`` result from a wire dict (§25.7, R-25.7-e..l).

  Verifies ``resultType`` is exactly ``"complete"`` (R-25.7-e), then reads the
  flattened :class:`~mcp_sdk_py.tasks.DetailedTask` off the same object, which
  enforces the per-status variant discipline (R-25.7-f..l) via S39.

  Raises:
    TypeError: ``raw`` is not a dict or a member has the wrong type.
    ValueError: ``resultType`` is not ``"complete"``, or a REQUIRED Task/variant
      field is absent or appears on the wrong status.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"GetTaskResult must be a JSON object; got {type(raw).__name__}"
    )
  rt = raw.get("resultType")
  if rt != RESULT_TYPE_COMPLETE:
    raise ValueError(
      f"GetTaskResult.resultType must be exactly {RESULT_TYPE_COMPLETE!r} "
      f"(case-sensitive); got {rt!r} (R-25.7-e)"
    )
  detailed = parse_detailed_task(raw)
  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )
  return GetTaskResult(detailed_task=detailed, meta=meta)


def build_get_task_result(
  detailed_task: DetailedTask,
  *,
  meta: dict[str, Any] | None = None,
) -> GetTaskResult:
  """Build the ``tasks/get`` result for a task's current ``DetailedTask`` (§25.7, R-25.7-f).

  On receiving ``tasks/get`` the server MUST inspect the task's current status
  and return the matching :class:`~mcp_sdk_py.tasks.DetailedTask` variant
  (R-25.7-f..l); ``detailed_task`` is that already-validated variant. The result
  ``resultType`` is always ``"complete"`` (R-25.7-e).
  """
  return GetTaskResult(detailed_task=detailed_task, meta=meta)


def build_get_task_response(
  request_id: RequestId,
  detailed_task: DetailedTask,
  *,
  meta: dict[str, Any] | None = None,
) -> JSONRPCResultResponse:
  """Build the full ``tasks/get`` JSON-RPC success response (§25.7, R-25.7-e/f).

  Wraps :func:`build_get_task_result` in a :class:`JSONRPCResultResponse` echoing
  the request id, with the ``DetailedTask`` for the current status inlined.
  """
  validate_request_id(request_id)
  result = build_get_task_result(detailed_task, meta=meta)
  return JSONRPCResultResponse(id=request_id, result=result.to_dict())


# ---------------------------------------------------------------------------
# §25.7 / §25.11  Unknown / expired taskId error  [R-25.7-r, R-25.7-s, R-25.11-d/e]
# ---------------------------------------------------------------------------

def build_task_not_found_response(
  request_id: RequestId,
  task_id: str,
) -> JSONRPCErrorResponse:
  """Build the ``-32602`` error response for an unknown / expired ``taskId`` (R-25.7-r).

  If the ``taskId`` does not correspond to a known task — never existed, or
  expired and removed (§25.11) — the server MUST answer ``tasks/get`` with a
  JSON-RPC error whose ``code`` is ``-32602`` (Invalid params) rather than a
  result (R-25.7-r, R-25.11-d). The same error is the SHOULD response for
  ``tasks/update`` / ``tasks/cancel`` against an unknown task (R-25.8-m,
  R-25.9-g). The ``message`` is informative and non-normative.

  Args:
    request_id: the JSON-RPC id of the failing request.
    task_id: the unknown ``taskId`` (carried in ``error.data`` per S39).

  Returns:
    A :class:`~mcp_sdk_py.jsonrpc.JSONRPCErrorResponse` carrying the §22 error.
  """
  validate_request_id(request_id)
  error = TaskNotFoundError(task_id).to_error_object()
  return JSONRPCErrorResponse(id=request_id, error=error)


def is_task_not_found_error(raw: Any) -> bool:
  """True when a wire error object is the unknown/expired-task ``-32602`` error (R-25.7-s).

  A client SHOULD treat a ``-32602`` response to ``tasks/get`` as evidence that
  the task is terminal and unavailable, and stop polling it (R-25.7-s,
  R-25.11-e). This recognizes that response from the ``error`` object of a
  :class:`~mcp_sdk_py.jsonrpc.JSONRPCErrorResponse`.
  """
  return isinstance(raw, dict) and raw.get("code") == TaskNotFoundError.json_rpc_code


def client_should_stop_polling(error: Any) -> bool:
  """True when a ``tasks/get`` error means the client SHOULD stop polling (R-25.7-s, R-25.11-e).

  A ``-32602`` response is evidence the task is terminal and unavailable — never
  existed, or expired and removed — so a conformant client stops polling it
  (R-25.7-s, R-25.11-d/e).
  """
  return is_task_not_found_error(error)


# ---------------------------------------------------------------------------
# §25.7  Polling semantics  [R-25.7-m, R-25.7-n, R-25.7-o, R-25.7-p, R-25.7-q]
# ---------------------------------------------------------------------------

class PollIntervalTracker:
  """Tracks the latest observed ``pollIntervalMs`` and enforces the poll gap (§25.7).

  A client SHOULD honor the most recently observed ``pollIntervalMs`` as the
  minimum interval between consecutive ``tasks/get`` requests and SHOULD NOT poll
  more frequently (R-25.7-m). Because ``pollIntervalMs`` MAY change over the
  task's lifetime, the client SHOULD adopt the LATEST value it observes
  (R-25.7-n). This object records the latest value (updated each time a fresh
  :class:`~mcp_sdk_py.tasks.Task` / ``pollIntervalMs`` is observed) and answers
  whether a candidate elapsed time would poll too soon.

  Attributes:
    interval_ms: the most recently observed ``pollIntervalMs``, or ``None`` until
      one has been observed (the client then chooses its own interval).
  """

  def __init__(self) -> None:
    self.interval_ms: float | None = None

  def observe(self, task: Task) -> float | None:
    """Adopt the latest ``pollIntervalMs`` from a freshly observed task (R-25.7-n).

    The value MAY change over the task's life, so the newest observation wins
    (R-25.7-n). ``None`` (the task omitted ``pollIntervalMs``) clears the tracked
    value, leaving the interval to the client's own choosing.

    Args:
      task: the most recently observed :class:`~mcp_sdk_py.tasks.Task`.

    Returns:
      The now-current tracked interval (the task's ``pollIntervalMs`` or ``None``).
    """
    value = task.poll_interval_ms
    self.interval_ms = None if value is None else float(value)
    return self.interval_ms

  def may_poll_now(self, elapsed_ms: float) -> bool:
    """True when ``elapsed_ms`` since the last poll meets the latest interval (R-25.7-m).

    The client SHOULD NOT poll until at least ``pollIntervalMs`` ms have elapsed
    (R-25.7-m). With no interval observed yet, polling is unconstrained here (the
    client chooses its own cadence).
    """
    if self.interval_ms is None:
      return True
    return elapsed_ms >= self.interval_ms

  def is_poll_too_soon(self, elapsed_ms: float) -> bool:
    """True when polling again after ``elapsed_ms`` would be too frequent (R-25.7-m)."""
    return not self.may_poll_now(elapsed_ms)


def server_may_rate_limit(elapsed_since_last_poll_ms: float, poll_interval_ms: float) -> bool:
  """True when a server MAY rate-limit a client that polled too frequently (R-25.7-o).

  A server MAY rate-limit a client that polls more frequently than the most
  recently advertised ``pollIntervalMs`` (R-25.7-o). This is permissive: it
  returns True exactly when the gap since the client's previous poll is below the
  advertised interval, marking the poll as eligible for rate-limiting.

  Args:
    elapsed_since_last_poll_ms: ms since the client's previous ``tasks/get``.
    poll_interval_ms: the most recently advertised ``pollIntervalMs``.
  """
  return elapsed_since_last_poll_ms < poll_interval_ms


def should_continue_polling(task: Task) -> bool:
  """True while a client SHOULD keep polling ``task`` (R-25.7-p).

  A client SHOULD continue polling until the task reaches a terminal status, or
  until it issues ``tasks/cancel`` (R-25.7-p). Polling continues exactly while the
  task is non-terminal; once cancellation is requested the client MAY also stop
  (see :func:`client_may_drop_state_after_cancel`).
  """
  return not task.is_terminal


# ---------------------------------------------------------------------------
# §25.7  Durable persistence of task ids  [R-25.7-q]
# ---------------------------------------------------------------------------

class DurableTaskIdStore:
  """A minimal durable store of task identifiers so polling survives a restart (§25.7).

  A client SHOULD persist task identifiers to durable storage so that polling can
  resume after a client crash or restart (R-25.7-q); a ``taskId`` is a durable
  handle that resolves independently of the connection it was created on. This is
  the durability contract in object form: ``remember`` records a ``taskId`` and
  ``restore`` reconstructs the set on a fresh start. Persistence is delegated to a
  caller-supplied backend so any durable medium (file, DB, KV) can be plugged in;
  an in-memory backend is the default for tests.

  The store deliberately keeps NOTHING but the opaque identifiers — a ``taskId``
  is opaque (S39, R-25.4-a) and is the only durable handle needed to resume.
  """

  def __init__(self, backend: set[str] | None = None) -> None:
    self._ids: set[str] = set() if backend is None else backend

  def remember(self, task_id: str) -> None:
    """Persist ``task_id`` so polling can resume after a restart (R-25.7-q).

    Raises:
      TypeError: ``task_id`` is not a string.
      ValueError: ``task_id`` is empty.
    """
    _validate_task_id(task_id)
    self._ids.add(task_id)

  def forget(self, task_id: str) -> None:
    """Drop a persisted ``task_id`` (e.g. once the task is known terminal).

    Idempotent: forgetting an unknown id is a no-op. A client MAY drop a task's
    state immediately after sending ``tasks/cancel`` (R-25.9-k).
    """
    self._ids.discard(task_id)

  def restore(self) -> frozenset[str]:
    """Return the durably persisted task ids, e.g. on a fresh start (R-25.7-q)."""
    return frozenset(self._ids)

  def __contains__(self, task_id: object) -> bool:
    return task_id in self._ids


# ---------------------------------------------------------------------------
# §25.8  tasks/update — request params & builder  [R-25.8-a, R-25.8-b]
# ---------------------------------------------------------------------------

@dataclass
class UpdateTaskRequestParams:
  """Params of a ``tasks/update`` request: ``taskId`` + ``inputResponses`` (§25.8).

  Both members are REQUIRED (R-25.8-a). ``inputResponses`` is the ``InputResponses``
  map of S17 (§11) reused verbatim — a ``{ key: InputResponse }`` object whose
  values are shaped like the responses to the corresponding inline server-to-
  client requests (e.g. an elicitation result per §20). The only task-specific
  binding S40 adds: each key MUST match a key that is currently outstanding in the
  task's ``inputRequests`` (R-25.8-b); that snapshot-relative check is enforced
  server-side by :class:`TaskInputState`, since the request shape itself cannot
  know the outstanding set.

  Fields:
    task_id (``taskId``): identifier of the task whose input is being supplied.
      REQUIRED.
    input_responses (``inputResponses``): ``InputResponses`` map keyed by
      outstanding ``inputRequests`` keys. REQUIRED.
  """

  task_id: str
  input_responses: dict[str, Any]

  def __post_init__(self) -> None:
    """Validate both REQUIRED members are present and well-typed (R-25.8-a).

    Raises:
      TypeError: ``task_id`` is not a string, ``input_responses`` is not a map,
        or a response value is not an object.
      ValueError: ``task_id`` is empty, a key is empty, or ``input_responses`` is
        absent (an empty map is malformed — there is nothing to supply).
    """
    _validate_task_id(self.task_id)
    if not isinstance(self.input_responses, dict):
      raise TypeError(
        f"inputResponses must be a map; got "
        f"{type(self.input_responses).__name__} (R-25.8-a)"
      )
    if not self.input_responses:
      raise ValueError(
        "inputResponses is REQUIRED and must carry at least one response; an "
        "empty map supplies nothing (R-25.8-a)"
      )
    for key, value in self.input_responses.items():
      if not isinstance(key, str) or not key:
        raise ValueError(
          "inputResponses keys must be non-empty strings, each matching a "
          "currently-outstanding inputRequests key (R-25.8-a/b)"
        )
      if not isinstance(value, dict):
        raise TypeError(
          f"inputResponses[{key!r}] must be a JSON object (an InputResponse "
          f"per §11/§20); got {type(value).__name__} (R-25.8-a)"
        )

  def to_dict(self) -> dict[str, Any]:
    """Serialize to the wire ``params`` object (§25.8, R-25.8-a)."""
    return {"taskId": self.task_id, "inputResponses": dict(self.input_responses)}


def parse_update_task_request_params(raw: Any) -> UpdateTaskRequestParams:
  """Parse and validate ``tasks/update`` params (§25.8, R-25.8-a).

  Both ``taskId`` and ``inputResponses`` are REQUIRED (R-25.8-a). The
  snapshot-relative key check (R-25.8-b) is NOT performed here — it requires the
  task's currently-outstanding ``inputRequests`` set and is done by
  :meth:`TaskInputState.apply_responses`.

  Raises:
    TypeError: ``raw`` is not a dict, or a member has the wrong type.
    ValueError: a REQUIRED member is absent.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"tasks/update params must be a JSON object; got {type(raw).__name__} (R-25.8-a)"
    )
  task_id = _require_task_id(raw, TASKS_UPDATE_METHOD)
  if "inputResponses" not in raw:
    raise ValueError(
      "tasks/update params.inputResponses is REQUIRED (R-25.8-a)"
    )
  return UpdateTaskRequestParams(
    task_id=task_id, input_responses=raw["inputResponses"]
  )


def build_update_task_request(
  request_id: RequestId,
  task_id: str,
  input_responses: dict[str, Any],
) -> JSONRPCRequest:
  """Build the ``tasks/update`` JSON-RPC request supplying input responses (§25.8).

  A client resolves a task's outstanding ``inputRequests`` by sending
  ``tasks/update`` carrying the corresponding ``inputResponses`` (R-25.8-a). Each
  key MUST match a currently-outstanding ``inputRequests`` key (R-25.8-b). The
  caller MUST have negotiated the Tasks extension (R-25.8-c); gating is the
  caller's responsibility (see :func:`assert_tasks_method_allowed`).

  Args:
    request_id: the JSON-RPC id.
    task_id: identifier of the task whose input is being supplied.
    input_responses: the ``InputResponses`` map keyed by outstanding keys.

  Returns:
    A :class:`~mcp_sdk_py.jsonrpc.JSONRPCRequest` for ``tasks/update``.
  """
  validate_request_id(request_id)
  params = UpdateTaskRequestParams(task_id=task_id, input_responses=input_responses)
  return JSONRPCRequest(
    id=request_id, method=TASKS_UPDATE_METHOD, params=params.to_dict()
  )


# ---------------------------------------------------------------------------
# §25.8  Outstanding-input state & key-uniqueness lifetime  [R-25.8-b/e..i]
# ---------------------------------------------------------------------------

class InputRequestKeyError(Exception):
  """Raised when a task's ``inputRequests`` key violates its lifetime uniqueness (§25.8).

  Each key in a task's ``inputRequests`` MUST be unique over the ENTIRE lifetime
  of the task; a server MUST NOT reuse a key for a subsequent request after a
  response for that key was delivered, nor use one key for two distinct requests
  during the task's lifetime (R-25.8-e, R-25.8-f). This guards both: it is raised
  when a server attempts to issue a key it has ever issued before.

  Attributes:
    key: the offending ``inputRequests`` key.
  """

  def __init__(self, key: str) -> None:
    super().__init__(
      f"inputRequests key {key!r} has already been used during this task's "
      f"lifetime; each key MUST be unique over the entire lifetime and MUST NOT "
      f"be reused for a distinct request (R-25.8-e, R-25.8-f)"
    )
    self.key: str = key


@dataclass
class InputResponseApplication:
  """The outcome of applying a ``tasks/update``'s ``inputResponses`` to a task (§25.8).

  Records which response keys the server accepted (currently-outstanding keys),
  which it ignored (not currently outstanding — never issued, already answered,
  or superseded; R-25.8-g), and whether any outstanding keys remain unanswered
  (a strict-subset / partial update keeps the task in ``input_required``;
  R-25.8-h).

  Fields:
    accepted: keys that were currently outstanding and are now answered.
    ignored: supplied keys that were not currently outstanding (R-25.8-g).
    remaining_outstanding: keys still outstanding after this update (R-25.8-h).
  """

  accepted: frozenset[str]
  ignored: frozenset[str]
  remaining_outstanding: frozenset[str]

  @property
  def is_partial(self) -> bool:
    """True when outstanding keys remain, so the task stays ``input_required`` (R-25.8-h)."""
    return bool(self.remaining_outstanding)

  @property
  def all_resolved(self) -> bool:
    """True when no outstanding input remains after this update (R-25.8-h)."""
    return not self.remaining_outstanding


class TaskInputState:
  """Server-side bookkeeping of a single task's ``inputRequests`` keys (§25.8).

  Enforces the key-lifetime and outstanding-set rules of §25.8 so the
  snapshot-relative binding (R-25.8-b) and the accept/ignore/partial behavior
  (R-25.8-g/h) are testable:

    - Every key issued is unique over the whole task lifetime; reissuing any key
      ever seen raises :class:`InputRequestKeyError` (R-25.8-e/f).
    - A ``tasks/update`` response is accepted only when its key is CURRENTLY
      outstanding (R-25.8-b); a key that was never issued, already answered, or
      superseded is ignored (R-25.8-g).
    - A strict subset of responses is accepted, leaving the rest outstanding
      (R-25.8-h).
  """

  def __init__(self) -> None:
    self._outstanding: set[str] = set()
    self._ever_issued: set[str] = set()

  def issue(self, *keys: str) -> None:
    """Mark one or more ``inputRequests`` keys as newly outstanding (R-25.8-e/f).

    Each key MUST be unique over the task's entire lifetime: a key that was ever
    issued before — whether still outstanding, already answered, or superseded —
    MUST NOT be reissued (R-25.8-e/f).

    Raises:
      ValueError: a key is not a non-empty string.
      InputRequestKeyError: a key was already issued during this task's lifetime.
    """
    for key in keys:
      if not isinstance(key, str) or not key:
        raise ValueError("inputRequests keys must be non-empty strings (R-25.8-e)")
      if key in self._ever_issued:
        raise InputRequestKeyError(key)
    for key in keys:
      self._ever_issued.add(key)
      self._outstanding.add(key)

  @property
  def outstanding(self) -> frozenset[str]:
    """The keys currently outstanding (the snapshot a ``tasks/get`` would show)."""
    return frozenset(self._outstanding)

  def is_outstanding(self, key: str) -> bool:
    """True iff ``key`` is currently outstanding for the task (R-25.8-b)."""
    return key in self._outstanding

  def apply_responses(self, input_responses: dict[str, Any]) -> InputResponseApplication:
    """Apply a ``tasks/update``'s ``inputResponses`` to the outstanding set (§25.8).

    Each key in ``inputResponses`` is accepted only if it is CURRENTLY
    outstanding (R-25.8-b); any other key (never issued, already answered, or
    superseded) is IGNORED (R-25.8-g). Accepting a strict subset leaves the rest
    outstanding so the task remains ``input_required`` (R-25.8-h).

    Args:
      input_responses: the ``InputResponses`` map from a ``tasks/update``.

    Returns:
      An :class:`InputResponseApplication` describing accepted/ignored keys and
      what remains outstanding.
    """
    accepted: set[str] = set()
    ignored: set[str] = set()
    for key in input_responses:
      if key in self._outstanding:
        accepted.add(key)
      else:
        ignored.add(key)
    self._outstanding -= accepted
    return InputResponseApplication(
      accepted=frozenset(accepted),
      ignored=frozenset(ignored),
      remaining_outstanding=frozenset(self._outstanding),
    )


class AnsweredKeyTracker:
  """Client-side record of which ``inputRequests`` keys have already been answered (§25.8).

  ``inputRequests`` is a point-in-time snapshot and the same key MAY appear on
  multiple consecutive ``tasks/get`` results until its response is processed
  (R-25.8-i). A client SHOULD track which keys it has already answered so it does
  not respond to the same request more than once (R-25.8-i). This tracker records
  answered keys and filters a fresh snapshot down to the not-yet-answered keys.
  """

  def __init__(self) -> None:
    self._answered: set[str] = set()

  def mark_answered(self, *keys: str) -> None:
    """Record that ``keys`` have been answered so they are not answered again (R-25.8-i)."""
    self._answered.update(keys)

  def has_answered(self, key: str) -> bool:
    """True iff ``key`` was already answered by this client (R-25.8-i)."""
    return key in self._answered

  def unanswered(self, snapshot_keys: frozenset[str] | set[str]) -> frozenset[str]:
    """Return the keys from a ``tasks/get`` snapshot not yet answered (R-25.8-i).

    A repeated key that the client has already answered is filtered out, so the
    client does not respond to the same request twice (R-25.8-i).
    """
    return frozenset(k for k in snapshot_keys if k not in self._answered)


# ---------------------------------------------------------------------------
# §25.8 / §25.9  Empty acknowledgement result  [R-25.8-j/k, R-25.9-e/f]
# ---------------------------------------------------------------------------

@dataclass
class EmptyAckResult:
  """The empty acknowledgement returned by ``tasks/update`` and ``tasks/cancel`` (§25.8/§25.9).

  Its ``resultType`` member MUST be the literal string ``"complete"`` and the body
  is otherwise empty (R-25.8-j, R-25.9-e). On success the server MUST acknowledge
  with this result (R-25.8-k, R-25.9-f). The acknowledgement is eventually
  consistent: the server MAY return it before the task's observable status
  reflects the change (R-25.8-l, R-25.9-i).

  Fields:
    meta: OPTIONAL result-level ``_meta`` (wire key ``_meta``).
  """

  meta: dict[str, Any] | None = None

  @property
  def result_type(self) -> ResultType:
    """The ``resultType`` discriminator; always ``"complete"`` (R-25.8-j, R-25.9-e)."""
    return RESULT_TYPE_COMPLETE

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire ``Result`` carrying only ``resultType: "complete"`` (§25.8/§25.9)."""
    out: dict[str, Any] = {"resultType": RESULT_TYPE_COMPLETE}
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def parse_empty_ack_result(raw: dict[str, Any]) -> EmptyAckResult:
  """Parse and validate an empty acknowledgement result (§25.8/§25.9, R-25.8-j, R-25.9-e).

  Verifies ``resultType`` is exactly ``"complete"`` (R-25.8-j, R-25.9-e); the body
  is otherwise empty (extra members beyond ``_meta`` are tolerated for forward
  compatibility but carry no defined meaning).

  Raises:
    TypeError: ``raw`` is not a dict or ``_meta`` has the wrong type.
    ValueError: ``resultType`` is not ``"complete"``.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"acknowledgement result must be a JSON object; got {type(raw).__name__}"
    )
  rt = raw.get("resultType")
  if rt != RESULT_TYPE_COMPLETE:
    raise ValueError(
      f"acknowledgement resultType must be exactly {RESULT_TYPE_COMPLETE!r} "
      f"(case-sensitive); got {rt!r} (R-25.8-j, R-25.9-e)"
    )
  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )
  return EmptyAckResult(meta=meta)


def build_update_task_response(
  request_id: RequestId,
  *,
  meta: dict[str, Any] | None = None,
) -> JSONRPCResultResponse:
  """Build the empty ``tasks/update`` acknowledgement response (§25.8, R-25.8-j/k).

  On success the server MUST acknowledge ``tasks/update`` with the empty result
  whose ``resultType`` is ``"complete"`` (R-25.8-j/k). The acknowledgement is
  eventually consistent (R-25.8-l).
  """
  validate_request_id(request_id)
  return JSONRPCResultResponse(
    id=request_id, result=EmptyAckResult(meta=meta).to_dict()
  )


# ---------------------------------------------------------------------------
# §25.9  tasks/cancel — request, ack & cooperative semantics  [R-25.9-a..k]
# ---------------------------------------------------------------------------

@dataclass
class CancelTaskRequestParams:
  """Params of a ``tasks/cancel`` request: the single REQUIRED ``taskId`` (§25.9).

  The params object carries exactly ``taskId`` — the identifier of the task to
  cancel (R-25.9-b). Cancellation is cooperative: this request only signals
  intent (R-25.9-h).

  Fields:
    task_id (``taskId``): identifier of the task to cancel. REQUIRED.
  """

  task_id: str

  def __post_init__(self) -> None:
    """Validate ``taskId`` is a non-empty opaque string (R-25.9-b).

    Raises:
      TypeError: ``task_id`` is not a string.
      ValueError: ``task_id`` is empty.
    """
    _validate_task_id(self.task_id)

  def to_dict(self) -> dict[str, Any]:
    """Serialize to the wire ``params`` object (§25.9, R-25.9-b)."""
    return {"taskId": self.task_id}


def parse_cancel_task_request_params(raw: Any) -> CancelTaskRequestParams:
  """Parse and validate ``tasks/cancel`` params (§25.9, R-25.9-b).

  ``taskId`` is REQUIRED (R-25.9-b).

  Raises:
    TypeError: ``raw`` is not a dict or ``taskId`` is not a string.
    ValueError: ``taskId`` is absent or empty.
  """
  task_id = _require_task_id(raw, TASKS_CANCEL_METHOD)
  return CancelTaskRequestParams(task_id=task_id)


def build_cancel_task_request(request_id: RequestId, task_id: str) -> JSONRPCRequest:
  """Build the ``tasks/cancel`` JSON-RPC request for cooperative cancellation (§25.9).

  Cancellation is cooperative and signals INTENT only: the server is obligated
  only to acknowledge, not to stop the work (R-25.9-h). The general-purpose
  ``notifications/cancelled`` notification MUST NOT be used to cancel a task —
  ``tasks/cancel`` is the only mechanism (R-25.9-a). The caller MUST have
  negotiated the Tasks extension (R-25.9-c).

  Args:
    request_id: the JSON-RPC id.
    task_id: identifier of the task to cancel.

  Returns:
    A :class:`~mcp_sdk_py.jsonrpc.JSONRPCRequest` for ``tasks/cancel``.
  """
  validate_request_id(request_id)
  params = CancelTaskRequestParams(task_id=task_id)
  return JSONRPCRequest(
    id=request_id, method=TASKS_CANCEL_METHOD, params=params.to_dict()
  )


def build_cancel_task_response(
  request_id: RequestId,
  *,
  meta: dict[str, Any] | None = None,
) -> JSONRPCResultResponse:
  """Build the empty ``tasks/cancel`` acknowledgement response (§25.9, R-25.9-e/f).

  On success the server MUST acknowledge ``tasks/cancel`` with the empty result
  whose ``resultType`` is ``"complete"`` (R-25.9-e/f). The acknowledgement does
  not guarantee a transition to ``cancelled`` (R-25.9-h/i).
  """
  validate_request_id(request_id)
  return JSONRPCResultResponse(
    id=request_id, result=EmptyAckResult(meta=meta).to_dict()
  )


def is_task_cancellation_notification(method: str) -> bool:
  """True iff ``method`` is the forbidden general-purpose cancellation notification (R-25.9-a).

  The ``notifications/cancelled`` notification MUST NOT be used to cancel a task;
  ``tasks/cancel`` is the only mechanism (R-25.9-a). This recognizes the forbidden
  method so a client/server can reject any attempt to use it for task
  cancellation.
  """
  return method == GENERAL_CANCELLED_NOTIFICATION_METHOD


def apply_cancellation(status: TaskStatus) -> TaskStatus:
  """Apply ``tasks/cancel`` to a task's current status, cooperatively (R-25.9-h/i/j).

  Cancellation is cooperative and eventually consistent: the server decides
  whether and when to honor it, and is only obligated to acknowledge (R-25.9-h).
  A task already in a terminal status MUST NOT change status as a result of
  ``tasks/cancel`` — terminal status is final (R-25.9-j). For a non-terminal task
  this returns the status UNCHANGED: cancellation never forces an immediate
  transition; the eventual move to ``cancelled`` (if any) is the server's
  decision (R-25.9-h/i). The helper therefore models the MUST NOT of R-25.9-j and
  the "only acknowledge" obligation of R-25.9-h.

  Args:
    status: the task's status when the cancel is processed.

  Returns:
    The status after applying cancellation — unchanged in all cases here, since a
    terminal task is immutable (R-25.9-j) and a non-terminal task is not forced to
    transition (R-25.9-h/i).
  """
  return status


def cancel_changes_terminal_status(status: TaskStatus) -> bool:
  """True iff ``tasks/cancel`` would change ``status`` — always False for terminal (R-25.9-j).

  A task that has already reached a terminal status MUST NOT change status as a
  result of ``tasks/cancel`` (R-25.9-j). This returns False for any terminal
  status (cancel is a no-op) and also False for non-terminal statuses, because
  cancellation never FORCES a transition — it only signals intent (R-25.9-h).
  """
  return False


def client_may_drop_state_after_cancel() -> bool:
  """True: a client MAY drop all local task state immediately after ``tasks/cancel`` (R-25.9-k).

  A client MAY drop all local state associated with a task as soon as it sends
  ``tasks/cancel`` (e.g. the answered-key set) and need not poll ``tasks/get``
  again to wait for the ``cancelled`` status (R-25.9-k).
  """
  return True


# ---------------------------------------------------------------------------
# §25.10  notifications/tasks — status push  [R-25.10-a, R-25.10-d, R-25.10-g]
# ---------------------------------------------------------------------------

def build_task_status_notification(
  detailed_task: DetailedTask,
  *,
  meta: dict[str, Any] | None = None,
) -> JSONRPCNotification:
  """Build a ``notifications/tasks`` push carrying a full ``DetailedTask`` (§25.10, R-25.10-a).

  A server MAY push task state changes through ``notifications/tasks``; each push
  carries a COMPLETE :class:`~mcp_sdk_py.tasks.DetailedTask` for the task's
  current status — identical to what ``tasks/get`` would return at that moment
  (R-25.10-a). The ``params`` is the flattened ``DetailedTask`` (always including
  ``taskId`` and ``status``, plus the status-specific payload) optionally carrying
  notification metadata per §3.

  A server MUST NOT push this for a task the client did not subscribe to via a
  ``taskIds`` filter (R-25.10-d); gating is the caller's responsibility — see
  :class:`TaskNotificationGate`.

  Args:
    detailed_task: the current :class:`~mcp_sdk_py.tasks.DetailedTask` to push.
    meta: OPTIONAL notification metadata merged into ``params._meta`` (§3).

  Returns:
    A :class:`~mcp_sdk_py.jsonrpc.JSONRPCNotification` for ``notifications/tasks``.
  """
  params: dict[str, Any] = detailed_task.to_dict()
  if meta is not None:
    params["_meta"] = meta
  return JSONRPCNotification(method=TASKS_NOTIFICATION_METHOD, params=params)


def parse_task_status_notification(notification: JSONRPCNotification) -> DetailedTask:
  """Parse a ``notifications/tasks`` push back into a ``DetailedTask`` (§25.10, R-25.10-a).

  The ``params`` is a flattened :class:`~mcp_sdk_py.tasks.DetailedTask` — the same
  variant union ``tasks/get`` returns — so a client receiving it need not issue an
  extra ``tasks/get`` round trip (R-25.10-a). Notification ``_meta`` is permitted
  and ignored by the parse.

  Raises:
    ValueError: the notification method is not ``notifications/tasks``, or a
      REQUIRED Task/variant field is absent.
    TypeError: ``params`` (or a member) has the wrong type.
  """
  if notification.method != TASKS_NOTIFICATION_METHOD:
    raise ValueError(
      f"expected a {TASKS_NOTIFICATION_METHOD!r} notification; got "
      f"{notification.method!r} (R-25.10-a)"
    )
  params = notification.params
  if not isinstance(params, dict):
    raise TypeError(
      f"notifications/tasks params must be a JSON object; got "
      f"{type(params).__name__} (R-25.10-a)"
    )
  return parse_detailed_task(params)


def notification_matches_get(
  notification: JSONRPCNotification,
  get_result: GetTaskResult,
) -> bool:
  """True iff a ``notifications/tasks`` push carries the same ``DetailedTask`` as ``tasks/get`` (R-25.10-a).

  Each ``notifications/tasks`` carries a complete ``DetailedTask`` IDENTICAL to
  what ``tasks/get`` would have returned at that moment (R-25.10-a). This compares
  the flattened ``DetailedTask`` body of the notification against the
  ``DetailedTask`` of a ``tasks/get`` result (the ``resultType`` discriminator and
  any ``_meta`` are not part of the ``DetailedTask`` body and are excluded).
  """
  pushed = parse_task_status_notification(notification)
  return pushed.to_dict() == get_result.detailed_task.to_dict()


def assert_task_notification_allowed(method: str) -> None:
  """Raise if ``method`` is a notification that MUST NOT be sent for a task (R-25.10-g).

  The ``notifications/progress`` and ``notifications/message`` notifications MUST
  NOT be sent for a task; task state is conveyed ONLY via ``tasks/get`` and
  ``notifications/tasks`` (R-25.10-g).

  Raises:
    ValueError: ``method`` is one of the forbidden notifications.
  """
  if method in FORBIDDEN_TASK_NOTIFICATION_METHODS:
    raise ValueError(
      f"{method!r} MUST NOT be sent for a task; task state is conveyed only via "
      f"{TASKS_GET_METHOD!r} and {TASKS_NOTIFICATION_METHOD!r} (R-25.10-g)"
    )


def is_forbidden_task_notification(method: str) -> bool:
  """True iff ``method`` MUST NOT be sent for a task (progress/message) (R-25.10-g)."""
  return method in FORBIDDEN_TASK_NOTIFICATION_METHODS


# ---------------------------------------------------------------------------
# §25.10  taskIds subscription filter & opt-in gating  [R-25.10-b..f]
# ---------------------------------------------------------------------------

@dataclass
class TaskIdsFilter:
  """The ``taskIds`` opt-in extension to S16's ``subscriptions/listen`` filter (§25.10).

  A client opts in to ``notifications/tasks`` by including the task identifiers it
  is interested in as a ``taskIds`` filter on ``subscriptions/listen`` (R-25.10-b).
  Each element MUST be a ``taskId`` the client holds (R-25.10-c). This wraps that
  member (added under ``params.notifications`` alongside S16's existing filter
  fields).

  Fields:
    task_ids: the task identifiers the client wishes to receive notifications for.
  """

  task_ids: tuple[str, ...] = ()

  def __post_init__(self) -> None:
    """Validate every element is a non-empty opaque ``taskId`` string (R-25.10-c).

    Raises:
      TypeError: an element is not a string.
      ValueError: an element is empty.
    """
    normalized = tuple(self.task_ids)
    for tid in normalized:
      _validate_task_id(tid)
    object.__setattr__(self, "task_ids", normalized)

  @property
  def has_task_ids(self) -> bool:
    """True when the client requested task status notifications (R-25.10-b)."""
    return bool(self.task_ids)

  def to_dict(self) -> dict[str, Any]:
    """Serialize to the ``notifications``-level ``taskIds`` member; omits when empty.

    Omission is equivalent to not requesting task notifications (R-25.10-b).
    """
    if not self.task_ids:
      return {}
    return {TASK_IDS_FILTER_KEY: list(self.task_ids)}


def parse_task_ids_filter(raw: Any) -> TaskIdsFilter:
  """Parse the ``taskIds`` member from a ``subscriptions/listen`` ``notifications`` filter (§25.10).

  ``taskIds`` is OPTIONAL; when present it MUST be an array of non-empty ``taskId``
  strings the client holds (R-25.10-b/c). An absent member yields an empty filter
  (no task notifications requested). Other ``notifications`` members (S16's filter
  fields) are ignored here.

  Raises:
    TypeError: the filter is not an object, or ``taskIds`` is not an array of
      strings.
    ValueError: a ``taskIds`` element is empty.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"notifications filter must be a JSON object; got {type(raw).__name__} (R-25.10-b)"
    )
  ids_raw = raw.get(TASK_IDS_FILTER_KEY)
  if ids_raw is None:
    return TaskIdsFilter()
  if not isinstance(ids_raw, list):
    raise TypeError(
      f"{TASK_IDS_FILTER_KEY} must be an array if present; got "
      f"{type(ids_raw).__name__} (R-25.10-b)"
    )
  for element in ids_raw:
    _validate_task_id(element)
  return TaskIdsFilter(task_ids=tuple(ids_raw))


def build_task_subscription_request(
  request_id: RequestId,
  task_ids: tuple[str, ...] | list[str],
  *,
  meta: dict[str, Any] | None = None,
) -> JSONRPCRequest:
  """Build a ``subscriptions/listen`` request opting in to ``notifications/tasks`` (§25.10).

  Opt-in is through the §10 subscription mechanism: the client adds a ``taskIds``
  filter under ``params.notifications`` naming the task ids it holds (R-25.10-b/c).
  This builds that ``subscriptions/listen`` request with only the ``taskIds``
  member; S16's other filter fields MAY be merged into ``notifications`` by the
  caller as needed.

  Args:
    request_id: the JSON-RPC id (also S16's subscription identifier).
    task_ids: the task ids the client holds and wishes notifications for.
    meta: OPTIONAL request metadata (wire key ``_meta``).

  Returns:
    A :class:`~mcp_sdk_py.jsonrpc.JSONRPCRequest` for ``subscriptions/listen``.
  """
  validate_request_id(request_id)
  filt = TaskIdsFilter(task_ids=tuple(task_ids))
  params: dict[str, Any] = {"notifications": filt.to_dict()}
  if meta is not None:
    params["_meta"] = meta
  return JSONRPCRequest(
    id=request_id, method=SUBSCRIPTIONS_LISTEN_METHOD, params=params
  )


def assert_task_subscription_capability(
  filt: TaskIdsFilter,
  client_extensions: Any,
  server_extensions: Any,
) -> None:
  """Raise the ``-32003`` error if ``taskIds`` is supplied without the extension (R-25.10-e).

  If a client supplies ``taskIds`` but has NOT negotiated the
  ``io.modelcontextprotocol/tasks`` extension capability, the server MUST respond
  to ``subscriptions/listen`` with error code ``-32003`` (Missing Required Client
  Capability) (R-25.10-e). When no ``taskIds`` are requested this is a no-op
  (S16's filter alone needs no Tasks capability).

  Args:
    filt: the parsed ``taskIds`` filter from the request.
    client_extensions: the client's per-request ``extensions`` map (or ``None``).
    server_extensions: the server's advertised ``extensions`` map (or ``None``).

  Raises:
    TasksExtensionNotActiveError: ``taskIds`` was supplied but the extension is
      not active, carrying the §22 ``-32003`` error (R-25.10-e).
  """
  if not filt.has_task_ids:
    return
  if not tasks_active(client_extensions, server_extensions):
    raise TasksExtensionNotActiveError(SUBSCRIPTIONS_LISTEN_METHOD)


class TaskNotificationGate:
  """Server-side gate enforcing the ``notifications/tasks`` opt-in subset (§25.10).

  A server MUST NOT push ``notifications/tasks`` for any task the client did not
  subscribe to via a ``taskIds`` filter on ``subscriptions/listen`` (R-25.10-d).
  This records the subscribed-to set (the subset the server agreed to push) and
  answers whether a given ``taskId`` may be pushed. Polling remains available
  regardless: a client MAY rely solely on notifications, solely on polling, or
  combine both (R-25.10-f) — this gate constrains only the push side.
  """

  def __init__(self, subscribed_task_ids: frozenset[str] | set[str] | None = None) -> None:
    self._subscribed: set[str] = set(subscribed_task_ids or ())

  def subscribe(self, *task_ids: str) -> None:
    """Record task ids the server agreed to push ``notifications/tasks`` for (R-25.10-c)."""
    for tid in task_ids:
      _validate_task_id(tid)
      self._subscribed.add(tid)

  def unsubscribe(self, *task_ids: str) -> None:
    """Drop task ids from the push subset (e.g. once a task is terminal/removed)."""
    for tid in task_ids:
      self._subscribed.discard(tid)

  @property
  def subscribed(self) -> frozenset[str]:
    """The task ids the server may push ``notifications/tasks`` for (R-25.10-d)."""
    return frozenset(self._subscribed)

  def may_push(self, task_id: str) -> bool:
    """True iff the server MAY push ``notifications/tasks`` for ``task_id`` (R-25.10-d).

    True only when the client subscribed to this id via a ``taskIds`` filter; the
    server MUST NOT push for an unsubscribed task (R-25.10-d).
    """
    return task_id in self._subscribed

  def assert_may_push(self, task_id: str) -> None:
    """Raise if the server would push for a task the client did not subscribe to (R-25.10-d).

    Raises:
      ValueError: ``task_id`` was not subscribed via a ``taskIds`` filter.
    """
    if not self.may_push(task_id):
      raise ValueError(
        f"a server MUST NOT push {TASKS_NOTIFICATION_METHOD!r} for task "
        f"{task_id!r}; the client did not subscribe to it via a {TASK_IDS_FILTER_KEY!r} "
        f"filter on {SUBSCRIPTIONS_LISTEN_METHOD!r} (R-25.10-d)"
      )


def client_may_rely_on_notifications_only() -> bool:
  """True: a subscribed client MAY rely solely on notifications and need not poll (R-25.10-f).

  A client MAY rely solely on ``notifications/tasks``, MAY rely solely on polling
  ``tasks/get``, or MAY combine the two; a client that has subscribed need not
  poll (R-25.10-f).
  """
  return True


# ---------------------------------------------------------------------------
# §25.10  Relationship to multi-round-trip input  [R-25.10-h, R-25.10-i, R-25.10-j]
# ---------------------------------------------------------------------------

class InputResolutionChannel:
  """The single permitted channel for resolving a given outstanding input (§25.10).

  For a single outstanding input the §11 in-line retry mechanism and the
  ``tasks/update`` mechanism MUST NOT be mixed: input surfaced through a task's
  ``inputRequests`` is resolved ONLY via ``tasks/update``, and input surfaced
  through an in-line input-required result is resolved ONLY by re-issuing the
  original method (R-25.10-j).

  TASK_UPDATE: the input was surfaced via a task's ``inputRequests`` → resolve
    only with ``tasks/update``.
  INLINE_RETRY: the input was surfaced via an in-line input-required result →
    resolve only by re-issuing the original method.
  """

  TASK_UPDATE: str = "tasks/update"
  INLINE_RETRY: str = "inline_retry"


def required_input_resolution_channel(surfaced_via_task: bool) -> str:
  """Return the ONLY permitted resolution channel for an outstanding input (R-25.10-j).

  Input surfaced through a task's ``inputRequests`` is resolved only via
  ``tasks/update``; input surfaced through an in-line input-required result is
  resolved only by re-issuing the original method (R-25.10-j). The two MUST NOT be
  mixed.

  Args:
    surfaced_via_task: True if the input was surfaced via a task's
      ``inputRequests``; False if via an in-line input-required result.

  Returns:
    :data:`InputResolutionChannel.TASK_UPDATE` or
    :data:`InputResolutionChannel.INLINE_RETRY`.
  """
  return (
    InputResolutionChannel.TASK_UPDATE
    if surfaced_via_task
    else InputResolutionChannel.INLINE_RETRY
  )


def assert_resolution_channel_not_mixed(
  surfaced_via_task: bool,
  attempted_channel: str,
) -> None:
  """Raise if an outstanding input is resolved over the wrong channel (R-25.10-j).

  The in-line retry mechanism and the ``tasks/update`` mechanism MUST NOT be mixed
  for a single outstanding input (R-25.10-j).

  Raises:
    ValueError: ``attempted_channel`` is not the one required for how the input
      was surfaced.
  """
  required = required_input_resolution_channel(surfaced_via_task)
  if attempted_channel != required:
    raise ValueError(
      f"input surfaced "
      f"{'via a task inputRequests' if surfaced_via_task else 'inline'} MUST be "
      f"resolved only via {required!r}, not {attempted_channel!r}; the §11 "
      f"in-line retry and tasks/update mechanisms MUST NOT be mixed (R-25.10-j)"
    )


def should_resolve_pre_task_input_synchronously() -> bool:
  """True: a server SHOULD resolve pre-task input synchronously before a task exists (R-25.10-h).

  When a server needs client input BEFORE a task exists, it SHOULD resolve that
  exchange synchronously via the in-line multi-round-trip flow of §11 before
  returning a ``CreateTaskResult`` (R-25.10-h).
  """
  return True


def input_request_trust_is_not_elevated() -> bool:
  """True: a task ``inputRequests`` entry carries no elevated trust (R-25.10-i).

  Each entry in ``inputRequests`` MUST be treated by the client exactly as it
  would treat the equivalent standalone server-to-client request — same trust
  model and user-facing behavior; a task is NOT a higher-trust channel
  (R-25.10-i). This asserts the contract: the trust model is identical (not
  elevated) whether the request is surfaced inline or via a task.
  """
  return True


# ---------------------------------------------------------------------------
# §25.11  Lifecycle & cleanup: ttlMs, expiry, protocol vs application error
#         [R-25.11-a..i]
# ---------------------------------------------------------------------------

def ttl_deadline_ms(created_at_epoch_ms: float, ttl_ms: float | int | None) -> float | None:
  """Return the backstop deadline ``createdAt + ttlMs`` in epoch ms, or ``None`` (R-25.11-c).

  A client MAY treat a non-null ``ttlMs`` as a backstop: if the task's observable
  status has not advanced by ``createdAt`` plus ``ttlMs``, the client MAY consider
  the task not usable (R-25.11-c). A ``null`` ``ttlMs`` means unlimited, so there
  is no deadline (R-25.11-a).

  Args:
    created_at_epoch_ms: the task's ``createdAt`` as epoch milliseconds.
    ttl_ms: the task's ``ttlMs`` (``None`` for unlimited).

  Returns:
    The deadline epoch-ms, or ``None`` when ``ttlMs`` is ``None``.
  """
  if ttl_ms is None:
    return None
  return created_at_epoch_ms + float(ttl_ms)


def is_task_expired(
  created_at_epoch_ms: float,
  ttl_ms: float | int | None,
  now_epoch_ms: float,
) -> bool:
  """True iff ``ttlMs`` has elapsed since ``createdAt`` by ``now`` (R-25.11-b/c).

  A server MAY mark a task ``failed`` at any point after ``ttlMs`` has elapsed,
  and a client MAY treat ``createdAt + ttlMs`` as a backstop (R-25.11-b/c). A
  ``null`` ``ttlMs`` (unlimited) never expires (R-25.11-a).

  Args:
    created_at_epoch_ms: the task's ``createdAt`` as epoch milliseconds.
    ttl_ms: the task's ``ttlMs`` (``None`` for unlimited).
    now_epoch_ms: the current time as epoch milliseconds.
  """
  deadline = ttl_deadline_ms(created_at_epoch_ms, ttl_ms)
  if deadline is None:
    return False
  return now_epoch_ms >= deadline


def task_unusable_backstop(
  created_at_epoch_ms: float,
  ttl_ms: float | int | None,
  now_epoch_ms: float,
  *,
  status_advanced: bool,
) -> bool:
  """True iff a client MAY consider the task not usable by its ``ttlMs`` backstop (R-25.11-c).

  A client MAY consider the task not usable if its observable status has not
  advanced by the time ``createdAt + ttlMs`` has elapsed (R-25.11-c). When the
  status HAS advanced, the backstop does not apply.

  Args:
    created_at_epoch_ms: the task's ``createdAt`` as epoch milliseconds.
    ttl_ms: the task's ``ttlMs`` (``None`` for unlimited).
    now_epoch_ms: the current time as epoch milliseconds.
    status_advanced: whether the task's observable status has advanced.
  """
  if status_advanced:
    return False
  return is_task_expired(created_at_epoch_ms, ttl_ms, now_epoch_ms)


def status_for_protocol_error(error: dict[str, Any]) -> TaskStatus:
  """Return ``failed`` — the status for a JSON-RPC protocol error during execution (R-25.11-f).

  When the underlying request encounters a JSON-RPC protocol error during
  execution, the task moves to ``failed`` and the ``tasks/get`` result MUST
  include the ``error`` field carrying that JSON-RPC error (R-25.11-f). This
  validates the error object's presence and returns the mandated status.

  Raises:
    TypeError: ``error`` is not a JSON object.

  Returns:
    :data:`TaskStatus.FAILED`.
  """
  if not isinstance(error, dict):
    raise TypeError(
      f"a protocol-error task's 'error' must be a JSON-RPC error object; got "
      f"{type(error).__name__} (R-25.11-f)"
    )
  return TaskStatus.FAILED


def build_failed_detailed_task(
  task: Task,
  error: dict[str, Any],
  *,
  status_message: str | None = None,
) -> DetailedTask:
  """Build the ``failed`` ``DetailedTask`` for a protocol error during execution (R-25.11-f/g).

  When the underlying request hits a JSON-RPC protocol error during execution, the
  task moves to ``failed``, the ``tasks/get`` result MUST include the ``error``
  field carrying that JSON-RPC error (R-25.11-f), and SHOULD include a
  ``statusMessage`` with diagnostic information (R-25.11-g). The ``failed`` status
  MUST NOT be used for non-protocol faults (R-25.11-h) — see
  :func:`build_completed_with_application_error` for that case.

  Args:
    task: the base :class:`~mcp_sdk_py.tasks.Task`; its status MUST be ``failed``.
    error: the JSON-RPC error object that occurred during execution.
    status_message: OPTIONAL diagnostic message (SHOULD be supplied; R-25.11-g).
      When given, a copy of ``task`` carrying it is used.

  Raises:
    ValueError: ``task.status`` is not ``failed``.
    TypeError: ``error`` is not a JSON object.
  """
  if task.status is not TaskStatus.FAILED:
    raise ValueError(
      f"build_failed_detailed_task requires a 'failed' task; got "
      f"{task.status.value!r} (R-25.11-f)"
    )
  if not isinstance(error, dict):
    raise TypeError(
      f"'error' must be a JSON-RPC error object; got {type(error).__name__} (R-25.11-f)"
    )
  if status_message is not None and task.status_message != status_message:
    task = Task(
      task_id=task.task_id,
      status=task.status,
      created_at=task.created_at,
      last_updated_at=task.last_updated_at,
      ttl_ms=task.ttl_ms,
      status_message=status_message,
      poll_interval_ms=task.poll_interval_ms,
    )
  return DetailedTask(task=task, error=error)


def is_application_level_error_result(result: dict[str, Any]) -> bool:
  """True iff a completed result conveys an application-level error (e.g. ``isError: true``) (R-25.11-i).

  A request that completes at the protocol level but conveys an application-level
  error within its result — for example a tool result carrying ``isError: true`` —
  is an application-level outcome, NOT a protocol fault (R-25.11-i). This
  recognizes that shape so the caller reports it as ``completed`` rather than
  ``failed`` (R-25.11-h/i).
  """
  return isinstance(result, dict) and result.get("isError") is True


def build_completed_with_application_error(task: Task, result: dict[str, Any]) -> DetailedTask:
  """Build the ``completed`` ``DetailedTask`` for an application-level error result (R-25.11-h/i).

  A request that completes at the protocol level but conveys an application-level
  error within its result (e.g. a tool result with ``isError: true``) MUST be
  reported with the ``completed`` status, with the error details inside the
  ``result`` field (R-25.11-i). The ``failed`` status MUST NOT be used for such
  non-protocol faults (R-25.11-h). This preserves the strict separation between
  protocol-level faults (``failed``) and application-level outcomes
  (``completed``).

  Args:
    task: the base :class:`~mcp_sdk_py.tasks.Task`; its status MUST be ``completed``.
    result: the ordinary result object carrying the application-level error.

  Raises:
    ValueError: ``task.status`` is not ``completed``.
    TypeError: ``result`` is not a JSON object.
  """
  if task.status is not TaskStatus.COMPLETED:
    raise ValueError(
      f"an application-level error MUST be reported as 'completed', not "
      f"{task.status.value!r}; 'failed' is only for protocol faults (R-25.11-h/i)"
    )
  if not isinstance(result, dict):
    raise TypeError(
      f"'result' must be a JSON object; got {type(result).__name__} (R-25.11-i)"
    )
  return DetailedTask(task=task, result=result)


def status_for_execution_outcome(
  *,
  is_protocol_error: bool,
) -> TaskStatus:
  """Return the terminal status for an execution outcome (R-25.11-f/h/i).

  A JSON-RPC protocol error during execution moves the task to ``failed``
  (R-25.11-f); any non-protocol outcome — including an application-level error
  conveyed within the result — is reported as ``completed`` (R-25.11-h/i). The
  ``failed`` status MUST NOT be used for non-protocol faults (R-25.11-h).

  Args:
    is_protocol_error: True iff a JSON-RPC protocol error occurred during
      execution.

  Returns:
    :data:`TaskStatus.FAILED` for a protocol error, else
    :data:`TaskStatus.COMPLETED`.
  """
  return TaskStatus.FAILED if is_protocol_error else TaskStatus.COMPLETED


# ---------------------------------------------------------------------------
# §25.7–§25.9  Shared capability gating for Tasks operations  [R-25.7-c/d, R-25.8-c/d, R-25.9-c/d]
# ---------------------------------------------------------------------------

def assert_tasks_method_allowed(
  method: str,
  client_extensions: Any,
  server_extensions: Any,
) -> None:
  """Raise the ``-32003`` error if a Tasks operation is invoked while inactive (R-25.7-d, R-25.8-d, R-25.9-d).

  A client MUST have negotiated the ``io.modelcontextprotocol/tasks`` extension
  before issuing ``tasks/get`` / ``tasks/update`` / ``tasks/cancel`` (R-25.7-c,
  R-25.8-c, R-25.9-c); a server receiving any of them from a client that did not
  declare the capability MUST respond with error code ``-32003`` (Missing Required
  Client Capability) (R-25.7-d, R-25.8-d, R-25.9-d). Call this server-side before
  servicing the operation. Reuses S39's per-request active-set predicate.

  Args:
    method: the Tasks operation method invoked.
    client_extensions: the client's per-request ``extensions`` map (or ``None``).
    server_extensions: the server's advertised ``extensions`` map (or ``None``).

  Raises:
    TasksExtensionNotActiveError: the extension is not active for this request,
      carrying the §22 ``-32003`` error.
  """
  if not tasks_active(client_extensions, server_extensions):
    raise TasksExtensionNotActiveError(method)


def build_missing_capability_response(
  request_id: RequestId,
  method: str,
) -> JSONRPCErrorResponse:
  """Build the ``-32003`` missing-capability error response for a Tasks operation (R-25.7-d, R-25.8-d, R-25.9-d).

  A server receiving a Tasks operation from a client that did not declare the
  extension capability MUST respond with error code ``-32003`` (R-25.7-d,
  R-25.8-d, R-25.9-d). This builds that JSON-RPC error response, reusing S39's
  :class:`~mcp_sdk_py.tasks.TasksExtensionNotActiveError` error object.

  Args:
    request_id: the JSON-RPC id of the rejected request.
    method: the Tasks operation method invoked while inactive.

  Returns:
    A :class:`~mcp_sdk_py.jsonrpc.JSONRPCErrorResponse` carrying the ``-32003`` error.
  """
  validate_request_id(request_id)
  error = TasksExtensionNotActiveError(method).to_error_object()
  return JSONRPCErrorResponse(id=request_id, error=error)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _validate_task_id(task_id: Any) -> None:
  """Validate a ``taskId`` is a non-empty opaque string (S39 R-25.4-a; §25.7 R-25.7-a/b).

  Raises:
    TypeError: ``task_id`` is not a string.
    ValueError: ``task_id`` is empty.
  """
  if not isinstance(task_id, str):
    raise TypeError(
      f"taskId must be an opaque string; got {type(task_id).__name__} (R-25.7-a/b)"
    )
  if not task_id:
    raise ValueError("taskId is REQUIRED and must be non-empty (R-25.7-a)")


def _require_task_id(raw: Any, method: str) -> str:
  """Extract a REQUIRED ``taskId`` from a params dict, validating it (R-25.7-a, R-25.9-b).

  Raises:
    TypeError: ``raw`` is not a dict, or ``taskId`` is not a string.
    ValueError: ``taskId`` is absent or empty.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"{method} params must be a JSON object; got {type(raw).__name__}"
    )
  if "taskId" not in raw:
    raise ValueError(f"{method} params.taskId is REQUIRED (R-25.7-a, R-25.9-b)")
  task_id = raw["taskId"]
  _validate_task_id(task_id)
  return task_id


__all__ = [
  # §25.7–§25.10 — method & notification names
  "TASKS_GET_METHOD",
  "TASKS_UPDATE_METHOD",
  "TASKS_CANCEL_METHOD",
  "TASKS_NOTIFICATION_METHOD",
  "TASKS_OPERATION_METHODS",
  "TASK_IDS_FILTER_KEY",
  "FORBIDDEN_TASK_NOTIFICATION_METHODS",
  "GENERAL_CANCELLED_NOTIFICATION_METHOD",
  # §25.7 — tasks/get
  "GetTaskRequestParams",
  "parse_get_task_request_params",
  "build_get_task_request",
  "GetTaskResult",
  "parse_get_task_result",
  "build_get_task_result",
  "build_get_task_response",
  # §25.7 / §25.11 — unknown / expired taskId
  "build_task_not_found_response",
  "is_task_not_found_error",
  "client_should_stop_polling",
  # §25.7 — polling semantics & durable persistence
  "PollIntervalTracker",
  "server_may_rate_limit",
  "should_continue_polling",
  "DurableTaskIdStore",
  # §25.8 — tasks/update
  "UpdateTaskRequestParams",
  "parse_update_task_request_params",
  "build_update_task_request",
  "build_update_task_response",
  # §25.8 — outstanding-input state & key lifetime
  "InputRequestKeyError",
  "InputResponseApplication",
  "TaskInputState",
  "AnsweredKeyTracker",
  # §25.8 / §25.9 — empty acknowledgement
  "EmptyAckResult",
  "parse_empty_ack_result",
  # §25.9 — tasks/cancel
  "CancelTaskRequestParams",
  "parse_cancel_task_request_params",
  "build_cancel_task_request",
  "build_cancel_task_response",
  "is_task_cancellation_notification",
  "apply_cancellation",
  "cancel_changes_terminal_status",
  "client_may_drop_state_after_cancel",
  # §25.10 — notifications/tasks
  "build_task_status_notification",
  "parse_task_status_notification",
  "notification_matches_get",
  "assert_task_notification_allowed",
  "is_forbidden_task_notification",
  # §25.10 — taskIds subscription filter & gating
  "TaskIdsFilter",
  "parse_task_ids_filter",
  "build_task_subscription_request",
  "assert_task_subscription_capability",
  "TaskNotificationGate",
  "client_may_rely_on_notifications_only",
  # §25.10 — relationship to multi-round-trip input
  "InputResolutionChannel",
  "required_input_resolution_channel",
  "assert_resolution_channel_not_mixed",
  "should_resolve_pre_task_input_synchronously",
  "input_request_trust_is_not_elevated",
  # §25.11 — lifecycle & cleanup
  "ttl_deadline_ms",
  "is_task_expired",
  "task_unusable_backstop",
  "status_for_protocol_error",
  "build_failed_detailed_task",
  "is_application_level_error_result",
  "build_completed_with_application_error",
  "status_for_execution_outcome",
  # §25.7–§25.9 — shared capability gating
  "assert_tasks_method_allowed",
  "build_missing_capability_response",
]
