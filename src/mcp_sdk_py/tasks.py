"""The Tasks Extension I — Model, Capability, Types & Lifecycle — S39 (spec §25.1–§25.6).

The Tasks extension, identified by the exact string ``io.modelcontextprotocol/tasks``,
models long-running, server-handled operations as durable, pollable **tasks**
rather than as blocking request/response exchanges (§25.1). A server that would
otherwise hold a connection open until work completes instead returns an opaque
**task handle** immediately (a :class:`CreateTaskResult`, whose ``resultType`` is
``"task"``), and the client retrieves the eventual outcome by polling.

This module delivers ONLY the foundational model of that extension (S39 = "Tasks
I"): the extension identifier and its negotiation/gating, the rule by which an
eligible request may be answered with a task handle, the ``Task`` /
``DetailedTask`` object types, the five-state status lifecycle, and the
durability/statelessness guarantees. The operational methods (``tasks/get``,
``tasks/update``, ``tasks/cancel``), the way input is supplied via
``inputResponses``, the task status **notifications**, and cleanup are owned by
S40 ("Tasks II") and are deliberately NOT implemented here (§25 "Out of scope").

It builds on three lower stories and REUSES, rather than re-implements, their
surfaces:

  - S38 (:mod:`mcp_sdk_py.extension_mechanism`) / S11
    (:mod:`mcp_sdk_py.extensions`) own the extension-identifier grammar, the
    ``extensions``-map parsing, the per-request active-set intersection, and the
    self-describing :class:`~mcp_sdk_py.extension_mechanism.ExtensionDefinition`.
    The Tasks extension is one such extension: :data:`TASKS_EXTENSION` is an
    ``ExtensionDefinition`` for it, and negotiation/gating defer to S11's active
    set (§25.2 ⇒ §24/§6.5).
  - S04 (:mod:`mcp_sdk_py.result_error`) owns the open ``resultType``
    discriminator (§3.6). This extension contributes exactly one new value,
    :data:`RESULT_TYPE_TASK` (``"task"``), per §24.5 item 3 (§25.3).
  - S17 (:mod:`mcp_sdk_py.multi_round_trip`) owns the ``InputRequest`` /
    ``InputRequests`` shape and the opaque continuation-token (``requestState``)
    mechanism. The ``input_required`` :class:`DetailedTask` variant carries an
    ``InputRequests`` map of S17's :class:`~mcp_sdk_py.multi_round_trip.InputRequest`
    (§25.4); the resumable-state encoding reuses S17/§11 (§25.6, R-25.6-e).

The concrete ``-32xxx`` numeric values for the missing-capability and not-found
error conditions are owned by §22/S34; this module references them through the
existing builders (:data:`MISSING_CAPABILITY_ERROR_CODE` reuses
:data:`~mcp_sdk_py.negotiation.MISSING_REQUIRED_CLIENT_CAPABILITY_CODE`, and the
not-found condition reuses the §22 ``-32602`` resource-not-found convention via
:data:`TASK_NOT_FOUND_ERROR_CODE`).

Spec: §25.1–§25.6 (lines 7161–7370)
Depends on: S38 (extension definition), S11 (active set), S17 (InputRequests),
  S04 (resultType), S22 (progress/cancellation concepts)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_sdk_py.extension_mechanism import ExtensionDefinition
from mcp_sdk_py.extensions import (
  active_extensions,
  is_extension_active,
)
from mcp_sdk_py.multi_round_trip import InputRequest, parse_input_request
from mcp_sdk_py.negotiation import MISSING_REQUIRED_CLIENT_CAPABILITY_CODE
from mcp_sdk_py.result_error import ResultType


# ---------------------------------------------------------------------------
# §25.1  Extension identifier  [R-25.1-a]
# ---------------------------------------------------------------------------

#: The exact, case-sensitive identifier for the Tasks extension (§25.1, R-25.1-a).
#: This string is the key used in the ``extensions`` capability map. A conforming
#: implementation MUST treat it as an opaque, exact string and MUST NOT match it
#: case-insensitively or by prefix — see :func:`is_tasks_extension_identifier`.
TASKS_EXTENSION_IDENTIFIER: str = "io.modelcontextprotocol/tasks"


def is_tasks_extension_identifier(identifier: str) -> bool:
  """Return True only for an EXACT, case-sensitive match of the Tasks identifier (R-25.1-a).

  A conforming implementation MUST treat the identifier as an opaque, exact
  string and MUST NOT match it case-insensitively or by prefix (R-25.1-a).
  Therefore strings that differ only in case (``IO.MODELCONTEXTPROTOCOL/TASKS``)
  or by prefix (``io.modelcontextprotocol/tasks-foo``) are NON-matching, even
  though they look similar.

  Args:
    identifier: a candidate ``extensions``-map key to compare.

  Returns:
    True iff ``identifier`` equals :data:`TASKS_EXTENSION_IDENTIFIER` byte-for-byte.
  """
  return identifier == TASKS_EXTENSION_IDENTIFIER


# ---------------------------------------------------------------------------
# §25.3  resultType discriminator value contributed by this extension  [R-25.3-c]
# ---------------------------------------------------------------------------

#: The open ``resultType`` discriminator value (§3.6) whose literal string marks
#: a result as a task handle (§25.3, R-25.3-c). A ``Result`` whose ``resultType``
#: is this value is a :class:`CreateTaskResult`. This is the single new
#: ``resultType`` the Tasks extension contributes through §24.5 item 3.
RESULT_TYPE_TASK: ResultType = "task"


# ---------------------------------------------------------------------------
# §25.2  Extension definition (reuses S38 ExtensionDefinition)
# ---------------------------------------------------------------------------

#: The Tasks-extension method names defined by §25.7–§25.9 (owned operationally by
#: S40). They are listed on the definition so the namespacing/active-set gating of
#: S38 recognizes them; their request/result shapes are NOT implemented in S39.
TASKS_METHODS: frozenset[str] = frozenset({
  "tasks/get",
  "tasks/update",
  "tasks/cancel",
})

#: The field names the Tasks extension adds to existing core objects: the
#: variant-specific members of :class:`DetailedTask` (``inputRequests`` on the
#: ``input_required`` variant, ``result`` on ``completed``, ``error`` on
#: ``failed``). Recorded on the definition for §24.5 channel-4 documentation.
TASKS_OBJECT_FIELDS: frozenset[str] = frozenset({
  "inputRequests",
  "result",
  "error",
})

#: The self-describing :class:`ExtensionDefinition` for the Tasks extension
#: (§25.1/§25.2). It declares the official ``io.modelcontextprotocol/tasks``
#: identifier (hence ``allow_reserved=True`` — only the protocol's own
#: extensions may use the reserved prefix), the ``tasks/*`` methods, the single
#: ``"task"`` ``resultType``, and the ``DetailedTask`` variant fields. Negotiation
#: and active-set gating reuse this definition through S38/S11.
TASKS_EXTENSION: ExtensionDefinition = ExtensionDefinition(
  identifier=TASKS_EXTENSION_IDENTIFIER,
  methods=TASKS_METHODS,
  result_types=frozenset({RESULT_TYPE_TASK}),
  object_fields=TASKS_OBJECT_FIELDS,
  fallback_doc=(
    "When the Tasks extension is not active for a request, the server returns "
    "the request's ordinary (direct) result and never a task handle; long-"
    "running work is handled by the core blocking request/response exchange "
    "(§25.2, §25.3)."
  ),
  allow_reserved=True,
)


# ---------------------------------------------------------------------------
# §25.2  Capability declaration & settings  [R-25.2-a, R-25.2-b]
# ---------------------------------------------------------------------------

#: The canonical settings value for the Tasks extension: an empty object. This
#: extension defines no settings, so the value associated with the identifier in
#: an ``extensions`` capability map is ``{}`` (§25.2, R-25.2-a).
TASKS_EXTENSION_CAPABILITY: dict[str, Any] = {}


def tasks_capability_entry() -> dict[str, dict[str, Any]]:
  """Return the ``extensions``-map entry that declares the Tasks extension (R-25.2-a/c).

  Both client and server declare support by including the identifier in their
  respective ``extensions`` capability maps; the value is the empty settings
  object (§25.2). The returned mapping is ready to be merged into an
  ``extensions`` map (e.g. ``{"io.modelcontextprotocol/tasks": {}}``).
  """
  return {TASKS_EXTENSION_IDENTIFIER: dict(TASKS_EXTENSION_CAPABILITY)}


def normalize_tasks_settings(settings: Any) -> dict[str, Any]:
  """Return the recognized members of a Tasks settings object, ignoring the rest (R-25.2-b).

  The Tasks extension defines NO settings members, so every member of the
  settings object is unrecognized; receivers MUST ignore unrecognized members
  (R-25.2-b). This therefore always returns an empty dict for any object-valued
  settings — accepting the declaration while ignoring anything it carries — and
  also for a non-object value (which carries no settings at all).

  Args:
    settings: the value associated with the identifier in an ``extensions`` map.

  Returns:
    An empty dict: the Tasks extension recognizes no settings members.
  """
  # The extension defines no settings keys, so the recognized subset is always
  # empty regardless of what the object carries (R-25.2-a/b).
  return {}


def request_declares_tasks(client_extensions: Any) -> bool:
  """Return True if a request's client capabilities declare the Tasks extension (R-25.2-c).

  A client that wishes a given request to be eligible for task augmentation MUST
  include the Tasks declaration in that request's client capabilities — i.e. in
  the ``extensions`` map of the per-request client capabilities (§25.2,
  R-25.2-c). A request lacking that declaration is NOT eligible for augmentation.
  Malformed ``null``/non-object entries are excluded by S11's parsing before the
  membership test, so a malformed entry does not count as a declaration.

  Args:
    client_extensions: the ``extensions`` field value of the per-request client
      capabilities (or ``None`` when absent).

  Returns:
    True iff the Tasks identifier is validly advertised in ``client_extensions``.
  """
  from mcp_sdk_py.extensions import advertised_extension_ids

  return TASKS_EXTENSION_IDENTIFIER in advertised_extension_ids(client_extensions)


# ---------------------------------------------------------------------------
# §25.2  Negotiation, gating & error codes  [R-25.2-d..g, R-25.4-c, R-25.6-g]
# ---------------------------------------------------------------------------

#: The error code a server returns when a client invokes a Tasks method against a
#: server that has not advertised the extension, or invokes a Tasks method the
#: server cannot service (§25.2/§25.7, R-25.2-f). The concrete value is owned by
#: §22/S34; per §25.7 it is ``-32003`` (MissingRequiredClientCapability), reused
#: here from :mod:`mcp_sdk_py.negotiation`.
MISSING_CAPABILITY_ERROR_CODE: int = MISSING_REQUIRED_CLIENT_CAPABILITY_CODE

#: The error code a server returns for a query against a ``taskId`` that has been
#: discarded (e.g. after a non-null ``ttlMs`` elapsed) or otherwise does not
#: exist (§25.4/§25.6, R-25.4-c, R-25.6-g). The concrete value is owned by §22/S34;
#: the §22 not-found condition is ``-32602`` (Invalid params) with the offending
#: identifier in ``error.data`` — reused here for an unknown task.
TASK_NOT_FOUND_ERROR_CODE: int = -32602


class TasksExtensionNotActiveError(Exception):
  """A Tasks method was invoked but the extension is not active in the intersection.

  If a client invokes one of the Tasks methods (``tasks/get``, ``tasks/update``,
  ``tasks/cancel``) against a server that has not advertised the extension, or
  invokes a Tasks method the server cannot service, the server MUST respond with
  the missing-capability error condition of §22 (R-25.2-f). This exception is
  that refusal in object form; :meth:`to_error_object` turns it into the §22
  ``-32003`` error.

  Attributes:
    method: the Tasks method that was invoked while the extension was inactive.
    json_rpc_code: the §22 error code (``-32003``, MissingRequiredClientCapability).
  """

  json_rpc_code: int = MISSING_CAPABILITY_ERROR_CODE

  def __init__(self, method: str) -> None:
    super().__init__(
      f"Tasks method {method!r} was invoked but the "
      f"{TASKS_EXTENSION_IDENTIFIER!r} extension is not active for this request "
      f"(the server has not advertised it, or cannot service the method); the "
      f"server MUST respond with the §22 missing-capability error (R-25.2-f)"
    )
    self.method: str = method

  def to_error_object(self) -> dict[str, Any]:
    """Return the §22 missing-capability error object naming the Tasks extension (R-25.2-f).

    The ``data.requiredCapabilities`` member names the extension the client must
    declare, matching the §5.6/§22 shape of the ``-32003`` error.
    """
    return {
      "code": self.json_rpc_code,
      "message": (
        f"Required client capability not declared: {TASKS_EXTENSION_IDENTIFIER}"
      ),
      "data": {
        "requiredCapabilities": {"extensions": tasks_capability_entry()},
      },
    }


class TaskNotFoundError(Exception):
  """A query referenced a ``taskId`` that has been discarded or never existed.

  After a non-null ``ttlMs`` has elapsed a server MAY discard the task and MUST
  thereafter answer queries for that ``taskId`` with the §22 not-found error
  (R-25.4-c, R-25.6-f, R-25.6-g). This exception is that not-found condition;
  :meth:`to_error_object` turns it into the §22 ``-32602`` error carrying the
  offending ``taskId`` in ``error.data``.

  Attributes:
    task_id: the ``taskId`` that could not be resolved.
    json_rpc_code: the §22 not-found error code (``-32602``).
  """

  json_rpc_code: int = TASK_NOT_FOUND_ERROR_CODE

  def __init__(self, task_id: str) -> None:
    super().__init__(
      f"Task {task_id!r} not found; it may have been discarded after its ttlMs "
      f"elapsed, or it never existed. The server MUST answer with the §22 "
      f"not-found error (R-25.4-c, R-25.6-g)"
    )
    self.task_id: str = task_id

  def to_error_object(self) -> dict[str, Any]:
    """Return the §22 not-found error object carrying the offending ``taskId`` (R-25.6-g)."""
    return {
      "code": self.json_rpc_code,
      "message": f"Task not found: {self.task_id}",
      "data": {"taskId": self.task_id},
    }


def tasks_active(
  client_extensions: Any,
  server_extensions: Any,
) -> bool:
  """Return True if the Tasks extension is active for this request (R-25.2-d, §24.3).

  The extension is active only when BOTH peers advertise the identifier — the
  per-request intersection of S11/§24.3. A server MUST NOT return a task handle
  to a request whose declared client capabilities do not include the identifier
  (R-25.2-d), and a client MUST NOT exercise Tasks methods otherwise. Activation
  is recomputed per request from the supplied maps; nothing is inferred from a
  prior request.

  Args:
    client_extensions: the client's per-request ``extensions`` map (or ``None``).
    server_extensions: the server's advertised ``extensions`` map (or ``None``).
  """
  return is_extension_active(
    TASKS_EXTENSION_IDENTIFIER, client_extensions, server_extensions
  )


def may_return_task_handle(
  client_extensions: Any,
  server_extensions: Any,
) -> bool:
  """Return True iff a server may answer this request with a task handle (R-25.2-d/g).

  A server MUST NOT return a result with ``resultType`` equal to ``"task"`` to a
  request whose declared client capabilities do not include the Tasks identifier
  (R-25.2-d). When the extension is active the server MAY (but need not) produce
  a task; the decision is server-directed and requires no per-call flag or warmup
  beyond the per-request capability (R-25.2-g, R-25.3-a/b). This predicate gates
  the MUST NOT: it is True exactly when augmentation is permitted (the extension
  is active), False otherwise.

  Args:
    client_extensions: the client's per-request ``extensions`` map (or ``None``).
    server_extensions: the server's advertised ``extensions`` map (or ``None``).
  """
  return tasks_active(client_extensions, server_extensions)


def assert_may_return_task_handle(
  client_extensions: Any,
  server_extensions: Any,
) -> None:
  """Raise if a server would return a task handle without the extension active (R-25.2-d).

  Guards the R-25.2-d MUST NOT: a server about to emit a ``CreateTaskResult``
  calls this first; if the Tasks extension is not active for the request the
  emission is a conformance violation and is refused.

  Raises:
    TasksExtensionNotActiveError: the Tasks extension is not active, so a task
      handle MUST NOT be returned (R-25.2-d).
  """
  if not may_return_task_handle(client_extensions, server_extensions):
    raise TasksExtensionNotActiveError(RESULT_TYPE_TASK)


def assert_client_may_invoke_tasks_method(
  method: str,
  client_extensions: Any,
  server_extensions: Any,
) -> None:
  """Raise the §22 missing-capability error if a Tasks method is invoked while inactive (R-25.2-f).

  If a client invokes a Tasks method (``tasks/get``, ``tasks/update``,
  ``tasks/cancel``) against a server that has not advertised the extension — so
  the extension is not active — the server MUST respond with the §22
  missing-capability error (R-25.2-f). Call this server-side before servicing any
  Tasks method.

  Args:
    method: the Tasks method string the client invoked.
    client_extensions: the client's per-request ``extensions`` map (or ``None``).
    server_extensions: the server's advertised ``extensions`` map (or ``None``).

  Raises:
    TasksExtensionNotActiveError: the extension is not active for this request,
      carrying the §22 ``-32003`` missing-capability error (R-25.2-f).
  """
  if not tasks_active(client_extensions, server_extensions):
    raise TasksExtensionNotActiveError(method)


def active_extension_ids(
  client_extensions: Any,
  server_extensions: Any,
) -> frozenset[str]:
  """Return the per-request active extension-identifier set (reuses S11; §24.3/§24.4).

  Thin pass-through to S11's intersection so callers working at the Tasks layer
  can obtain the active set (to confirm the Tasks identifier is, or is not, in
  it) without importing S11 directly. Activation is recomputed per request.
  """
  return active_extensions(client_extensions, server_extensions)


# ---------------------------------------------------------------------------
# §25.5  Task status lifecycle  [R-25.5-a..e]
# ---------------------------------------------------------------------------

class TaskStatus(Enum):
  """The five case-sensitive ``status`` values a task may take (§25.5, R-25.5-a).

  Exactly one of these five string values appears in a task's ``status`` field
  (R-25.5-a). Three are terminal and immutable once reached (R-25.5-b):

  WORKING (``"working"``):
    The operation is in progress. Non-terminal.
  INPUT_REQUIRED (``"input_required"``):
    The server requires client input before it can continue; the outstanding
    requests are named in the ``inputRequests`` map of the
    :class:`DetailedTask`. Non-terminal.
  COMPLETED (``"completed"``):
    Finished successfully; the underlying result is conveyed inline in
    ``result``. Terminal.
  FAILED (``"failed"``):
    A JSON-RPC error occurred; conveyed inline in ``error``. Terminal.
  CANCELLED (``"cancelled"``):
    Ended in response to a cancellation request. Terminal.

  The values are case-sensitive: ``"Working"`` or ``"WORKING"`` are NOT valid
  statuses (R-25.5-a) — see :func:`parse_task_status`.
  """

  WORKING = "working"
  INPUT_REQUIRED = "input_required"
  COMPLETED = "completed"
  FAILED = "failed"
  CANCELLED = "cancelled"

  @property
  def is_terminal(self) -> bool:
    """True for the three terminal states ``completed`` / ``failed`` / ``cancelled`` (R-25.5-b).

    Once a task reaches a terminal state its ``status`` and any inline
    ``result``/``error`` are immutable; the task MUST NOT subsequently transition
    to any other state (R-25.5-b).
    """
    return self in _TERMINAL_STATUSES


#: The three terminal, immutable task states (§25.5, R-25.5-b).
_TERMINAL_STATUSES: frozenset[TaskStatus] = frozenset({
  TaskStatus.COMPLETED,
  TaskStatus.FAILED,
  TaskStatus.CANCELLED,
})

#: The two non-terminal task states; either MAY move to a terminal state, and the
#: two MAY move between each other (§25.5, R-25.5-c).
_NON_TERMINAL_STATUSES: frozenset[TaskStatus] = frozenset({
  TaskStatus.WORKING,
  TaskStatus.INPUT_REQUIRED,
})

#: The legal source → {legal destinations} transition map (§25.5, R-25.5-b/c):
#:   - ``working`` MAY go to ``input_required`` or any terminal state;
#:   - ``input_required`` MAY go back to ``working`` or to any terminal state;
#:   - terminal states never transition again (empty destination set).
_LEGAL_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
  TaskStatus.WORKING: frozenset({
    TaskStatus.INPUT_REQUIRED,
    TaskStatus.COMPLETED,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
  }),
  TaskStatus.INPUT_REQUIRED: frozenset({
    TaskStatus.WORKING,
    TaskStatus.COMPLETED,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
  }),
  TaskStatus.COMPLETED: frozenset(),
  TaskStatus.FAILED: frozenset(),
  TaskStatus.CANCELLED: frozenset(),
}

#: All five status string values, in their canonical case (§25.5, R-25.5-a).
TASK_STATUS_VALUES: frozenset[str] = frozenset(s.value for s in TaskStatus)


def parse_task_status(value: Any) -> TaskStatus:
  """Parse a ``status`` wire value into a :class:`TaskStatus`, case-sensitively (R-25.5-a).

  The ``status`` field takes exactly one of the five case-sensitive values. A
  value differing in case (``"Working"``) or not among the five is invalid
  (R-25.5-a).

  Raises:
    TypeError: ``value`` is not a string.
    ValueError: ``value`` is a string but not one of the five exact values.
  """
  if not isinstance(value, str):
    raise TypeError(
      f"task status must be a string; got {type(value).__name__} (R-25.5-a)"
    )
  try:
    return TaskStatus(value)
  except ValueError:
    raise ValueError(
      f"invalid task status {value!r}; must be exactly one of "
      f"{sorted(TASK_STATUS_VALUES)!r} (case-sensitive) (R-25.5-a)"
    ) from None


def is_terminal_status(status: TaskStatus) -> bool:
  """Return True if ``status`` is one of the three terminal states (R-25.5-b)."""
  return status.is_terminal


def is_legal_transition(current: TaskStatus, nxt: TaskStatus) -> bool:
  """Return True if a task may transition from ``current`` to ``nxt`` (R-25.5-b/c).

  A task in ``working`` MAY transition to ``input_required`` or any terminal
  state; a task in ``input_required`` MAY transition back to ``working`` or to
  any terminal state (R-25.5-c). A terminal task MUST NOT transition to any other
  state, including a no-op back to itself, because its status is immutable once
  reached (R-25.5-b).

  Args:
    current: the task's current status.
    nxt: the proposed next status.

  Returns:
    True iff the transition is permitted by the lifecycle.
  """
  return nxt in _LEGAL_TRANSITIONS[current]


def assert_legal_transition(current: TaskStatus, nxt: TaskStatus) -> None:
  """Raise if transitioning from ``current`` to ``nxt`` is not permitted (R-25.5-b/c).

  Raises:
    TerminalTaskMutationError: ``current`` is already terminal — its status is
      immutable and MUST NOT change (R-25.5-b).
    ValueError: the (non-terminal) transition is otherwise not in the legal set
      (R-25.5-c).
  """
  if current.is_terminal:
    raise TerminalTaskMutationError(current, nxt)
  if not is_legal_transition(current, nxt):
    raise ValueError(
      f"illegal task transition {current.value!r} -> {nxt.value!r}; a "
      f"{current.value!r} task may transition only to "
      f"{sorted(s.value for s in _LEGAL_TRANSITIONS[current])!r} (R-25.5-c)"
    )


class TerminalTaskMutationError(Exception):
  """An attempt was made to transition a task out of a terminal, immutable state.

  Once a task reaches a terminal state (``completed`` / ``failed`` /
  ``cancelled``), its ``status`` and the inline ``result``/``error`` it carries
  are immutable; the task MUST NOT subsequently transition to any other state
  (R-25.5-b).

  Attributes:
    current: the terminal status the task already holds.
    attempted: the status the caller attempted to move it to.
  """

  def __init__(self, current: TaskStatus, attempted: TaskStatus) -> None:
    super().__init__(
      f"task is in terminal state {current.value!r}; its status and inline "
      f"result/error are immutable and it MUST NOT transition to "
      f"{attempted.value!r} (R-25.5-b)"
    )
    self.current: TaskStatus = current
    self.attempted: TaskStatus = attempted


# ---------------------------------------------------------------------------
# §25.4  Task object  [R-25.4-a, R-25.4-b, R-25.4-d, R-25.4-e]
# ---------------------------------------------------------------------------

#: Sentinel distinguishing "no pollIntervalMs given" from an explicit value, so an
#: explicit ``0`` (a valid non-negative interval) is preserved on the wire.
_UNSET: object = object()


@dataclass
class Task:
  """The handle and status record for a long-running operation (§25.4).

  A ``Task`` is server-minted and retrieved by polling rather than by holding a
  connection open. Its REQUIRED fields are ``taskId``, ``status``, ``createdAt``,
  ``lastUpdatedAt``, and ``ttlMs`` (R-25.4-b); ``statusMessage`` and
  ``pollIntervalMs`` are OPTIONAL (R-25.4-e). The client MUST treat ``taskId`` as
  an opaque string and MUST NOT parse or derive meaning from its contents
  (R-25.4-a).

  Fields (wire keys in parentheses):
    task_id (``taskId``): server-minted opaque identifier. REQUIRED, opaque
      (R-25.4-a/b).
    status (``status``): the current :class:`TaskStatus`. REQUIRED (R-25.4-b).
    created_at (``createdAt``): RFC 3339 date-time of creation. REQUIRED.
    last_updated_at (``lastUpdatedAt``): RFC 3339 date-time of last change.
      REQUIRED.
    ttl_ms (``ttlMs``): lifetime in ms from creation, a number ``>= 0`` or
      ``None`` (unbounded). REQUIRED (the field is always present; its value MAY
      be ``null``) (R-25.4-b).
    status_message (``statusMessage``): OPTIONAL human-readable progress text;
      display only, no protocol semantics.
    poll_interval_ms (``pollIntervalMs``): OPTIONAL recommended minimum ms
      between successive ``tasks/get`` polls; clients SHOULD NOT poll more
      frequently (R-25.4-d/e). ``None`` means absent (client chooses an interval).
  """

  task_id: str
  status: TaskStatus
  created_at: str
  last_updated_at: str
  ttl_ms: float | int | None
  status_message: str | None = None
  poll_interval_ms: float | int | None = None

  def __post_init__(self) -> None:
    """Validate the REQUIRED fields and field-level constraints (R-25.4-a/b/e).

    Raises:
      TypeError: a field has the wrong JSON type.
      ValueError: ``task_id`` is empty, or ``ttl_ms``/``poll_interval_ms`` is
        negative (both must be non-negative when present) (R-25.4-b/e).
    """
    if not isinstance(self.task_id, str):
      raise TypeError(
        f"taskId must be a string; got {type(self.task_id).__name__} (R-25.4-a/b)"
      )
    if not self.task_id:
      raise ValueError("taskId is REQUIRED and must be non-empty (R-25.4-b)")
    if not isinstance(self.status, TaskStatus):
      raise TypeError(
        f"status must be a TaskStatus; got {type(self.status).__name__} "
        f"(R-25.4-b, R-25.5-a)"
      )
    for label, value in (
      ("createdAt", self.created_at),
      ("lastUpdatedAt", self.last_updated_at),
    ):
      if not isinstance(value, str) or not value:
        raise TypeError(
          f"{label} is REQUIRED and must be a non-empty RFC 3339 date-time "
          f"string (R-25.4-b)"
        )
    self._validate_non_negative_or_none("ttlMs", self.ttl_ms, allow_none=True)
    self._validate_non_negative_or_none(
      "pollIntervalMs", self.poll_interval_ms, allow_none=True
    )
    if self.status_message is not None and not isinstance(self.status_message, str):
      raise TypeError(
        f"statusMessage must be a string when present; got "
        f"{type(self.status_message).__name__} (§25.4)"
      )

  @staticmethod
  def _validate_non_negative_or_none(
    label: str, value: Any, *, allow_none: bool
  ) -> None:
    """Validate a numeric field is a non-negative number or (if allowed) ``None`` (R-25.4-b/e)."""
    if value is None:
      if allow_none:
        return
      raise ValueError(f"{label} must not be null")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
      raise TypeError(
        f"{label} must be a number{' or null' if allow_none else ''}; got "
        f"{type(value).__name__} (R-25.4-b)"
      )
    if value < 0:
      raise ValueError(f"{label} must be non-negative (>= 0); got {value} (R-25.4-b)")

  @property
  def is_terminal(self) -> bool:
    """True when the task's current status is terminal (R-25.5-b)."""
    return self.status.is_terminal

  def to_dict(self) -> dict[str, Any]:
    """Serialize the ``Task`` fields to a wire-compatible dict (§25.4).

    Emits every REQUIRED field (``taskId``, ``status``, ``createdAt``,
    ``lastUpdatedAt``, ``ttlMs``) — ``ttlMs`` is always present, with value
    ``null`` for an unbounded lifetime — and the OPTIONAL ``statusMessage`` /
    ``pollIntervalMs`` only when set (R-25.4-b/e).
    """
    out: dict[str, Any] = {
      "taskId": self.task_id,
      "status": self.status.value,
      "createdAt": self.created_at,
      "lastUpdatedAt": self.last_updated_at,
      "ttlMs": self.ttl_ms,
    }
    if self.status_message is not None:
      out["statusMessage"] = self.status_message
    if self.poll_interval_ms is not None:
      out["pollIntervalMs"] = self.poll_interval_ms
    return out


def parse_task(raw: dict[str, Any]) -> Task:
  """Parse and validate a :class:`Task` from a wire dict (§25.4, R-25.4-a/b/e).

  Enforces presence of every REQUIRED field — ``taskId``, ``status``,
  ``createdAt``, ``lastUpdatedAt``, ``ttlMs`` (R-25.4-b) — where ``ttlMs`` MUST be
  present even though its value MAY be ``null``. ``status`` is parsed
  case-sensitively (R-25.5-a). The opaque ``taskId`` is taken verbatim with no
  attempt to interpret it (R-25.4-a).

  Raises:
    TypeError: ``raw`` is not a dict, or a field has the wrong JSON type.
    ValueError: a REQUIRED field is absent, or a value is out of range.
  """
  if not isinstance(raw, dict):
    raise TypeError(f"Task must be a JSON object; got {type(raw).__name__}")

  for required in ("taskId", "status", "createdAt", "lastUpdatedAt"):
    if required not in raw:
      raise ValueError(f"Task.{required} is REQUIRED (R-25.4-b)")
  # ttlMs MUST be present, though its value MAY be null (R-25.4-b).
  if "ttlMs" not in raw:
    raise ValueError(
      "Task.ttlMs is REQUIRED (its value MAY be null for an unbounded "
      "lifetime, but the field MUST be present) (R-25.4-b)"
    )

  status = parse_task_status(raw["status"])
  poll_raw = raw.get("pollIntervalMs")
  return Task(
    task_id=raw["taskId"],
    status=status,
    created_at=raw["createdAt"],
    last_updated_at=raw["lastUpdatedAt"],
    ttl_ms=raw["ttlMs"],
    status_message=raw.get("statusMessage"),
    poll_interval_ms=poll_raw,
  )


# ---------------------------------------------------------------------------
# §25.4  Opaque taskId & polling helpers  [R-25.4-a, R-25.4-d, R-25.4-e, R-25.6-h]
# ---------------------------------------------------------------------------

def echo_task_id(task_id: str) -> str:
  """Return ``task_id`` verbatim, deriving no meaning from it (R-25.4-a).

  The client MUST treat ``taskId`` as an opaque string and MUST NOT parse or
  derive meaning from its contents (R-25.4-a). The only conforming handling is to
  store and forward the value verbatim; this helper makes that the explicit
  contract. It validates only that the value is a string (a non-string ``taskId``
  is malformed), never inspecting its structure.

  Raises:
    TypeError: ``task_id`` is not a string.
  """
  if not isinstance(task_id, str):
    raise TypeError(
      f"taskId must be an opaque string; got {type(task_id).__name__} (R-25.4-a)"
    )
  return task_id


#: The interval a client uses between ``tasks/get`` polls when a task carries no
#: ``pollIntervalMs`` — a reasonable default the client is free to choose
#: (R-25.4-e). One second; callers MAY override.
DEFAULT_POLL_INTERVAL_MS: float = 1000.0


def effective_poll_interval_ms(
  task: Task,
  *,
  default_ms: float = DEFAULT_POLL_INTERVAL_MS,
) -> float:
  """Return the ms a client should wait before the next poll for ``task`` (R-25.4-d/e).

  When the task provides ``pollIntervalMs`` the client SHOULD wait at least that
  many ms and SHOULD NOT poll more frequently (R-25.4-d). When it is absent the
  client chooses a reasonable interval — ``default_ms`` here (R-25.4-e).

  Args:
    task: the task being polled.
    default_ms: the interval to use when the task omits ``pollIntervalMs``.

  Returns:
    The recommended minimum number of ms to wait before the next ``tasks/get``.
  """
  if task.poll_interval_ms is None:
    return default_ms
  return float(task.poll_interval_ms)


def is_poll_too_soon(task: Task, elapsed_ms: float) -> bool:
  """Return True if polling again after ``elapsed_ms`` would be too frequent (R-25.4-d).

  A client SHOULD wait at least ``pollIntervalMs`` between successive
  ``tasks/get`` polls and SHOULD NOT poll more frequently (R-25.4-d). This is
  True when ``elapsed_ms`` is below the effective interval, so a conforming
  client would defer the next poll. When the task omits ``pollIntervalMs`` the
  effective interval is the client-chosen default (R-25.4-e).
  """
  return elapsed_ms < effective_poll_interval_ms(task)


def should_continue_polling(task: Task) -> bool:
  """Return True while a client SHOULD keep polling ``task`` (R-25.5-e).

  A client SHOULD continue polling (subject to ``pollIntervalMs``) until the task
  reaches a terminal state (R-25.5-e). Polling continues exactly while the task
  is non-terminal.
  """
  return not task.is_terminal


# ---------------------------------------------------------------------------
# §25.3  CreateTaskResult — the task handle  [R-25.3-c]
# ---------------------------------------------------------------------------

@dataclass
class CreateTaskResult:
  """A ``Result`` whose ``resultType`` is ``"task"``: the wire form of a task handle (§25.3).

  Returned in place of a request's direct result to signal that the work is now a
  task (R-25.3-c). It carries ALL :class:`Task` fields directly (not nested),
  plus the result-level ``resultType`` discriminator (always ``"task"``) and the
  OPTIONAL ``_meta`` permitted on any ``Result`` (§3.6).

  Fields:
    task: the initial :class:`Task` describing the newly created handle. Its
      fields are flattened onto the result by :meth:`to_dict`.
    meta: OPTIONAL result-level ``_meta`` (wire key ``_meta``).
  """

  task: Task
  meta: dict[str, Any] | None = None

  @property
  def result_type(self) -> ResultType:
    """The ``resultType`` discriminator; always :data:`RESULT_TYPE_TASK` (R-25.3-c)."""
    return RESULT_TYPE_TASK

  @property
  def task_id(self) -> str:
    """Convenience accessor for the underlying task's opaque ``taskId`` (R-25.4-a)."""
    return self.task.task_id

  @property
  def status(self) -> TaskStatus:
    """Convenience accessor for the underlying task's current status."""
    return self.task.status

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire ``Result`` with ``resultType: "task"`` and all Task fields (§25.3).

    ``resultType`` is emitted first, every :class:`Task` field appears directly
    on the result (not nested), and ``_meta`` is appended when present (R-25.3-c).
    """
    out: dict[str, Any] = {"resultType": RESULT_TYPE_TASK}
    out.update(self.task.to_dict())
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def parse_create_task_result(raw: dict[str, Any]) -> CreateTaskResult:
  """Parse and validate a :class:`CreateTaskResult` from a wire dict (§25.3, R-25.3-c).

  Verifies ``resultType`` is exactly ``"task"`` (the discriminator that marks the
  payload as a task handle), then reads the flattened :class:`Task` fields off the
  same object. A client that declared the capability MUST inspect ``resultType``
  and handle the ``"task"`` case this way (R-25.3-c); see
  :func:`classify_eligible_result`.

  Raises:
    TypeError: ``raw`` is not a dict or a field has the wrong type.
    ValueError: ``resultType`` is not ``"task"``, or a REQUIRED Task field is
      absent.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"CreateTaskResult must be a JSON object; got {type(raw).__name__}"
    )
  rt = raw.get("resultType")
  if rt != RESULT_TYPE_TASK:
    raise ValueError(
      f"CreateTaskResult.resultType must be exactly {RESULT_TYPE_TASK!r} "
      f"(case-sensitive); got {rt!r} (R-25.3-c)"
    )
  task = parse_task(raw)
  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )
  return CreateTaskResult(task=task, meta=meta)


def is_task_handle(raw: dict[str, Any]) -> bool:
  """Return True if a wire ``Result`` is a task handle (``resultType == "task"``) (R-25.3-c).

  A client that has declared the capability MUST inspect ``resultType`` on each
  eligible response and handle the ``"task"`` case (R-25.3-c). This is the
  dispatch test: True means treat the payload as a :class:`CreateTaskResult`;
  False means it is the request's ordinary result shape.
  """
  return isinstance(raw, dict) and raw.get("resultType") == RESULT_TYPE_TASK


def classify_eligible_result(raw: dict[str, Any]) -> str:
  """Classify an eligible response as a task handle or the ordinary result (R-25.2-e, R-25.3-c).

  A client that declared the capability MUST be prepared to receive EITHER the
  request's ordinary result shape OR a task handle in its place (R-25.2-e), and
  MUST dispatch on ``resultType`` (R-25.3-c). This returns:

    - :data:`RESULT_TYPE_TASK` (``"task"``) when the payload is a task handle —
      parse it with :func:`parse_create_task_result`;
    - ``"ordinary"`` otherwise — handle it as the request's normal result.

  Args:
    raw: the wire ``Result`` object of an eligible response.

  Returns:
    ``"task"`` for a task handle, ``"ordinary"`` for the direct result shape.
  """
  return RESULT_TYPE_TASK if is_task_handle(raw) else "ordinary"


# ---------------------------------------------------------------------------
# §25.4  DetailedTask — status-discriminated variants  [R-25.5-d]
# ---------------------------------------------------------------------------

@dataclass
class DetailedTask:
  """A :class:`Task` that additionally conveys terminal payload or pending input inline (§25.4).

  ``DetailedTask`` is the shape ``tasks/get`` returns (the method itself is owned
  by S40). It is a union discriminated by ``status``, modeled here as one dataclass
  whose variant-specific members are mutually exclusive and validated against the
  status:

    - ``working`` — no additional fields.
    - ``input_required`` — ``input_requests`` (an ``InputRequests`` map of S17's
      :class:`~mcp_sdk_py.multi_round_trip.InputRequest`, keyed by opaque string),
      REQUIRED on this variant.
    - ``completed`` — ``result`` (the verbatim ordinary result object the
      augmented request would have produced, including its own ``resultType`` and
      ``_meta``), REQUIRED on this variant.
    - ``failed`` — ``error`` (a JSON-RPC error object per §22), REQUIRED on this
      variant.
    - ``cancelled`` — no additional fields.

  The underlying outcome is conveyed ONLY once the task is terminal and ONLY
  inline here: ``result`` for ``completed``, ``error`` for ``failed``. A
  non-terminal ``DetailedTask`` carries neither ``result`` nor ``error``
  (R-25.5-d). Construction enforces exactly that variant discipline.

  Fields:
    task: the base :class:`Task` (its fields are flattened onto the wire object).
    input_requests: outstanding :class:`InputRequest` map (``input_required``
      only).
    result: the verbatim ordinary result object (``completed`` only).
    error: the JSON-RPC error object (``failed`` only).
  """

  task: Task
  input_requests: dict[str, InputRequest] | None = None
  result: dict[str, Any] | None = None
  error: dict[str, Any] | None = None

  def __post_init__(self) -> None:
    """Enforce the status-discriminated variant discipline (§25.4, R-25.5-d).

    Raises:
      ValueError: a variant-specific member is present on the wrong status, or a
        REQUIRED variant member is missing, or a non-terminal task carries
        ``result``/``error`` (R-25.5-d).
      TypeError: a variant member has the wrong type.
    """
    status = self.task.status

    # A non-terminal DetailedTask carries neither result nor error (R-25.5-d).
    if not status.is_terminal:
      if self.result is not None:
        raise ValueError(
          f"a non-terminal task ({status.value!r}) MUST NOT carry 'result'; the "
          f"outcome is conveyed only once terminal (R-25.5-d)"
        )
      if self.error is not None:
        raise ValueError(
          f"a non-terminal task ({status.value!r}) MUST NOT carry 'error'; the "
          f"outcome is conveyed only once terminal (R-25.5-d)"
        )

    if status is TaskStatus.INPUT_REQUIRED:
      if self.input_requests is None:
        raise ValueError(
          "an 'input_required' DetailedTask MUST carry 'inputRequests' naming "
          "the outstanding server requests (§25.4)"
        )
      if not isinstance(self.input_requests, dict):
        raise TypeError(
          f"inputRequests must be a map; got {type(self.input_requests).__name__}"
        )
      for key, value in self.input_requests.items():
        if not isinstance(value, InputRequest):
          raise TypeError(
            f"inputRequests[{key!r}] must be an InputRequest; got "
            f"{type(value).__name__} (§25.4 ⇒ §11.2)"
          )
    elif self.input_requests is not None:
      raise ValueError(
        f"'inputRequests' is only valid on the 'input_required' variant; status "
        f"is {status.value!r} (§25.4)"
      )

    if status is TaskStatus.COMPLETED:
      if self.result is None:
        raise ValueError(
          "a 'completed' DetailedTask MUST carry 'result' (the verbatim ordinary "
          "result the augmented request would have produced) (R-25.5-d)"
        )
      if not isinstance(self.result, dict):
        raise TypeError(
          f"result must be a JSON object; got {type(self.result).__name__}"
        )

    if status is TaskStatus.FAILED:
      if self.error is None:
        raise ValueError(
          "a 'failed' DetailedTask MUST carry 'error' (the JSON-RPC error object "
          "per §22) (R-25.5-d)"
        )
      if not isinstance(self.error, dict):
        raise TypeError(
          f"error must be a JSON object; got {type(self.error).__name__}"
        )

  @property
  def status(self) -> TaskStatus:
    """The discriminating status of this detailed task."""
    return self.task.status

  @property
  def is_terminal(self) -> bool:
    """True when this detailed task's status is terminal (R-25.5-b)."""
    return self.task.is_terminal

  def to_dict(self) -> dict[str, Any]:
    """Serialize to a wire dict: all Task fields plus the variant member (§25.4).

    Emits the flattened :class:`Task` fields, then the single variant-specific
    member appropriate to the status — ``inputRequests`` for ``input_required``,
    ``result`` for ``completed``, ``error`` for ``failed`` — and nothing extra
    for ``working`` / ``cancelled`` (R-25.5-d).
    """
    out: dict[str, Any] = self.task.to_dict()
    if self.input_requests is not None:
      out["inputRequests"] = {
        key: value.to_dict() for key, value in self.input_requests.items()
      }
    if self.result is not None:
      out["result"] = self.result
    if self.error is not None:
      out["error"] = self.error
    return out


def parse_detailed_task(raw: dict[str, Any]) -> DetailedTask:
  """Parse and validate a :class:`DetailedTask` from a wire dict (§25.4, R-25.5-d).

  Parses the base :class:`Task`, then reads the variant member dictated by the
  ``status`` discriminator and validates the variant discipline (a non-terminal
  task carries neither ``result`` nor ``error``; each terminal/​input variant
  carries exactly its REQUIRED member) via :class:`DetailedTask` construction.
  The ``inputRequests`` map reuses S17's :func:`parse_input_request` for each
  entry.

  Raises:
    TypeError: ``raw`` (or a member) has the wrong type.
    ValueError: a REQUIRED Task or variant field is absent, or a variant member
      appears on the wrong status (R-25.5-d).
    UnrecognizedInputRequestKindError: an ``inputRequests`` entry names an
      unrecognized kind (delegated to S17, §11.2).
  """
  task = parse_task(raw)

  input_requests: dict[str, InputRequest] | None = None
  raw_ir = raw.get("inputRequests")
  if raw_ir is not None:
    if not isinstance(raw_ir, dict):
      raise TypeError(
        f"inputRequests must be a JSON object; got {type(raw_ir).__name__}"
      )
    input_requests = {}
    for key, value in raw_ir.items():
      if not isinstance(key, str) or not key:
        raise ValueError("inputRequests keys must be non-empty strings (§25.4)")
      input_requests[key] = parse_input_request(value)

  result = raw.get("result")
  if result is not None and not isinstance(result, dict):
    raise TypeError(
      f"result must be a JSON object if present; got {type(result).__name__}"
    )
  error = raw.get("error")
  if error is not None and not isinstance(error, dict):
    raise TypeError(
      f"error must be a JSON object if present; got {type(error).__name__}"
    )

  return DetailedTask(
    task=task,
    input_requests=input_requests,
    result=result,
    error=error,
  )


__all__ = [
  # §25.1 — extension identifier
  "TASKS_EXTENSION_IDENTIFIER",
  "is_tasks_extension_identifier",
  # §25.3 — resultType discriminator value
  "RESULT_TYPE_TASK",
  # §25.2 — extension definition & capability declaration
  "TASKS_EXTENSION",
  "TASKS_METHODS",
  "TASKS_OBJECT_FIELDS",
  "TASKS_EXTENSION_CAPABILITY",
  "tasks_capability_entry",
  "normalize_tasks_settings",
  "request_declares_tasks",
  # §25.2 — negotiation, gating & error conditions
  "MISSING_CAPABILITY_ERROR_CODE",
  "TASK_NOT_FOUND_ERROR_CODE",
  "TasksExtensionNotActiveError",
  "TaskNotFoundError",
  "tasks_active",
  "may_return_task_handle",
  "assert_may_return_task_handle",
  "assert_client_may_invoke_tasks_method",
  "active_extension_ids",
  # §25.5 — status lifecycle
  "TaskStatus",
  "TASK_STATUS_VALUES",
  "parse_task_status",
  "is_terminal_status",
  "is_legal_transition",
  "assert_legal_transition",
  "TerminalTaskMutationError",
  # §25.4 — Task object & polling helpers
  "Task",
  "parse_task",
  "echo_task_id",
  "DEFAULT_POLL_INTERVAL_MS",
  "effective_poll_interval_ms",
  "is_poll_too_soon",
  "should_continue_polling",
  # §25.3 — CreateTaskResult (task handle)
  "CreateTaskResult",
  "parse_create_task_result",
  "is_task_handle",
  "classify_eligible_result",
  # §25.4 — DetailedTask (status-discriminated)
  "DetailedTask",
  "parse_detailed_task",
]
