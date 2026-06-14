"""Tests for S40 — Tasks Extension II: get/update/cancel, Notifications & Cleanup (§25.7–§25.12).

Each test class maps to one acceptance criterion (AC-40.x). S40 delivers the
client-facing operations that drive a task created under S39 through its
lifecycle: retrieving state (``tasks/get``), supplying input (``tasks/update``),
cooperative cancellation (``tasks/cancel``), the optional ``notifications/tasks``
push and its ``taskIds`` subscription opt-in, and the rules governing task
expiry, removal, and protocol-vs-application error reporting. The surface is
exercised through ``mcp_sdk_py.tasks_ops`` directly, reusing S39's task model.

AC → test coverage map:
  AC-40.1  (R-25.7-a, R-25.7-b, R-25.7-e)          — TestAC4001GetRequestAndCompleteResult
  AC-40.2  (R-25.7-c, R-25.7-d)                     — TestAC4002GetMissingCapability
  AC-40.3  (R-25.7-f, R-25.7-g)                     — TestAC4003WorkingVariant
  AC-40.4  (R-25.7-h, R-25.7-i)                     — TestAC4004InputRequiredVariant
  AC-40.5  (R-25.7-j)                               — TestAC4005CompletedVariant
  AC-40.6  (R-25.7-k)                               — TestAC4006FailedVariant
  AC-40.7  (R-25.7-l)                               — TestAC4007CancelledVariant
  AC-40.8  (R-25.7-m, R-25.7-n)                     — TestAC4008PollIntervalHonored
  AC-40.9  (R-25.7-o)                               — TestAC4009ServerMayRateLimit
  AC-40.10 (R-25.7-p)                               — TestAC4010ContinuePolling
  AC-40.11 (R-25.7-q)                               — TestAC4011DurablePersistence
  AC-40.12 (R-25.7-r, R-25.7-s, R-25.11-d, R-25.11-e) — TestAC4012UnknownTaskIdError
  AC-40.13 (R-25.8-a, R-25.8-b)                     — TestAC4013UpdateRequestWellFormed
  AC-40.14 (R-25.8-c, R-25.8-d)                     — TestAC4014UpdateMissingCapability
  AC-40.15 (R-25.8-e, R-25.8-f)                     — TestAC4015KeyUniqueOverLifetime
  AC-40.16 (R-25.8-g)                               — TestAC4016IgnoreStaleKeys
  AC-40.17 (R-25.8-h)                               — TestAC4017PartialResponsesAccepted
  AC-40.18 (R-25.8-i)                               — TestAC4018ClientTracksAnswered
  AC-40.19 (R-25.8-j, R-25.8-k)                     — TestAC4019UpdateEmptyAck
  AC-40.20 (R-25.8-l)                               — TestAC4020UpdateEventuallyConsistent
  AC-40.21 (R-25.8-m)                               — TestAC4021UpdateUnknownTaskId
  AC-40.22 (R-25.8-n)                               — TestAC4022ContinueObservingAfterUpdate
  AC-40.23 (R-25.9-a)                               — TestAC4023NoNotificationsCancelled
  AC-40.24 (R-25.9-b)                               — TestAC4024CancelRequestWellFormed
  AC-40.25 (R-25.9-c, R-25.9-d)                     — TestAC4025CancelMissingCapability
  AC-40.26 (R-25.9-e, R-25.9-f)                     — TestAC4026CancelEmptyAck
  AC-40.27 (R-25.9-g)                               — TestAC4027CancelUnknownTaskId
  AC-40.28 (R-25.9-h, R-25.9-i)                     — TestAC4028CancelCooperative
  AC-40.29 (R-25.9-j)                               — TestAC4029CancelTerminalNoOp
  AC-40.30 (R-25.9-k)                               — TestAC4030ClientMayDropState
  AC-40.31 (R-25.10-a)                              — TestAC4031NotificationMatchesGet
  AC-40.32 (R-25.10-b, R-25.10-c)                   — TestAC4032OptInViaTaskIds
  AC-40.33 (R-25.10-d)                              — TestAC4033NoPushWithoutSubscription
  AC-40.34 (R-25.10-e)                              — TestAC4034TaskIdsMissingCapability
  AC-40.35 (R-25.10-f)                              — TestAC4035NotificationsOrPolling
  AC-40.36 (R-25.10-g)                              — TestAC4036NoProgressOrMessage
  AC-40.37 (R-25.10-h)                              — TestAC4037PreTaskInputSynchronous
  AC-40.38 (R-25.10-i)                              — TestAC4038TrustNotElevated
  AC-40.39 (R-25.10-j)                              — TestAC4039ChannelsNotMixed
  AC-40.40 (R-25.11-a, R-25.11-b)                   — TestAC4040TtlMutableAndExpiry
  AC-40.41 (R-25.11-c)                              — TestAC4041TtlBackstop
  AC-40.42 (R-25.11-f, R-25.11-g)                   — TestAC4042ProtocolErrorFailed
  AC-40.43 (R-25.11-h, R-25.11-i)                   — TestAC4043ApplicationErrorCompleted
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.jsonrpc import (
  JSONRPCErrorResponse,
  JSONRPCNotification,
  JSONRPCRequest,
  JSONRPCResultResponse,
)
from mcp_sdk_py.multi_round_trip import InputRequest
from mcp_sdk_py.negotiation import MISSING_REQUIRED_CLIENT_CAPABILITY_CODE
from mcp_sdk_py.subscriptions import SUBSCRIPTIONS_LISTEN_METHOD
from mcp_sdk_py.tasks import (
  TASKS_EXTENSION_IDENTIFIER,
  DetailedTask,
  Task,
  TaskStatus,
  TasksExtensionNotActiveError,
)
from mcp_sdk_py.tasks_ops import (
  FORBIDDEN_TASK_NOTIFICATION_METHODS,
  GENERAL_CANCELLED_NOTIFICATION_METHOD,
  TASK_IDS_FILTER_KEY,
  TASKS_CANCEL_METHOD,
  TASKS_GET_METHOD,
  TASKS_NOTIFICATION_METHOD,
  TASKS_UPDATE_METHOD,
  AnsweredKeyTracker,
  CancelTaskRequestParams,
  DurableTaskIdStore,
  EmptyAckResult,
  GetTaskRequestParams,
  GetTaskResult,
  InputRequestKeyError,
  InputResolutionChannel,
  PollIntervalTracker,
  TaskIdsFilter,
  TaskInputState,
  TaskNotificationGate,
  UpdateTaskRequestParams,
  apply_cancellation,
  assert_resolution_channel_not_mixed,
  assert_task_notification_allowed,
  assert_task_subscription_capability,
  assert_tasks_method_allowed,
  build_cancel_task_request,
  build_cancel_task_response,
  build_completed_with_application_error,
  build_failed_detailed_task,
  build_get_task_request,
  build_get_task_response,
  build_get_task_result,
  build_missing_capability_response,
  build_task_not_found_response,
  build_task_status_notification,
  build_task_subscription_request,
  build_update_task_request,
  build_update_task_response,
  cancel_changes_terminal_status,
  client_may_drop_state_after_cancel,
  client_may_rely_on_notifications_only,
  client_should_stop_polling,
  input_request_trust_is_not_elevated,
  is_application_level_error_result,
  is_forbidden_task_notification,
  is_task_cancellation_notification,
  is_task_expired,
  is_task_not_found_error,
  notification_matches_get,
  parse_cancel_task_request_params,
  parse_empty_ack_result,
  parse_get_task_request_params,
  parse_get_task_result,
  parse_task_ids_filter,
  parse_task_status_notification,
  parse_update_task_request_params,
  required_input_resolution_channel,
  server_may_rate_limit,
  should_continue_polling,
  should_resolve_pre_task_input_synchronously,
  status_for_execution_outcome,
  status_for_protocol_error,
  task_unusable_backstop,
  ttl_deadline_ms,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

TASK_ID = "786512e2-9e0d-44bd-8f29-789f320fe840"
CREATED = "2026-07-28T10:30:00Z"
UPDATED = "2026-07-28T10:50:00Z"

#: Extension maps that make the Tasks extension active for a request.
ACTIVE = {TASKS_EXTENSION_IDENTIFIER: {}}
#: A client that did NOT declare the Tasks extension.
NO_CLIENT = None


def make_task(
  status: TaskStatus = TaskStatus.WORKING,
  *,
  task_id: str = TASK_ID,
  ttl_ms: float | int | None = 3600000,
  poll_interval_ms: float | int | None = 5000,
  status_message: str | None = None,
) -> Task:
  """Build a valid base Task for the given status."""
  return Task(
    task_id=task_id,
    status=status,
    created_at=CREATED,
    last_updated_at=UPDATED,
    ttl_ms=ttl_ms,
    status_message=status_message,
    poll_interval_ms=poll_interval_ms,
  )


def make_detailed(
  status: TaskStatus = TaskStatus.WORKING,
  **kwargs,
) -> DetailedTask:
  """Build a valid DetailedTask for the given status, supplying its variant member."""
  task = make_task(status)
  if status is TaskStatus.INPUT_REQUIRED:
    kwargs.setdefault(
      "input_requests",
      {"name": InputRequest(method="elicitation/create", params={"message": "?"})},
    )
  elif status is TaskStatus.COMPLETED:
    kwargs.setdefault(
      "result", {"content": [{"type": "text", "text": "Hello, Luca!"}], "isError": False}
    )
  elif status is TaskStatus.FAILED:
    kwargs.setdefault("error", {"code": -32603, "message": "internal error"})
  return DetailedTask(task=task, **kwargs)


# ---------------------------------------------------------------------------
# AC-40.1  (R-25.7-a, R-25.7-b, R-25.7-e)
# ---------------------------------------------------------------------------

class TestAC4001GetRequestAndCompleteResult:
  """tasks/get sends taskId verbatim and the result's resultType is "complete"."""

  def test_request_carries_taskid_verbatim(self) -> None:
    req = build_get_task_request(8, TASK_ID)
    assert isinstance(req, JSONRPCRequest)
    assert req.method == TASKS_GET_METHOD
    assert req.params == {"taskId": TASK_ID}  # verbatim (R-25.7-a/b)

  def test_params_roundtrip_preserves_taskid(self) -> None:
    params = parse_get_task_request_params({"taskId": TASK_ID})
    assert params.task_id == TASK_ID
    assert params.to_dict() == {"taskId": TASK_ID}

  def test_result_result_type_is_complete(self) -> None:
    result = build_get_task_result(make_detailed(TaskStatus.WORKING))
    assert result.result_type == "complete"
    assert result.to_dict()["resultType"] == "complete"  # R-25.7-e

  def test_response_echoes_id_and_is_complete(self) -> None:
    resp = build_get_task_response(8, make_detailed(TaskStatus.WORKING))
    assert isinstance(resp, JSONRPCResultResponse)
    assert resp.id == 8
    assert resp.result["resultType"] == "complete"
    assert resp.result["taskId"] == TASK_ID

  def test_missing_taskid_rejected(self) -> None:
    with pytest.raises(ValueError):
      parse_get_task_request_params({})

  def test_non_string_taskid_rejected(self) -> None:
    with pytest.raises(TypeError):
      GetTaskRequestParams(task_id=123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-40.2  (R-25.7-c, R-25.7-d)
# ---------------------------------------------------------------------------

class TestAC4002GetMissingCapability:
  """A client that did not declare the extension gets -32003 on tasks/get."""

  def test_gating_raises_when_inactive(self) -> None:
    with pytest.raises(TasksExtensionNotActiveError):
      assert_tasks_method_allowed(TASKS_GET_METHOD, NO_CLIENT, ACTIVE)

  def test_gating_passes_when_active(self) -> None:
    assert_tasks_method_allowed(TASKS_GET_METHOD, ACTIVE, ACTIVE)  # no raise

  def test_error_response_code_is_32003(self) -> None:
    resp = build_missing_capability_response(8, TASKS_GET_METHOD)
    assert isinstance(resp, JSONRPCErrorResponse)
    assert resp.error["code"] == MISSING_REQUIRED_CLIENT_CAPABILITY_CODE == -32003
    assert resp.id == 8


# ---------------------------------------------------------------------------
# AC-40.3  (R-25.7-f, R-25.7-g)
# ---------------------------------------------------------------------------

class TestAC4003WorkingVariant:
  """A working task returns status "working" and no status-specific payload."""

  def test_working_has_no_payload(self) -> None:
    out = build_get_task_result(make_detailed(TaskStatus.WORKING)).to_dict()
    assert out["status"] == "working"
    assert "inputRequests" not in out
    assert "result" not in out
    assert "error" not in out

  def test_working_roundtrip(self) -> None:
    out = build_get_task_result(make_detailed(TaskStatus.WORKING)).to_dict()
    parsed = parse_get_task_result(out)
    assert parsed.status is TaskStatus.WORKING


# ---------------------------------------------------------------------------
# AC-40.4  (R-25.7-h, R-25.7-i)
# ---------------------------------------------------------------------------

class TestAC4004InputRequiredVariant:
  """input_required returns inputRequests with every outstanding request."""

  def test_input_required_carries_input_requests(self) -> None:
    irs = {
      "name": InputRequest(method="elicitation/create", params={"message": "name?"}),
      "age": InputRequest(method="elicitation/create", params={"message": "age?"}),
    }
    out = build_get_task_result(
      make_detailed(TaskStatus.INPUT_REQUIRED, input_requests=irs)
    ).to_dict()
    assert out["status"] == "input_required"
    assert set(out["inputRequests"].keys()) == {"name", "age"}  # every outstanding (R-25.7-i)

  def test_input_required_roundtrip(self) -> None:
    out = build_get_task_result(make_detailed(TaskStatus.INPUT_REQUIRED)).to_dict()
    parsed = parse_get_task_result(out)
    assert parsed.status is TaskStatus.INPUT_REQUIRED
    assert "name" in parsed.detailed_task.input_requests


# ---------------------------------------------------------------------------
# AC-40.5  (R-25.7-j)
# ---------------------------------------------------------------------------

class TestAC4005CompletedVariant:
  """completed returns status "completed" and the inline result object."""

  def test_completed_carries_result(self) -> None:
    result_obj = {"content": [{"type": "text", "text": "Hello, Luca!"}], "isError": False}
    out = build_get_task_result(
      make_detailed(TaskStatus.COMPLETED, result=result_obj)
    ).to_dict()
    assert out["status"] == "completed"
    assert out["result"] == result_obj  # same value the request would return (R-25.7-j)

  def test_completed_roundtrip(self) -> None:
    out = build_get_task_result(make_detailed(TaskStatus.COMPLETED)).to_dict()
    assert parse_get_task_result(out).detailed_task.result is not None


# ---------------------------------------------------------------------------
# AC-40.6  (R-25.7-k)
# ---------------------------------------------------------------------------

class TestAC4006FailedVariant:
  """failed returns status "failed" and an error object."""

  def test_failed_carries_error(self) -> None:
    err = {"code": -32603, "message": "boom"}
    out = build_get_task_result(make_detailed(TaskStatus.FAILED, error=err)).to_dict()
    assert out["status"] == "failed"
    assert out["error"] == err  # JSON-RPC error from execution (R-25.7-k)

  def test_failed_roundtrip(self) -> None:
    out = build_get_task_result(make_detailed(TaskStatus.FAILED)).to_dict()
    assert parse_get_task_result(out).detailed_task.error is not None


# ---------------------------------------------------------------------------
# AC-40.7  (R-25.7-l)
# ---------------------------------------------------------------------------

class TestAC4007CancelledVariant:
  """cancelled returns status "cancelled" and no status-specific payload."""

  def test_cancelled_has_no_payload(self) -> None:
    out = build_get_task_result(make_detailed(TaskStatus.CANCELLED)).to_dict()
    assert out["status"] == "cancelled"
    assert "result" not in out
    assert "error" not in out
    assert "inputRequests" not in out


# ---------------------------------------------------------------------------
# AC-40.8  (R-25.7-m, R-25.7-n)
# ---------------------------------------------------------------------------

class TestAC4008PollIntervalHonored:
  """Client waits >= pollIntervalMs and adopts the latest observed value."""

  def test_waits_at_least_interval(self) -> None:
    tracker = PollIntervalTracker()
    tracker.observe(make_task(poll_interval_ms=5000))
    assert tracker.is_poll_too_soon(4999) is True  # SHOULD NOT poll yet (R-25.7-m)
    assert tracker.may_poll_now(5000) is True

  def test_adopts_latest_value(self) -> None:
    tracker = PollIntervalTracker()
    tracker.observe(make_task(poll_interval_ms=5000))
    assert tracker.interval_ms == 5000.0
    tracker.observe(make_task(poll_interval_ms=2000))  # value changed (R-25.7-n)
    assert tracker.interval_ms == 2000.0
    assert tracker.may_poll_now(2000) is True

  def test_absent_interval_unconstrained(self) -> None:
    tracker = PollIntervalTracker()
    tracker.observe(make_task(poll_interval_ms=None))
    assert tracker.interval_ms is None
    assert tracker.may_poll_now(0) is True


# ---------------------------------------------------------------------------
# AC-40.9  (R-25.7-o)
# ---------------------------------------------------------------------------

class TestAC4009ServerMayRateLimit:
  """A server MAY rate-limit a client polling faster than pollIntervalMs."""

  def test_too_frequent_is_rate_limit_eligible(self) -> None:
    assert server_may_rate_limit(1000, 5000) is True  # polled too soon (R-25.7-o)

  def test_within_interval_not_eligible(self) -> None:
    assert server_may_rate_limit(5000, 5000) is False
    assert server_may_rate_limit(6000, 5000) is False


# ---------------------------------------------------------------------------
# AC-40.10  (R-25.7-p)
# ---------------------------------------------------------------------------

class TestAC4010ContinuePolling:
  """Continue polling until terminal status or tasks/cancel."""

  def test_continue_while_non_terminal(self) -> None:
    assert should_continue_polling(make_task(TaskStatus.WORKING)) is True
    assert should_continue_polling(make_task(TaskStatus.INPUT_REQUIRED)) is True

  @pytest.mark.parametrize(
    "status",
    [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED],
  )
  def test_stop_at_terminal(self, status: TaskStatus) -> None:
    assert should_continue_polling(make_task(status)) is False


# ---------------------------------------------------------------------------
# AC-40.11  (R-25.7-q)
# ---------------------------------------------------------------------------

class TestAC4011DurablePersistence:
  """Persist taskId to durable storage so polling resumes after a restart."""

  def test_remember_and_restore_across_restart(self) -> None:
    backend: set[str] = set()
    store = DurableTaskIdStore(backend=backend)
    store.remember(TASK_ID)
    # Simulate a restart: a fresh store over the SAME durable backend.
    revived = DurableTaskIdStore(backend=backend)
    assert TASK_ID in revived.restore()  # resumes after restart (R-25.7-q)

  def test_forget_drops_id(self) -> None:
    store = DurableTaskIdStore()
    store.remember(TASK_ID)
    store.forget(TASK_ID)
    assert TASK_ID not in store
    store.forget(TASK_ID)  # idempotent

  def test_remember_rejects_empty(self) -> None:
    with pytest.raises(ValueError):
      DurableTaskIdStore().remember("")


# ---------------------------------------------------------------------------
# AC-40.12  (R-25.7-r, R-25.7-s, R-25.11-d, R-25.11-e)
# ---------------------------------------------------------------------------

class TestAC4012UnknownTaskIdError:
  """Unknown/expired taskId -> -32602 error; client stops polling."""

  def test_error_response_code_is_32602(self) -> None:
    resp = build_task_not_found_response(70, TASK_ID)
    assert isinstance(resp, JSONRPCErrorResponse)
    assert resp.error["code"] == -32602  # R-25.7-r / R-25.11-d
    assert resp.id == 70
    assert resp.error["data"]["taskId"] == TASK_ID

  def test_client_recognizes_and_stops_polling(self) -> None:
    resp = build_task_not_found_response(70, TASK_ID)
    assert is_task_not_found_error(resp.error) is True
    assert client_should_stop_polling(resp.error) is True  # R-25.7-s / R-25.11-e

  def test_other_error_does_not_stop_polling(self) -> None:
    assert client_should_stop_polling({"code": -32603}) is False


# ---------------------------------------------------------------------------
# AC-40.13  (R-25.8-a, R-25.8-b)
# ---------------------------------------------------------------------------

class TestAC4013UpdateRequestWellFormed:
  """tasks/update is well-formed only with taskId + inputResponses; keys must be outstanding."""

  def test_both_fields_required(self) -> None:
    req = build_update_task_request(6, TASK_ID, {"name": {"action": "accept"}})
    assert req.method == TASKS_UPDATE_METHOD
    assert req.params["taskId"] == TASK_ID
    assert "inputResponses" in req.params

  def test_missing_input_responses_rejected(self) -> None:
    with pytest.raises(ValueError):
      parse_update_task_request_params({"taskId": TASK_ID})

  def test_missing_taskid_rejected(self) -> None:
    with pytest.raises(ValueError):
      parse_update_task_request_params({"inputResponses": {"name": {}}})

  def test_key_must_match_outstanding(self) -> None:
    state = TaskInputState()
    state.issue("name")
    # "name" is currently outstanding -> accepted; "other" is not -> ignored (R-25.8-b)
    app = state.apply_responses({"name": {"action": "accept"}, "other": {}})
    assert "name" in app.accepted
    assert "other" in app.ignored


# ---------------------------------------------------------------------------
# AC-40.14  (R-25.8-c, R-25.8-d)
# ---------------------------------------------------------------------------

class TestAC4014UpdateMissingCapability:
  """A client without the extension gets -32003 on tasks/update."""

  def test_gating_raises_when_inactive(self) -> None:
    with pytest.raises(TasksExtensionNotActiveError):
      assert_tasks_method_allowed(TASKS_UPDATE_METHOD, NO_CLIENT, ACTIVE)

  def test_error_response_code(self) -> None:
    resp = build_missing_capability_response(6, TASKS_UPDATE_METHOD)
    assert resp.error["code"] == -32003


# ---------------------------------------------------------------------------
# AC-40.15  (R-25.8-e, R-25.8-f)
# ---------------------------------------------------------------------------

class TestAC4015KeyUniqueOverLifetime:
  """Every inputRequests key is unique over the task's entire lifetime; never reused."""

  def test_reissuing_outstanding_key_raises(self) -> None:
    state = TaskInputState()
    state.issue("name")
    with pytest.raises(InputRequestKeyError):
      state.issue("name")  # duplicate during lifetime (R-25.8-f)

  def test_reissuing_answered_key_raises(self) -> None:
    state = TaskInputState()
    state.issue("name")
    state.apply_responses({"name": {"action": "accept"}})  # answered & removed
    with pytest.raises(InputRequestKeyError):
      state.issue("name")  # MUST NOT reuse after a response delivered (R-25.8-f)

  def test_distinct_keys_allowed(self) -> None:
    state = TaskInputState()
    state.issue("name", "age")  # unique keys are fine (R-25.8-e)
    assert state.outstanding == frozenset({"name", "age"})


# ---------------------------------------------------------------------------
# AC-40.16  (R-25.8-g)
# ---------------------------------------------------------------------------

class TestAC4016IgnoreStaleKeys:
  """A server ignores inputResponses whose key is not currently outstanding."""

  def test_never_issued_ignored(self) -> None:
    state = TaskInputState()
    state.issue("name")
    app = state.apply_responses({"ghost": {}})  # never issued (R-25.8-g)
    assert app.ignored == frozenset({"ghost"})
    assert app.accepted == frozenset()
    assert "name" in app.remaining_outstanding

  def test_already_answered_ignored(self) -> None:
    state = TaskInputState()
    state.issue("name")
    state.apply_responses({"name": {"action": "accept"}})
    app = state.apply_responses({"name": {"action": "accept"}})  # already answered
    assert app.ignored == frozenset({"name"})  # R-25.8-g
    assert app.accepted == frozenset()


# ---------------------------------------------------------------------------
# AC-40.17  (R-25.8-h)
# ---------------------------------------------------------------------------

class TestAC4017PartialResponsesAccepted:
  """A strict subset is accepted; the task stays input_required until the rest arrive."""

  def test_partial_keeps_outstanding(self) -> None:
    state = TaskInputState()
    state.issue("name", "age")
    app = state.apply_responses({"name": {"action": "accept"}})  # strict subset
    assert app.accepted == frozenset({"name"})
    assert app.remaining_outstanding == frozenset({"age"})
    assert app.is_partial is True  # remains input_required (R-25.8-h)
    assert app.all_resolved is False

  def test_full_resolution(self) -> None:
    state = TaskInputState()
    state.issue("name", "age")
    app = state.apply_responses({"name": {}, "age": {}})
    assert app.all_resolved is True
    assert app.is_partial is False


# ---------------------------------------------------------------------------
# AC-40.18  (R-25.8-i)
# ---------------------------------------------------------------------------

class TestAC4018ClientTracksAnswered:
  """The client tracks answered keys and does not answer the same request twice."""

  def test_unanswered_filters_repeated_key(self) -> None:
    tracker = AnsweredKeyTracker()
    snapshot = {"name", "age"}
    tracker.mark_answered("name")
    # Same key repeats on the next snapshot but is filtered out (R-25.8-i).
    assert tracker.unanswered(snapshot) == frozenset({"age"})
    assert tracker.has_answered("name") is True
    assert tracker.has_answered("age") is False


# ---------------------------------------------------------------------------
# AC-40.19  (R-25.8-j, R-25.8-k)
# ---------------------------------------------------------------------------

class TestAC4019UpdateEmptyAck:
  """tasks/update is acknowledged with an empty result whose resultType is "complete"."""

  def test_ack_is_empty_complete(self) -> None:
    resp = build_update_task_response(6)
    assert isinstance(resp, JSONRPCResultResponse)
    assert resp.result == {"resultType": "complete"}  # empty ack (R-25.8-j/k)

  def test_ack_roundtrip(self) -> None:
    parsed = parse_empty_ack_result({"resultType": "complete"})
    assert isinstance(parsed, EmptyAckResult)
    assert parsed.result_type == "complete"

  def test_wrong_result_type_rejected(self) -> None:
    with pytest.raises(ValueError):
      parse_empty_ack_result({"resultType": "task"})


# ---------------------------------------------------------------------------
# AC-40.20  (R-25.8-l)
# ---------------------------------------------------------------------------

class TestAC4020UpdateEventuallyConsistent:
  """The ack may precede the observable status reflecting the responses."""

  def test_ack_before_status_reflects(self) -> None:
    # The server may accept responses and ack before observable status changes:
    # immediately after applying, the task may still be observed input_required.
    state = TaskInputState()
    state.issue("name")
    app = state.apply_responses({"name": {"action": "accept"}})
    ack = build_update_task_response(6)
    # Acknowledged (R-25.8-k) though a concurrent tasks/get MAY still show
    # input_required until the server's processing catches up (R-25.8-l).
    assert ack.result["resultType"] == "complete"
    assert app.accepted == frozenset({"name"})
    still_input_required = make_detailed(TaskStatus.INPUT_REQUIRED)
    assert still_input_required.status is TaskStatus.INPUT_REQUIRED


# ---------------------------------------------------------------------------
# AC-40.21  (R-25.8-m)
# ---------------------------------------------------------------------------

class TestAC4021UpdateUnknownTaskId:
  """tasks/update for an unknown taskId -> -32602."""

  def test_unknown_taskid_error(self) -> None:
    resp = build_task_not_found_response(6, TASK_ID)
    assert resp.error["code"] == -32602  # R-25.8-m


# ---------------------------------------------------------------------------
# AC-40.22  (R-25.8-n)
# ---------------------------------------------------------------------------

class TestAC4022ContinueObservingAfterUpdate:
  """After tasks/update, keep observing until terminal."""

  def test_continue_after_update(self) -> None:
    # After updating, the task is typically still working/input_required.
    assert should_continue_polling(make_task(TaskStatus.WORKING)) is True
    assert should_continue_polling(make_task(TaskStatus.COMPLETED)) is False


# ---------------------------------------------------------------------------
# AC-40.23  (R-25.9-a)
# ---------------------------------------------------------------------------

class TestAC4023NoNotificationsCancelled:
  """notifications/cancelled is never used to cancel a task; only tasks/cancel."""

  def test_general_cancellation_recognized_as_forbidden(self) -> None:
    assert is_task_cancellation_notification(GENERAL_CANCELLED_NOTIFICATION_METHOD) is True
    assert GENERAL_CANCELLED_NOTIFICATION_METHOD == "notifications/cancelled"

  def test_tasks_cancel_is_the_mechanism(self) -> None:
    req = build_cancel_task_request(9, TASK_ID)
    assert req.method == TASKS_CANCEL_METHOD  # the only mechanism (R-25.9-a)
    assert is_task_cancellation_notification(TASKS_CANCEL_METHOD) is False


# ---------------------------------------------------------------------------
# AC-40.24  (R-25.9-b)
# ---------------------------------------------------------------------------

class TestAC4024CancelRequestWellFormed:
  """tasks/cancel is well-formed only when params.taskId is present."""

  def test_request_carries_taskid(self) -> None:
    req = build_cancel_task_request(9, TASK_ID)
    assert req.params == {"taskId": TASK_ID}

  def test_missing_taskid_rejected(self) -> None:
    with pytest.raises(ValueError):
      parse_cancel_task_request_params({})

  def test_roundtrip(self) -> None:
    params = parse_cancel_task_request_params({"taskId": TASK_ID})
    assert isinstance(params, CancelTaskRequestParams)
    assert params.task_id == TASK_ID


# ---------------------------------------------------------------------------
# AC-40.25  (R-25.9-c, R-25.9-d)
# ---------------------------------------------------------------------------

class TestAC4025CancelMissingCapability:
  """A client without the extension gets -32003 on tasks/cancel."""

  def test_gating_raises_when_inactive(self) -> None:
    with pytest.raises(TasksExtensionNotActiveError):
      assert_tasks_method_allowed(TASKS_CANCEL_METHOD, NO_CLIENT, ACTIVE)

  def test_error_response_code(self) -> None:
    resp = build_missing_capability_response(9, TASKS_CANCEL_METHOD)
    assert resp.error["code"] == -32003


# ---------------------------------------------------------------------------
# AC-40.26  (R-25.9-e, R-25.9-f)
# ---------------------------------------------------------------------------

class TestAC4026CancelEmptyAck:
  """tasks/cancel is acknowledged with an empty result whose resultType is "complete"."""

  def test_ack_is_empty_complete(self) -> None:
    resp = build_cancel_task_response(9)
    assert resp.result == {"resultType": "complete"}  # R-25.9-e/f


# ---------------------------------------------------------------------------
# AC-40.27  (R-25.9-g)
# ---------------------------------------------------------------------------

class TestAC4027CancelUnknownTaskId:
  """tasks/cancel for an unknown taskId -> -32602."""

  def test_unknown_taskid_error(self) -> None:
    resp = build_task_not_found_response(9, TASK_ID)
    assert resp.error["code"] == -32602  # R-25.9-g


# ---------------------------------------------------------------------------
# AC-40.28  (R-25.9-h, R-25.9-i)
# ---------------------------------------------------------------------------

class TestAC4028CancelCooperative:
  """Cancel only obligates an ack; status may stay non-terminal or end non-cancelled."""

  def test_non_terminal_status_unchanged_by_cancel(self) -> None:
    # Cancellation does not force a transition (R-25.9-h/i).
    assert apply_cancellation(TaskStatus.WORKING) is TaskStatus.WORKING
    assert apply_cancellation(TaskStatus.INPUT_REQUIRED) is TaskStatus.INPUT_REQUIRED

  def test_may_end_completed_if_work_finished_first(self) -> None:
    # The work may finish before cancel takes effect, reaching a terminal status
    # OTHER than cancelled (R-25.9-i); cancel never forces "cancelled".
    assert cancel_changes_terminal_status(TaskStatus.COMPLETED) is False


# ---------------------------------------------------------------------------
# AC-40.29  (R-25.9-j)
# ---------------------------------------------------------------------------

class TestAC4029CancelTerminalNoOp:
  """tasks/cancel on a terminal task does not change its status; terminal is final."""

  @pytest.mark.parametrize(
    "status",
    [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED],
  )
  def test_terminal_unchanged(self, status: TaskStatus) -> None:
    assert apply_cancellation(status) is status  # unchanged (R-25.9-j)
    assert cancel_changes_terminal_status(status) is False


# ---------------------------------------------------------------------------
# AC-40.30  (R-25.9-k)
# ---------------------------------------------------------------------------

class TestAC4030ClientMayDropState:
  """A client may drop local state immediately after tasks/cancel and need not poll again."""

  def test_may_drop_state(self) -> None:
    assert client_may_drop_state_after_cancel() is True  # R-25.9-k

  def test_forgetting_persisted_id_is_fine(self) -> None:
    store = DurableTaskIdStore()
    store.remember(TASK_ID)
    store.forget(TASK_ID)  # drop local state after cancel (R-25.9-k)
    assert TASK_ID not in store


# ---------------------------------------------------------------------------
# AC-40.31  (R-25.10-a)
# ---------------------------------------------------------------------------

class TestAC4031NotificationMatchesGet:
  """A pushed notifications/tasks carries a DetailedTask identical to tasks/get."""

  def test_notification_params_are_detailed_task(self) -> None:
    detailed = make_detailed(TaskStatus.COMPLETED)
    note = build_task_status_notification(detailed)
    assert isinstance(note, JSONRPCNotification)
    assert note.method == TASKS_NOTIFICATION_METHOD
    assert note.params["taskId"] == TASK_ID
    assert note.params["status"] == "completed"
    assert "result" in note.params  # full DetailedTask (R-25.10-a)

  def test_notification_matches_get_result(self) -> None:
    detailed = make_detailed(TaskStatus.COMPLETED)
    note = build_task_status_notification(detailed)
    get_result = build_get_task_result(detailed)
    assert notification_matches_get(note, get_result) is True  # identical (R-25.10-a)

  def test_parse_notification_roundtrip(self) -> None:
    detailed = make_detailed(TaskStatus.INPUT_REQUIRED)
    note = build_task_status_notification(detailed)
    parsed = parse_task_status_notification(note)
    assert parsed.status is TaskStatus.INPUT_REQUIRED


# ---------------------------------------------------------------------------
# AC-40.32  (R-25.10-b, R-25.10-c)
# ---------------------------------------------------------------------------

class TestAC4032OptInViaTaskIds:
  """Opt-in via a taskIds filter on subscriptions/listen; each element is a held taskId."""

  def test_subscription_request_carries_task_ids(self) -> None:
    req = build_task_subscription_request(11, [TASK_ID])
    assert req.method == SUBSCRIPTIONS_LISTEN_METHOD
    assert req.params["notifications"][TASK_IDS_FILTER_KEY] == [TASK_ID]

  def test_filter_roundtrip(self) -> None:
    filt = parse_task_ids_filter({TASK_IDS_FILTER_KEY: [TASK_ID]})
    assert filt.task_ids == (TASK_ID,)
    assert filt.has_task_ids is True

  def test_each_element_must_be_a_taskid(self) -> None:
    with pytest.raises(ValueError):
      TaskIdsFilter(task_ids=("",))  # empty is not a held taskId (R-25.10-c)
    with pytest.raises(TypeError):
      parse_task_ids_filter({TASK_IDS_FILTER_KEY: [123]})

  def test_absent_filter_is_empty(self) -> None:
    filt = parse_task_ids_filter({})
    assert filt.has_task_ids is False


# ---------------------------------------------------------------------------
# AC-40.33  (R-25.10-d)
# ---------------------------------------------------------------------------

class TestAC4033NoPushWithoutSubscription:
  """A server never pushes notifications/tasks for an unsubscribed task."""

  def test_unsubscribed_task_not_pushable(self) -> None:
    gate = TaskNotificationGate()
    gate.subscribe(TASK_ID)
    assert gate.may_push(TASK_ID) is True
    assert gate.may_push("other-task") is False  # not subscribed (R-25.10-d)

  def test_assert_raises_for_unsubscribed(self) -> None:
    gate = TaskNotificationGate({TASK_ID})
    gate.assert_may_push(TASK_ID)  # no raise
    with pytest.raises(ValueError):
      gate.assert_may_push("other-task")  # R-25.10-d


# ---------------------------------------------------------------------------
# AC-40.34  (R-25.10-e)
# ---------------------------------------------------------------------------

class TestAC4034TaskIdsMissingCapability:
  """taskIds supplied without the negotiated extension -> -32003."""

  def test_raises_when_taskids_without_capability(self) -> None:
    filt = TaskIdsFilter(task_ids=(TASK_ID,))
    with pytest.raises(TasksExtensionNotActiveError):
      assert_task_subscription_capability(filt, NO_CLIENT, ACTIVE)  # R-25.10-e

  def test_passes_when_capability_present(self) -> None:
    filt = TaskIdsFilter(task_ids=(TASK_ID,))
    assert_task_subscription_capability(filt, ACTIVE, ACTIVE)  # no raise

  def test_no_taskids_needs_no_capability(self) -> None:
    # An ordinary §10 subscription (no taskIds) needs no Tasks capability.
    assert_task_subscription_capability(TaskIdsFilter(), NO_CLIENT, ACTIVE)  # no raise

  def test_error_object_is_32003(self) -> None:
    filt = TaskIdsFilter(task_ids=(TASK_ID,))
    try:
      assert_task_subscription_capability(filt, NO_CLIENT, ACTIVE)
    except TasksExtensionNotActiveError as exc:
      assert exc.to_error_object()["code"] == -32003
      assert exc.method == SUBSCRIPTIONS_LISTEN_METHOD


# ---------------------------------------------------------------------------
# AC-40.35  (R-25.10-f)
# ---------------------------------------------------------------------------

class TestAC4035NotificationsOrPolling:
  """A subscribed client may rely solely on notifications, or poll, or combine both."""

  def test_may_rely_on_notifications_only(self) -> None:
    assert client_may_rely_on_notifications_only() is True  # need not poll (R-25.10-f)

  def test_polling_remains_available(self) -> None:
    # Polling is independent of the notification gate.
    assert should_continue_polling(make_task(TaskStatus.WORKING)) is True


# ---------------------------------------------------------------------------
# AC-40.36  (R-25.10-g)
# ---------------------------------------------------------------------------

class TestAC4036NoProgressOrMessage:
  """A server never sends notifications/progress or notifications/message for a task."""

  @pytest.mark.parametrize(
    "method", ["notifications/progress", "notifications/message"]
  )
  def test_forbidden_methods_rejected(self, method: str) -> None:
    assert is_forbidden_task_notification(method) is True
    assert method in FORBIDDEN_TASK_NOTIFICATION_METHODS
    with pytest.raises(ValueError):
      assert_task_notification_allowed(method)  # R-25.10-g

  def test_task_state_methods_allowed(self) -> None:
    assert_task_notification_allowed(TASKS_NOTIFICATION_METHOD)  # no raise
    assert is_forbidden_task_notification(TASKS_NOTIFICATION_METHOD) is False


# ---------------------------------------------------------------------------
# AC-40.37  (R-25.10-h)
# ---------------------------------------------------------------------------

class TestAC4037PreTaskInputSynchronous:
  """Pre-task input is resolved synchronously via the §11 inline flow before a task exists."""

  def test_resolve_pre_task_synchronously(self) -> None:
    assert should_resolve_pre_task_input_synchronously() is True  # R-25.10-h


# ---------------------------------------------------------------------------
# AC-40.38  (R-25.10-i)
# ---------------------------------------------------------------------------

class TestAC4038TrustNotElevated:
  """An inputRequests entry carries the same trust model as a standalone request."""

  def test_trust_not_elevated(self) -> None:
    assert input_request_trust_is_not_elevated() is True  # not higher-trust (R-25.10-i)


# ---------------------------------------------------------------------------
# AC-40.39  (R-25.10-j)
# ---------------------------------------------------------------------------

class TestAC4039ChannelsNotMixed:
  """Task-surfaced input -> tasks/update only; inline input-required -> reissue only; never mixed."""

  def test_task_surfaced_requires_update(self) -> None:
    assert (
      required_input_resolution_channel(surfaced_via_task=True)
      == InputResolutionChannel.TASK_UPDATE
    )

  def test_inline_surfaced_requires_reissue(self) -> None:
    assert (
      required_input_resolution_channel(surfaced_via_task=False)
      == InputResolutionChannel.INLINE_RETRY
    )

  def test_mixing_raises(self) -> None:
    # Task-surfaced input resolved via the inline retry channel is forbidden.
    with pytest.raises(ValueError):
      assert_resolution_channel_not_mixed(
        surfaced_via_task=True, attempted_channel=InputResolutionChannel.INLINE_RETRY
      )
    # Inline input resolved via tasks/update is forbidden.
    with pytest.raises(ValueError):
      assert_resolution_channel_not_mixed(
        surfaced_via_task=False, attempted_channel=InputResolutionChannel.TASK_UPDATE
      )

  def test_correct_channel_passes(self) -> None:
    assert_resolution_channel_not_mixed(
      surfaced_via_task=True, attempted_channel=InputResolutionChannel.TASK_UPDATE
    )
    assert_resolution_channel_not_mixed(
      surfaced_via_task=False, attempted_channel=InputResolutionChannel.INLINE_RETRY
    )


# ---------------------------------------------------------------------------
# AC-40.40  (R-25.11-a, R-25.11-b)
# ---------------------------------------------------------------------------

class TestAC4040TtlMutableAndExpiry:
  """ttlMs may change; a server may mark failed after it elapses and remove later."""

  def test_ttl_mutability_observed_via_fresh_task(self) -> None:
    # ttlMs MAY change over the task's life (R-25.11-a): two observations differ.
    early = make_task(ttl_ms=3600000)
    later = make_task(ttl_ms=60000)
    assert early.ttl_ms != later.ttl_ms

  def test_expiry_after_ttl_elapsed(self) -> None:
    created = 1000.0
    # ttl 5000ms: expired once now >= created + ttl (R-25.11-b).
    assert is_task_expired(created, 5000, created + 4999) is False
    assert is_task_expired(created, 5000, created + 5000) is True

  def test_null_ttl_never_expires(self) -> None:
    assert is_task_expired(0.0, None, 10**12) is False  # unlimited (R-25.11-a)

  def test_expired_removed_then_not_found(self) -> None:
    # After expiry+removal, tasks/get returns -32602 (R-25.11-d via the not-found error).
    resp = build_task_not_found_response(70, TASK_ID)
    assert resp.error["code"] == -32602


# ---------------------------------------------------------------------------
# AC-40.41  (R-25.11-c)
# ---------------------------------------------------------------------------

class TestAC4041TtlBackstop:
  """A client may treat createdAt + ttlMs as a backstop if status hasn't advanced."""

  def test_deadline_computed(self) -> None:
    assert ttl_deadline_ms(1000.0, 5000) == 6000.0
    assert ttl_deadline_ms(1000.0, None) is None  # unlimited

  def test_unusable_when_not_advanced_past_deadline(self) -> None:
    created = 1000.0
    # Status not advanced and past the deadline -> may consider unusable (R-25.11-c).
    assert task_unusable_backstop(created, 5000, created + 5000, status_advanced=False) is True
    # Status advanced -> backstop does not apply.
    assert task_unusable_backstop(created, 5000, created + 5000, status_advanced=True) is False
    # Before deadline -> not unusable.
    assert task_unusable_backstop(created, 5000, created + 100, status_advanced=False) is False


# ---------------------------------------------------------------------------
# AC-40.42  (R-25.11-f, R-25.11-g)
# ---------------------------------------------------------------------------

class TestAC4042ProtocolErrorFailed:
  """A protocol error during execution -> failed with the error field and diagnostic message."""

  def test_protocol_error_status_is_failed(self) -> None:
    err = {"code": -32603, "message": "internal error"}
    assert status_for_protocol_error(err) is TaskStatus.FAILED  # R-25.11-f
    assert status_for_execution_outcome(is_protocol_error=True) is TaskStatus.FAILED

  def test_failed_detailed_task_carries_error_and_message(self) -> None:
    err = {"code": -32603, "message": "internal error"}
    detailed = build_failed_detailed_task(
      make_task(TaskStatus.FAILED), err, status_message="execution crashed"
    )
    out = detailed.to_dict()
    assert out["status"] == "failed"
    assert out["error"] == err  # error field carries the JSON-RPC error (R-25.11-f)
    assert out["statusMessage"] == "execution crashed"  # diagnostic (R-25.11-g)

  def test_failed_requires_failed_status(self) -> None:
    with pytest.raises(ValueError):
      build_failed_detailed_task(make_task(TaskStatus.WORKING), {"code": -1})


# ---------------------------------------------------------------------------
# AC-40.43  (R-25.11-h, R-25.11-i)
# ---------------------------------------------------------------------------

class TestAC4043ApplicationErrorCompleted:
  """An application-level error (isError: true) -> completed; failed never used for it."""

  def test_application_error_recognized(self) -> None:
    assert is_application_level_error_result({"isError": True}) is True
    assert is_application_level_error_result({"isError": False}) is False

  def test_application_error_reported_as_completed(self) -> None:
    result_obj = {"content": [{"type": "text", "text": "bad"}], "isError": True}
    detailed = build_completed_with_application_error(
      make_task(TaskStatus.COMPLETED), result_obj
    )
    out = detailed.to_dict()
    assert out["status"] == "completed"  # NOT failed (R-25.11-h/i)
    assert out["result"] == result_obj  # error details inside result (R-25.11-i)

  def test_completed_required_for_app_error(self) -> None:
    # Using failed for a non-protocol fault is rejected (R-25.11-h).
    with pytest.raises(ValueError):
      build_completed_with_application_error(
        make_task(TaskStatus.FAILED), {"isError": True}
      )

  def test_non_protocol_outcome_is_completed(self) -> None:
    assert status_for_execution_outcome(is_protocol_error=False) is TaskStatus.COMPLETED
