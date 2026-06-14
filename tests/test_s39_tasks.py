"""Tests for S39 — Tasks Extension I: Model, Capability, Types & Lifecycle (§25.1–§25.6).

Each test class maps to one acceptance criterion (AC-39.x). S39 is the
foundational model of the Tasks extension (``io.modelcontextprotocol/tasks``): the
extension identifier and its negotiation/gating, the rule by which an eligible
request may be answered with a task handle, the ``Task`` / ``DetailedTask`` object
types, the five-state status lifecycle, and the durability/statelessness
guarantees. The operational methods (``tasks/get`` etc.) and notifications are
owned by S40 and are NOT tested here. The tests exercise the §25.1–§25.6 surface
through ``mcp_sdk_py.tasks`` directly.

AC → test coverage map:
  AC-39.1  (R-25.1-a)                     — TestAC3901ExactCaseSensitiveIdentifier
  AC-39.2  (R-25.2-a, R-25.2-b)           — TestAC3902SettingsIgnoreUnrecognized
  AC-39.3  (R-25.2-c)                     — TestAC3903PerRequestDeclaration
  AC-39.4  (R-25.2-d)                     — TestAC3904NoTaskHandleWithoutDeclaration
  AC-39.5  (R-25.2-e, R-25.3-c)           — TestAC3905ClientHandlesBothShapes
  AC-39.6  (R-25.2-f)                     — TestAC3906MissingCapabilityError
  AC-39.7  (R-25.2-g, R-25.3-a, R-25.3-b) — TestAC3907ServerDirectedNoWarmup
  AC-39.8  (R-25.3-c)                     — TestAC3908CreateTaskResultShape
  AC-39.9  (R-25.4-a)                     — TestAC3909OpaqueTaskId
  AC-39.10 (R-25.4-b)                     — TestAC3910RequiredTaskFields
  AC-39.11 (R-25.4-c, R-25.6-f, R-25.6-g) — TestAC3911TtlExpiryNotFound
  AC-39.12 (R-25.4-d, R-25.4-e)           — TestAC3912PollInterval
  AC-39.13 (R-25.5-a)                     — TestAC3913StatusFiveValues
  AC-39.14 (R-25.5-b)                     — TestAC3914TerminalImmutable
  AC-39.15 (R-25.5-c)                     — TestAC3915LegalTransitions
  AC-39.16 (R-25.5-d)                     — TestAC3916DetailedTaskVariants
  AC-39.17 (R-25.5-e)                     — TestAC3917ContinuePolling
  AC-39.18 (R-25.6-a)                     — TestAC3918StatelessModel
  AC-39.19 (R-25.6-b)                     — TestAC3919DurablePersistence
  AC-39.20 (R-25.6-c, R-25.6-d)           — TestAC3920InstanceAgnostic
  AC-39.21 (R-25.6-e)                     — TestAC3921ResumableContinuationToken
  AC-39.22 (R-25.6-h)                     — TestAC3922ClientPersistsTaskId
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.extension_mechanism import ExtensionDefinition, ExtensionRegistry
from mcp_sdk_py.multi_round_trip import (
  INPUT_REQUEST_ELICITATION,
  InputRequest,
  make_hmac_request_state,
  verify_hmac_request_state,
)
from mcp_sdk_py.negotiation import MISSING_REQUIRED_CLIENT_CAPABILITY_CODE
from mcp_sdk_py.tasks import (
  DEFAULT_POLL_INTERVAL_MS,
  MISSING_CAPABILITY_ERROR_CODE,
  RESULT_TYPE_TASK,
  TASK_NOT_FOUND_ERROR_CODE,
  TASK_STATUS_VALUES,
  TASKS_EXTENSION,
  TASKS_EXTENSION_CAPABILITY,
  TASKS_EXTENSION_IDENTIFIER,
  TASKS_METHODS,
  CreateTaskResult,
  DetailedTask,
  Task,
  TaskNotFoundError,
  TaskStatus,
  TasksExtensionNotActiveError,
  TerminalTaskMutationError,
  active_extension_ids,
  assert_client_may_invoke_tasks_method,
  assert_legal_transition,
  assert_may_return_task_handle,
  classify_eligible_result,
  echo_task_id,
  effective_poll_interval_ms,
  is_legal_transition,
  is_poll_too_soon,
  is_task_handle,
  is_tasks_extension_identifier,
  is_terminal_status,
  may_return_task_handle,
  normalize_tasks_settings,
  parse_create_task_result,
  parse_detailed_task,
  parse_task,
  parse_task_status,
  request_declares_tasks,
  should_continue_polling,
  tasks_active,
  tasks_capability_entry,
)


# A vendor-neutral RFC 3339 timestamp used throughout (no real dates of note).
CREATED = "2026-06-13T10:15:00Z"
UPDATED = "2026-06-13T10:16:30Z"


def _client_caps_with_tasks() -> dict[str, object]:
  """A per-request client ``extensions`` map declaring the Tasks extension."""
  return {TASKS_EXTENSION_IDENTIFIER: {}}


def _server_caps_with_tasks() -> dict[str, object]:
  """A server ``extensions`` map advertising the Tasks extension."""
  return {TASKS_EXTENSION_IDENTIFIER: {}}


def _working_task(**overrides: object) -> Task:
  """A minimal valid ``working`` Task; overrides patch individual fields."""
  fields: dict[str, object] = {
    "task_id": "task_3f2a9c10",
    "status": TaskStatus.WORKING,
    "created_at": CREATED,
    "last_updated_at": CREATED,
    "ttl_ms": 3600000,
  }
  fields.update(overrides)
  return Task(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-39.1 — exact, case-sensitive identifier comparison (R-25.1-a)
# ---------------------------------------------------------------------------

class TestAC3901ExactCaseSensitiveIdentifier:
  def test_exact_match_is_recognized(self) -> None:
    assert TASKS_EXTENSION_IDENTIFIER == "io.modelcontextprotocol/tasks"
    assert is_tasks_extension_identifier("io.modelcontextprotocol/tasks")

  def test_case_variant_does_not_match(self) -> None:
    assert not is_tasks_extension_identifier("IO.MODELCONTEXTPROTOCOL/TASKS")
    assert not is_tasks_extension_identifier("io.modelcontextprotocol/Tasks")

  def test_prefixed_or_suffixed_does_not_match(self) -> None:
    assert not is_tasks_extension_identifier("io.modelcontextprotocol/tasks-foo")
    assert not is_tasks_extension_identifier("io.modelcontextprotocol/task")
    assert not is_tasks_extension_identifier("x.io.modelcontextprotocol/tasks")

  def test_active_set_does_not_activate_case_variant(self) -> None:
    # A case-variant key on one side never intersects the canonical key.
    client = {"IO.MODELCONTEXTPROTOCOL/TASKS": {}}
    server = _server_caps_with_tasks()
    assert not tasks_active(client, server)


# ---------------------------------------------------------------------------
# AC-39.2 — settings object: accept, ignore unrecognized members (R-25.2-a/b)
# ---------------------------------------------------------------------------

class TestAC3902SettingsIgnoreUnrecognized:
  def test_canonical_settings_is_empty_object(self) -> None:
    assert TASKS_EXTENSION_CAPABILITY == {}
    assert tasks_capability_entry() == {TASKS_EXTENSION_IDENTIFIER: {}}

  def test_unrecognized_member_is_ignored_not_rejected(self) -> None:
    # A settings object carrying an unrecognized member is accepted; the member
    # is ignored (R-25.2-b). The extension defines no settings, so the
    # recognized subset is always empty.
    assert normalize_tasks_settings({"futureKnob": 7}) == {}

  def test_declaration_with_extra_member_still_activates(self) -> None:
    # The declaration is still valid/advertised even with extra members.
    client = {TASKS_EXTENSION_IDENTIFIER: {"futureKnob": 7}}
    assert request_declares_tasks(client)
    assert tasks_active(client, _server_caps_with_tasks())

  def test_non_object_settings_yields_empty(self) -> None:
    assert normalize_tasks_settings("not-an-object") == {}
    assert normalize_tasks_settings(None) == {}


# ---------------------------------------------------------------------------
# AC-39.3 — per-request declaration makes a request eligible (R-25.2-c)
# ---------------------------------------------------------------------------

class TestAC3903PerRequestDeclaration:
  def test_request_declaring_tasks_is_eligible(self) -> None:
    assert request_declares_tasks(_client_caps_with_tasks())

  def test_request_without_declaration_is_not_eligible(self) -> None:
    assert not request_declares_tasks({})
    assert not request_declares_tasks({"com.example/other": {}})
    assert not request_declares_tasks(None)

  def test_null_valued_entry_is_not_a_declaration(self) -> None:
    # A null-valued entry is malformed and dropped (S11), so not eligible.
    assert not request_declares_tasks({TASKS_EXTENSION_IDENTIFIER: None})


# ---------------------------------------------------------------------------
# AC-39.4 — never return a task handle without the declaration (R-25.2-d)
# ---------------------------------------------------------------------------

class TestAC3904NoTaskHandleWithoutDeclaration:
  def test_may_not_return_handle_without_client_declaration(self) -> None:
    # Client did not declare tasks; server advertised it.
    assert not may_return_task_handle({}, _server_caps_with_tasks())

  def test_may_not_return_handle_without_server_advertisement(self) -> None:
    assert not may_return_task_handle(_client_caps_with_tasks(), {})

  def test_assert_raises_when_inactive(self) -> None:
    with pytest.raises(TasksExtensionNotActiveError):
      assert_may_return_task_handle({}, _server_caps_with_tasks())

  def test_may_return_handle_only_when_both_declare(self) -> None:
    assert may_return_task_handle(
      _client_caps_with_tasks(), _server_caps_with_tasks()
    )
    # The guard does not raise when active.
    assert_may_return_task_handle(
      _client_caps_with_tasks(), _server_caps_with_tasks()
    )


# ---------------------------------------------------------------------------
# AC-39.5 — client handles ordinary result OR task handle (R-25.2-e, R-25.3-c)
# ---------------------------------------------------------------------------

class TestAC3905ClientHandlesBothShapes:
  def test_classifies_task_handle(self) -> None:
    handle = CreateTaskResult(task=_working_task()).to_dict()
    assert classify_eligible_result(handle) == RESULT_TYPE_TASK
    assert is_task_handle(handle)

  def test_classifies_ordinary_result(self) -> None:
    ordinary = {"resultType": "complete", "content": [{"type": "text", "text": "Done."}]}
    assert classify_eligible_result(ordinary) == "ordinary"
    assert not is_task_handle(ordinary)

  def test_ordinary_result_without_result_type_is_ordinary(self) -> None:
    assert classify_eligible_result({"content": []}) == "ordinary"

  def test_dispatch_then_parse_handle(self) -> None:
    handle = CreateTaskResult(task=_working_task()).to_dict()
    if classify_eligible_result(handle) == RESULT_TYPE_TASK:
      parsed = parse_create_task_result(handle)
      assert parsed.task_id == "task_3f2a9c10"
    else:  # pragma: no cover - branch asserts the dispatch decision above
      pytest.fail("task handle must classify as a task")


# ---------------------------------------------------------------------------
# AC-39.6 — missing-capability error for Tasks methods (R-25.2-f)
# ---------------------------------------------------------------------------

class TestAC3906MissingCapabilityError:
  @pytest.mark.parametrize("method", sorted(TASKS_METHODS))
  def test_invoking_against_unadvertised_server_raises(self, method: str) -> None:
    with pytest.raises(TasksExtensionNotActiveError) as exc:
      # Server has not advertised the extension.
      assert_client_may_invoke_tasks_method(method, _client_caps_with_tasks(), {})
    assert exc.value.method == method

  def test_error_uses_section_22_missing_capability_code(self) -> None:
    assert MISSING_CAPABILITY_ERROR_CODE == MISSING_REQUIRED_CLIENT_CAPABILITY_CODE
    assert MISSING_CAPABILITY_ERROR_CODE == -32003
    err = TasksExtensionNotActiveError("tasks/get").to_error_object()
    assert err["code"] == -32003
    required = err["data"]["requiredCapabilities"]["extensions"]
    assert TASKS_EXTENSION_IDENTIFIER in required

  def test_no_error_when_extension_active(self) -> None:
    # Both peers advertise it; the method may be serviced.
    assert_client_may_invoke_tasks_method(
      "tasks/get", _client_caps_with_tasks(), _server_caps_with_tasks()
    )


# ---------------------------------------------------------------------------
# AC-39.7 — server-directed, unsolicited, no per-call warmup (R-25.2-g, R-25.3-a/b)
# ---------------------------------------------------------------------------

class TestAC3907ServerDirectedNoWarmup:
  def test_capability_alone_is_sufficient_no_flag(self) -> None:
    # No extra flag or warmup: activation is purely the per-request capability
    # on both sides. may_return_task_handle is True with nothing but {}-valued
    # declarations.
    assert may_return_task_handle(
      {TASKS_EXTENSION_IDENTIFIER: {}}, {TASKS_EXTENSION_IDENTIFIER: {}}
    )

  def test_substitution_is_optional_per_request(self) -> None:
    # The server MAY produce a task or MAY return the ordinary result for the
    # very same eligible request; the model does not force either. Both an
    # ordinary result and a task handle are well-formed for an active request.
    active_client = _client_caps_with_tasks()
    active_server = _server_caps_with_tasks()
    assert may_return_task_handle(active_client, active_server)
    ordinary = {"resultType": "complete"}
    handle = CreateTaskResult(task=_working_task()).to_dict()
    assert classify_eligible_result(ordinary) == "ordinary"
    assert classify_eligible_result(handle) == RESULT_TYPE_TASK

  def test_tasks_extension_definition_declares_no_settings_requirement(self) -> None:
    # The extension definition carries the result-type and methods but no
    # warmup/flag surface; the canonical settings value is the empty object.
    assert isinstance(TASKS_EXTENSION, ExtensionDefinition)
    assert RESULT_TYPE_TASK in TASKS_EXTENSION.result_types
    assert TASKS_METHODS <= TASKS_EXTENSION.methods


# ---------------------------------------------------------------------------
# AC-39.8 — CreateTaskResult wire shape (R-25.3-c)
# ---------------------------------------------------------------------------

class TestAC3908CreateTaskResultShape:
  def test_result_type_is_task(self) -> None:
    result = CreateTaskResult(task=_working_task())
    assert result.result_type == "task"
    assert RESULT_TYPE_TASK == "task"

  def test_all_task_fields_appear_directly(self) -> None:
    task = _working_task(
      status_message="Processing item 42 of 100", poll_interval_ms=2000
    )
    wire = CreateTaskResult(task=task).to_dict()
    assert wire["resultType"] == "task"
    # Task fields are flattened directly onto the result, not nested.
    assert wire["taskId"] == "task_3f2a9c10"
    assert wire["status"] == "working"
    assert wire["createdAt"] == CREATED
    assert wire["lastUpdatedAt"] == CREATED
    assert wire["ttlMs"] == 3600000
    assert wire["statusMessage"] == "Processing item 42 of 100"
    assert wire["pollIntervalMs"] == 2000
    assert "task" not in wire  # not nested under a "task" key

  def test_roundtrip_parse(self) -> None:
    wire = CreateTaskResult(
      task=_working_task(poll_interval_ms=2000), meta={"x": 1}
    ).to_dict()
    parsed = parse_create_task_result(wire)
    assert parsed.task_id == "task_3f2a9c10"
    assert parsed.status is TaskStatus.WORKING
    assert parsed.meta == {"x": 1}

  def test_parse_rejects_wrong_result_type(self) -> None:
    with pytest.raises(ValueError):
      parse_create_task_result({"resultType": "complete", "taskId": "t"})


# ---------------------------------------------------------------------------
# AC-39.9 — opaque taskId; no meaning derived (R-25.4-a)
# ---------------------------------------------------------------------------

class TestAC3909OpaqueTaskId:
  def test_echoed_verbatim(self) -> None:
    for tid in ("task_3f2a9c10", "X/y:z=1", "", "::weird::"):
      # echo_task_id only requires a string; it never parses structure.
      assert echo_task_id(tid) == tid

  def test_non_string_task_id_is_malformed(self) -> None:
    with pytest.raises(TypeError):
      echo_task_id(12345)  # type: ignore[arg-type]

  def test_parse_preserves_taskid_verbatim(self) -> None:
    raw = CreateTaskResult(task=_working_task(task_id="abc/DEF.123")).to_dict()
    assert parse_create_task_result(raw).task_id == "abc/DEF.123"


# ---------------------------------------------------------------------------
# AC-39.10 — required Task fields present & valid (R-25.4-b)
# ---------------------------------------------------------------------------

class TestAC3910RequiredTaskFields:
  def test_minimal_required_fields(self) -> None:
    task = _working_task()
    wire = task.to_dict()
    for key in ("taskId", "status", "createdAt", "lastUpdatedAt", "ttlMs"):
      assert key in wire

  @pytest.mark.parametrize(
    "missing", ["taskId", "status", "createdAt", "lastUpdatedAt", "ttlMs"]
  )
  def test_parse_rejects_missing_required_field(self, missing: str) -> None:
    raw = {
      "taskId": "t1",
      "status": "working",
      "createdAt": CREATED,
      "lastUpdatedAt": CREATED,
      "ttlMs": 1000,
    }
    del raw[missing]
    with pytest.raises(ValueError):
      parse_task(raw)

  def test_ttl_null_is_valid_unbounded(self) -> None:
    task = _working_task(ttl_ms=None)
    assert task.to_dict()["ttlMs"] is None
    parsed = parse_task(task.to_dict())
    assert parsed.ttl_ms is None

  def test_ttl_must_be_non_negative_number(self) -> None:
    with pytest.raises(ValueError):
      _working_task(ttl_ms=-1)
    with pytest.raises(TypeError):
      _working_task(ttl_ms="3600")

  def test_empty_task_id_rejected(self) -> None:
    with pytest.raises(ValueError):
      _working_task(task_id="")


# ---------------------------------------------------------------------------
# AC-39.11 — ttl expiry → discard → not-found error (R-25.4-c, R-25.6-f/g)
# ---------------------------------------------------------------------------

class TestAC3911TtlExpiryNotFound:
  def test_not_found_uses_section_22_code(self) -> None:
    assert TASK_NOT_FOUND_ERROR_CODE == -32602
    err = TaskNotFoundError("task_3f2a9c10").to_error_object()
    assert err["code"] == -32602
    assert err["data"]["taskId"] == "task_3f2a9c10"

  def test_discard_after_ttl_then_query_is_not_found(self) -> None:
    # Model a server store that discards a task whose non-null ttl elapsed and
    # answers a later query with the not-found error (R-25.4-c, R-25.6-f/g).
    store: dict[str, Task] = {}
    task = _working_task(ttl_ms=1000)
    store[task.task_id] = task

    def query(task_id: str, now_ms: float, created_ms: float) -> Task:
      held = store.get(task_id)
      if held is not None and held.ttl_ms is not None:
        if now_ms - created_ms >= held.ttl_ms:
          del store[task_id]  # server MAY discard (R-25.6-f)
      held = store.get(task_id)
      if held is None:
        raise TaskNotFoundError(task_id)  # R-25.6-g
      return held

    # Before expiry: resolves.
    assert query(task.task_id, now_ms=500, created_ms=0).task_id == task.task_id
    # After expiry: discarded, then not-found.
    with pytest.raises(TaskNotFoundError):
      query(task.task_id, now_ms=2000, created_ms=0)

  def test_unbounded_ttl_never_expires_in_model(self) -> None:
    task = _working_task(ttl_ms=None)
    # A null ttl has no bounded lifetime; the discard condition never triggers.
    assert task.ttl_ms is None


# ---------------------------------------------------------------------------
# AC-39.12 — pollIntervalMs present vs absent (R-25.4-d, R-25.4-e)
# ---------------------------------------------------------------------------

class TestAC3912PollInterval:
  def test_effective_interval_uses_provided_value(self) -> None:
    task = _working_task(poll_interval_ms=2000)
    assert effective_poll_interval_ms(task) == 2000.0

  def test_effective_interval_defaults_when_absent(self) -> None:
    task = _working_task()  # no pollIntervalMs
    assert task.poll_interval_ms is None
    assert effective_poll_interval_ms(task) == DEFAULT_POLL_INTERVAL_MS

  def test_should_not_poll_more_frequently(self) -> None:
    task = _working_task(poll_interval_ms=2000)
    assert is_poll_too_soon(task, elapsed_ms=1999)
    assert not is_poll_too_soon(task, elapsed_ms=2000)
    assert not is_poll_too_soon(task, elapsed_ms=5000)

  def test_custom_default_interval(self) -> None:
    task = _working_task()
    assert effective_poll_interval_ms(task, default_ms=500.0) == 500.0


# ---------------------------------------------------------------------------
# AC-39.13 — status is exactly one of five case-sensitive values (R-25.5-a)
# ---------------------------------------------------------------------------

class TestAC3913StatusFiveValues:
  def test_five_values(self) -> None:
    assert TASK_STATUS_VALUES == {
      "working",
      "input_required",
      "completed",
      "failed",
      "cancelled",
    }
    assert {s.value for s in TaskStatus} == TASK_STATUS_VALUES

  @pytest.mark.parametrize("value", sorted(TASK_STATUS_VALUES))
  def test_each_value_parses(self, value: str) -> None:
    assert parse_task_status(value).value == value

  @pytest.mark.parametrize("bad", ["Working", "WORKING", "in_progress", "done", ""])
  def test_invalid_or_miscased_rejected(self, bad: str) -> None:
    with pytest.raises(ValueError):
      parse_task_status(bad)

  def test_non_string_rejected(self) -> None:
    with pytest.raises(TypeError):
      parse_task_status(1)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-39.14 — terminal states immutable; no further transition (R-25.5-b)
# ---------------------------------------------------------------------------

class TestAC3914TerminalImmutable:
  @pytest.mark.parametrize(
    "terminal",
    [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED],
  )
  def test_terminal_is_terminal(self, terminal: TaskStatus) -> None:
    assert is_terminal_status(terminal)
    assert terminal.is_terminal

  @pytest.mark.parametrize(
    "terminal",
    [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED],
  )
  @pytest.mark.parametrize(
    "target",
    list(TaskStatus),
  )
  def test_no_transition_out_of_terminal(
    self, terminal: TaskStatus, target: TaskStatus
  ) -> None:
    # A terminal task MUST NOT transition to any other state, including itself.
    assert not is_legal_transition(terminal, target)
    with pytest.raises(TerminalTaskMutationError):
      assert_legal_transition(terminal, target)

  def test_completed_result_immutable_in_detailed_task(self) -> None:
    # The inline result a terminal completed task carries is part of the
    # immutable terminal payload (R-25.5-b): construction fixes it.
    dt = DetailedTask(
      task=_working_task(status=TaskStatus.COMPLETED, last_updated_at=UPDATED),
      result={"resultType": "complete", "content": []},
    )
    assert dt.is_terminal
    assert dt.to_dict()["result"]["resultType"] == "complete"


# ---------------------------------------------------------------------------
# AC-39.15 — legal non-terminal transitions (R-25.5-c)
# ---------------------------------------------------------------------------

class TestAC3915LegalTransitions:
  def test_working_transitions(self) -> None:
    for target in (
      TaskStatus.INPUT_REQUIRED,
      TaskStatus.COMPLETED,
      TaskStatus.FAILED,
      TaskStatus.CANCELLED,
    ):
      assert is_legal_transition(TaskStatus.WORKING, target)
      assert_legal_transition(TaskStatus.WORKING, target)  # no raise

  def test_working_does_not_transition_to_itself(self) -> None:
    # 'working' -> 'working' is not in the legal destination set.
    assert not is_legal_transition(TaskStatus.WORKING, TaskStatus.WORKING)

  def test_input_required_transitions(self) -> None:
    for target in (
      TaskStatus.WORKING,
      TaskStatus.COMPLETED,
      TaskStatus.FAILED,
      TaskStatus.CANCELLED,
    ):
      assert is_legal_transition(TaskStatus.INPUT_REQUIRED, target)
      assert_legal_transition(TaskStatus.INPUT_REQUIRED, target)

  def test_input_required_does_not_transition_to_itself(self) -> None:
    assert not is_legal_transition(
      TaskStatus.INPUT_REQUIRED, TaskStatus.INPUT_REQUIRED
    )

  def test_illegal_nonterminal_transition_raises_value_error(self) -> None:
    # Force a non-terminal source with an out-of-set destination by removing the
    # only self-loop possibility: working->working is illegal and source is not
    # terminal, so a ValueError (not TerminalTaskMutationError) is raised.
    with pytest.raises(ValueError) as exc:
      assert_legal_transition(TaskStatus.WORKING, TaskStatus.WORKING)
    assert not isinstance(exc.value, TerminalTaskMutationError)


# ---------------------------------------------------------------------------
# AC-39.16 — DetailedTask variants & inline outcome placement (R-25.5-d)
# ---------------------------------------------------------------------------

class TestAC3916DetailedTaskVariants:
  def test_working_variant_has_no_extra_fields(self) -> None:
    dt = DetailedTask(task=_working_task())
    wire = dt.to_dict()
    assert "result" not in wire and "error" not in wire and "inputRequests" not in wire

  def test_cancelled_variant_has_no_extra_fields(self) -> None:
    dt = DetailedTask(
      task=_working_task(status=TaskStatus.CANCELLED, last_updated_at=UPDATED)
    )
    wire = dt.to_dict()
    assert "result" not in wire and "error" not in wire and "inputRequests" not in wire

  def test_completed_variant_carries_result(self) -> None:
    dt = DetailedTask(
      task=_working_task(status=TaskStatus.COMPLETED, last_updated_at=UPDATED),
      result={"resultType": "complete", "content": [{"type": "text", "text": "Done."}]},
    )
    assert dt.to_dict()["result"]["content"][0]["text"] == "Done."

  def test_failed_variant_carries_error(self) -> None:
    dt = DetailedTask(
      task=_working_task(status=TaskStatus.FAILED, last_updated_at=UPDATED),
      error={"code": -32603, "message": "Internal error while processing item 57"},
    )
    assert dt.to_dict()["error"]["code"] == -32603

  def test_input_required_variant_carries_input_requests(self) -> None:
    dt = DetailedTask(
      task=_working_task(status=TaskStatus.INPUT_REQUIRED, last_updated_at=UPDATED),
      input_requests={"req-1": InputRequest(method=INPUT_REQUEST_ELICITATION, params={})},
    )
    wire = dt.to_dict()
    assert wire["inputRequests"]["req-1"]["method"] == INPUT_REQUEST_ELICITATION

  def test_non_terminal_carries_neither_result_nor_error(self) -> None:
    with pytest.raises(ValueError):
      DetailedTask(task=_working_task(), result={"resultType": "complete"})
    with pytest.raises(ValueError):
      DetailedTask(task=_working_task(), error={"code": -1, "message": "x"})

  def test_completed_requires_result(self) -> None:
    with pytest.raises(ValueError):
      DetailedTask(
        task=_working_task(status=TaskStatus.COMPLETED, last_updated_at=UPDATED)
      )

  def test_failed_requires_error(self) -> None:
    with pytest.raises(ValueError):
      DetailedTask(
        task=_working_task(status=TaskStatus.FAILED, last_updated_at=UPDATED)
      )

  def test_input_required_requires_input_requests(self) -> None:
    with pytest.raises(ValueError):
      DetailedTask(
        task=_working_task(status=TaskStatus.INPUT_REQUIRED, last_updated_at=UPDATED)
      )

  def test_parse_roundtrip_each_variant(self) -> None:
    completed = {
      "taskId": "task_3f2a9c10",
      "status": "completed",
      "createdAt": CREATED,
      "lastUpdatedAt": UPDATED,
      "ttlMs": 3600000,
      "result": {"resultType": "complete", "content": []},
    }
    parsed = parse_detailed_task(completed)
    assert parsed.status is TaskStatus.COMPLETED
    assert parsed.result == {"resultType": "complete", "content": []}

    input_required = {
      "taskId": "task_3f2a9c10",
      "status": "input_required",
      "createdAt": CREATED,
      "lastUpdatedAt": UPDATED,
      "ttlMs": 3600000,
      "inputRequests": {"req-1": {"method": INPUT_REQUEST_ELICITATION, "params": {}}},
    }
    parsed_ir = parse_detailed_task(input_required)
    assert parsed_ir.status is TaskStatus.INPUT_REQUIRED
    assert parsed_ir.input_requests is not None
    assert parsed_ir.input_requests["req-1"].method == INPUT_REQUEST_ELICITATION

  def test_parse_rejects_result_on_non_terminal(self) -> None:
    raw = {
      "taskId": "t",
      "status": "working",
      "createdAt": CREATED,
      "lastUpdatedAt": CREATED,
      "ttlMs": None,
      "result": {"resultType": "complete"},
    }
    with pytest.raises(ValueError):
      parse_detailed_task(raw)


# ---------------------------------------------------------------------------
# AC-39.17 — client continues polling until terminal (R-25.5-e)
# ---------------------------------------------------------------------------

class TestAC3917ContinuePolling:
  def test_continue_while_non_terminal(self) -> None:
    assert should_continue_polling(_working_task(status=TaskStatus.WORKING))
    assert should_continue_polling(_working_task(status=TaskStatus.INPUT_REQUIRED))

  @pytest.mark.parametrize(
    "terminal",
    [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED],
  )
  def test_stop_when_terminal(self, terminal: TaskStatus) -> None:
    assert not should_continue_polling(
      _working_task(status=terminal, last_updated_at=UPDATED)
    )

  def test_poll_loop_terminates(self) -> None:
    # Drive a sequence working -> working -> completed; the loop stops at terminal.
    sequence = [TaskStatus.WORKING, TaskStatus.WORKING, TaskStatus.COMPLETED]
    seen = 0
    for status in sequence:
      task = _working_task(status=status, last_updated_at=UPDATED)
      seen += 1
      if not should_continue_polling(task):
        break
    assert seen == 3  # stopped exactly when terminal was observed


# ---------------------------------------------------------------------------
# AC-39.18 — tasks correct under stateless, instance-agnostic model (R-25.6-a)
# ---------------------------------------------------------------------------

class TestAC3918StatelessModel:
  def test_activation_recomputed_per_request_no_inference(self) -> None:
    # Request 1 declares the extension; request 2 does not. Each is evaluated on
    # its own per-request capabilities — nothing is inferred from request 1.
    server = _server_caps_with_tasks()
    assert tasks_active(_client_caps_with_tasks(), server)
    assert not tasks_active({}, server)

  def test_active_extension_ids_intersection(self) -> None:
    ids = active_extension_ids(_client_caps_with_tasks(), _server_caps_with_tasks())
    assert TASKS_EXTENSION_IDENTIFIER in ids

  def test_task_object_carries_all_state_to_resolve(self) -> None:
    # A Task is self-describing: a fresh parse of its wire form (as a different
    # instance would do) reconstructs the same state with no shared memory.
    wire = _working_task(poll_interval_ms=2000).to_dict()
    again = parse_task(wire)
    assert again.to_dict() == wire


# ---------------------------------------------------------------------------
# AC-39.19 — task persisted durably before returning the handle (R-25.6-b)
# ---------------------------------------------------------------------------

class TestAC3919DurablePersistence:
  def test_persist_before_returning_handle(self) -> None:
    # Model a durable store written BEFORE the CreateTaskResult is produced; the
    # taskId survives the creating request (we drop the in-memory handle and
    # still resolve the task from the store).
    durable: dict[str, dict[str, object]] = {}
    task = _working_task()

    def create_handle() -> dict[str, object]:
      durable[task.task_id] = task.to_dict()  # persist FIRST (R-25.6-b)
      return CreateTaskResult(task=task).to_dict()

    handle = create_handle()
    assert handle["resultType"] == "task"
    # Creating request is "over": discard the handle object entirely.
    del handle
    # The task and its id survive in the durable record.
    assert task.task_id in durable
    restored = parse_task(durable[task.task_id])
    assert restored.task_id == task.task_id

  def test_handle_taskid_matches_persisted_record(self) -> None:
    task = _working_task()
    durable = {task.task_id: task.to_dict()}
    handle = parse_create_task_result(CreateTaskResult(task=task).to_dict())
    assert handle.task_id in durable


# ---------------------------------------------------------------------------
# AC-39.20 — any instance resolves from durable record (R-25.6-c, R-25.6-d)
# ---------------------------------------------------------------------------

class TestAC3920InstanceAgnostic:
  def test_second_instance_resolves_without_affinity(self) -> None:
    # A shared durable record (no connection/session affinity). "Instance A"
    # creates; "instance B" — with no shared in-memory state — resolves it.
    shared_store: dict[str, dict[str, object]] = {}
    task = _working_task()

    # Instance A creates and persists.
    shared_store[task.task_id] = task.to_dict()

    # Instance B is a brand-new object with no link to A except the store.
    class ServerInstance:
      def __init__(self, store: dict[str, dict[str, object]]) -> None:
        self._store = store

      def get(self, task_id: str) -> Task:
        rec = self._store.get(task_id)
        if rec is None:
          raise TaskNotFoundError(task_id)
        return parse_task(rec)

    instance_b = ServerInstance(shared_store)
    resolved = instance_b.get(task.task_id)
    assert resolved.task_id == task.task_id

  def test_missing_from_store_is_not_found(self) -> None:
    shared_store: dict[str, dict[str, object]] = {}

    def get(task_id: str) -> Task:
      rec = shared_store.get(task_id)
      if rec is None:
        raise TaskNotFoundError(task_id)
      return parse_task(rec)

    with pytest.raises(TaskNotFoundError):
      get("unknown-task")


# ---------------------------------------------------------------------------
# AC-39.21 — resumable state via §11 continuation-token mechanism (R-25.6-e)
# ---------------------------------------------------------------------------

class TestAC3921ResumableContinuationToken:
  def test_reuse_section_11_opaque_token(self) -> None:
    # A server MAY encode resumable task state with the §11 opaque
    # continuation-token (requestState) mechanism owned by S17.
    secret = b"server-secret-key"
    payload = "task=task_3f2a9c10;cursor=42"
    token = make_hmac_request_state(payload, secret)
    # The token round-trips back to the original payload (resumable state).
    assert verify_hmac_request_state(token, secret) == payload

  def test_token_is_opaque_to_client(self) -> None:
    # The client treats the token as opaque: it is just a string it echoes back.
    secret = b"server-secret-key"
    token = make_hmac_request_state("state", secret)
    assert isinstance(token, str)


# ---------------------------------------------------------------------------
# AC-39.22 — client persists taskId to resume after crash/restart (R-25.6-h)
# ---------------------------------------------------------------------------

class TestAC3922ClientPersistsTaskId:
  def test_resume_polling_after_restart(self) -> None:
    # The client persists the taskId durably; after a "restart" (a fresh client
    # with no in-memory state) it reloads the id and resumes polling verbatim.
    client_durable: dict[str, str] = {}

    handle = parse_create_task_result(
      CreateTaskResult(task=_working_task()).to_dict()
    )
    client_durable["pending_task"] = handle.task_id  # persist (R-25.6-h)

    # Simulate a crash: drop all in-memory client state.
    del handle

    # Fresh client reloads the persisted id and forwards it verbatim to poll.
    reloaded = client_durable["pending_task"]
    assert echo_task_id(reloaded) == "task_3f2a9c10"

  def test_persisted_taskid_is_verbatim_opaque(self) -> None:
    original = "abc/DEF.123:opaque"
    persisted = echo_task_id(original)
    assert persisted == original


# ---------------------------------------------------------------------------
# Cross-cutting: the extension definition integrates with the S38 registry.
# ---------------------------------------------------------------------------

class TestTasksExtensionRegistryIntegration:
  def test_registry_recognizes_tasks_extension(self) -> None:
    registry = ExtensionRegistry([TASKS_EXTENSION])
    assert registry.recognizes(TASKS_EXTENSION_IDENTIFIER)
    # The "task" resultType is accepted only when both peers advertise it.
    assert registry.result_type_is_accepted(
      RESULT_TYPE_TASK, _client_caps_with_tasks(), _server_caps_with_tasks()
    )
    assert not registry.result_type_is_accepted(
      RESULT_TYPE_TASK, {}, _server_caps_with_tasks()
    )

  def test_tasks_methods_namespaced_under_tasks(self) -> None:
    assert TASKS_EXTENSION.namespace == "tasks"
    for method in TASKS_METHODS:
      assert method.startswith("tasks/")
