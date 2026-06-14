"""Tests for S22 — Progress & Cancellation.

Coverage map (26 ACs):
  AC-22.1  → TestProgressMethodNames
  AC-22.2  → TestProgressNotificationParams
  AC-22.3  → TestProgressTokenValidation
  AC-22.4  → TestProgressTotalOptional
  AC-22.5  → TestProgressMessageOptional
  AC-22.6  → TestProgressTrackerRegistration
  AC-22.7  → TestProgressTrackerDuplicateToken
  AC-22.8  → TestProgressTrackerEmitValid
  AC-22.9  → TestProgressTrackerStrictlyIncreasing
  AC-22.10 → TestProgressTrackerUnregisteredToken
  AC-22.11 → TestProgressTrackerCompleteState
  AC-22.12 → TestProgressTrackerActiveTokens
  AC-22.13 → TestProgressTrackerUnregister
  AC-22.14 → TestProgressToDict
  AC-22.15 → TestCancelledNotificationParams
  AC-22.16 → TestCancelledRequestIdTypes
  AC-22.17 → TestCancelledBoolRejected
  AC-22.18 → TestCancelledReasonOptional
  AC-22.19 → TestCancelledToDict
  AC-22.20 → TestIsCancellableMethod
  AC-22.21 → TestDiscoverNotCancellable
  AC-22.22 → TestProgressValidationErrors
  AC-22.23 → TestCancelledValidationErrors
  AC-22.24 → TestProgressNumberTypes
  AC-22.25 → TestProgressTrackerReRegisterAfterComplete
  AC-22.26 → TestProgressTokenStringAndNumeric
"""

import pytest

from mcp_sdk_py.progress import (
  CANCELLED_NOTIFICATION_METHOD,
  DISCOVER_METHOD,
  PROGRESS_NOTIFICATION_METHOD,
  CancelledNotificationParams,
  ProgressNotificationParams,
  ProgressTracker,
  is_cancellable_method,
  validate_cancelled_notification_params,
  validate_progress_notification_params,
)


# ---------------------------------------------------------------------------
# AC-22.1 — Method name constants  (§15.1 §15.2)
# ---------------------------------------------------------------------------

class TestProgressMethodNames:
  def test_progress_method_name(self):
    assert PROGRESS_NOTIFICATION_METHOD == "notifications/progress"

  def test_cancelled_method_name(self):
    assert CANCELLED_NOTIFICATION_METHOD == "notifications/cancelled"

  def test_discover_method_name(self):
    assert DISCOVER_METHOD == "server/discover"


# ---------------------------------------------------------------------------
# AC-22.2 — ProgressNotificationParams: token and progress required  (R-15.1.3-a/d)
# ---------------------------------------------------------------------------

class TestProgressNotificationParams:
  def test_minimal_valid(self):
    p = validate_progress_notification_params({
      "progressToken": "tok-1",
      "progress": 50,
    })
    assert p.progress_token == "tok-1"
    assert p.progress == 50

  def test_missing_progress_token_raises(self):
    with pytest.raises(ValueError, match="progressToken"):
      validate_progress_notification_params({"progress": 10})

  def test_missing_progress_raises(self):
    with pytest.raises(ValueError, match="progress"):
      validate_progress_notification_params({"progressToken": "tok"})

  def test_not_a_dict_raises(self):
    with pytest.raises(TypeError):
      validate_progress_notification_params([1, 2, 3])


# ---------------------------------------------------------------------------
# AC-22.3 — progressToken must be str or number, not bool  (§3.7)
# ---------------------------------------------------------------------------

class TestProgressTokenValidation:
  def test_string_token_valid(self):
    p = validate_progress_notification_params({"progressToken": "my-op", "progress": 1})
    assert p.progress_token == "my-op"

  def test_integer_token_valid(self):
    p = validate_progress_notification_params({"progressToken": 42, "progress": 1})
    assert p.progress_token == 42

  def test_bool_token_rejected(self):
    with pytest.raises(TypeError):
      validate_progress_notification_params({"progressToken": True, "progress": 1})

  def test_none_token_rejected(self):
    with pytest.raises(TypeError):
      validate_progress_notification_params({"progressToken": None, "progress": 1})


# ---------------------------------------------------------------------------
# AC-22.4 — total is optional  (R-15.1.3-g/h)
# ---------------------------------------------------------------------------

class TestProgressTotalOptional:
  def test_total_accepted_when_present(self):
    p = validate_progress_notification_params({
      "progressToken": "t",
      "progress": 30,
      "total": 100,
    })
    assert p.total == 100

  def test_total_none_when_absent(self):
    p = validate_progress_notification_params({"progressToken": "t", "progress": 5})
    assert p.total is None

  def test_total_must_be_number(self):
    with pytest.raises(TypeError):
      validate_progress_notification_params({
        "progressToken": "t",
        "progress": 1,
        "total": "100",
      })

  def test_total_bool_rejected(self):
    with pytest.raises(TypeError):
      validate_progress_notification_params({
        "progressToken": "t",
        "progress": 1,
        "total": True,
      })


# ---------------------------------------------------------------------------
# AC-22.5 — message is optional  (R-15.1.3-j/k)
# ---------------------------------------------------------------------------

class TestProgressMessageOptional:
  def test_message_accepted(self):
    p = validate_progress_notification_params({
      "progressToken": "t",
      "progress": 10,
      "message": "Loading…",
    })
    assert p.message == "Loading…"

  def test_message_none_when_absent(self):
    p = validate_progress_notification_params({"progressToken": "t", "progress": 10})
    assert p.message is None

  def test_message_must_be_string(self):
    with pytest.raises(TypeError):
      validate_progress_notification_params({
        "progressToken": "t",
        "progress": 10,
        "message": 42,
      })


# ---------------------------------------------------------------------------
# AC-22.6 — ProgressTracker.register()  (R-15.1.1-c)
# ---------------------------------------------------------------------------

class TestProgressTrackerRegistration:
  def test_register_token(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    assert tracker.is_active("tok")

  def test_registered_token_in_active_tokens(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    assert "tok" in tracker.active_tokens

  def test_unregistered_token_not_active(self):
    tracker = ProgressTracker()
    assert not tracker.is_active("tok")


# ---------------------------------------------------------------------------
# AC-22.7 — Duplicate registration raises  (R-15.1.1-c)
# ---------------------------------------------------------------------------

class TestProgressTrackerDuplicateToken:
  def test_duplicate_registration_raises(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    with pytest.raises(ValueError, match="already active"):
      tracker.register("tok")

  def test_two_different_tokens_allowed(self):
    tracker = ProgressTracker()
    tracker.register("a")
    tracker.register("b")
    assert tracker.is_active("a")
    assert tracker.is_active("b")


# ---------------------------------------------------------------------------
# AC-22.8 — ProgressTracker.emit() with valid increasing values  (R-15.1.3-d/e)
# ---------------------------------------------------------------------------

class TestProgressTrackerEmitValid:
  def test_first_emit_succeeds(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    tracker.emit("tok", 10)

  def test_increasing_emit_succeeds(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    tracker.emit("tok", 10)
    tracker.emit("tok", 20)
    tracker.emit("tok", 100)


# ---------------------------------------------------------------------------
# AC-22.9 — Emit must strictly increase  (R-15.1.3-e)
# ---------------------------------------------------------------------------

class TestProgressTrackerStrictlyIncreasing:
  def test_same_value_raises(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    tracker.emit("tok", 50)
    with pytest.raises(ValueError, match="strictly increase"):
      tracker.emit("tok", 50)

  def test_lower_value_raises(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    tracker.emit("tok", 80)
    with pytest.raises(ValueError, match="strictly increase"):
      tracker.emit("tok", 79)


# ---------------------------------------------------------------------------
# AC-22.10 — Emit on unregistered token raises  (R-15.1.3-b/c)
# ---------------------------------------------------------------------------

class TestProgressTrackerUnregisteredToken:
  def test_emit_unregistered_raises(self):
    tracker = ProgressTracker()
    with pytest.raises(ValueError, match="not registered"):
      tracker.emit("unknown", 1)


# ---------------------------------------------------------------------------
# AC-22.11 — complete() marks terminal state; emit() raises after  (R-15.1.4-g)
# ---------------------------------------------------------------------------

class TestProgressTrackerCompleteState:
  def test_complete_prevents_further_emit(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    tracker.emit("tok", 50)
    tracker.complete("tok")
    with pytest.raises(ValueError, match="terminal"):
      tracker.emit("tok", 51)

  def test_is_active_false_after_complete(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    tracker.complete("tok")
    assert not tracker.is_active("tok")

  def test_complete_on_unregistered_raises(self):
    tracker = ProgressTracker()
    with pytest.raises(ValueError):
      tracker.complete("nope")


# ---------------------------------------------------------------------------
# AC-22.12 — active_tokens property  (R-15.1.4-e)
# ---------------------------------------------------------------------------

class TestProgressTrackerActiveTokens:
  def test_active_tokens_empty_initially(self):
    tracker = ProgressTracker()
    assert tracker.active_tokens == frozenset()

  def test_active_tokens_after_register(self):
    tracker = ProgressTracker()
    tracker.register("a")
    tracker.register("b")
    assert tracker.active_tokens == frozenset({"a", "b"})

  def test_completed_token_not_in_active(self):
    tracker = ProgressTracker()
    tracker.register("a")
    tracker.register("b")
    tracker.complete("a")
    assert tracker.active_tokens == frozenset({"b"})


# ---------------------------------------------------------------------------
# AC-22.13 — unregister() removes token  (§15.1)
# ---------------------------------------------------------------------------

class TestProgressTrackerUnregister:
  def test_unregister_removes_from_active(self):
    tracker = ProgressTracker()
    tracker.register("tok")
    tracker.unregister("tok")
    assert not tracker.is_active("tok")
    assert "tok" not in tracker.active_tokens

  def test_unregister_nonexistent_is_noop(self):
    tracker = ProgressTracker()
    tracker.unregister("ghost")  # should not raise


# ---------------------------------------------------------------------------
# AC-22.14 — ProgressNotificationParams.to_dict()  (§15.1.3)
# ---------------------------------------------------------------------------

class TestProgressToDict:
  def test_minimal_serialization(self):
    p = ProgressNotificationParams(progress_token="tok", progress=42)
    d = p.to_dict()
    assert d == {"progressToken": "tok", "progress": 42}

  def test_full_serialization(self):
    p = ProgressNotificationParams(
      progress_token="tok",
      progress=50,
      total=100,
      message="Half done",
      meta={"trace": "x"},
    )
    d = p.to_dict()
    assert d["progressToken"] == "tok"
    assert d["progress"] == 50
    assert d["total"] == 100
    assert d["message"] == "Half done"
    assert d["_meta"] == {"trace": "x"}

  def test_absent_optionals_not_in_dict(self):
    p = ProgressNotificationParams(progress_token="tok", progress=1)
    d = p.to_dict()
    assert "total" not in d
    assert "message" not in d
    assert "_meta" not in d


# ---------------------------------------------------------------------------
# AC-22.15 — CancelledNotificationParams: requestId required  (R-15.2.1-a)
# ---------------------------------------------------------------------------

class TestCancelledNotificationParams:
  def test_minimal_valid(self):
    p = validate_cancelled_notification_params({"requestId": "req-42"})
    assert p.request_id == "req-42"

  def test_missing_request_id_raises(self):
    with pytest.raises(ValueError, match="requestId"):
      validate_cancelled_notification_params({})

  def test_not_a_dict_raises(self):
    with pytest.raises(TypeError):
      validate_cancelled_notification_params("nope")


# ---------------------------------------------------------------------------
# AC-22.16 — requestId: string or integer only  (R-15.2.1-a)
# ---------------------------------------------------------------------------

class TestCancelledRequestIdTypes:
  def test_string_request_id(self):
    p = validate_cancelled_notification_params({"requestId": "abc"})
    assert p.request_id == "abc"

  def test_integer_request_id(self):
    p = validate_cancelled_notification_params({"requestId": 7})
    assert p.request_id == 7

  def test_float_request_id_rejected(self):
    with pytest.raises(TypeError):
      validate_cancelled_notification_params({"requestId": 1.5})

  def test_none_request_id_rejected(self):
    with pytest.raises(TypeError):
      validate_cancelled_notification_params({"requestId": None})


# ---------------------------------------------------------------------------
# AC-22.17 — bool requestId rejected  (§3.7 JSON-RPC id)
# ---------------------------------------------------------------------------

class TestCancelledBoolRejected:
  def test_true_rejected(self):
    with pytest.raises(TypeError):
      validate_cancelled_notification_params({"requestId": True})

  def test_false_rejected(self):
    with pytest.raises(TypeError):
      validate_cancelled_notification_params({"requestId": False})


# ---------------------------------------------------------------------------
# AC-22.18 — reason is optional string  (R-15.2.1-c/d)
# ---------------------------------------------------------------------------

class TestCancelledReasonOptional:
  def test_reason_present(self):
    p = validate_cancelled_notification_params({
      "requestId": "x",
      "reason": "user requested",
    })
    assert p.reason == "user requested"

  def test_reason_absent_is_none(self):
    p = validate_cancelled_notification_params({"requestId": "x"})
    assert p.reason is None

  def test_reason_must_be_string(self):
    with pytest.raises(TypeError):
      validate_cancelled_notification_params({"requestId": "x", "reason": 99})


# ---------------------------------------------------------------------------
# AC-22.19 — CancelledNotificationParams.to_dict()  (§15.2.1)
# ---------------------------------------------------------------------------

class TestCancelledToDict:
  def test_minimal_serialization(self):
    p = CancelledNotificationParams(request_id="req-1")
    assert p.to_dict() == {"requestId": "req-1"}

  def test_full_serialization(self):
    p = CancelledNotificationParams(
      request_id=42,
      reason="timeout",
      meta={"x": "y"},
    )
    d = p.to_dict()
    assert d["requestId"] == 42
    assert d["reason"] == "timeout"
    assert d["_meta"] == {"x": "y"}

  def test_absent_optionals_not_in_dict(self):
    p = CancelledNotificationParams(request_id="r")
    d = p.to_dict()
    assert "reason" not in d
    assert "_meta" not in d


# ---------------------------------------------------------------------------
# AC-22.20 — is_cancellable_method: standard methods are cancellable  (R-15.2.2-b)
# ---------------------------------------------------------------------------

class TestIsCancellableMethod:
  def test_tools_call_is_cancellable(self):
    assert is_cancellable_method("tools/call")

  def test_any_other_method_is_cancellable(self):
    assert is_cancellable_method("resources/read")
    assert is_cancellable_method("prompts/get")
    assert is_cancellable_method("custom/method")


# ---------------------------------------------------------------------------
# AC-22.21 — server/discover MUST NOT be cancelled  (R-15.2.2-b)
# ---------------------------------------------------------------------------

class TestDiscoverNotCancellable:
  def test_discover_not_cancellable(self):
    assert not is_cancellable_method(DISCOVER_METHOD)

  def test_discover_method_constant(self):
    assert DISCOVER_METHOD == "server/discover"


# ---------------------------------------------------------------------------
# AC-22.22 — progress validation errors
# ---------------------------------------------------------------------------

class TestProgressValidationErrors:
  def test_progress_bool_rejected(self):
    with pytest.raises(TypeError):
      validate_progress_notification_params({
        "progressToken": "t",
        "progress": True,
      })

  def test_progress_string_rejected(self):
    with pytest.raises(TypeError):
      validate_progress_notification_params({
        "progressToken": "t",
        "progress": "50%",
      })

  def test_meta_must_be_object(self):
    with pytest.raises(TypeError):
      validate_progress_notification_params({
        "progressToken": "t",
        "progress": 1,
        "_meta": "not-a-dict",
      })


# ---------------------------------------------------------------------------
# AC-22.23 — cancelled validation errors
# ---------------------------------------------------------------------------

class TestCancelledValidationErrors:
  def test_meta_must_be_object(self):
    with pytest.raises(TypeError):
      validate_cancelled_notification_params({
        "requestId": "x",
        "_meta": ["not", "a", "dict"],
      })


# ---------------------------------------------------------------------------
# AC-22.24 — progress and total accept float  (§15.1.3)
# ---------------------------------------------------------------------------

class TestProgressNumberTypes:
  def test_float_progress_accepted(self):
    p = validate_progress_notification_params({
      "progressToken": "t",
      "progress": 0.5,
      "total": 1.0,
    })
    assert p.progress == 0.5
    assert p.total == 1.0

  def test_zero_progress_accepted(self):
    p = validate_progress_notification_params({
      "progressToken": "t",
      "progress": 0,
    })
    assert p.progress == 0


# ---------------------------------------------------------------------------
# AC-22.25 — re-register after complete is allowed  (R-15.1.1-c)
# ---------------------------------------------------------------------------

class TestProgressTrackerReRegisterAfterComplete:
  def test_can_reregister_after_complete(self):
    """A token can be reused after the previous operation completes."""
    tracker = ProgressTracker()
    tracker.register("tok")
    tracker.complete("tok")
    # Now re-register the same token for a new operation.
    tracker.register("tok")
    assert tracker.is_active("tok")


# ---------------------------------------------------------------------------
# AC-22.26 — ProgressToken: string and numeric  (§3.7)
# ---------------------------------------------------------------------------

class TestProgressTokenStringAndNumeric:
  def test_string_token_in_tracker(self):
    tracker = ProgressTracker()
    tracker.register("str-token")
    tracker.emit("str-token", 10)
    assert tracker.is_active("str-token")

  def test_integer_token_in_tracker(self):
    tracker = ProgressTracker()
    tracker.register(99)
    tracker.emit(99, 5)
    assert tracker.is_active(99)

  def test_float_token_in_tracker(self):
    tracker = ProgressTracker()
    tracker.register(1.5)
    tracker.emit(1.5, 10)
    assert tracker.is_active(1.5)
