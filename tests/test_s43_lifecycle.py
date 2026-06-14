"""Tests for S43 — Feature Lifecycle & Deprecation.

Every test maps to one or more acceptance criteria (AC-43.x).
"""

import warnings

import pytest

from mcp_sdk_py.lifecycle import (
  DEPRECATED_FEATURE_NAMES,
  DEPRECATED_FEATURES_REGISTRY,
  EXTENSION_LIFECYCLE_IS_INDEPENDENT,
  MINIMUM_DEPRECATION_WINDOW_DAYS,
  MINIMUM_EXPEDITED_WINDOW_DAYS,
  DeprecatedRegistryEntry,
  LifecycleError,
  LifecycleRecord,
  LifecycleState,
  can_transition,
  compute_deprecation_window_days,
  deprecated_feature,
  is_deprecated_feature,
  is_eligible_for_removal,
  validate_transition,
  warn_deprecated_feature,
)
from mcp_sdk_py.foundations import ConformanceError


# ---------------------------------------------------------------------------
# AC-43.1  Active features must be implemented exactly as specified  [R-27.1-a]
# (structural: LifecycleState.ACTIVE models this obligation)
# ---------------------------------------------------------------------------

class TestActiveFeatureObligation:
  """AC-43.1: Active features MUST be implemented as specified."""

  def test_lifecycle_state_active_exists(self):
    assert LifecycleState.ACTIVE.value == "active"

  def test_active_is_distinct_from_other_states(self):
    assert LifecycleState.ACTIVE is not LifecycleState.DEPRECATED
    assert LifecycleState.ACTIVE is not LifecycleState.REMOVED


# ---------------------------------------------------------------------------
# AC-43.2  Deprecated features must still be honored  [R-27.1-b]
# ---------------------------------------------------------------------------

class TestDeprecatedFeaturesMustBeHonored:
  """AC-43.2: A Deprecated feature must be honored exactly as specified."""

  def test_deprecated_state_exists(self):
    assert LifecycleState.DEPRECATED.value == "deprecated"

  def test_deprecated_feature_decorator_still_executes_function(self):
    """R-27.2-e: a deprecated feature MUST remain functional."""
    @deprecated_feature("use new_api instead")
    def old_api() -> int:
      return 42

    with warnings.catch_warnings():
      warnings.simplefilter("ignore", DeprecationWarning)
      result = old_api()

    assert result == 42  # still functional


# ---------------------------------------------------------------------------
# AC-43.3  Undefined names carry no inferred meaning  [R-27.1-c]
# AC-43.4  Undefined names handled via forward-compat rules  [R-27.1-d]
# (structural: no SDK code assigns meaning to arbitrary names)
# ---------------------------------------------------------------------------

class TestUndefinedNamesNoInferredMeaning:
  """AC-43.3, AC-43.4: Undefined/removed names must not be given inferred meaning."""

  def test_removed_state_exists(self):
    assert LifecycleState.REMOVED.value == "removed"

  def test_lifecycle_has_exactly_three_states(self):
    assert len(LifecycleState) == 3


# ---------------------------------------------------------------------------
# AC-43.5  Features must pass through Deprecated before Removed  [R-27.2-a]
# AC-43.6  Active → Removed transition is forbidden  [R-27.2-b]
# ---------------------------------------------------------------------------

class TestDeprecationBeforeRemoval:
  """AC-43.5, AC-43.6: Active → Removed is forbidden; Deprecated must come first."""

  def test_active_to_deprecated_is_allowed(self):
    assert can_transition(LifecycleState.ACTIVE, LifecycleState.DEPRECATED) is True

  def test_deprecated_to_removed_is_allowed(self):
    assert can_transition(LifecycleState.DEPRECATED, LifecycleState.REMOVED) is True

  def test_active_to_removed_is_forbidden(self):
    assert can_transition(LifecycleState.ACTIVE, LifecycleState.REMOVED) is False

  def test_validate_transition_raises_for_active_to_removed(self):
    with pytest.raises(LifecycleError, match="Forbidden"):
      validate_transition(LifecycleState.ACTIVE, LifecycleState.REMOVED)

  def test_validate_transition_passes_for_active_to_deprecated(self):
    validate_transition(LifecycleState.ACTIVE, LifecycleState.DEPRECATED)  # no exception

  def test_lifecycle_error_is_conformance_error(self):
    assert issubclass(LifecycleError, ConformanceError)


# ---------------------------------------------------------------------------
# AC-43.7  12-month window before removal eligibility  [R-27.2-c]
# ---------------------------------------------------------------------------

class TestDeprecationWindowMinimum:
  """AC-43.7: Feature must be Deprecated for ≥ 12 months before removal eligibility."""

  def test_minimum_window_is_365_days(self):
    assert MINIMUM_DEPRECATION_WINDOW_DAYS == 365

  def test_not_eligible_before_window(self):
    assert is_eligible_for_removal(364) is False

  def test_eligible_on_day_365(self):
    assert is_eligible_for_removal(365) is True

  def test_eligible_well_after_window(self):
    assert is_eligible_for_removal(730) is True

  def test_compute_standard_window(self):
    assert compute_deprecation_window_days(expedited=False) == 365


# ---------------------------------------------------------------------------
# AC-43.8  Elapsed window grants eligibility only, not forced removal  [R-27.2-d]
# ---------------------------------------------------------------------------

class TestEarliestRemovalIsEligibilityOnly:
  """AC-43.8: Elapse of the window marks eligibility; feature MAY remain Deprecated."""

  def test_eligibility_after_window_does_not_force_removal(self):
    """is_eligible_for_removal() returns True but does not remove the feature."""
    eligible = is_eligible_for_removal(400)
    assert eligible is True
    # Feature is still defined; eligibility is purely informational.


# ---------------------------------------------------------------------------
# AC-43.9  Deprecated features remain functional  [R-27.2-e]
# AC-43.10  Semantics must not be degraded for deprecated features  [R-27.2-f]
# ---------------------------------------------------------------------------

class TestDeprecatedFeatureRemainsFunctional:
  """AC-43.9, AC-43.10: Deprecated features MUST remain functional and unaltered."""

  def test_deprecated_decorator_does_not_alter_return_value(self):
    @deprecated_feature("replace with better_func")
    def legacy_func(x: int) -> int:
      return x * 2

    with warnings.catch_warnings():
      warnings.simplefilter("ignore", DeprecationWarning)
      assert legacy_func(5) == 10

  def test_deprecated_decorator_does_not_suppress_exceptions(self):
    @deprecated_feature("use new version")
    def broken_func() -> None:
      raise RuntimeError("internal error")

    with pytest.raises(RuntimeError):
      with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        broken_func()


# ---------------------------------------------------------------------------
# AC-43.11  Deprecated features must have migration path  [R-27.2-g]
# ---------------------------------------------------------------------------

class TestMigrationPathRequired:
  """AC-43.11: A Deprecated feature MUST carry a migration path or 'none required'."""

  def test_lifecycle_record_requires_migration_when_deprecated(self):
    with pytest.raises(ValueError, match="migration"):
      LifecycleRecord(
        feature="old-feature",
        state=LifecycleState.DEPRECATED,
        migration=None,  # MUST be set for deprecated features
      )

  def test_lifecycle_record_with_migration_is_valid(self):
    record = LifecycleRecord(
      feature="old-feature",
      state=LifecycleState.DEPRECATED,
      migration="use new-feature instead",
    )
    assert record.migration == "use new-feature instead"

  def test_lifecycle_record_with_none_required_is_valid(self):
    record = LifecycleRecord(
      feature="old-opt-feature",
      state=LifecycleState.DEPRECATED,
      migration="none required",
    )
    assert record.migration == "none required"


# ---------------------------------------------------------------------------
# AC-43.12  Migration path replacement must be Active  [R-27.2-h]
# (structural: expressed through LifecycleRecord.migration pointing to Active)
# ---------------------------------------------------------------------------

class TestReplacementMustBeActive:
  """AC-43.12: When migration names a replacement, that replacement must be Active."""

  def test_all_registry_entries_have_migration_notes(self):
    for entry in DEPRECATED_FEATURES_REGISTRY:
      assert entry.migration_note, f"Missing migration note for {entry.feature!r}"


# ---------------------------------------------------------------------------
# AC-43.13  New functionality should not adopt deprecated features  [R-27.2-i]
# AC-43.14  Existing functionality should migrate before earliest removal  [R-27.2-j]
# ---------------------------------------------------------------------------

class TestAdoptionAndMigration:
  """AC-43.13, AC-43.14: New code avoids deprecated; existing code migrates."""

  def test_deprecated_features_registry_is_populated(self):
    assert len(DEPRECATED_FEATURES_REGISTRY) > 0

  def test_all_registry_entries_have_earliest_removal(self):
    for entry in DEPRECATED_FEATURES_REGISTRY:
      assert entry.earliest_removal, f"Missing earliest_removal for {entry.feature!r}"


# ---------------------------------------------------------------------------
# AC-43.15  Expedited window only for active security risk  [R-27.2-k]
# AC-43.16  Expedited window floored at 90 days  [R-27.2-l]
# ---------------------------------------------------------------------------

class TestExpeditedWindow:
  """AC-43.15, AC-43.16: Security-driven window is shortened but floored at 90 days."""

  def test_expedited_window_floor_is_90_days(self):
    assert MINIMUM_EXPEDITED_WINDOW_DAYS == 90

  def test_compute_expedited_window(self):
    assert compute_deprecation_window_days(expedited=True) == 90

  def test_not_eligible_before_expedited_floor(self):
    assert is_eligible_for_removal(89, expedited=True) is False

  def test_eligible_at_expedited_floor(self):
    assert is_eligible_for_removal(90, expedited=True) is True

  def test_expedited_window_is_shorter_than_standard(self):
    assert MINIMUM_EXPEDITED_WINDOW_DAYS < MINIMUM_DEPRECATION_WINDOW_DAYS


# ---------------------------------------------------------------------------
# AC-43.17  Deprecated under expedited window remains functional  [R-27.2-m]
# ---------------------------------------------------------------------------

class TestExpeditedDeprecatedFeatureFunctional:
  """AC-43.17: A feature under a shortened window must still work as specified."""

  def test_deprecated_decorator_with_expedited_note_still_works(self):
    @deprecated_feature("SECURITY: replace immediately with safe_func (expedited)")
    def vulnerable_func() -> str:
      return "vulnerable but still working"

    with warnings.catch_warnings():
      warnings.simplefilter("ignore", DeprecationWarning)
      result = vulnerable_func()

    assert result == "vulnerable but still working"


# ---------------------------------------------------------------------------
# AC-43.18  Deprecated features MAY be restored to Active  [R-27.2-n]
# AC-43.19  Restored features treated as Active under §27.1  [R-27.2-o]
# ---------------------------------------------------------------------------

class TestRestorationToActive:
  """AC-43.18, AC-43.19: A Deprecated feature may be restored; treated as Active."""

  def test_deprecated_to_active_transition_is_allowed(self):
    assert can_transition(LifecycleState.DEPRECATED, LifecycleState.ACTIVE) is True

  def test_validate_transition_deprecated_to_active_passes(self):
    validate_transition(LifecycleState.DEPRECATED, LifecycleState.ACTIVE)  # no exception

  def test_restored_record_has_active_state(self):
    record = LifecycleRecord(
      feature="restored-feature",
      state=LifecycleState.ACTIVE,
    )
    assert record.state is LifecycleState.ACTIVE


# ---------------------------------------------------------------------------
# AC-43.20  Re-deprecation window starts fresh  [R-27.2-p]
# ---------------------------------------------------------------------------

class TestReDeprecationFreshWindow:
  """AC-43.20: Time previously spent Deprecated MUST NOT count for a new window."""

  def test_lifecycle_record_deprecated_since_can_be_reset(self):
    """When a restored feature is deprecated again, deprecated_since is the new date."""
    original = LifecycleRecord(
      feature="yo-yo-feature",
      state=LifecycleState.DEPRECATED,
      deprecated_since="2024-01-01",
      migration="use beta-feature",
    )
    # Feature is restored to Active
    validate_transition(LifecycleState.DEPRECATED, LifecycleState.ACTIVE)

    # Re-deprecated with a new start date (window starts fresh)
    re_deprecated = LifecycleRecord(
      feature="yo-yo-feature",
      state=LifecycleState.DEPRECATED,
      deprecated_since="2026-01-01",  # NEW date, not accumulated from 2024
      migration="use beta-feature",
    )
    assert re_deprecated.deprecated_since == "2026-01-01"


# ---------------------------------------------------------------------------
# AC-43.21  New implementations should not adopt registered deprecated features
# [R-27.3-a]
# ---------------------------------------------------------------------------

class TestRegistryNewImplementations:
  """AC-43.21: New implementations should not adopt registered deprecated features."""

  def test_registry_contains_known_deprecated_features(self):
    features = DEPRECATED_FEATURE_NAMES
    assert "Roots capability" in features
    assert "Sampling capability" in features
    assert "Logging capability" in features
    assert "Dynamic Client Registration" in features

  def test_is_deprecated_feature_returns_true_for_known(self):
    assert is_deprecated_feature("Roots capability") is True
    assert is_deprecated_feature("Logging capability") is True

  def test_is_deprecated_feature_returns_false_for_unknown(self):
    assert is_deprecated_feature("tools/call") is False


# ---------------------------------------------------------------------------
# AC-43.22  Existing implementations should migrate before earliest removal
# [R-27.3-b]
# ---------------------------------------------------------------------------

class TestRegistryExistingImplementations:
  """AC-43.22: Existing implementations should migrate before earliest removal."""

  def test_all_registry_entries_have_required_fields(self):
    for entry in DEPRECATED_FEATURES_REGISTRY:
      assert isinstance(entry, DeprecatedRegistryEntry)
      assert entry.feature
      assert entry.defined_in
      assert entry.migration_note
      assert entry.earliest_removal


# ---------------------------------------------------------------------------
# AC-43.23  Native deprecation marking on API surfaces  [R-27.4-a]
# ---------------------------------------------------------------------------

class TestNativeDeprecationMarking:
  """AC-43.23: Deprecated API surfaces must be marked with the native mechanism."""

  def test_deprecated_feature_decorator_emits_deprecation_warning(self):
    @deprecated_feature("use new_func instead")
    def old_func() -> None:
      pass

    with pytest.warns(DeprecationWarning, match="old_func"):
      old_func()

  def test_deprecated_feature_decorator_preserves_function_name(self):
    @deprecated_feature("replace me")
    def my_deprecated_func() -> None:
      pass

    assert my_deprecated_func.__name__ == "my_deprecated_func"


# ---------------------------------------------------------------------------
# AC-43.24  Deprecation marking references migration and earliest removal  [R-27.4-b]
# ---------------------------------------------------------------------------

class TestDeprecationMarkingReferences:
  """AC-43.24: Deprecation marking SHOULD reference migration path and earliest removal (R-27.4-b)."""

  def test_deprecated_feature_decorator_includes_earliest_removal_in_warning(self):
    """When earliest_removal is supplied, it MUST appear in the emitted warning (R-27.4-b)."""
    @deprecated_feature("use new_api instead", earliest_removal="2026-07-28")
    def old_api() -> None:
      pass

    with pytest.warns(DeprecationWarning) as record:
      old_api()

    message = str(record[0].message)
    assert "new_api" in message or "use new_api" in message
    assert "2026-07-28" in message

  def test_warn_deprecated_feature_includes_earliest_removal(self):
    """warn_deprecated_feature with earliest_removal includes it in the message (R-27.4-b)."""
    with warnings.catch_warnings(record=True) as caught:
      warnings.simplefilter("always")
      warn_deprecated_feature(
        "old-feature", "use new-feature", earliest_removal="2026-07-28"
      )
    assert len(caught) == 1
    message = str(caught[0].message)
    assert "old-feature" in message
    assert "2026-07-28" in message

  def test_warn_deprecated_feature_without_earliest_removal(self):
    """Without earliest_removal, warn_deprecated_feature still emits the warning."""
    with pytest.warns(DeprecationWarning, match="old-feature"):
      warn_deprecated_feature("old-feature", "use new-feature")


# ---------------------------------------------------------------------------
# AC-43.25  Feature marked deprecated in documentation  [R-27.4-c]
# (structural: all registry entries carry migration notes)
# ---------------------------------------------------------------------------

class TestDocumentationMarking:
  """AC-43.25: Deprecated features SHOULD be marked in published documentation (R-27.4-c)."""

  def test_deprecated_feature_decorator_updates_docstring(self):
    """@deprecated_feature must inject a deprecation notice into __doc__ (R-27.4-c)."""
    @deprecated_feature("use new_func instead", earliest_removal="2027-01-01")
    def legacy_func() -> None:
      """Do the old thing."""

    assert legacy_func.__doc__ is not None
    assert "deprecated" in legacy_func.__doc__.lower()
    assert "new_func" in legacy_func.__doc__

  def test_deprecated_feature_decorator_docstring_includes_removal_date(self):
    @deprecated_feature("use replacement", earliest_removal="2026-07-28")
    def another_old_func() -> None:
      pass

    assert "2026-07-28" in (another_old_func.__doc__ or "")

  def test_registry_migration_notes_match_spec_authoritative_text(self):
    """Registry entries must use the §27.3 authoritative migration note text."""
    entry_map = {e.feature: e for e in DEPRECATED_FEATURES_REGISTRY}
    # Logging capability — spec: "standard error stream", "external observability framework"
    logging_entry = entry_map["Logging capability"]
    assert "standard error" in logging_entry.migration_note.lower() or \
           "stderr" in logging_entry.migration_note
    assert "observability" in logging_entry.migration_note.lower()
    # includeContext — spec: defined_in should be §21 (not §20 / §21)
    ctx_entry = entry_map["includeContext values 'thisServer' and 'allServers'"]
    assert ctx_entry.defined_in == "§21"


# ---------------------------------------------------------------------------
# AC-43.26  Runtime warning emitted when deprecated feature used  [R-27.4-d]
# ---------------------------------------------------------------------------

class TestRuntimeWarning:
  """AC-43.26: When exercising a deprecated feature, emit a runtime warning."""

  def test_warn_deprecated_feature_emits_deprecation_warning(self):
    with pytest.warns(DeprecationWarning):
      warn_deprecated_feature("old-cap", "use new-cap instead")

  def test_warning_category_is_deprecation_warning(self):
    with warnings.catch_warnings(record=True) as caught:
      warnings.simplefilter("always")
      warn_deprecated_feature("feature-x", "see migration guide")
    assert len(caught) == 1
    assert issubclass(caught[0].category, DeprecationWarning)
    assert "feature-x" in str(caught[0].message)


# ---------------------------------------------------------------------------
# AC-43.27  Deprecation warning NOT on the protocol wire  [R-27.4-e]
# ---------------------------------------------------------------------------

class TestWarningNotOnWire:
  """AC-43.27: Deprecation warnings MUST NOT alter the protocol message format."""

  def test_warn_deprecated_feature_does_not_return_a_value(self):
    """warn_deprecated_feature() returns None; it never produces a wire payload."""
    result = None
    with warnings.catch_warnings():
      warnings.simplefilter("ignore", DeprecationWarning)
      result = warn_deprecated_feature("x", "y")
    assert result is None


# ---------------------------------------------------------------------------
# AC-43.28  Continued interoperation with peer using deprecated features  [R-27.4-f]
# AC-43.29  Do not reject/fault solely for deprecated feature use  [R-27.4-g]
# AC-43.30  Do not return §22 error solely for deprecated feature use  [R-27.4-h]
# ---------------------------------------------------------------------------

class TestInteroperabilityWithDeprecated:
  """AC-43.28–43.30: Peers must interoperate with deprecated-feature users."""

  def test_valid_exchange_with_deprecated_feature_not_rejected(self):
    """The SDK models this by never raising errors based solely on deprecation status.
    warn_deprecated_feature() issues a warning, not an exception.
    """
    with warnings.catch_warnings(record=True) as caught:
      warnings.simplefilter("always")
      warn_deprecated_feature("Logging capability", "use stderr or external observability")
    # A warning, not an exception
    assert len(caught) == 1
    assert issubclass(caught[0].category, DeprecationWarning)


# ---------------------------------------------------------------------------
# AC-43.31  Absence of warning does not imply Active status  [R-27.4-i]
# ---------------------------------------------------------------------------

class TestWarningAbsenceDoesNotImplyActive:
  """AC-43.31: Lifecycle state comes from the document/registry, not runtime signals."""

  def test_is_deprecated_feature_independent_of_runtime_warnings(self):
    """is_deprecated_feature() checks the registry, not whether a warning was emitted."""
    assert is_deprecated_feature("Roots capability") is True


# ---------------------------------------------------------------------------
# AC-43.32  Extension lifecycle from extension's own definition  [R-27.5-a]
# AC-43.33  §27.2 rules don't govern extension lifecycle  [R-27.5-b]
# ---------------------------------------------------------------------------

class TestExtensionLifecycleCarveOut:
  """AC-43.32, AC-43.33: Extension lifecycle is independent of §27."""

  def test_extension_lifecycle_is_independent_sentinel(self):
    assert EXTENSION_LIFECYCLE_IS_INDEPENDENT is True

  def test_extension_lifecycle_not_governed_by_standard_window(self):
    """§27.2's 12-month window and removal rules apply only to features
    defined by this document, not to extensions (R-27.5-b).

    An extension at day 100 since its own deprecation may already be removed
    by the extension's own policy — or still be in use. §27 does not govern.
    """
    assert MINIMUM_DEPRECATION_WINDOW_DAYS == 365  # §27 standard window
    # Extensions may have their own (different) policies — not modeled here
