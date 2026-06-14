"""Feature Lifecycle & Deprecation — S43.

Delivers the three-state lifecycle model (Active / Deprecated / Removed),
the 12-month deprecation window policy, the derived registry of currently-
deprecated features, native-language deprecation marking helpers, and the
runtime-warning mechanism that keeps deprecation signals out of the wire.

Spec: §27
"""

from __future__ import annotations

import enum
import functools
import warnings
from dataclasses import dataclass
from typing import Any, Callable, TypeVar

from mcp_sdk_py.foundations import ConformanceError


# ---------------------------------------------------------------------------
# §27.1  Lifecycle state model  [R-27.1-a–d]
# ---------------------------------------------------------------------------

class LifecycleState(enum.Enum):
  """The three states any governed protocol feature may occupy (§27.1).

  ACTIVE:
    Fully supported; MUST be implemented exactly as specified, subject to
    capability negotiation (§6) (R-27.1-a).

  DEPRECATED:
    Still defined and fully functional, but discouraged for new use.
    Receivers MUST continue to honor it exactly as specified (R-27.1-b).
    New implementations SHOULD NOT adopt it (R-27.2-i).

  REMOVED:
    Not defined by the document; carries no normative meaning.
    Implementations MUST NOT infer meaning for Removed names/codes/keys/
    methods; they MUST apply forward-compatibility and error-handling rules
    instead (R-27.1-c, R-27.1-d).
  """

  ACTIVE = "active"
  DEPRECATED = "deprecated"
  REMOVED = "removed"


# ---------------------------------------------------------------------------
# §27.2  Deprecation policy constants  [R-27.2-c, R-27.2-l]
# ---------------------------------------------------------------------------

#: Minimum days a feature MUST remain Deprecated before removal (R-27.2-c).
MINIMUM_DEPRECATION_WINDOW_DAYS: int = 365   # twelve months

#: Floor for a security-driven shortened window (R-27.2-l).
MINIMUM_EXPEDITED_WINDOW_DAYS: int = 90


def compute_deprecation_window_days(expedited: bool = False) -> int:
  """Return the minimum window in days for a given deprecation mode (R-27.2-c, l)."""
  return MINIMUM_EXPEDITED_WINDOW_DAYS if expedited else MINIMUM_DEPRECATION_WINDOW_DAYS


def is_eligible_for_removal(days_deprecated: int, expedited: bool = False) -> bool:
  """Return True when the deprecation window has elapsed (R-27.2-c, R-27.2-d).

  Elapse of the window grants eligibility only — a feature MAY stay Deprecated
  indefinitely (R-27.2-d).
  """
  return days_deprecated >= compute_deprecation_window_days(expedited)


# ---------------------------------------------------------------------------
# §27.2  Lifecycle transitions  [R-27.2-a, R-27.2-b, R-27.2-n, R-27.2-o]
# ---------------------------------------------------------------------------

class LifecycleError(ConformanceError):
  """Raised for a forbidden lifecycle-state transition (R-27.2-b)."""


#: State transitions that are explicitly FORBIDDEN by the spec.
#: ACTIVE → REMOVED must not happen; DEPRECATED must come first (R-27.2-b).
_FORBIDDEN_TRANSITIONS: frozenset[tuple[LifecycleState, LifecycleState]] = frozenset({
  (LifecycleState.ACTIVE, LifecycleState.REMOVED),
})


def can_transition(
  from_state: LifecycleState,
  to_state: LifecycleState,
) -> bool:
  """Return True if the state transition is permitted (R-27.2-a, R-27.2-b)."""
  return (from_state, to_state) not in _FORBIDDEN_TRANSITIONS


def validate_transition(
  from_state: LifecycleState,
  to_state: LifecycleState,
) -> None:
  """Raise LifecycleError for a forbidden transition (R-27.2-b)."""
  if not can_transition(from_state, to_state):
    raise LifecycleError(
      f"Forbidden lifecycle transition: {from_state.value!r} → {to_state.value!r}. "
      f"A feature MUST pass through Deprecated before it becomes Removed (R-27.2-a, R-27.2-b)."
    )


# ---------------------------------------------------------------------------
# §27.1 / §27.2  LifecycleRecord  (conceptual bookkeeping type)
# ---------------------------------------------------------------------------

@dataclass
class LifecycleRecord:
  """Lifecycle bookkeeping for a single protocol feature (§27.1, §27.2).

  This is an organisational record, not a wire-level message.  SDK consumers
  MAY use it to track the lifecycle state of features they implement.

  Note on re-deprecation (R-27.2-p): when a restored-Active feature is
  deprecated again, ``deprecated_since`` MUST be reset to the NEW date; time
  previously spent Deprecated MUST NOT be counted toward the new window.
  """

  feature: str
  state: LifecycleState
  deprecated_since: str | None = None     # ISO-date or revision string
  earliest_removal: str | None = None     # protocol-revision string
  migration: str | None = None            # replacement feature or "none required"
  expedited: bool = False                 # security-driven shortened window

  def __post_init__(self) -> None:
    if self.state is LifecycleState.DEPRECATED:
      if self.migration is None:
        raise ValueError(
          f"Deprecated feature {self.feature!r} MUST have a migration path "
          f"or explicit 'none required' statement (R-27.2-g)"
        )


# ---------------------------------------------------------------------------
# §27.3  Registry of deprecated features  [R-27.3-a, R-27.3-b]
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeprecatedRegistryEntry:
  """One row of the derived registry of deprecated features (§27.3)."""

  feature: str
  defined_in: str      # section reference
  migration_note: str
  earliest_removal: str  # revision on or after which removal is eligible


#: Derived registry of currently-deprecated protocol features (§27.3).
#: New implementations SHOULD NOT adopt any of these (R-27.3-a).
#: Existing implementations SHOULD migrate before each feature's earliest
#: removal (R-27.3-b).
#: The per-feature deprecation notices at the cross-referenced sections are
#: authoritative; this registry is a consolidated derived view.
DEPRECATED_FEATURES_REGISTRY: tuple[DeprecatedRegistryEntry, ...] = (
  DeprecatedRegistryEntry(
    feature="Roots capability",
    defined_in="§21",
    migration_note=(
      "Roots is deprecated; use resource subscriptions or "
      "explicit resource URIs supplied by the host."
    ),
    earliest_removal="2026-07-28",
  ),
  DeprecatedRegistryEntry(
    feature="Sampling capability",
    defined_in="§21",
    migration_note=(
      "Sampling is deprecated; use elicitation (§20) for "
      "structured client-to-host input requests."
    ),
    earliest_removal="2026-07-28",
  ),
  DeprecatedRegistryEntry(
    feature="includeContext values 'thisServer' and 'allServers'",
    defined_in="§20 / §21",
    migration_note=(
      "The 'thisServer' and 'allServers' includeContext values are deprecated; "
      "omit includeContext or use 'none'."
    ),
    earliest_removal="2026-07-28",
  ),
  DeprecatedRegistryEntry(
    feature="Logging capability",
    defined_in="§15",
    migration_note=(
      "For stdio (§8), write diagnostics to stderr; for general observability "
      "emit telemetry via an external observability framework."
    ),
    earliest_removal="2026-07-28",
  ),
  DeprecatedRegistryEntry(
    feature="io.modelcontextprotocol/logLevel _meta key",
    defined_in="§15",
    migration_note=(
      "The io.modelcontextprotocol/logLevel _meta key is deprecated alongside "
      "the Logging capability; use out-of-band log configuration instead."
    ),
    earliest_removal="2026-07-28",
  ),
  DeprecatedRegistryEntry(
    feature="Dynamic Client Registration",
    defined_in="§23",
    migration_note=(
      "Dynamic Client Registration (OAuth 2.0 RFC 7591) is deprecated; "
      "register clients statically with the authorization server."
    ),
    earliest_removal="2026-07-28",
  ),
)

#: Set of deprecated feature names for fast membership checks.
DEPRECATED_FEATURE_NAMES: frozenset[str] = frozenset(
  e.feature for e in DEPRECATED_FEATURES_REGISTRY
)


def is_deprecated_feature(feature_name: str) -> bool:
  """Return True if feature_name appears in the §27.3 registry."""
  return feature_name in DEPRECATED_FEATURE_NAMES


# ---------------------------------------------------------------------------
# §27.4  Signaling deprecation  [R-27.4-a–i]
# ---------------------------------------------------------------------------

def warn_deprecated_feature(feature_name: str, migration_info: str) -> None:
  """Emit a runtime DeprecationWarning for feature_name (R-27.4-d).

  The warning is emitted through Python's ``warnings`` module — it never
  appears on the protocol wire and never alters the message format or
  response semantics (R-27.4-e).
  """
  warnings.warn(
    f"Deprecated MCP feature {feature_name!r}: {migration_info}",
    DeprecationWarning,
    stacklevel=2,
  )


_F = TypeVar("_F", bound=Callable[..., Any])


def deprecated_feature(migration_info: str) -> Callable[[_F], _F]:
  """Decorator: wrap a callable to emit a DeprecationWarning on every call (R-27.4-a, d).

  Satisfies the native-language deprecation-marking requirement (R-27.4-a) for
  Python API surfaces that expose a deprecated feature.  The decorated callable
  remains fully functional (R-27.2-e, R-27.2-f).
  """
  def decorator(func: _F) -> _F:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
      warnings.warn(
        f"Deprecated MCP feature {func.__name__!r}: {migration_info}",
        DeprecationWarning,
        stacklevel=2,
      )
      return func(*args, **kwargs)
    return wrapper  # type: ignore[return-value]
  return decorator


# ---------------------------------------------------------------------------
# §27.5  Extension lifecycle carve-out  [R-27.5-a, R-27.5-b]
# ---------------------------------------------------------------------------

#: Sentinel that makes R-27.5 explicit in code: extension lifecycle is NOT
#: governed by §27.2's window/removal rules.  Consumers MUST determine an
#: extension's lifecycle from its own definition.
EXTENSION_LIFECYCLE_IS_INDEPENDENT: bool = True
