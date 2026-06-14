"""Response Caching — S19.

Delivers advisory caching hints that certain server results carry:
  - CacheableResult: base result shape augmented with ttlMs and cacheScope
  - CACHEABLE_METHODS: the closed set of results that carry these hints
  - Validation, freshness computation, and scope-consistency helpers

Spec: §13
Depends on: S04
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, NamedTuple

from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE, ResultType


# ---------------------------------------------------------------------------
# §13  CacheScope constants  [R-13.1-d]
# ---------------------------------------------------------------------------

#: Any client or shared intermediary may store and serve this response.
CACHE_SCOPE_PUBLIC: str = "public"

#: Only the originating authorization context may reuse this response.
CACHE_SCOPE_PRIVATE: str = "private"

#: The two valid cacheScope values; case-sensitive (R-13.1-d).
VALID_CACHE_SCOPES: frozenset[str] = frozenset({
  CACHE_SCOPE_PUBLIC,
  CACHE_SCOPE_PRIVATE,
})


# ---------------------------------------------------------------------------
# §13.4  Closed set of results that carry caching hints  [R-13.4-a]
# ---------------------------------------------------------------------------

#: Server results that MUST include both ttlMs and cacheScope (R-13.4-a).
CACHEABLE_METHODS: frozenset[str] = frozenset({
  "tools/list",
  "prompts/list",
  "resources/list",
  "resources/templates/list",
  "resources/read",
})


# ---------------------------------------------------------------------------
# §13  CacheableResult shape  [R-13.1-a, R-13.1-d]
# ---------------------------------------------------------------------------

@dataclass
class CacheableResult:
  """A result that augments the base shape with advisory caching hints (§13).

  Both fields are independent and both must be satisfied for a client to
  reuse a stored copy.  They never alter the result's meaning and are never
  authoritative access-control (R-13.3-d, R-13.3-e).

  Fields:
    ttl_ms: Non-negative integer freshness hint in milliseconds (R-13.1-a).
      Wire key: "ttlMs".  0 = immediately stale (R-13.2-b).
    cache_scope: One of "public" or "private" (R-13.1-d).
      Wire key: "cacheScope".
    result_type: Inherited base field. Wire key: "resultType".
    meta: Optional _meta. Wire key: "_meta".
    extra: Method-specific payload beyond the base caching fields.
  """

  ttl_ms: int
  cache_scope: str
  result_type: ResultType = RESULT_TYPE_COMPLETE
  meta: dict[str, Any] | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict."""
    out: dict[str, Any] = {
      "resultType": self.result_type,
      "ttlMs": self.ttl_ms,
      "cacheScope": self.cache_scope,
    }
    if self.meta is not None:
      out["_meta"] = self.meta
    out.update(self.extra)
    return out


# ---------------------------------------------------------------------------
# §13.1  Field validation  [R-13.1-a–g]
# ---------------------------------------------------------------------------

def is_valid_ttl_ms(value: Any) -> bool:
  """Return True if value is a valid non-negative integer ttlMs (R-13.2-a).

  Booleans are not integers in this context.
  """
  if isinstance(value, bool):
    return False
  if not isinstance(value, int):
    return False
  return value >= 0


def effective_ttl_ms(raw_ttl: Any) -> int | None:
  """Return the ttlMs if valid, or None if invalid/missing.

  None signals that the result MUST NOT be treated as cacheable and SHOULD
  be considered immediately stale (R-13.1-b, R-13.1-c).
  """
  if not is_valid_ttl_ms(raw_ttl):
    return None
  return raw_ttl


def effective_cache_scope(raw_scope: Any, *, can_distinguish_contexts: bool = True) -> str:
  """Return the effective cacheScope, defaulting to 'private' for unknown/missing.

  R-13.1-e: Any value that is not exactly "public" or "private" MUST be
  treated as "private" (the more conservative scope).
  R-13.1-f: An absent cacheScope is treated as malformed; decline to share.
  R-13.3-h: A receiver that cannot reliably distinguish authorization contexts
  MUST treat every cached result as "private".

  Args:
    raw_scope: The raw cacheScope value from the wire, or None if absent.
    can_distinguish_contexts: When False, always returns "private" regardless
      of the wire value (R-13.3-h).
  """
  if not can_distinguish_contexts:
    return CACHE_SCOPE_PRIVATE  # R-13.3-h: cannot distinguish → always private
  if raw_scope == CACHE_SCOPE_PUBLIC:
    return CACHE_SCOPE_PUBLIC
  return CACHE_SCOPE_PRIVATE


class CacheScopeResult(NamedTuple):
  """Classification result from classify_cache_scope (R-13.1-e/f)."""

  scope: str      # effective scope to use ("public" or "private")
  is_malformed: bool  # True when raw value was absent or not "public"/"private"


def classify_cache_scope(
  raw_scope: Any,
  *,
  can_distinguish_contexts: bool = True,
) -> CacheScopeResult:
  """Classify a cacheScope value, surfacing the malformed-vs-valid distinction.

  Whereas effective_cache_scope() always returns a safe string for downstream
  logic, this function additionally surfaces whether the raw value was absent or
  unrecognized — allowing the caller to apply R-13.1-f (SHOULD: absent cacheScope
  is malformed; decline to share the response).

  Args:
    raw_scope: The raw wire value, or None if the field is absent.
    can_distinguish_contexts: Forwarded to effective_cache_scope (R-13.3-h).

  Returns:
    CacheScopeResult(scope, is_malformed) where is_malformed is True when
    raw_scope is None or any value not in VALID_CACHE_SCOPES.
  """
  is_malformed = raw_scope not in VALID_CACHE_SCOPES
  scope = effective_cache_scope(raw_scope, can_distinguish_contexts=can_distinguish_contexts)
  return CacheScopeResult(scope=scope, is_malformed=is_malformed)


def validate_caching_fields_paired(raw: dict[str, Any]) -> None:
  """Raise ValueError if exactly one of ttlMs/cacheScope is present.

  A server MUST NOT emit one of the two caching fields without the other
  on results specified to carry caching hints (R-13.1-g).

  Raises:
    ValueError: exactly one field is present.
  """
  has_ttl = "ttlMs" in raw
  has_scope = "cacheScope" in raw
  if has_ttl and not has_scope:
    raise ValueError(
      "ttlMs is present but cacheScope is absent; both must appear together (R-13.1-g)"
    )
  if has_scope and not has_ttl:
    raise ValueError(
      "cacheScope is present but ttlMs is absent; both must appear together (R-13.1-g)"
    )


def validate_cacheable_result(raw: dict[str, Any]) -> CacheableResult:
  """Parse and validate a cacheable result from a wire dict (§13).

  Both ttlMs and cacheScope MUST be present and valid on results specified
  to carry caching hints (R-13.1-a, R-13.1-d, R-13.4-a).

  Raises:
    TypeError: raw is not a dict, or a field has the wrong type.
    ValueError: ttlMs or cacheScope is absent, ttlMs is negative, or
      cacheScope is not exactly "public" or "private".
  """
  from mcp_sdk_py.result_error import parse_result

  if not isinstance(raw, dict):
    raise TypeError(
      f"cacheable result must be a JSON object; got {type(raw).__name__}"
    )

  # Both caching fields must be present together (R-13.1-g).
  validate_caching_fields_paired(raw)

  # ttlMs: REQUIRED non-negative integer (R-13.1-a, R-13.2-a).
  if "ttlMs" not in raw:
    raise ValueError("ttlMs is REQUIRED on cacheable results (R-13.1-a)")
  ttl_raw = raw["ttlMs"]
  if not is_valid_ttl_ms(ttl_raw):
    raise ValueError(
      f"ttlMs must be a non-negative integer; got {ttl_raw!r} (R-13.2-a)"
    )

  # cacheScope: REQUIRED, must be exactly "public" or "private" (R-13.1-d).
  if "cacheScope" not in raw:
    raise ValueError("cacheScope is REQUIRED on cacheable results (R-13.1-d)")
  scope_raw = raw["cacheScope"]
  if scope_raw not in VALID_CACHE_SCOPES:
    raise ValueError(
      f"cacheScope must be exactly 'public' or 'private' (case-sensitive); "
      f"got {scope_raw!r} (R-13.1-d)"
    )

  # Validate base Result fields (resultType, _meta) via S04.
  base = parse_result(raw, interop_fallback=True)

  # Extra members: exclude all known fields.
  reserved = {"resultType", "_meta", "ttlMs", "cacheScope"}
  extra = {k: v for k, v in raw.items() if k not in reserved}

  return CacheableResult(
    ttl_ms=ttl_raw,
    cache_scope=scope_raw,
    result_type=base.result_type,
    meta=base.meta,
    extra=extra,
  )


# ---------------------------------------------------------------------------
# §13.2  Freshness computation  [R-13.2-e–g]
# ---------------------------------------------------------------------------

def is_fresh(ttl_ms: int, received_at_ms: int, now_ms: int) -> bool:
  """Return True if the cached result is still within its freshness interval.

  Freshness rule (R-13.2-e, R-13.2-f):
    expiresAt = receivedAt + ttlMs
    isFresh(now) = (ttlMs > 0) AND (now < expiresAt)

  Uses only the client's own local clock (R-13.2-g); no server-clock
  synchronization is assumed.  A ttlMs of 0 is always stale (R-13.2-b).

  Args:
    ttl_ms: The ttlMs value from the server result; must be non-negative.
    received_at_ms: Local clock time (ms) when the response was received.
    now_ms: Current local clock time (ms).
  """
  if ttl_ms <= 0:
    return False  # R-13.2-b: 0 means immediately stale
  expires_at = received_at_ms + ttl_ms
  return now_ms < expires_at


# ---------------------------------------------------------------------------
# §13.4  Composed cache-reuse gate  [R-13.4-g, R-13.3-b/c/h]
# ---------------------------------------------------------------------------

def can_reuse_cached_result(
  ttl_ms: int,
  received_at_ms: int,
  now_ms: int,
  cache_scope: str,
  *,
  is_same_auth_context: bool = True,
  can_distinguish_contexts: bool = True,
) -> bool:
  """Return True if a cached result may be reused right now (R-13.4-g).

  A client that honors caching hints MUST respect BOTH constraints:
  1. Freshness: is_fresh(ttl_ms, received_at_ms, now_ms)  (§13.2)
  2. Scope permits serving for this caller                 (§13.3)

  For "public" results any caller may reuse within the freshness interval.
  For "private" results (or when contexts cannot be distinguished per R-13.3-h),
  the caller must be the originating authorization context.  A shared
  intermediary MUST NOT serve a "private" result to a different authorization
  context (R-13.3-c) — pass is_same_auth_context=False to enforce this.

  Args:
    ttl_ms: ttlMs from the cached result.
    received_at_ms: Local clock (ms) when the response was received.
    now_ms: Current local clock (ms).
    cache_scope: The cacheScope value from the cached result.
    is_same_auth_context: Whether the current requester is the same authorization
      context as the one that originated the cached response (R-13.3-c).
    can_distinguish_contexts: When False, every result is treated as "private"
      regardless of cacheScope (R-13.3-h).
  """
  if not is_fresh(ttl_ms, received_at_ms, now_ms):
    return False
  effective = effective_cache_scope(cache_scope, can_distinguish_contexts=can_distinguish_contexts)
  if effective == CACHE_SCOPE_PUBLIC:
    return True  # any authorization context may serve this result
  # "private" — only the originating authorization context may reuse (R-13.3-b/c)
  return is_same_auth_context


# ---------------------------------------------------------------------------
# §13.5  Pagination × caching  [R-13.5-f–i]
# ---------------------------------------------------------------------------

def validate_page_scope_consistency(scopes: list[str]) -> str:
  """Validate that all pages of one list traversal share the same cacheScope.

  R-13.5-f: cacheScope MUST be consistent across all pages.
  R-13.5-g: Server MUST NOT mix "public" and "private" across pages.
  R-13.5-h: Client that observes inconsistent scopes MUST treat the entire
    list as "private".

  Returns the consistent scope when all entries agree, or "private" when
  inconsistent.  Also returns "private" for an empty input.
  """
  unique = set(scopes)
  if len(unique) <= 1:
    return unique.pop() if unique else CACHE_SCOPE_PRIVATE
  # Inconsistent scopes → treat entire list as private (R-13.5-h).
  return CACHE_SCOPE_PRIVATE


def assert_server_page_scope_consistent(scopes: list[str]) -> None:
  """Assert that a server never emits mixed scopes across pages of one traversal.

  R-13.5-g: A server MUST NOT mix "public" and "private" cacheScope across the
  pages produced for a single list traversal.  This function is called server-side,
  at result-emission time, to detect and reject such violations before they reach
  the client.

  For the client-side coercion (observe inconsistency → treat list as "private"),
  use validate_page_scope_consistency() instead (R-13.5-h).

  Raises:
    ValueError: scopes contains both "public" and "private".
  """
  if CACHE_SCOPE_PUBLIC in scopes and CACHE_SCOPE_PRIVATE in scopes:
    raise ValueError(
      "server MUST NOT mix 'public' and 'private' cacheScope across pages "
      "of a single list traversal (R-13.5-g)"
    )


# ---------------------------------------------------------------------------
# §13.5  Notification-based invalidation  [R-13.5-a, R-13.5-b, R-13.5-c]
# ---------------------------------------------------------------------------

#: Maps change notification method names to the cacheable result methods they
#: invalidate.  A change notification takes precedence over a still-fresh ttlMs
#: (R-13.5-c); the client SHOULD invalidate and re-fetch on receipt (R-13.5-a/b).
NOTIFICATION_INVALIDATION_MAP: dict[str, frozenset[str]] = {
  "notifications/tools/list_changed": frozenset({"tools/list"}),
  "notifications/prompts/list_changed": frozenset({"prompts/list"}),
  "notifications/resources/list_changed": frozenset({
    "resources/list",
    "resources/templates/list",
  }),
  "notifications/resources/updated": frozenset({"resources/read"}),
}


def invalidated_methods_for_notification(notification_method: str) -> frozenset[str]:
  """Return the cacheable methods invalidated by a change notification (R-13.5-a).

  A relevant change notification takes precedence over a still-fresh ttlMs
  (R-13.5-c).  Returns an empty frozenset for unknown notification methods.
  """
  return NOTIFICATION_INVALIDATION_MAP.get(notification_method, frozenset())


def should_invalidate_on_notification(
  cached_method: str,
  notification_method: str,
) -> bool:
  """Return True if this notification requires invalidating a cached result.

  When True, the client SHOULD invalidate the cached entry and re-fetch before
  relying on the result again, even if still within the ttlMs interval
  (R-13.5-a, R-13.5-b, R-13.5-c).
  """
  return cached_method in invalidated_methods_for_notification(notification_method)
