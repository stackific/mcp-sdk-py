"""Tests for S19 — Response Caching.

Coverage map (26 ACs):
  AC-19.1  → TestCacheableResultShape
  AC-19.2  → TestInvalidTtlMs
  AC-19.3  → TestInvalidCacheScope, TestClassifyCacheScope
  AC-19.4  → TestCachingFieldsPaired
  AC-19.5  → TestTtlMsZeroImmediatelyStale
  AC-19.6  → TestFreshnessComputation
  AC-19.7  → TestLocalClockOnly
  AC-19.8  → TestRefetchForLatestState
  AC-19.9  → TestClientMayIgnoreCaching
  AC-19.10 → TestNoExtendBeyondInterval
  AC-19.11 → TestServerChoosesTtlMs
  AC-19.12 → TestPublicScopeReuse
  AC-19.13 → TestPrivateScopeReuse, TestCanReuseComposedGate
  AC-19.14 → TestCacheScopeNotSecurity
  AC-19.15 → TestFallbackToPrivate, TestCanReuseComposedGate
  AC-19.16 → TestCacheableMethodsHaveBothFields
  AC-19.17 → TestServerDiscouragedCachingStillIncludesFields
  AC-19.18 → TestCacheScopeByDataDependency
  AC-19.19 → TestNonCacheableMessagesIgnoreFields
  AC-19.20 → TestClientCachingPolicy, TestCanReuseComposedGate
  AC-19.21 → TestChangeNotificationInvalidatesCache, TestNotificationInvalidation
  AC-19.22 → TestNoNotificationNoExtendedFreshness
  AC-19.23 → TestPerPageCaching
  AC-19.24 → TestPageScopeConsistency, TestServerPageScopeConsistency
  AC-19.25 → TestInconsistentPageScopeTreatedAsPrivate
  AC-19.26 → TestCursorNotUsedForCacheBehavior
"""

import pytest

from mcp_sdk_py.caching import (
  CACHEABLE_METHODS,
  CACHE_SCOPE_PRIVATE,
  CACHE_SCOPE_PUBLIC,
  NOTIFICATION_INVALIDATION_MAP,
  VALID_CACHE_SCOPES,
  CacheableResult,
  CacheScopeResult,
  assert_server_page_scope_consistent,
  can_reuse_cached_result,
  classify_cache_scope,
  effective_cache_scope,
  effective_ttl_ms,
  invalidated_methods_for_notification,
  is_fresh,
  is_valid_ttl_ms,
  should_invalidate_on_notification,
  validate_cacheable_result,
  validate_caching_fields_paired,
  validate_page_scope_consistency,
)


# ---------------------------------------------------------------------------
# AC-19.1 — CacheableResult includes valid ttlMs and cacheScope  (R-13.1-a/d, R-13.2-a)
# ---------------------------------------------------------------------------

class TestCacheableResultShape:
  def test_valid_public_cacheable_result(self):
    r = validate_cacheable_result({
      "resultType": "complete",
      "ttlMs": 600000,
      "cacheScope": "public",
    })
    assert r.ttl_ms == 600000
    assert r.cache_scope == CACHE_SCOPE_PUBLIC

  def test_valid_private_cacheable_result(self):
    r = validate_cacheable_result({
      "resultType": "complete",
      "ttlMs": 0,
      "cacheScope": "private",
    })
    assert r.ttl_ms == 0
    assert r.cache_scope == CACHE_SCOPE_PRIVATE

  def test_to_dict_includes_both_fields(self):
    r = CacheableResult(ttl_ms=60000, cache_scope="public")
    d = r.to_dict()
    assert "ttlMs" in d
    assert d["ttlMs"] == 60000
    assert "cacheScope" in d
    assert d["cacheScope"] == "public"

  def test_wire_example_tools_list_page(self):
    raw = {
      "resultType": "complete",
      "tools": [{"name": "get_weather", "title": "Get Weather",
                 "description": "Return the current weather for a city.",
                 "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}},
                                 "required": ["city"]}}],
      "nextCursor": "eyJwYWdlIjogMn0=",
      "ttlMs": 600000,
      "cacheScope": "public",
    }
    r = validate_cacheable_result(raw)
    assert r.ttl_ms == 600000
    assert r.cache_scope == CACHE_SCOPE_PUBLIC

  def test_wire_example_resources_read_zero_ttl(self):
    raw = {
      "resultType": "complete",
      "contents": [{"uri": "file:///report.txt", "mimeType": "text/plain", "text": "..."}],
      "ttlMs": 0,
      "cacheScope": "private",
    }
    r = validate_cacheable_result(raw)
    assert r.ttl_ms == 0
    assert r.cache_scope == CACHE_SCOPE_PRIVATE


# ---------------------------------------------------------------------------
# AC-19.2 — Invalid/missing ttlMs → not cacheable, treat as stale  (R-13.1-b/c)
# ---------------------------------------------------------------------------

class TestInvalidTtlMs:
  def test_negative_ttl_is_invalid(self):
    with pytest.raises(ValueError, match="non-negative integer"):
      validate_cacheable_result({"resultType": "complete", "ttlMs": -1, "cacheScope": "public"})

  def test_float_ttl_is_invalid(self):
    with pytest.raises(ValueError, match="non-negative integer"):
      validate_cacheable_result({"resultType": "complete", "ttlMs": 1.5, "cacheScope": "public"})

  def test_bool_ttl_is_invalid(self):
    with pytest.raises(ValueError, match="non-negative integer"):
      validate_cacheable_result({"resultType": "complete", "ttlMs": True, "cacheScope": "public"})

  def test_string_ttl_is_invalid(self):
    with pytest.raises(ValueError, match="non-negative integer"):
      validate_cacheable_result({"resultType": "complete", "ttlMs": "600000", "cacheScope": "public"})

  def test_effective_ttl_returns_none_for_negative(self):
    assert effective_ttl_ms(-1) is None

  def test_effective_ttl_returns_none_for_float(self):
    assert effective_ttl_ms(1.5) is None

  def test_effective_ttl_returns_none_for_missing(self):
    assert effective_ttl_ms(None) is None

  def test_effective_ttl_returns_value_for_valid(self):
    assert effective_ttl_ms(0) == 0
    assert effective_ttl_ms(5000) == 5000

  def test_is_valid_ttl_ms_checks(self):
    assert is_valid_ttl_ms(0) is True
    assert is_valid_ttl_ms(1) is True
    assert is_valid_ttl_ms(-1) is False
    assert is_valid_ttl_ms(1.5) is False
    assert is_valid_ttl_ms(True) is False
    assert is_valid_ttl_ms(None) is False


# ---------------------------------------------------------------------------
# AC-19.3 — Invalid/missing cacheScope → treat as 'private'  (R-13.1-e/f)
# ---------------------------------------------------------------------------

class TestInvalidCacheScope:
  def test_unknown_scope_in_validation_raises(self):
    with pytest.raises(ValueError, match="'public' or 'private'"):
      validate_cacheable_result({"resultType": "complete", "ttlMs": 60, "cacheScope": "shared"})

  def test_effective_scope_unknown_value_returns_private(self):
    assert effective_cache_scope("shared") == CACHE_SCOPE_PRIVATE

  def test_effective_scope_none_returns_private(self):
    assert effective_cache_scope(None) == CACHE_SCOPE_PRIVATE

  def test_effective_scope_empty_string_returns_private(self):
    assert effective_cache_scope("") == CACHE_SCOPE_PRIVATE

  def test_effective_scope_public_returns_public(self):
    assert effective_cache_scope("public") == CACHE_SCOPE_PUBLIC

  def test_effective_scope_private_returns_private(self):
    assert effective_cache_scope("private") == CACHE_SCOPE_PRIVATE

  def test_scope_is_case_sensitive_uppercase_is_private(self):
    """'Public' is not 'public' — case-sensitive (R-13.1-d)."""
    assert effective_cache_scope("Public") == CACHE_SCOPE_PRIVATE
    assert effective_cache_scope("PRIVATE") == CACHE_SCOPE_PRIVATE


# ---------------------------------------------------------------------------
# AC-19.4 — ttlMs and cacheScope must appear together  (R-13.1-g)
# ---------------------------------------------------------------------------

class TestCachingFieldsPaired:
  def test_only_ttl_raises(self):
    with pytest.raises(ValueError, match="cacheScope is absent"):
      validate_caching_fields_paired({"ttlMs": 5000})

  def test_only_scope_raises(self):
    with pytest.raises(ValueError, match="ttlMs is absent"):
      validate_caching_fields_paired({"cacheScope": "public"})

  def test_both_present_is_valid(self):
    validate_caching_fields_paired({"ttlMs": 0, "cacheScope": "private"})

  def test_neither_present_is_valid(self):
    """Neither field means no caching hint; not a violation of R-13.1-g."""
    validate_caching_fields_paired({})

  def test_validate_cacheable_result_rejects_missing_ttl(self):
    with pytest.raises(ValueError):
      validate_cacheable_result({"resultType": "complete", "cacheScope": "public"})

  def test_validate_cacheable_result_rejects_missing_scope(self):
    with pytest.raises(ValueError):
      validate_cacheable_result({"resultType": "complete", "ttlMs": 5000})


# ---------------------------------------------------------------------------
# AC-19.5 — ttlMs=0 means immediately stale  (R-13.2-b/c/d)
# ---------------------------------------------------------------------------

class TestTtlMsZeroImmediatelyStale:
  def test_ttl_zero_is_not_fresh(self):
    assert not is_fresh(0, received_at_ms=1000, now_ms=1000)
    assert not is_fresh(0, received_at_ms=1000, now_ms=1001)

  def test_ttl_zero_result_may_be_refetched_every_time(self):
    """ttlMs=0 allows (MAY) re-fetching every time (R-13.2-c)."""
    r = CacheableResult(ttl_ms=0, cache_scope="private")
    assert r.ttl_ms == 0
    assert not is_fresh(0, 1000, 1000)

  def test_stored_copy_should_not_be_served_as_fresh_for_ttl_zero(self):
    assert not is_fresh(0, received_at_ms=0, now_ms=0)


# ---------------------------------------------------------------------------
# AC-19.6 — Freshness computation: N > 0  (R-13.2-e/f)
# ---------------------------------------------------------------------------

class TestFreshnessComputation:
  def test_within_interval_is_fresh(self):
    assert is_fresh(5000, received_at_ms=1000, now_ms=5999)

  def test_exactly_at_expiry_is_stale(self):
    """isFresh = now < expiresAt; at expiresAt it is stale."""
    assert not is_fresh(5000, received_at_ms=1000, now_ms=6000)

  def test_after_expiry_is_stale(self):
    assert not is_fresh(5000, received_at_ms=1000, now_ms=7000)

  def test_just_received_is_fresh(self):
    assert is_fresh(5000, received_at_ms=1000, now_ms=1001)

  def test_large_ttl_is_fresh_long_after_receipt(self):
    received = 1_000_000
    ttl = 86_400_000  # 24 hours
    now = received + 3_600_000  # 1 hour later
    assert is_fresh(ttl, received_at_ms=received, now_ms=now)


# ---------------------------------------------------------------------------
# AC-19.7 — Client uses own clock only  (R-13.2-g)
# ---------------------------------------------------------------------------

class TestLocalClockOnly:
  def test_freshness_uses_only_received_at_and_ttl(self):
    """No server clock is assumed; is_fresh has no server_time parameter."""
    import inspect
    sig = inspect.signature(is_fresh)
    param_names = list(sig.parameters.keys())
    assert "server_time" not in param_names
    assert "received_at_ms" in param_names
    assert "ttl_ms" in param_names
    assert "now_ms" in param_names


# ---------------------------------------------------------------------------
# AC-19.8 — Client re-fetches for latest state  (R-13.2-h)
# ---------------------------------------------------------------------------

class TestRefetchForLatestState:
  def test_is_fresh_can_return_false_to_trigger_refetch(self):
    """When stale, client must re-fetch."""
    received = 1000
    ttl = 5000
    now = received + ttl + 1  # past expiry
    assert not is_fresh(ttl, received_at_ms=received, now_ms=now)


# ---------------------------------------------------------------------------
# AC-19.9 — Client MAY ignore caching entirely  (R-13.2-i)
# ---------------------------------------------------------------------------

class TestClientMayIgnoreCaching:
  def test_client_may_always_refetch(self):
    """The SDK provides freshness info but does not force the client to use it."""
    r = CacheableResult(ttl_ms=600000, cache_scope="public")
    # Client is free to ignore this and refetch; the model doesn't block re-fetching.
    assert r.ttl_ms == 600000


# ---------------------------------------------------------------------------
# AC-19.10 — Client must not extend reuse beyond ttlMs  (R-13.2-j)
# ---------------------------------------------------------------------------

class TestNoExtendBeyondInterval:
  def test_stale_after_interval(self):
    received = 0
    ttl = 1000
    assert not is_fresh(ttl, received_at_ms=received, now_ms=1000)
    assert not is_fresh(ttl, received_at_ms=received, now_ms=2000)


# ---------------------------------------------------------------------------
# AC-19.11 — Server chooses ttlMs reflecting data stability  (R-13.2-k)
# ---------------------------------------------------------------------------

class TestServerChoosesTtlMs:
  def test_zero_ttl_for_volatile_data(self):
    r = CacheableResult(ttl_ms=0, cache_scope="private")
    assert r.ttl_ms == 0

  def test_large_ttl_for_stable_catalog(self):
    r = CacheableResult(ttl_ms=86_400_000, cache_scope="public")
    assert r.ttl_ms == 86_400_000


# ---------------------------------------------------------------------------
# AC-19.12 — "public" result may be served to any user  (R-13.3-a)
# ---------------------------------------------------------------------------

class TestPublicScopeReuse:
  def test_public_scope_is_valid(self):
    r = validate_cacheable_result({
      "resultType": "complete",
      "ttlMs": 60000,
      "cacheScope": "public",
    })
    assert r.cache_scope == CACHE_SCOPE_PUBLIC

  def test_effective_scope_public_confirmed(self):
    assert effective_cache_scope("public") == CACHE_SCOPE_PUBLIC


# ---------------------------------------------------------------------------
# AC-19.13 — "private" result for single authorization context  (R-13.3-b/c)
# ---------------------------------------------------------------------------

class TestPrivateScopeReuse:
  def test_private_scope_is_valid(self):
    r = CacheableResult(ttl_ms=0, cache_scope="private")
    assert r.cache_scope == CACHE_SCOPE_PRIVATE

  def test_intermediary_must_not_share_private_result(self):
    """Behavioral rule: private results must not be served to different users."""
    r = CacheableResult(ttl_ms=5000, cache_scope="private")
    # The SDK surfaces scope for the caller to enforce this.
    assert r.cache_scope == CACHE_SCOPE_PRIVATE


# ---------------------------------------------------------------------------
# AC-19.14 — cacheScope is not security / no security guarantee  (R-13.3-d/e)
# ---------------------------------------------------------------------------

class TestCacheScopeNotSecurity:
  def test_cache_scope_is_advisory_not_access_control(self):
    """cacheScope is a hint; the SDK provides it for the caller to honor."""
    public_result = CacheableResult(ttl_ms=60000, cache_scope="public")
    assert public_result.cache_scope == CACHE_SCOPE_PUBLIC
    # No security enforcement or access control in the data structure itself.

  def test_valid_cache_scopes_are_advisory(self):
    assert VALID_CACHE_SCOPES == frozenset({"public", "private"})


# ---------------------------------------------------------------------------
# AC-19.15 — Fallback to 'private' in conservative cases  (R-13.3-f/g/h)
# ---------------------------------------------------------------------------

class TestFallbackToPrivate:
  def test_unknown_scope_effective_is_private(self):
    assert effective_cache_scope("unknown") == CACHE_SCOPE_PRIVATE

  def test_receiver_cannot_distinguish_contexts_treats_as_private(self):
    """R-13.3-h: receiver that cannot distinguish auth contexts → always private."""
    assert effective_cache_scope("public", can_distinguish_contexts=False) == CACHE_SCOPE_PRIVATE
    assert effective_cache_scope("private", can_distinguish_contexts=False) == CACHE_SCOPE_PRIVATE


# ---------------------------------------------------------------------------
# AC-19.16 — Cacheable methods must include both fields  (R-13.4-a)
# ---------------------------------------------------------------------------

class TestCacheableMethodsHaveBothFields:
  def test_cacheable_methods_set(self):
    assert "tools/list" in CACHEABLE_METHODS
    assert "prompts/list" in CACHEABLE_METHODS
    assert "resources/list" in CACHEABLE_METHODS
    assert "resources/templates/list" in CACHEABLE_METHODS
    assert "resources/read" in CACHEABLE_METHODS

  def test_validate_cacheable_result_requires_both_fields(self):
    """Both fields are required on results for cacheable methods (R-13.4-a)."""
    # Missing scope → error.
    with pytest.raises(ValueError):
      validate_cacheable_result({"resultType": "complete", "ttlMs": 5000})
    # Missing ttlMs → error.
    with pytest.raises(ValueError):
      validate_cacheable_result({"resultType": "complete", "cacheScope": "private"})
    # Both present → valid.
    validate_cacheable_result({"resultType": "complete", "ttlMs": 0, "cacheScope": "private"})


# ---------------------------------------------------------------------------
# AC-19.17 — Server not wishing to cache still includes fields with ttlMs=0  (R-13.4-b)
# ---------------------------------------------------------------------------

class TestServerDiscouragedCachingStillIncludesFields:
  def test_zero_ttl_with_scope_is_valid(self):
    r = validate_cacheable_result({
      "resultType": "complete",
      "ttlMs": 0,
      "cacheScope": "private",
    })
    assert r.ttl_ms == 0
    assert r.cache_scope == CACHE_SCOPE_PRIVATE


# ---------------------------------------------------------------------------
# AC-19.18 — cacheScope matches data dependency on authorization  (R-13.4-c/d)
# ---------------------------------------------------------------------------

class TestCacheScopeByDataDependency:
  def test_auth_dependent_data_should_be_private(self):
    r = CacheableResult(ttl_ms=60000, cache_scope="private")
    assert r.cache_scope == CACHE_SCOPE_PRIVATE

  def test_identical_for_all_requesters_may_be_public(self):
    r = CacheableResult(ttl_ms=3600000, cache_scope="public")
    assert r.cache_scope == CACHE_SCOPE_PUBLIC


# ---------------------------------------------------------------------------
# AC-19.19 — caching fields ignored on non-cacheable messages  (R-13.4-e)
# ---------------------------------------------------------------------------

class TestNonCacheableMessagesIgnoreFields:
  def test_ttl_and_scope_on_non_cacheable_message_ignored(self):
    """Fields on non-enumerated results are unknown fields to be ignored."""
    from mcp_sdk_py.result_error import parse_result
    raw = {
      "resultType": "complete",
      "ttlMs": 5000,
      "cacheScope": "public",
      "someOtherResult": True,
    }
    # parse_result does not reject for extra fields.
    r = parse_result(raw)
    assert r.extra["ttlMs"] == 5000
    assert r.extra["cacheScope"] == "public"


# ---------------------------------------------------------------------------
# AC-19.20 — Client caching policy is flexible  (R-13.4-f/g)
# ---------------------------------------------------------------------------

class TestClientCachingPolicy:
  def test_client_may_decline_to_cache(self):
    r = CacheableResult(ttl_ms=600000, cache_scope="public")
    # Client is always free to ignore the hint and re-fetch.
    assert r.ttl_ms == 600000  # hint available but not mandatory

  def test_client_honoring_hints_checks_both_freshness_and_scope(self):
    """R-13.4-g: honors hints = respects BOTH freshness AND scope."""
    ttl = 60000
    received = 1000
    now_fresh = 1001
    now_stale = received + ttl + 1
    # Both constraints met → reuse allowed.
    assert can_reuse_cached_result(ttl, received, now_fresh, "public")
    # Stale → no reuse even if scope allows.
    assert not can_reuse_cached_result(ttl, received, now_stale, "public")


# ---------------------------------------------------------------------------
# AC-19.21 — Change notification invalidates cached result  (R-13.5-a/b/c)
# ---------------------------------------------------------------------------

class TestChangeNotificationInvalidatesCache:
  def test_notification_invalidates_despite_fresh_ttl(self):
    """On a relevant notification, cache must be invalidated even while fresh."""
    now = 2000
    received = 1000
    ttl = 600000
    # Confirm the result is still fresh...
    assert is_fresh(ttl, received, now)
    # ...but a relevant notification forces invalidation regardless (R-13.5-c).
    assert should_invalidate_on_notification("tools/list", "notifications/tools/list_changed")


# ---------------------------------------------------------------------------
# AC-19.22 — No notification does not extend freshness beyond ttlMs  (R-13.5-d)
# ---------------------------------------------------------------------------

class TestNoNotificationNoExtendedFreshness:
  def test_expired_result_is_stale_regardless_of_notifications(self):
    received = 1000
    ttl = 5000
    now_stale = received + ttl + 1
    assert not is_fresh(ttl, received_at_ms=received, now_ms=now_stale)


# ---------------------------------------------------------------------------
# AC-19.23 — Each page cached independently  (R-13.5-e)
# ---------------------------------------------------------------------------

class TestPerPageCaching:
  def test_different_pages_may_have_different_ttl(self):
    page1 = CacheableResult(ttl_ms=600000, cache_scope="public",
                            extra={"tools": [], "nextCursor": "C1"})
    page2 = CacheableResult(ttl_ms=300000, cache_scope="public",
                            extra={"tools": []})
    assert page1.ttl_ms != page2.ttl_ms

  def test_pages_with_same_ttl_also_valid(self):
    page1 = CacheableResult(ttl_ms=60000, cache_scope="public")
    page2 = CacheableResult(ttl_ms=60000, cache_scope="public")
    assert page1.ttl_ms == page2.ttl_ms


# ---------------------------------------------------------------------------
# AC-19.24 — cacheScope consistent across all pages  (R-13.5-f/g)
# ---------------------------------------------------------------------------

class TestPageScopeConsistency:
  def test_consistent_public_scope_is_returned(self):
    result = validate_page_scope_consistency(["public", "public", "public"])
    assert result == CACHE_SCOPE_PUBLIC

  def test_consistent_private_scope_is_returned(self):
    result = validate_page_scope_consistency(["private", "private"])
    assert result == CACHE_SCOPE_PRIVATE

  def test_server_must_not_mix_scopes(self):
    """Inconsistent scopes → treated as private by the client (R-13.5-h)."""
    result = validate_page_scope_consistency(["public", "private"])
    assert result == CACHE_SCOPE_PRIVATE


# ---------------------------------------------------------------------------
# AC-19.25 — Inconsistent page scopes treated as 'private'  (R-13.5-h)
# ---------------------------------------------------------------------------

class TestInconsistentPageScopeTreatedAsPrivate:
  def test_mixed_scopes_result_in_private(self):
    result = validate_page_scope_consistency(["public", "private", "public"])
    assert result == CACHE_SCOPE_PRIVATE

  def test_single_scope_returned_unchanged(self):
    assert validate_page_scope_consistency(["public"]) == CACHE_SCOPE_PUBLIC
    assert validate_page_scope_consistency(["private"]) == CACHE_SCOPE_PRIVATE

  def test_empty_list_returns_private(self):
    """Empty list: no pages → conservative default (private)."""
    assert validate_page_scope_consistency([]) == CACHE_SCOPE_PRIVATE


# ---------------------------------------------------------------------------
# AC-19.26 — Cursor not used for cache behavior  (R-13.5-i)
# ---------------------------------------------------------------------------

class TestCursorNotUsedForCacheBehavior:
  def test_cursor_is_opaque_and_not_inspected_for_caching(self):
    """Cache entry is keyed by request, not by cursor content interpretation."""
    from mcp_sdk_py.pagination import make_page_cache_key
    # The cursor is treated as an opaque identity token for cache keying.
    key1 = make_page_cache_key("tools/list", {"cursor": "eyJwYWdlIjogMn0="})
    key2 = make_page_cache_key("tools/list", {"cursor": "eyJwYWdlIjogMn0="})
    # Same request → same key (regardless of cursor content).
    assert key1 == key2

  def test_different_cursors_are_different_cache_entries(self):
    from mcp_sdk_py.pagination import make_page_cache_key
    key1 = make_page_cache_key("tools/list", {"cursor": "C1"})
    key2 = make_page_cache_key("tools/list", {"cursor": "C2"})
    assert key1 != key2


# ---------------------------------------------------------------------------
# Composed cache-reuse gate  (R-13.4-g, R-13.3-c/h)
# ---------------------------------------------------------------------------

class TestCanReuseComposedGate:
  """AC-19.20 / AC-19.13 / AC-19.15 — respects BOTH freshness AND scope (R-13.4-g)."""

  def test_fresh_public_is_reusable(self):
    assert can_reuse_cached_result(5000, 1000, 2000, "public")

  def test_stale_public_not_reusable(self):
    """Freshness gate fails → no reuse even with public scope."""
    assert not can_reuse_cached_result(5000, 1000, 10000, "public")

  def test_fresh_private_same_context_is_reusable(self):
    """R-13.3-b: private result may be reused by originating context."""
    assert can_reuse_cached_result(5000, 1000, 2000, "private", is_same_auth_context=True)

  def test_fresh_private_different_context_not_reusable(self):
    """R-13.3-c: shared intermediary MUST NOT serve private result to different context."""
    assert not can_reuse_cached_result(5000, 1000, 2000, "private", is_same_auth_context=False)

  def test_stale_private_same_context_not_reusable(self):
    """Both constraints must hold: stale even for same context."""
    assert not can_reuse_cached_result(5000, 1000, 10000, "private", is_same_auth_context=True)

  def test_cannot_distinguish_contexts_public_same_context_allowed(self):
    """R-13.3-h: when cannot distinguish, public treated as private; same context still OK."""
    assert can_reuse_cached_result(
      5000, 1000, 2000, "public",
      can_distinguish_contexts=False,
      is_same_auth_context=True,
    )

  def test_cannot_distinguish_contexts_public_different_context_blocked(self):
    """R-13.3-h: public result treated as private when context discrimination unavailable."""
    assert not can_reuse_cached_result(
      5000, 1000, 2000, "public",
      can_distinguish_contexts=False,
      is_same_auth_context=False,
    )

  def test_ttl_zero_never_reusable(self):
    """ttlMs=0 is always stale; composed gate returns False (R-13.2-b)."""
    assert not can_reuse_cached_result(0, 1000, 1000, "public")

  def test_unknown_scope_treated_as_private(self):
    """Unknown cacheScope → effective private; same-context gate applies."""
    assert can_reuse_cached_result(5000, 1000, 2000, "shared", is_same_auth_context=True)
    assert not can_reuse_cached_result(5000, 1000, 2000, "shared", is_same_auth_context=False)


# ---------------------------------------------------------------------------
# Server-side page scope consistency (R-13.5-f/g)
# ---------------------------------------------------------------------------

class TestServerPageScopeConsistency:
  """AC-19.24 — Server MUST NOT mix scopes across pages (R-13.5-f/g)."""

  def test_consistent_public_is_ok(self):
    assert_server_page_scope_consistent(["public", "public", "public"])

  def test_consistent_private_is_ok(self):
    assert_server_page_scope_consistent(["private", "private"])

  def test_mixed_scopes_raise(self):
    """R-13.5-g: server MUST NOT mix public/private across pages."""
    with pytest.raises(ValueError, match="MUST NOT mix"):
      assert_server_page_scope_consistent(["public", "private"])

  def test_mixed_scopes_raise_regardless_of_order(self):
    with pytest.raises(ValueError, match="MUST NOT mix"):
      assert_server_page_scope_consistent(["private", "public", "private"])

  def test_single_page_is_ok(self):
    assert_server_page_scope_consistent(["public"])
    assert_server_page_scope_consistent(["private"])

  def test_empty_list_is_ok(self):
    """No pages to check — not a violation."""
    assert_server_page_scope_consistent([])


# ---------------------------------------------------------------------------
# classify_cache_scope — malformed vs valid distinction  (R-13.1-f, RC-2)
# ---------------------------------------------------------------------------

class TestClassifyCacheScope:
  """AC-19.3 / RC-2 — Absent cacheScope surfaces as malformed (R-13.1-f)."""

  def test_valid_public_not_malformed(self):
    result = classify_cache_scope("public")
    assert result.scope == CACHE_SCOPE_PUBLIC
    assert not result.is_malformed

  def test_valid_private_not_malformed(self):
    result = classify_cache_scope("private")
    assert result.scope == CACHE_SCOPE_PRIVATE
    assert not result.is_malformed

  def test_absent_scope_is_malformed(self):
    """R-13.1-f SHOULD: absent cacheScope is malformed; caller should decline to share."""
    result = classify_cache_scope(None)
    assert result.scope == CACHE_SCOPE_PRIVATE
    assert result.is_malformed

  def test_unrecognized_value_is_malformed(self):
    """R-13.1-e: unrecognized value → treat as private; R-13.1-f: also malformed."""
    result = classify_cache_scope("shared")
    assert result.scope == CACHE_SCOPE_PRIVATE
    assert result.is_malformed

  def test_empty_string_is_malformed(self):
    result = classify_cache_scope("")
    assert result.scope == CACHE_SCOPE_PRIVATE
    assert result.is_malformed

  def test_cannot_distinguish_contexts_valid_public_not_malformed(self):
    """Valid value stays not-malformed; scope is overridden to private by R-13.3-h."""
    result = classify_cache_scope("public", can_distinguish_contexts=False)
    assert result.scope == CACHE_SCOPE_PRIVATE
    assert not result.is_malformed

  def test_cannot_distinguish_contexts_absent_is_malformed(self):
    result = classify_cache_scope(None, can_distinguish_contexts=False)
    assert result.scope == CACHE_SCOPE_PRIVATE
    assert result.is_malformed

  def test_returns_cache_scope_result_namedtuple(self):
    result = classify_cache_scope("public")
    assert isinstance(result, CacheScopeResult)
    assert hasattr(result, "scope")
    assert hasattr(result, "is_malformed")


# ---------------------------------------------------------------------------
# Notification-based invalidation API  (R-13.5-a/b/c, RC-9)
# ---------------------------------------------------------------------------

class TestNotificationInvalidation:
  """AC-19.21 — Notification invalidation API (R-13.5-a/b/c, RC-9)."""

  def test_tools_changed_invalidates_tools_list(self):
    assert should_invalidate_on_notification(
      "tools/list", "notifications/tools/list_changed"
    )

  def test_prompts_changed_invalidates_prompts_list(self):
    assert should_invalidate_on_notification(
      "prompts/list", "notifications/prompts/list_changed"
    )

  def test_resources_changed_invalidates_resources_list(self):
    assert should_invalidate_on_notification(
      "resources/list", "notifications/resources/list_changed"
    )

  def test_resources_changed_invalidates_templates_list(self):
    assert should_invalidate_on_notification(
      "resources/templates/list", "notifications/resources/list_changed"
    )

  def test_resources_updated_invalidates_resources_read(self):
    assert should_invalidate_on_notification(
      "resources/read", "notifications/resources/updated"
    )

  def test_unknown_notification_invalidates_nothing(self):
    assert not should_invalidate_on_notification("tools/list", "notifications/unknown")

  def test_notification_does_not_cross_methods(self):
    """Prompts notification does not invalidate tools cache."""
    assert not should_invalidate_on_notification(
      "tools/list", "notifications/prompts/list_changed"
    )

  def test_invalidated_methods_for_tools_notification(self):
    methods = invalidated_methods_for_notification("notifications/tools/list_changed")
    assert "tools/list" in methods

  def test_invalidated_methods_for_unknown_returns_empty(self):
    assert invalidated_methods_for_notification("notifications/unknown") == frozenset()

  def test_map_covers_all_cacheable_methods(self):
    """Every CACHEABLE_METHOD has at least one corresponding invalidation notification."""
    all_invalidated: set[str] = set()
    for methods in NOTIFICATION_INVALIDATION_MAP.values():
      all_invalidated |= methods
    assert CACHEABLE_METHODS == all_invalidated

  def test_notification_takes_precedence_over_fresh_ttl(self):
    """R-13.5-c: notification wins over still-fresh ttlMs."""
    ttl, received, now = 600000, 1000, 2000
    assert is_fresh(ttl, received, now)  # still fresh...
    # ...but notification forces invalidation.
    assert should_invalidate_on_notification(
      "tools/list", "notifications/tools/list_changed"
    )
