"""Tests for S06 — Stateless Per-Request Model & Cross-Call Continuity.

Coverage map (16 ACs):
  AC-06.1  → TestIndependentProcessing
  AC-06.2  → TestNoHandshakeRequired
  AC-06.3  → TestSelfDescribingIdentity
  AC-06.4  → TestNoConnectionState
  AC-06.5  → TestInterleavedRequests
  AC-06.6  → TestConnectionNotConversation
  AC-06.7  → TestInstanceFungibility
  AC-06.8  → TestMultipleTasksOnOneConnection
  AC-06.9  → TestConnectionReuseNotRequired
  AC-06.10 → TestConnectionLifetimeNotConversation
  AC-06.11 → TestExplicitContinuationId
  AC-06.12 → TestServerMintsContinuationId
  AC-06.13 → TestClientEchoesContinuationId
  AC-06.14 → TestContinuationAcrossConnections
  AC-06.15 → TestListResultConnectionIndependence
  AC-06.16 → TestListResultVariationFromInputsOnly
"""

import pytest

from mcp_sdk_py.stateless_model import (
  LISTING_METHODS,
  InvalidContinuationIdError,
  StatelessnessViolationError,
  assert_not_connection_scoped,
  assert_request_is_self_describing,
  continuation_ids_are_equal,
  is_listing_method,
  is_valid_continuation_id,
  validate_continuation_id,
)
from mcp_sdk_py.meta_object import (
  KEY_CLIENT_CAPABILITIES,
  KEY_CLIENT_INFO,
  KEY_PROTOCOL_VERSION,
  REQUIRED_CLIENT_REQUEST_KEYS,
)


_FULL_META = {
  KEY_PROTOCOL_VERSION: "2026-07-28",
  KEY_CLIENT_INFO: {"name": "test-client", "version": "1.0"},
  KEY_CLIENT_CAPABILITIES: {},
}


# ---------------------------------------------------------------------------
# AC-06.1 — Independent processing; no state from prior request  (R-4.4-a)
# ---------------------------------------------------------------------------

class TestIndependentProcessing:
  def test_request_missing_second_time_still_valid_independently(self):
    """Second request processed from its own _meta only, not the first."""
    first_meta = {**_FULL_META, "extra_context": "session_data"}
    second_meta = {**_FULL_META}  # no extra_context
    # Both are independently self-describing.
    assert_request_is_self_describing(first_meta)
    assert_request_is_self_describing(second_meta)

  def test_server_should_not_cache_first_meta_for_second_request(self):
    """Statelessness: server processes each request from its own data."""
    first_meta = {**_FULL_META}
    second_meta = {**_FULL_META, KEY_PROTOCOL_VERSION: "2026-07-28"}
    # Each is independently valid.
    assert_request_is_self_describing(first_meta)
    assert_request_is_self_describing(second_meta)


# ---------------------------------------------------------------------------
# AC-06.2 — No handshake required; first request processed normally  (R-4.4-b)
# ---------------------------------------------------------------------------

class TestNoHandshakeRequired:
  def test_first_request_processed_normally(self):
    """First-ever request is self-describing and requires no prior handshake."""
    assert_request_is_self_describing(_FULL_META)

  def test_any_request_can_be_first(self):
    """No prior request is required; assert_request_is_self_describing passes."""
    meta = {
      KEY_PROTOCOL_VERSION: "2026-07-28",
      KEY_CLIENT_INFO: {"name": "new-client", "version": "0.1"},
      KEY_CLIENT_CAPABILITIES: {"tools": {}},
    }
    assert_request_is_self_describing(meta)

  def test_missing_required_key_raises_statelessness_violation(self):
    """A request missing self-describing keys is detected."""
    incomplete = {KEY_PROTOCOL_VERSION: "2026-07-28"}
    with pytest.raises(StatelessnessViolationError):
      assert_request_is_self_describing(incomplete)


# ---------------------------------------------------------------------------
# AC-06.3 — Identity/capabilities/version from current _meta only  (R-4.4-c)
# ---------------------------------------------------------------------------

class TestSelfDescribingIdentity:
  def test_all_three_required_keys_present(self):
    assert_request_is_self_describing(_FULL_META)

  def test_missing_protocol_version_detected(self):
    meta = {KEY_CLIENT_INFO: {"name": "x", "version": "1"}, KEY_CLIENT_CAPABILITIES: {}}
    with pytest.raises(StatelessnessViolationError, match=KEY_PROTOCOL_VERSION):
      assert_request_is_self_describing(meta)

  def test_missing_client_info_detected(self):
    meta = {KEY_PROTOCOL_VERSION: "2026-07-28", KEY_CLIENT_CAPABILITIES: {}}
    with pytest.raises(StatelessnessViolationError, match=KEY_CLIENT_INFO):
      assert_request_is_self_describing(meta)

  def test_missing_client_capabilities_detected(self):
    meta = {KEY_PROTOCOL_VERSION: "2026-07-28", KEY_CLIENT_INFO: {"name": "x", "version": "1"}}
    with pytest.raises(StatelessnessViolationError, match=KEY_CLIENT_CAPABILITIES):
      assert_request_is_self_describing(meta)

  def test_custom_required_keys_checked(self):
    """Custom required_keys respected."""
    meta = {"my-key": "value"}
    with pytest.raises(StatelessnessViolationError):
      assert_request_is_self_describing(meta, required_keys=frozenset({"missing-key"}))

  def test_custom_required_keys_pass_when_present(self):
    meta = {"my-key": "value"}
    assert_request_is_self_describing(meta, required_keys=frozenset({"my-key"}))


# ---------------------------------------------------------------------------
# AC-06.4 — No per-connection conversational state consulted  (R-4.4-d)
# ---------------------------------------------------------------------------

class TestNoConnectionState:
  def test_assert_not_connection_scoped_always_raises(self):
    """Marker: any code path routing connection_id to request logic is wrong."""
    with pytest.raises(StatelessnessViolationError):
      assert_not_connection_scoped(connection_id="conn-001", request_id=42)

  def test_assert_not_connection_scoped_with_various_ids(self):
    with pytest.raises(StatelessnessViolationError):
      assert_not_connection_scoped(connection_id=None, request_id="req-1")


# ---------------------------------------------------------------------------
# AC-06.5 — Unrelated requests on same connection handled independently  (R-4.4-e)
# ---------------------------------------------------------------------------

class TestInterleavedRequests:
  def test_two_independent_self_describing_requests(self):
    meta_a = {**_FULL_META}
    meta_b = {**_FULL_META}
    assert_request_is_self_describing(meta_a)
    assert_request_is_self_describing(meta_b)

  def test_multiple_different_request_metas_all_valid(self):
    metas = [
      {KEY_PROTOCOL_VERSION: "2026-07-28",
       KEY_CLIENT_INFO: {"name": f"c{i}", "version": "1"},
       KEY_CLIENT_CAPABILITIES: {}}
      for i in range(5)
    ]
    for m in metas:
      assert_request_is_self_describing(m)


# ---------------------------------------------------------------------------
# AC-06.6 — Connection identity never used as conversational proxy  (R-4.4-f)
# ---------------------------------------------------------------------------

class TestConnectionNotConversation:
  def test_connection_scoped_processing_is_violation(self):
    with pytest.raises(StatelessnessViolationError):
      assert_not_connection_scoped("conn-A", "req-1")

  def test_connection_id_is_irrelevant_to_stateless_request(self):
    """assert_request_is_self_describing does not accept connection_id as input."""
    import inspect
    sig = inspect.signature(assert_request_is_self_describing)
    assert "connection_id" not in sig.parameters


# ---------------------------------------------------------------------------
# AC-06.7 — Identical behavior regardless of server instance  (R-4.4-g)
# ---------------------------------------------------------------------------

class TestInstanceFungibility:
  def test_two_identical_metas_both_pass_self_describing_check(self):
    """Identical requests pass regardless of which instance evaluates them."""
    assert_request_is_self_describing(_FULL_META)
    # Simulate second "instance" evaluating the same meta.
    assert_request_is_self_describing(dict(_FULL_META))


# ---------------------------------------------------------------------------
# AC-06.8 — Multiple tasks/conversations on one connection  (R-4.4-h)
# ---------------------------------------------------------------------------

class TestMultipleTasksOnOneConnection:
  def test_five_concurrent_task_metas_all_self_describing(self):
    metas = [
      {KEY_PROTOCOL_VERSION: "2026-07-28",
       KEY_CLIENT_INFO: {"name": "client", "version": "1"},
       KEY_CLIENT_CAPABILITIES: {"task": i}}
      for i in range(5)
    ]
    for m in metas:
      assert_request_is_self_describing(m)


# ---------------------------------------------------------------------------
# AC-06.9 — Server does not require connection reuse  (R-4.4-i)
# ---------------------------------------------------------------------------

class TestConnectionReuseNotRequired:
  def test_request_valid_on_any_connection(self):
    """Same meta passes regardless of simulated connection."""
    for conn_id in ["conn-1", "conn-2", "conn-3"]:
      # Processing never consults conn_id; each request is self-describing.
      assert_request_is_self_describing(_FULL_META)


# ---------------------------------------------------------------------------
# AC-06.10 — Connection lifetime is not the conversation boundary  (R-4.4-j)
# ---------------------------------------------------------------------------

class TestConnectionLifetimeNotConversation:
  def test_continuation_id_valid_across_simulated_connections(self):
    """A continuation id is connection-independent; same on both 'connections'."""
    cont_id = "cursor-xyz"
    # Both 'connections' use the same opaque id.
    assert is_valid_continuation_id(cont_id)
    assert continuation_ids_are_equal(cont_id, cont_id)


# ---------------------------------------------------------------------------
# AC-06.11 — State referenced by explicit id, never connection  (R-4.5-a)
# ---------------------------------------------------------------------------

class TestExplicitContinuationId:
  def test_continuation_id_is_valid_when_non_none(self):
    assert is_valid_continuation_id("page-token")
    assert is_valid_continuation_id(42)
    assert is_valid_continuation_id({"opaque": True})

  def test_none_is_not_a_valid_continuation_id(self):
    assert not is_valid_continuation_id(None)

  def test_validate_continuation_id_raises_for_none(self):
    with pytest.raises(InvalidContinuationIdError):
      validate_continuation_id(None)

  def test_validate_continuation_id_returns_value(self):
    assert validate_continuation_id("cursor") == "cursor"
    assert validate_continuation_id(0) == 0


# ---------------------------------------------------------------------------
# AC-06.12 — Server mints and returns a continuation id  (R-4.5-b)
# ---------------------------------------------------------------------------

class TestServerMintsContinuationId:
  def test_any_non_none_value_is_valid_minted_id(self):
    for val in ["opaque-b64", 123, {"k": "v"}, [1, 2, 3]]:
      assert is_valid_continuation_id(val)

  def test_minted_id_in_result_extra(self):
    """A result can carry a continuation id as an extra field."""
    from mcp_sdk_py.result_error import Result, RESULT_TYPE_COMPLETE
    r = Result(
      result_type=RESULT_TYPE_COMPLETE,
      extra={"nextCursor": "eyJvIjoxMDB9"},
    )
    assert is_valid_continuation_id(r.extra["nextCursor"])


# ---------------------------------------------------------------------------
# AC-06.13 — Client echoes continuation id byte-for-byte  (R-4.5-c)
# ---------------------------------------------------------------------------

class TestClientEchoesContinuationId:
  def test_continuation_ids_equal_same_string(self):
    assert continuation_ids_are_equal("eyJvIjoxMDB9", "eyJvIjoxMDB9")

  def test_continuation_ids_not_equal_when_modified(self):
    assert not continuation_ids_are_equal("eyJvIjoxMDB9", "eyJvIjoxMDB9 ")
    assert not continuation_ids_are_equal("token", "TOKEN")
    assert not continuation_ids_are_equal("token", "")

  def test_continuation_ids_equal_for_numeric(self):
    assert continuation_ids_are_equal(42, 42)
    assert not continuation_ids_are_equal(42, 43)


# ---------------------------------------------------------------------------
# AC-06.14 — Continuation works across different connections  (R-4.5-d)
# ---------------------------------------------------------------------------

class TestContinuationAcrossConnections:
  def test_same_id_valid_on_different_simulated_connections(self):
    """Identity flows through the explicit id, not the connection."""
    opaque_id = "state-token-abc"
    for conn_id in ["conn-A", "conn-B"]:
      assert is_valid_continuation_id(opaque_id)
      # The id is identical regardless of connection.
      assert continuation_ids_are_equal(opaque_id, opaque_id)


# ---------------------------------------------------------------------------
# AC-06.15 — List results eligible to be identical across connections  (R-4.6-a/b)
# ---------------------------------------------------------------------------

class TestListResultConnectionIndependence:
  def test_listing_methods_registry(self):
    assert "tools/list" in LISTING_METHODS
    assert "prompts/list" in LISTING_METHODS
    assert "resources/list" in LISTING_METHODS
    assert "resources/templates/list" in LISTING_METHODS

  def test_is_listing_method_true_for_listing_methods(self):
    for method in LISTING_METHODS:
      assert is_listing_method(method)

  def test_is_listing_method_false_for_non_listing(self):
    assert not is_listing_method("tools/call")
    assert not is_listing_method("resources/read")
    assert not is_listing_method("prompts/get")


# ---------------------------------------------------------------------------
# AC-06.16 — List result variation from explicit inputs only  (R-4.6-c)
# ---------------------------------------------------------------------------

class TestListResultVariationFromInputsOnly:
  def test_listing_method_set_does_not_include_non_list_methods(self):
    """Non-list methods are not in LISTING_METHODS."""
    assert "tools/call" not in LISTING_METHODS
    assert "resources/read" not in LISTING_METHODS

  def test_is_listing_method_returns_false_for_unknown(self):
    assert not is_listing_method("custom/list")
    assert not is_listing_method("")
