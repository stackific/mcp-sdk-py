"""Tests for S09 — Revision Selection & Negotiation Errors.

Coverage map (18 story ACs):
  AC-09.1  → TestProceedWithoutDiscovery
  AC-09.2  → TestSelectionRule
  AC-09.3  → TestEmptyIntersectionNoFabrication
  AC-09.4  → TestEmptyIntersectionSurfaces
  AC-09.5  → TestUnsupportedVersionCode
  AC-09.6  → TestUnsupportedVersionHttp400
  AC-09.7  → TestUnsupportedVersionData
  AC-09.8  → TestClientReselectsAndRetries
  AC-09.9  → TestNoInfiniteRetry
  AC-09.10 → TestStatelessCapabilityDeclaration
  AC-09.11 → TestMissingCapabilityCode
  AC-09.12 → TestMissingCapabilityHttp400
  AC-09.13 → TestMissingCapabilityData
  AC-09.14 → TestClientRetriesWithCapability
  AC-09.15 → TestProbeOpeningRequest
  AC-09.16 → TestProbeUnrecognized
  AC-09.17 → TestProbeCacheAndPersist
  AC-09.18 → TestServerNamesSupportedRevisions
"""

import pytest

from mcp_sdk_py.capabilities import ClientCapabilities
from mcp_sdk_py.meta_object import (
  KEY_CLIENT_CAPABILITIES,
  KEY_PROTOCOL_VERSION,
  MissingRequiredClientCapabilityError,
  require_client_capability,
)
from mcp_sdk_py.negotiation import (
  HTTP_BAD_REQUEST,
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
  IncompatibleRevisionsError,
  ProbeOutcome,
  ProtocolSupportCache,
  RevisionNegotiator,
  build_missing_required_client_capability_response,
  build_probe_request,
  build_unspeakable_opening_error,
  build_unsupported_protocol_version_error,
  build_unsupported_protocol_version_response,
  can_satisfy_required_capabilities,
  http_status_for_negotiation_error,
  interpret_probe_response,
  parse_missing_required_client_capability_error,
  parse_unsupported_protocol_version_error,
  retry_meta_with_capabilities,
  select_revision,
  select_revision_or_raise,
)

CURRENT = "2026-07-28"


# AC-09.1 (R-5.4-a)
class TestProceedWithoutDiscovery:
  def test_client_may_declare_revision_without_discover(self):
    # No server/discover call; the client declares a revision directly and the
    # selection rule works from its own preferences against a known server set.
    chosen = select_revision([CURRENT], [CURRENT])
    assert chosen == CURRENT

  def test_meta_carries_selected_revision(self):
    meta = {KEY_PROTOCOL_VERSION: select_revision([CURRENT], [CURRENT])}
    assert meta[KEY_PROTOCOL_VERSION] == CURRENT


# AC-09.2 (R-5.4-b)
class TestSelectionRule:
  def test_highest_by_client_preference_not_string_order(self):
    # Client prefers B then A; server supports A and B. Highest = B (first in
    # client preference present in the server set), not lexical max.
    assert select_revision(["B", "A"], ["A", "B"]) == "B"

  def test_exact_matching(self):
    # Identifiers compare exactly: a near-miss is not selected.
    assert select_revision(["2026-07-28"], ["2026-07-29"]) is None

  def test_first_preference_wins(self):
    assert select_revision(["A", "B"], ["A", "B"]) == "A"


# AC-09.3 (R-5.4-c)
class TestEmptyIntersectionNoFabrication:
  def test_returns_none_does_not_fabricate(self):
    assert select_revision(["X", "Y"], ["A", "B"]) is None


# AC-09.4 (R-5.4-d)
class TestEmptyIntersectionSurfaces:
  def test_raises_actionable_incompatibility(self):
    with pytest.raises(IncompatibleRevisionsError) as exc:
      select_revision_or_raise(["X"], ["A", "B"])
    assert exc.value.client_revisions == ["X"]
    assert exc.value.server_revisions == ["A", "B"]


# AC-09.5 (R-5.5-a, R-5.5-d)
class TestUnsupportedVersionCode:
  def test_code_is_minus_32004(self):
    err = build_unsupported_protocol_version_error([CURRENT], "1900-01-01")
    assert err.code == UNSUPPORTED_PROTOCOL_VERSION_CODE == -32004

  def test_response_carries_code(self):
    resp = build_unsupported_protocol_version_response(1, [CURRENT], "1900-01-01")
    assert resp.to_dict()["error"]["code"] == -32004


# AC-09.6 (R-5.5-b)
class TestUnsupportedVersionHttp400:
  def test_http_status_400(self):
    assert http_status_for_negotiation_error(-32004) == HTTP_BAD_REQUEST == 400


# AC-09.7 (R-5.5-c/e/f/g)
class TestUnsupportedVersionData:
  def test_data_has_exactly_supported_and_requested(self):
    err = build_unsupported_protocol_version_error([CURRENT], "1900-01-01")
    data = err.to_dict()["data"]
    assert set(data.keys()) == {"supported", "requested"}

  def test_supported_nonempty_array_requested_string_message_present(self):
    err = build_unsupported_protocol_version_error([CURRENT], "1900-01-01")
    d = err.to_dict()
    assert isinstance(d["data"]["supported"], list) and d["data"]["supported"]
    assert isinstance(d["data"]["requested"], str)
    assert isinstance(d["message"], str) and d["message"]

  def test_empty_supported_rejected(self):
    with pytest.raises(ValueError):
      build_unsupported_protocol_version_error([], "1900-01-01")

  def test_wire_example_matches_spec(self):
    err = build_unsupported_protocol_version_error(["2026-07-28"], "1900-01-01")
    assert err.to_dict() == {
      "code": -32004,
      "message": "Unsupported protocol version",
      "data": {"supported": ["2026-07-28"], "requested": "1900-01-01"},
    }


# AC-09.8 (R-5.5-h)
class TestClientReselectsAndRetries:
  def test_reselect_from_error_supported_and_retry(self):
    neg = RevisionNegotiator(client_preferences=["2026-07-28", "2025-01-01"])
    # Initial attempt picked the current revision against a stale assumption.
    neg.select(["2026-07-28"])
    # Server actually rejects it and advertises only the older revision.
    error = build_unsupported_protocol_version_error(["2025-01-01"], "2026-07-28")
    chosen = neg.react_to_unsupported(error)
    assert chosen == "2025-01-01"

  def test_parse_extracts_supported_and_requested(self):
    error = build_unsupported_protocol_version_error([CURRENT], "1900-01-01")
    supported, requested = parse_unsupported_protocol_version_error(error)
    assert supported == [CURRENT]
    assert requested == "1900-01-01"


# AC-09.9 (R-5.5-i, R-5.5-j)
class TestNoInfiniteRetry:
  def test_no_mutual_revision_raises_not_loops(self):
    neg = RevisionNegotiator(client_preferences=["2026-07-28"])
    neg.select(["2026-07-28"])
    # Server advertises a revision the client does not support → cannot re-select.
    error = build_unsupported_protocol_version_error(["1999-01-01"], "2026-07-28")
    with pytest.raises(IncompatibleRevisionsError):
      neg.react_to_unsupported(error)

  def test_does_not_reattempt_same_revision(self):
    neg = RevisionNegotiator(client_preferences=["A", "B"])
    neg.select(["A", "B"])  # picks A
    # Error still only lists A (already attempted) → no new revision → raise.
    error = build_unsupported_protocol_version_error(["A"], "A")
    with pytest.raises(IncompatibleRevisionsError):
      neg.react_to_unsupported(error)


# AC-09.10 (R-5.6-a, R-5.6-b)
class TestStatelessCapabilityDeclaration:
  def test_empty_object_declares_no_caps_no_inference(self):
    # First request declared elicitation; second declares {} → must be treated
    # as no optional capabilities, with no inference from the first.
    first_meta = {KEY_CLIENT_CAPABILITIES: {"elicitation": {}}}
    second_meta = {KEY_CLIENT_CAPABILITIES: {}}
    # The second request's gate uses only the second request's caps.
    with pytest.raises(MissingRequiredClientCapabilityError):
      require_client_capability(second_meta, {"elicitation": {}})
    # The first request, by contrast, satisfied it.
    require_client_capability(first_meta, {"elicitation": {}})  # no raise


# AC-09.11 (R-5.6-c, R-5.6-f)
class TestMissingCapabilityCode:
  def test_code_is_minus_32003(self):
    resp = build_missing_required_client_capability_response(42, {"elicitation": {}})
    assert resp.to_dict()["error"]["code"] == MISSING_REQUIRED_CLIENT_CAPABILITY_CODE == -32003


# AC-09.12 (R-5.6-d)
class TestMissingCapabilityHttp400:
  def test_http_400(self):
    assert http_status_for_negotiation_error(-32003) == 400


# AC-09.13 (R-5.6-e/g/h)
class TestMissingCapabilityData:
  def test_data_has_required_capabilities_and_message(self):
    resp = build_missing_required_client_capability_response(42, {"elicitation": {}})
    err = resp.to_dict()["error"]
    assert err["data"]["requiredCapabilities"] == {"elicitation": {}}
    assert isinstance(err["message"], str) and err["message"]

  def test_accepts_client_capabilities_object(self):
    caps = ClientCapabilities(elicitation={})
    resp = build_missing_required_client_capability_response(1, caps)
    assert resp.to_dict()["error"]["data"]["requiredCapabilities"] == {"elicitation": {}}

  def test_parse_extracts_required(self):
    resp = build_missing_required_client_capability_response(1, {"elicitation": {}})
    required = parse_missing_required_client_capability_error(resp.to_dict()["error"])
    assert required == {"elicitation": {}}

  def test_wire_example_matches_spec(self):
    resp = build_missing_required_client_capability_response(42, {"elicitation": {}})
    assert resp.to_dict() == {
      "jsonrpc": "2.0",
      "id": 42,
      "error": {
        "code": -32003,
        "message": "Required client capability not declared",
        "data": {"requiredCapabilities": {"elicitation": {}}},
      },
    }


# AC-09.14 (R-5.6-i)
class TestClientRetriesWithCapability:
  def test_can_satisfy_and_retry_adds_capability(self):
    error = {"code": -32003, "message": "x", "data": {"requiredCapabilities": {"elicitation": {}}}}
    required = parse_missing_required_client_capability_error(error)
    assert can_satisfy_required_capabilities({"elicitation": {}}, required) is True
    original_meta = {KEY_CLIENT_CAPABILITIES: {}}
    retried = retry_meta_with_capabilities(original_meta, required)
    assert retried[KEY_CLIENT_CAPABILITIES] == {"elicitation": {}}
    # Original meta is not mutated (per-request, stateless).
    assert original_meta[KEY_CLIENT_CAPABILITIES] == {}

  def test_cannot_satisfy(self):
    required = {"elicitation": {}}
    assert can_satisfy_required_capabilities({"sampling": {}}, required) is False


# AC-09.15 (R-5.7-a, R-5.7-b)
class TestProbeOpeningRequest:
  def test_probe_is_server_discover(self):
    req = build_probe_request()
    assert req.method == "server/discover"
    assert req.params == {}

  def test_successful_discover_means_supported(self):
    response = {
      "jsonrpc": "2.0",
      "id": 0,
      "result": {
        "resultType": "complete",
        "supportedVersions": [CURRENT],
        "capabilities": {},
        "serverInfo": {"name": "S", "version": "1"},
      },
    }
    result = interpret_probe_response(response)
    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.supported_versions == [CURRENT]
    assert result.speaks_protocol is True

  def test_recognized_unsupported_error_means_family_supported(self):
    response = {
      "jsonrpc": "2.0",
      "id": 0,
      "error": build_unsupported_protocol_version_error([CURRENT], "1900-01-01").to_dict(),
    }
    result = interpret_probe_response(response)
    assert result.outcome is ProbeOutcome.FAMILY_SUPPORTED_REVISION_UNSUPPORTED
    assert result.supported_versions == [CURRENT]
    assert result.speaks_protocol is True


# AC-09.16 (R-5.7-c, R-5.7-d)
class TestProbeUnrecognized:
  def test_unknown_method_error_not_speaking(self):
    response = {"jsonrpc": "2.0", "id": 0, "error": {"code": -32601, "message": "Method not found"}}
    result = interpret_probe_response(response)
    assert result.outcome is ProbeOutcome.NOT_SUPPORTED
    assert result.speaks_protocol is False

  def test_timeout_none_not_speaking(self):
    assert interpret_probe_response(None).outcome is ProbeOutcome.NOT_SUPPORTED

  def test_malformed_result_not_speaking(self):
    # A "result" that does not validate as a DiscoverResult is not recognized.
    response = {"jsonrpc": "2.0", "id": 0, "result": {"resultType": "complete"}}
    assert interpret_probe_response(response).outcome is ProbeOutcome.NOT_SUPPORTED

  def test_response_with_neither_result_nor_error_not_speaking(self):
    assert interpret_probe_response({"jsonrpc": "2.0", "id": 0}).outcome is ProbeOutcome.NOT_SUPPORTED


# AC-09.17 (R-5.7-e, R-5.7-f)
class TestProbeCacheAndPersist:
  def test_cache_for_endpoint_lifetime(self):
    cache = ProtocolSupportCache()
    response = {
      "jsonrpc": "2.0", "id": 0,
      "result": {
        "resultType": "complete", "supportedVersions": [CURRENT],
        "capabilities": {}, "serverInfo": {"name": "S", "version": "1"},
      },
    }
    cache.record("https://example.com/mcp", interpret_probe_response(response))
    cached = cache.get("https://example.com/mcp")
    assert cached is not None and cached.speaks_protocol is True
    assert cache.is_cached("https://example.com/mcp")

  def test_persist_round_trip(self):
    cache = ProtocolSupportCache()
    cache.record("ep", interpret_probe_response(None))  # NOT_SUPPORTED
    persisted = cache.to_dict()
    revived = ProtocolSupportCache.from_dict(persisted)
    assert revived.get("ep").speaks_protocol is False

  def test_reprobe_after_invalidation(self):
    cache = ProtocolSupportCache()
    cache.record("ep", interpret_probe_response(None))
    cache.invalidate("ep")  # cached assumption proved wrong → re-probe
    assert cache.get("ep") is None
    assert not cache.is_cached("ep")


# AC-09.18 (R-5.7-g)
class TestServerNamesSupportedRevisions:
  def test_error_names_supported_revisions(self):
    resp = build_unspeakable_opening_error(None, [CURRENT])
    data = resp.to_dict()["error"]["data"]
    assert data["supported"] == [CURRENT]
    assert resp.to_dict()["error"]["code"] == -32004


# Extra: HTTP mapping rejects non-negotiation codes
class TestHttpMappingGuard:
  def test_non_negotiation_code_rejected(self):
    with pytest.raises(ValueError):
      http_status_for_negotiation_error(-32601)


# Validation guards — malformed errors and inputs are rejected
class TestNegotiationGuards:
  def test_build_unsupported_rejects_non_string_supported(self):
    with pytest.raises(ValueError):
      build_unsupported_protocol_version_error([123], "x")

  def test_build_unsupported_rejects_non_string_requested(self):
    with pytest.raises(TypeError):
      build_unsupported_protocol_version_error([CURRENT], 123)

  def test_parse_unsupported_wrong_code(self):
    with pytest.raises(ValueError):
      parse_unsupported_protocol_version_error({"code": -1, "message": "x"})

  def test_parse_unsupported_missing_data(self):
    with pytest.raises(ValueError):
      parse_unsupported_protocol_version_error({"code": -32004, "message": "x"})

  def test_parse_unsupported_empty_supported(self):
    with pytest.raises(ValueError):
      parse_unsupported_protocol_version_error(
        {"code": -32004, "message": "x", "data": {"supported": [], "requested": "y"}}
      )

  def test_parse_unsupported_requested_not_string(self):
    with pytest.raises(ValueError):
      parse_unsupported_protocol_version_error(
        {"code": -32004, "message": "x", "data": {"supported": ["a"], "requested": 1}}
      )

  def test_parse_missing_wrong_code(self):
    with pytest.raises(ValueError):
      parse_missing_required_client_capability_error({"code": -1, "message": "x"})

  def test_parse_missing_no_required_field(self):
    with pytest.raises(ValueError):
      parse_missing_required_client_capability_error({"code": -32003, "message": "x", "data": {}})

  def test_parse_missing_required_not_object(self):
    with pytest.raises(ValueError):
      parse_missing_required_client_capability_error(
        {"code": -32003, "message": "x", "data": {"requiredCapabilities": []}}
      )

  def test_negotiator_attempted_snapshot(self):
    neg = RevisionNegotiator(["A", "B"])
    neg.select(["A", "B"])
    assert neg.attempted == frozenset({"A"})
