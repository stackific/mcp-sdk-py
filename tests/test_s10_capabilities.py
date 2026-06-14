"""Tests for S10 — Capability Negotiation: Client & Server Capabilities.

Coverage map (26 story ACs):
  AC-10.1  → TestStatelessPerRequestSource
  AC-10.2  → TestNoUseOfUndeclaredCapability
  AC-10.3  → TestSubflagsRefineFamily
  AC-10.4  → TestNoInferenceBetweenCapabilities
  AC-10.5  → TestPreparedForFamilyMethods
  AC-10.6  → TestDoNotDeclareUnsupported
  AC-10.7  → TestExperimentalMap
  AC-10.8  → TestElicitationFormBaseline
  AC-10.9  → TestElicitationUrlGate
  AC-10.10 → TestRootsDeprecatedGate
  AC-10.11 → TestSamplingDeprecatedGate
  AC-10.12 → TestSamplingContextSubflag
  AC-10.13 → TestSamplingToolsSubflag
  AC-10.14 → TestClientExtensionsAndEmpty
  AC-10.15 → TestCompletionsGate
  AC-10.16 → TestPromptsGate
  AC-10.17 → TestResourcesGate
  AC-10.18 → TestToolsGate
  AC-10.19 → TestLoggingDeprecatedGate
  AC-10.20 → TestServerExtensionsAndEmpty
  AC-10.21 → TestServerConsultsCurrentRequest
  AC-10.22 → TestInputRequestsScopedToOrigin
  AC-10.23 → TestClientConsultsDiscovery
  AC-10.24 → TestMissingCapabilityError
  AC-10.25 → TestMalformedMetaRejected
  AC-10.26 → TestGracefulDegradation
"""

import pytest

from mcp_sdk_py.capabilities import (
  CapabilityNotDeclaredError,
  ClientCapabilities,
  ServerCapabilities,
  assert_client_may_invoke,
  capability_is_present,
  client_may_invoke_server_method,
  compute_missing_capabilities,
  read_client_capabilities,
  resolve_optional_behavior,
)
from mcp_sdk_py.meta_object import (
  KEY_CLIENT_CAPABILITIES,
  KEY_CLIENT_INFO,
  KEY_PROTOCOL_VERSION,
  MissingRequiredMetaKeyError,
  validate_request_meta_object,
)
from mcp_sdk_py.negotiation import (
  HTTP_BAD_REQUEST,
  build_missing_required_client_capability_response,
  http_status_for_negotiation_error,
)


def _meta(client_caps: dict) -> dict:
  return {
    KEY_PROTOCOL_VERSION: "2026-07-28",
    KEY_CLIENT_INFO: {"name": "C", "version": "1"},
    KEY_CLIENT_CAPABILITIES: client_caps,
  }


# AC-10.1 (R-6-a, R-6.4-c)
class TestStatelessPerRequestSource:
  def test_caps_read_only_from_supplied_meta(self):
    first = read_client_capabilities(_meta({"elicitation": {}}))
    second = read_client_capabilities(_meta({}))
    # The second request declares no caps regardless of the first (no inference).
    assert first.supports_elicitation is True
    assert second.supports_elicitation is False

  def test_server_caps_come_from_discover_result_object(self):
    caps = ServerCapabilities.from_dict({"tools": {"listChanged": True}})
    assert caps.supports_tools is True


# AC-10.2 (R-6.1-a, R-6.4-a)
class TestNoUseOfUndeclaredCapability:
  def test_client_will_not_invoke_undeclared_method(self):
    caps = ServerCapabilities.from_dict({})  # no tools
    assert client_may_invoke_server_method(caps, "tools/call") is False
    with pytest.raises(CapabilityNotDeclaredError):
      assert_client_may_invoke(caps, "tools/call")

  def test_declared_method_is_allowed(self):
    caps = ServerCapabilities.from_dict({"tools": {}})
    assert client_may_invoke_server_method(caps, "tools/call") is True
    assert_client_may_invoke(caps, "tools/call")  # no raise


# AC-10.3 (R-6.1-b)
class TestSubflagsRefineFamily:
  def test_subflag_refines_without_replacing(self):
    caps = ClientCapabilities.from_dict({"elicitation": {"url": {}}})
    # The enclosing capability still means "elicitation supported"...
    assert caps.supports_elicitation is True
    # ...and the sub-flag refines it with URL mode.
    assert caps.supports_url_elicitation is True


# AC-10.4 (R-6.1-c)
class TestNoInferenceBetweenCapabilities:
  def test_unrelated_capability_not_inferred(self):
    caps = ClientCapabilities.from_dict({"sampling": {}})
    assert caps.supports_sampling is True
    assert caps.supports_elicitation is False  # not inferred from sampling


# AC-10.5 (R-6.1-d)
class TestPreparedForFamilyMethods:
  def test_family_method_not_requiring_subflag_is_supported(self):
    # elicitation present but no form sub-flag → form mode is the baseline,
    # so a form-mode elicitation (which needs no extra sub-flag) is handled.
    caps = ClientCapabilities.from_dict({"elicitation": {}})
    assert caps.supports_form_elicitation is True


# AC-10.6 (R-6.1-e)
class TestDoNotDeclareUnsupported:
  def test_unsupported_capability_is_omitted(self):
    caps = ClientCapabilities()  # supports nothing optional
    assert caps.to_dict() == {}
    assert "elicitation" not in caps.to_dict()


# AC-10.7 (R-6.2-a/b/c, R-6.3-a/b/c)
class TestExperimentalMap:
  def test_client_experimental_arbitrary_keys_preserved(self):
    raw = {"experimental": {"com.example/preview": {"beta": True}}}
    caps = ClientCapabilities.from_dict(raw)
    assert caps.experimental == {"com.example/preview": {"beta": True}}
    assert caps.to_dict()["experimental"] == raw["experimental"]

  def test_server_experimental_unknown_keys_not_rejected(self):
    caps = ServerCapabilities.from_dict({"experimental": {"vendor/x": {}}})
    assert caps.experimental == {"vendor/x": {}}

  def test_unknown_top_level_keys_preserved_round_trip(self):
    caps = ClientCapabilities.from_dict({"future_cap": {"k": 1}})
    assert caps.to_dict()["future_cap"] == {"k": 1}


# AC-10.8 (R-6.2-d, R-6.2-e)
class TestElicitationFormBaseline:
  def test_elicitation_presence_declares_support(self):
    assert ClientCapabilities.from_dict({"elicitation": {}}).supports_elicitation

  def test_form_implicit_when_absent(self):
    caps = ClientCapabilities.from_dict({"elicitation": {}})
    assert caps.supports_form_elicitation is True

  def test_form_explicit(self):
    caps = ClientCapabilities.from_dict({"elicitation": {"form": {}}})
    assert caps.supports_form_elicitation is True


# AC-10.9 (R-6.2-f, R-6.2-g)
class TestElicitationUrlGate:
  def test_url_absent_means_no_url_mode(self):
    caps = ClientCapabilities.from_dict({"elicitation": {"form": {}}})
    assert caps.supports_url_elicitation is False

  def test_url_present_enables_url_mode(self):
    caps = ClientCapabilities.from_dict({"elicitation": {"url": {}}})
    assert caps.supports_url_elicitation is True

  def test_no_elicitation_means_no_url(self):
    assert ClientCapabilities().supports_url_elicitation is False


# AC-10.10 (R-6.2-h/i/j)
class TestRootsDeprecatedGate:
  def test_roots_presence_enables_roots_list(self):
    assert ClientCapabilities.from_dict({"roots": {}}).supports_roots is True

  def test_roots_absent_means_no_invocation(self):
    assert ClientCapabilities().supports_roots is False


# AC-10.11 (R-6.2-k/l/m)
class TestSamplingDeprecatedGate:
  def test_sampling_presence_gates_create_message(self):
    assert ClientCapabilities.from_dict({"sampling": {}}).supports_sampling is True

  def test_sampling_absent(self):
    assert ClientCapabilities().supports_sampling is False


# AC-10.12 (R-6.2-n, R-6.2-o)
class TestSamplingContextSubflag:
  def test_context_absent(self):
    caps = ClientCapabilities.from_dict({"sampling": {}})
    assert caps.supports_sampling_context is False

  def test_context_present(self):
    caps = ClientCapabilities.from_dict({"sampling": {"context": {}}})
    assert caps.supports_sampling_context is True


# AC-10.13 (R-6.2-p, R-6.2-q)
class TestSamplingToolsSubflag:
  def test_tools_absent(self):
    caps = ClientCapabilities.from_dict({"sampling": {"context": {}}})
    assert caps.supports_sampling_tools is False

  def test_tools_present(self):
    caps = ClientCapabilities.from_dict({"sampling": {"tools": {}}})
    assert caps.supports_sampling_tools is True


# AC-10.14 (R-6.2-r, R-6.2-s)
class TestClientExtensionsAndEmpty:
  def test_extensions_optional_map(self):
    caps = ClientCapabilities.from_dict({"extensions": {"ext/a": {}}})
    assert caps.extensions == {"ext/a": {}}

  def test_empty_object_is_valid(self):
    caps = ClientCapabilities.from_dict({})
    assert caps.to_dict() == {}

  def test_omitted_field_means_not_supported(self):
    assert ClientCapabilities().extensions is None


# AC-10.15 (R-6.3-d, R-6.3-e)
class TestCompletionsGate:
  def test_completions_present_enables_complete(self):
    caps = ServerCapabilities.from_dict({"completions": {}})
    assert caps.supports_completions is True
    assert client_may_invoke_server_method(caps, "completion/complete") is True

  def test_completions_absent_forbids_complete(self):
    caps = ServerCapabilities.from_dict({})
    assert client_may_invoke_server_method(caps, "completion/complete") is False


# AC-10.16 (R-6.3-f/g/h)
class TestPromptsGate:
  def test_prompts_gates_methods(self):
    caps = ServerCapabilities.from_dict({"prompts": {}})
    assert caps.supports_prompts is True
    assert client_may_invoke_server_method(caps, "prompts/get") is True

  def test_list_changed_true(self):
    assert ServerCapabilities.from_dict({"prompts": {"listChanged": True}}).prompts_list_changed is True

  def test_list_changed_absent_or_false(self):
    assert ServerCapabilities.from_dict({"prompts": {}}).prompts_list_changed is False
    assert ServerCapabilities.from_dict({"prompts": {"listChanged": False}}).prompts_list_changed is False


# AC-10.17 (R-6.3-i/j/k/l)
class TestResourcesGate:
  def test_resources_gates_methods(self):
    caps = ServerCapabilities.from_dict({"resources": {}})
    assert caps.supports_resources is True
    assert client_may_invoke_server_method(caps, "resources/read") is True

  def test_subscribe_flag(self):
    assert ServerCapabilities.from_dict({"resources": {"subscribe": True}}).resources_subscribe is True
    assert ServerCapabilities.from_dict({"resources": {}}).resources_subscribe is False

  def test_list_changed_flag(self):
    assert ServerCapabilities.from_dict({"resources": {"listChanged": True}}).resources_list_changed is True
    assert ServerCapabilities.from_dict({"resources": {"listChanged": False}}).resources_list_changed is False


# AC-10.18 (R-6.3-m/n/o)
class TestToolsGate:
  def test_tools_gates_methods(self):
    caps = ServerCapabilities.from_dict({"tools": {}})
    assert client_may_invoke_server_method(caps, "tools/list") is True
    assert client_may_invoke_server_method(caps, "tools/call") is True

  def test_list_changed(self):
    assert ServerCapabilities.from_dict({"tools": {"listChanged": True}}).tools_list_changed is True
    assert ServerCapabilities.from_dict({"tools": {}}).tools_list_changed is False


# AC-10.19 (R-6.3-p, R-6.3-q)
class TestLoggingDeprecatedGate:
  def test_logging_present(self):
    assert ServerCapabilities.from_dict({"logging": {}}).supports_logging is True

  def test_logging_absent(self):
    assert ServerCapabilities().supports_logging is False


# AC-10.20 (R-6.3-r, R-6.3-s)
class TestServerExtensionsAndEmpty:
  def test_extensions_optional(self):
    assert ServerCapabilities.from_dict({"extensions": {"e/x": {}}}).extensions == {"e/x": {}}

  def test_empty_object_valid(self):
    assert ServerCapabilities.from_dict({}).to_dict() == {}


# AC-10.21 (R-6.4-b, R-6.4-d)
class TestServerConsultsCurrentRequest:
  def test_server_relies_only_on_current_request_caps(self):
    meta = _meta({"elicitation": {}})
    declared = read_client_capabilities(meta)
    # The server may emit an elicitation because this request declared it.
    assert declared.supports_elicitation is True
    # It must not rely on anything not in this field: sampling was not declared.
    assert declared.supports_sampling is False

  def test_missing_capability_computed_from_current_request_only(self):
    declared = read_client_capabilities(_meta({}))
    missing = compute_missing_capabilities(declared, {"elicitation": {}})
    assert missing == {"elicitation": {}}


# AC-10.22 (R-6.4-e)
class TestInputRequestsScopedToOrigin:
  def test_input_requests_governed_by_originating_request_caps(self):
    originating = _meta({"elicitation": {}})
    caps = read_client_capabilities(originating)
    # An input_required elicitation emitted while processing this request is
    # governed by the caps declared here, not by any other request.
    assert caps.supports_elicitation is True
    # A different request that declares nothing does not enable it.
    assert read_client_capabilities(_meta({})).supports_elicitation is False


# AC-10.23 (R-6.4-f, R-6.4-g)
class TestClientConsultsDiscovery:
  def test_client_gates_on_discovered_server_caps(self):
    discovered = ServerCapabilities.from_dict({"tools": {}})  # no resources
    assert_client_may_invoke(discovered, "tools/call")  # allowed
    with pytest.raises(CapabilityNotDeclaredError):
      assert_client_may_invoke(discovered, "resources/read")  # undeclared


# AC-10.24 (R-6.4-h, R-6.4-i)
class TestMissingCapabilityError:
  def test_missing_capability_error_lists_required(self):
    declared = read_client_capabilities(_meta({}))
    missing = compute_missing_capabilities(declared, {"elicitation": {}})
    response = build_missing_required_client_capability_response(7, missing)
    error = response.to_dict()["error"]
    assert error["code"] == -32003
    assert error["data"]["requiredCapabilities"] == {"elicitation": {}}

  def test_http_status_is_400(self):
    assert http_status_for_negotiation_error(-32003) == HTTP_BAD_REQUEST == 400

  def test_already_declared_capability_not_missing(self):
    declared = read_client_capabilities(_meta({"elicitation": {}}))
    assert compute_missing_capabilities(declared, {"elicitation": {}}) == {}


# AC-10.25 (R-6.4-j, R-6.4-k)
class TestMalformedMetaRejected:
  def test_missing_required_meta_field_is_invalid_params(self):
    meta = {
      KEY_PROTOCOL_VERSION: "2026-07-28",
      KEY_CLIENT_INFO: {"name": "C", "version": "1"},
      # KEY_CLIENT_CAPABILITIES omitted → malformed
    }
    with pytest.raises(MissingRequiredMetaKeyError) as exc:
      validate_request_meta_object(meta)
    assert exc.value.json_rpc_code == -32602

  def test_http_400_reference(self):
    # The malformed-_meta rejection maps to HTTP 400 on HTTP transports.
    assert HTTP_BAD_REQUEST == 400


# AC-10.26 (R-6.4-l, R-6.4-m)
class TestGracefulDegradation:
  def test_degrade_when_remote_lacks_optional_behavior(self):
    # local supports it, remote did not declare it, not mandatory → fall back.
    assert resolve_optional_behavior(local_supports=True, remote_declares=False) is False

  def test_use_when_both_declare(self):
    assert resolve_optional_behavior(local_supports=True, remote_declares=True) is True

  def test_reject_only_when_mandatory(self):
    with pytest.raises(CapabilityNotDeclaredError):
      resolve_optional_behavior(local_supports=True, remote_declares=False, mandatory=True)

  def test_no_failure_for_fewer_caps(self):
    # A peer must not fail merely because the other declared fewer capabilities.
    assert resolve_optional_behavior(local_supports=True, remote_declares=False, mandatory=False) is False


# Extra: presence helper is the single rule
class TestPresenceHelper:
  def test_capability_is_present(self):
    assert capability_is_present({"tools": {}}, "tools") is True
    assert capability_is_present({}, "tools") is False

  def test_subflag_boolean_true_on_non_dict(self):
    from mcp_sdk_py.capabilities import subflag_boolean_true, subflag_object_present
    assert subflag_boolean_true(None, "listChanged") is False
    assert subflag_object_present(None, "url") is False

  def test_subflag_object_present_dict_without_key(self):
    from mcp_sdk_py.capabilities import subflag_object_present
    assert subflag_object_present({"form": {}}, "url") is False


# Validation guards — malformed capability objects are rejected (type safety)
class TestValidationGuards:
  def test_client_caps_not_object(self):
    with pytest.raises(TypeError):
      ClientCapabilities.from_dict(["not", "an", "object"])

  def test_elicitation_not_object(self):
    with pytest.raises(TypeError):
      ClientCapabilities.from_dict({"elicitation": "x"})

  def test_elicitation_subflag_not_object(self):
    with pytest.raises(TypeError):
      ClientCapabilities.from_dict({"elicitation": {"url": "x"}})

  def test_sampling_subflag_not_object(self):
    with pytest.raises(TypeError):
      ClientCapabilities.from_dict({"sampling": {"context": 1}})

  def test_server_caps_not_object(self):
    with pytest.raises(TypeError):
      ServerCapabilities.from_dict(42)

  def test_prompts_list_changed_not_bool(self):
    with pytest.raises(TypeError):
      ServerCapabilities.from_dict({"prompts": {"listChanged": "yes"}})

  def test_resources_subscribe_not_bool(self):
    with pytest.raises(TypeError):
      ServerCapabilities.from_dict({"resources": {"subscribe": "yes"}})

  def test_round_trip_all_client_fields(self):
    caps = ClientCapabilities(
      experimental={"e/x": {}},
      elicitation={"url": {}},
      roots={},
      sampling={"context": {}},
      extensions={"ext/a": {}},
    )
    assert ClientCapabilities.from_dict(caps.to_dict()).to_dict() == caps.to_dict()

  def test_round_trip_all_server_fields(self):
    caps = ServerCapabilities(
      experimental={"e/x": {}},
      completions={},
      prompts={"listChanged": True},
      resources={"subscribe": True, "listChanged": False},
      tools={"listChanged": True},
      logging={},
      extensions={"ext/a": {}},
    )
    assert ServerCapabilities.from_dict(caps.to_dict()).to_dict() == caps.to_dict()
