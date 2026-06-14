"""Tests for S30 — Elicitation I: Capability, Delivery & Modes.

Covers every normative atom and acceptance criterion of §20.1–§20.3.

AC → test coverage map (each AC has a dedicated test class):

  AC-30.1  (R-20.1-a)            → TestAC301DeclareCapability
  AC-30.2  (R-20.1-f)            → TestAC302SubflagShape
  AC-30.3  (R-20.1-b)            → TestAC303AtLeastOneMode
  AC-30.4  (R-20.1-c)            → TestAC304EmptyObjectEqualsFormOnly
  AC-30.5  (R-20.1-d)            → TestAC305ServerModeGating
  AC-30.6  (R-20.1-e)            → TestAC306ServerUndeclaredGating
  AC-30.7  (R-20.2-a)            → TestAC307DeliveryViaInputRequired
  AC-30.8  (R-20.2-b)            → TestAC308MethodLiteral
  AC-30.9  (R-20.2-c)            → TestAC309ParamsRequired
  AC-30.10 (R-20.3-a/b/c)        → TestAC3010FormModeOptional
  AC-30.11 (R-20.3-d)            → TestAC3011FormMessageRequired
  AC-30.12 (R-20.3-e)            → TestAC3012RequestedSchemaTypeObject
  AC-30.13 (R-20.3-f)            → TestAC3013PropertiesFlatMap
  AC-30.14 (R-20.3-g/h)          → TestAC3014RequiredAndSchemaOptional
  AC-30.15 (R-20.3-i/j)          → TestAC3015UrlModeRequired
  AC-30.16 (R-20.3-k/l)          → TestAC3016ElicitationIdOpaque
  AC-30.17 (R-20.3-m/n)          → TestAC3017UrlValid
"""

import pytest

from mcp_sdk_py.capabilities import ClientCapabilities
from mcp_sdk_py.meta_object import KEY_CLIENT_CAPABILITIES
from mcp_sdk_py.multi_round_trip import INPUT_REQUEST_ELICITATION
from mcp_sdk_py.elicitation import (
  CAPABILITY_NAME,
  ELICITATION_METHOD,
  MODE_FORM,
  MODE_URL,
  ElicitationCapabilityError,
  ElicitRequest,
  ElicitRequestFormParams,
  ElicitRequestParams,
  ElicitRequestURLParams,
  InvalidElicitRequestError,
  assert_server_may_elicit,
  client_supports_elicitation,
  client_supports_elicitation_mode,
  normalize_elicitation_capability,
  parse_elicit_request_params,
  read_client_capabilities_from_meta,
  supported_elicitation_modes,
  validate_elicitation_url,
)


# Convenience factories shared across tests.

def _form_schema() -> dict:
  return {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
    "required": ["name"],
  }


def _form_params_dict(*, with_mode: bool = True) -> dict:
  d = {"message": "Please provide your contact details", "requestedSchema": _form_schema()}
  if with_mode:
    d["mode"] = "form"
  return d


def _url_params_dict() -> dict:
  return {
    "mode": "url",
    "message": "Please complete payment authorization in your browser",
    "elicitationId": "elic-9f3c1a7e",
    "url": "https://pay.example.com/authorize?session=9f3c1a7e",
  }


# ---------------------------------------------------------------------------
# AC-30.1 — must declare the capability to support elicitation (R-20.1-a)
# ---------------------------------------------------------------------------

class TestAC301DeclareCapability:
  def test_declared_capability_means_supported(self):
    caps = ClientCapabilities.from_dict({"elicitation": {}})
    assert client_supports_elicitation(caps) is True

  def test_declared_via_raw_dict_means_supported(self):
    assert client_supports_elicitation({"elicitation": {"form": {}}}) is True

  def test_absent_capability_means_not_supported(self):
    caps = ClientCapabilities.from_dict({})
    assert client_supports_elicitation(caps) is False

  def test_absent_capability_raw_dict_not_supported(self):
    assert client_supports_elicitation({"sampling": {}}) is False

  def test_capability_name_constant(self):
    assert CAPABILITY_NAME == "elicitation"


# ---------------------------------------------------------------------------
# AC-30.2 — sub-flag shape: up to two optional object sub-flags (R-20.1-f)
# ---------------------------------------------------------------------------

class TestAC302SubflagShape:
  def test_both_subflags_present_objects(self):
    modes = normalize_elicitation_capability({"form": {}, "url": {}})
    assert modes == {"form": {}, "url": {}}

  def test_subflag_carries_settings_object(self):
    modes = normalize_elicitation_capability({"form": {"foo": "bar"}})
    assert modes["form"] == {"foo": "bar"}

  def test_empty_subflag_object_denotes_support(self):
    assert "url" in supported_elicitation_modes({"url": {}})

  def test_subflags_are_optional(self):
    # {} is a valid value (resolves to form-only via the equivalence).
    assert normalize_elicitation_capability({}) == {"form": {}}

  def test_non_object_capability_rejected(self):
    with pytest.raises(TypeError):
      normalize_elicitation_capability("nope")

  def test_non_object_subflag_rejected(self):
    with pytest.raises(TypeError):
      normalize_elicitation_capability({"form": True})

  def test_non_object_url_subflag_rejected(self):
    with pytest.raises(TypeError):
      normalize_elicitation_capability({"url": []})


# ---------------------------------------------------------------------------
# AC-30.3 — a declared capability supports at least one mode (R-20.1-b)
# ---------------------------------------------------------------------------

class TestAC303AtLeastOneMode:
  def test_form_only_has_a_mode(self):
    assert supported_elicitation_modes({"form": {}}) == frozenset({"form"})

  def test_url_only_has_a_mode(self):
    assert supported_elicitation_modes({"url": {}}) == frozenset({"url"})

  def test_empty_object_resolves_to_form_mode(self):
    # The backwards-compat equivalence guarantees at least one mode.
    assert supported_elicitation_modes({}) == frozenset({"form"})

  def test_declared_with_no_mode_keys_is_rejected(self):
    # A non-empty value naming neither form nor url declares no mode.
    with pytest.raises(ValueError):
      normalize_elicitation_capability({"other": {}})


# ---------------------------------------------------------------------------
# AC-30.4 — "elicitation": {} ≡ { "form": {} } (R-20.1-c)
# ---------------------------------------------------------------------------

class TestAC304EmptyObjectEqualsFormOnly:
  def test_empty_object_equivalent_to_form_only(self):
    assert normalize_elicitation_capability({}) == normalize_elicitation_capability({"form": {}})

  def test_empty_object_supports_form(self):
    assert client_supports_elicitation_mode({"elicitation": {}}, "form") is True

  def test_empty_object_does_not_support_url(self):
    assert client_supports_elicitation_mode({"elicitation": {}}, "url") is False

  def test_empty_object_modes_is_form_only(self):
    assert supported_elicitation_modes({}) == frozenset({"form"})

  def test_via_parsed_client_capabilities(self):
    caps = ClientCapabilities.from_dict({"elicitation": {}})
    assert client_supports_elicitation_mode(caps, "form") is True
    assert client_supports_elicitation_mode(caps, "url") is False


# ---------------------------------------------------------------------------
# AC-30.5 — server does not send an unsupported mode (R-20.1-d)
# ---------------------------------------------------------------------------

class TestAC305ServerModeGating:
  def test_url_mode_blocked_when_only_form_declared(self):
    with pytest.raises(ElicitationCapabilityError) as exc:
      assert_server_may_elicit({"elicitation": {}}, "url")
    assert exc.value.mode == "url"

  def test_url_mode_allowed_when_url_declared(self):
    # Should not raise.
    assert_server_may_elicit({"elicitation": {"url": {}}}, "url")

  def test_form_mode_allowed_when_form_declared(self):
    assert_server_may_elicit({"elicitation": {"form": {}}}, "form")

  def test_form_mode_allowed_under_empty_object(self):
    assert_server_may_elicit({"elicitation": {}}, "form")

  def test_form_blocked_when_only_url_declared(self):
    with pytest.raises(ElicitationCapabilityError):
      assert_server_may_elicit({"elicitation": {"url": {}}}, "form")

  def test_mode_support_query_helper(self):
    assert client_supports_elicitation_mode({"elicitation": {"url": {}}}, "url") is True
    assert client_supports_elicitation_mode({"elicitation": {"url": {}}}, "form") is False


# ---------------------------------------------------------------------------
# AC-30.6 — no elicitation/create to an undeclared client (R-20.1-e)
# ---------------------------------------------------------------------------

class TestAC306ServerUndeclaredGating:
  def test_undeclared_client_blocks_form(self):
    with pytest.raises(ElicitationCapabilityError) as exc:
      assert_server_may_elicit({}, "form")
    assert exc.value.mode is None

  def test_undeclared_client_blocks_url(self):
    with pytest.raises(ElicitationCapabilityError):
      assert_server_may_elicit({}, "url")

  def test_undeclared_via_parsed_capabilities(self):
    caps = ClientCapabilities.from_dict({"sampling": {}})
    with pytest.raises(ElicitationCapabilityError):
      assert_server_may_elicit(caps, "form")

  def test_mode_support_false_when_undeclared(self):
    assert client_supports_elicitation_mode({}, "form") is False


# ---------------------------------------------------------------------------
# AC-30.7 — delivery via input-required, not a server-initiated request (R-20.2-a)
# ---------------------------------------------------------------------------

class TestAC307DeliveryViaInputRequired:
  def test_method_is_an_input_request_kind(self):
    # The discriminator is the S17 recognized input-request kind, proving it
    # rides the multi-round-trip mechanism, not a server-initiated request.
    assert ELICITATION_METHOD == INPUT_REQUEST_ELICITATION

  def test_elicit_request_serializes_into_input_request_shape(self):
    req = ElicitRequest(params=ElicitRequestFormParams.from_dict(_form_params_dict()))
    wire = req.to_dict()
    # Matches the {method, params} member of the inputRequests map (§11/§20.2).
    assert set(wire.keys()) == {"method", "params"}
    assert wire["method"] == "elicitation/create"

  def test_read_caps_from_meta_envelope(self):
    meta = {KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}}}
    caps = read_client_capabilities_from_meta(meta)
    assert client_supports_elicitation(caps) is True

  def test_read_caps_from_meta_absent_key(self):
    caps = read_client_capabilities_from_meta({})
    assert client_supports_elicitation(caps) is False


# ---------------------------------------------------------------------------
# AC-30.8 — method is exact, case-sensitive "elicitation/create" (R-20.2-b)
# ---------------------------------------------------------------------------

class TestAC308MethodLiteral:
  def test_constant_value(self):
    assert ELICITATION_METHOD == "elicitation/create"

  def test_method_fixed_on_request(self):
    req = ElicitRequest(params=ElicitRequestURLParams.from_dict(_url_params_dict()))
    assert req.method == "elicitation/create"

  def test_method_not_settable(self):
    # method is init=False; constructing with a different method is impossible.
    with pytest.raises(TypeError):
      ElicitRequest(params=ElicitRequestFormParams.from_dict(_form_params_dict()), method="x")  # type: ignore[call-arg]

  def test_from_dict_accepts_exact_literal(self):
    req = ElicitRequest.from_dict({"method": "elicitation/create", "params": _form_params_dict()})
    assert req.method == "elicitation/create"

  def test_from_dict_rejects_wrong_case(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequest.from_dict({"method": "Elicitation/Create", "params": _form_params_dict()})

  def test_from_dict_rejects_wrong_method(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequest.from_dict({"method": "sampling/createMessage", "params": _form_params_dict()})

  def test_from_dict_rejects_absent_method(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequest.from_dict({"params": _form_params_dict()})


# ---------------------------------------------------------------------------
# AC-30.9 — params is present and an ElicitRequestParams (R-20.2-c)
# ---------------------------------------------------------------------------

class TestAC309ParamsRequired:
  def test_params_required_in_from_dict(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequest.from_dict({"method": "elicitation/create"})

  def test_params_must_be_object(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequest.from_dict({"method": "elicitation/create", "params": "x"})

  def test_constructor_rejects_non_params(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequest(params={"mode": "form"})  # type: ignore[arg-type]

  def test_valid_params_accepted(self):
    req = ElicitRequest(params=ElicitRequestFormParams.from_dict(_form_params_dict()))
    assert isinstance(req.params, ElicitRequestFormParams)


# ---------------------------------------------------------------------------
# AC-30.10 — form mode: mode optional; absent ⇒ form (R-20.3-a/b/c)
# ---------------------------------------------------------------------------

class TestAC3010FormModeOptional:
  def test_mode_present_must_be_form(self):
    params = ElicitRequestFormParams.from_dict(_form_params_dict(with_mode=True))
    assert params.mode == "form"

  def test_mode_present_wrong_value_rejected(self):
    bad = _form_params_dict(with_mode=False)
    bad["mode"] = "URL"
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams.from_dict(bad)

  def test_mode_may_be_omitted(self):
    params = ElicitRequestFormParams.from_dict(_form_params_dict(with_mode=False))
    assert params.mode is None

  def test_absent_mode_dispatches_to_form(self):
    params = parse_elicit_request_params(_form_params_dict(with_mode=False))
    assert isinstance(params, ElicitRequestFormParams)

  def test_explicit_form_mode_dispatches_to_form(self):
    params = parse_elicit_request_params(_form_params_dict(with_mode=True))
    assert isinstance(params, ElicitRequestFormParams)

  def test_omitted_mode_not_serialized(self):
    params = ElicitRequestFormParams.from_dict(_form_params_dict(with_mode=False))
    assert "mode" not in params.to_dict()

  def test_present_mode_round_trips(self):
    params = ElicitRequestFormParams.from_dict(_form_params_dict(with_mode=True))
    assert params.to_dict()["mode"] == "form"

  def test_unrecognized_mode_value_rejected_by_dispatcher(self):
    bad = _form_params_dict(with_mode=False)
    bad["mode"] = "carrier-pigeon"
    with pytest.raises(InvalidElicitRequestError):
      parse_elicit_request_params(bad)

  def test_mode_form_constant(self):
    assert MODE_FORM == "form"


# ---------------------------------------------------------------------------
# AC-30.11 — form message present and a string (R-20.3-d)
# ---------------------------------------------------------------------------

class TestAC3011FormMessageRequired:
  def test_message_required(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams.from_dict({"requestedSchema": _form_schema()})

  def test_message_must_be_string(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message=123, requested_schema=_form_schema())  # type: ignore[arg-type]

  def test_message_preserved(self):
    params = ElicitRequestFormParams.from_dict(_form_params_dict())
    assert params.message == "Please provide your contact details"
    assert params.to_dict()["message"] == params.message


# ---------------------------------------------------------------------------
# AC-30.12 — requestedSchema present, type == "object" (R-20.3-e)
# ---------------------------------------------------------------------------

class TestAC3012RequestedSchemaTypeObject:
  def test_requested_schema_required(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams.from_dict({"message": "hi"})

  def test_type_must_be_object_literal(self):
    bad = _form_schema()
    bad["type"] = "string"
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message="hi", requested_schema=bad)

  def test_type_absent_rejected(self):
    bad = {"properties": {"x": {"type": "string"}}}
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message="hi", requested_schema=bad)

  def test_schema_must_be_object(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message="hi", requested_schema="not-an-object")  # type: ignore[arg-type]

  def test_valid_schema_accepted(self):
    params = ElicitRequestFormParams.from_dict(_form_params_dict())
    assert params.requested_schema["type"] == "object"


# ---------------------------------------------------------------------------
# AC-30.13 — properties present, flat map of primitive schemas (R-20.3-f)
# ---------------------------------------------------------------------------

class TestAC3013PropertiesFlatMap:
  def test_properties_required(self):
    bad = {"type": "object"}
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message="hi", requested_schema=bad)

  def test_properties_must_be_map(self):
    bad = {"type": "object", "properties": ["name"]}
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message="hi", requested_schema=bad)

  def test_property_value_must_be_object(self):
    bad = {"type": "object", "properties": {"name": "string"}}
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message="hi", requested_schema=bad)

  def test_flat_map_of_primitive_schemas_accepted(self):
    params = ElicitRequestFormParams.from_dict(_form_params_dict())
    assert set(params.requested_schema["properties"]) == {"name", "age"}

  def test_empty_properties_object_accepted(self):
    # A flat map may legitimately be empty; the primitive-schema rules are S31.
    schema = {"type": "object", "properties": {}}
    params = ElicitRequestFormParams(message="hi", requested_schema=schema)
    assert params.requested_schema["properties"] == {}


# ---------------------------------------------------------------------------
# AC-30.14 — required[] and $schema optional (R-20.3-g/h)
# ---------------------------------------------------------------------------

class TestAC3014RequiredAndSchemaOptional:
  def test_required_absent_ok(self):
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}
    params = ElicitRequestFormParams(message="hi", requested_schema=schema)
    assert "required" not in params.requested_schema

  def test_schema_dialect_absent_ok(self):
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}
    params = ElicitRequestFormParams(message="hi", requested_schema=schema)
    assert "$schema" not in params.requested_schema

  def test_required_present_array_of_strings(self):
    params = ElicitRequestFormParams.from_dict(_form_params_dict())
    assert params.requested_schema["required"] == ["name"]

  def test_required_must_be_array(self):
    bad = {"type": "object", "properties": {"x": {"type": "string"}}, "required": "x"}
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message="hi", requested_schema=bad)

  def test_required_entries_must_be_strings(self):
    bad = {"type": "object", "properties": {"x": {"type": "string"}}, "required": [1]}
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message="hi", requested_schema=bad)

  def test_schema_dialect_present_string(self):
    params = ElicitRequestFormParams.from_dict(_form_params_dict())
    assert params.requested_schema["$schema"].startswith("https://")

  def test_schema_dialect_must_be_string(self):
    bad = {"type": "object", "properties": {"x": {"type": "string"}}, "$schema": 1}
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestFormParams(message="hi", requested_schema=bad)


# ---------------------------------------------------------------------------
# AC-30.15 — url mode: mode == "url" required; message required (R-20.3-i/j)
# ---------------------------------------------------------------------------

class TestAC3015UrlModeRequired:
  def test_mode_required(self):
    bad = _url_params_dict()
    del bad["mode"]
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestURLParams.from_dict(bad)

  def test_mode_must_be_url_literal(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestURLParams(
        message="hi", elicitation_id="e1", url="https://x.example/y", mode="form"
      )

  def test_message_required(self):
    bad = _url_params_dict()
    del bad["message"]
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestURLParams.from_dict(bad)

  def test_message_must_be_string(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestURLParams(
        message=5, elicitation_id="e1", url="https://x.example/y"  # type: ignore[arg-type]
      )

  def test_url_mode_dispatches_correctly(self):
    params = parse_elicit_request_params(_url_params_dict())
    assert isinstance(params, ElicitRequestURLParams)
    assert params.mode == "url"

  def test_mode_url_constant(self):
    assert MODE_URL == "url"

  def test_message_preserved(self):
    params = ElicitRequestURLParams.from_dict(_url_params_dict())
    assert "payment authorization" in params.message


# ---------------------------------------------------------------------------
# AC-30.16 — elicitationId present, opaque (R-20.3-k/l)
# ---------------------------------------------------------------------------

class TestAC3016ElicitationIdOpaque:
  def test_elicitation_id_required(self):
    bad = _url_params_dict()
    del bad["elicitationId"]
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestURLParams.from_dict(bad)

  def test_elicitation_id_must_be_string(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestURLParams(
        message="hi", elicitation_id=123, url="https://x.example/y"  # type: ignore[arg-type]
      )

  def test_elicitation_id_non_empty(self):
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestURLParams(message="hi", elicitation_id="", url="https://x.example/y")

  def test_elicitation_id_preserved_verbatim(self):
    # Opaque: stored and echoed unchanged, never parsed or interpreted.
    weird = "elic-{not:json}/../%%opaque"
    params = ElicitRequestURLParams(
      message="hi", elicitation_id=weird, url="https://x.example/y"
    )
    assert params.elicitation_id == weird
    assert params.to_dict()["elicitationId"] == weird

  def test_elicitation_id_round_trips(self):
    params = ElicitRequestURLParams.from_dict(_url_params_dict())
    assert params.elicitation_id == "elic-9f3c1a7e"


# ---------------------------------------------------------------------------
# AC-30.17 — url present, valid RFC3986 URI containing a valid URL (R-20.3-m/n)
# ---------------------------------------------------------------------------

class TestAC3017UrlValid:
  def test_url_required(self):
    bad = _url_params_dict()
    del bad["url"]
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestURLParams.from_dict(bad)

  def test_valid_https_url_accepted(self):
    assert validate_elicitation_url("https://pay.example.com/authorize?session=9f3c1a7e")

  def test_url_with_fragment_accepted(self):
    # Fragments are permitted in a navigable URL.
    assert validate_elicitation_url("https://example.com/page#section")

  def test_url_must_be_string(self):
    with pytest.raises(InvalidElicitRequestError):
      validate_elicitation_url(123)

  def test_empty_url_rejected(self):
    with pytest.raises(InvalidElicitRequestError):
      validate_elicitation_url("")

  def test_url_without_scheme_rejected(self):
    with pytest.raises(InvalidElicitRequestError):
      validate_elicitation_url("example.com/authorize")

  def test_url_without_host_rejected(self):
    with pytest.raises(InvalidElicitRequestError):
      validate_elicitation_url("mailto:user@example.com")

  def test_relative_reference_rejected(self):
    with pytest.raises(InvalidElicitRequestError):
      validate_elicitation_url("/authorize?session=1")

  def test_invalid_url_in_params_rejected(self):
    bad = _url_params_dict()
    bad["url"] = "not a url"
    with pytest.raises(InvalidElicitRequestError):
      ElicitRequestURLParams.from_dict(bad)

  def test_valid_url_round_trips(self):
    params = ElicitRequestURLParams.from_dict(_url_params_dict())
    assert params.url == "https://pay.example.com/authorize?session=9f3c1a7e"


# ---------------------------------------------------------------------------
# End-to-end wire examples from the story (§9)
# ---------------------------------------------------------------------------

class TestWireExamples:
  def test_example_c_form_input_request(self):
    raw = {
      "method": "elicitation/create",
      "params": {
        "mode": "form",
        "message": "Please provide your contact details",
        "requestedSchema": {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
          "required": ["name"],
        },
      },
    }
    req = ElicitRequest.from_dict(raw)
    assert isinstance(req.params, ElicitRequestFormParams)
    assert req.mode == "form"
    assert req.to_dict()["params"]["mode"] == "form"

  def test_example_d_form_mode_omitted(self):
    raw = {
      "method": "elicitation/create",
      "params": {
        "message": "Confirm the destination folder",
        "requestedSchema": {
          "type": "object",
          "properties": {"folder": {"type": "string"}},
        },
      },
    }
    req = ElicitRequest.from_dict(raw)
    assert isinstance(req.params, ElicitRequestFormParams)
    assert req.params.mode is None
    assert req.mode == "form"  # treated as form mode (R-20.3-c)

  def test_example_e_url_mode(self):
    raw = {
      "method": "elicitation/create",
      "params": {
        "mode": "url",
        "message": "Please complete payment authorization in your browser",
        "elicitationId": "elic-9f3c1a7e",
        "url": "https://pay.example.com/authorize?session=9f3c1a7e",
      },
    }
    req = ElicitRequest.from_dict(raw)
    assert isinstance(req.params, ElicitRequestURLParams)
    assert req.mode == "url"
    assert req.to_dict() == raw

  def test_params_union_alias_members(self):
    # The ElicitRequestParams alias resolves to the two mode shapes.
    assert ElicitRequestParams is not None
    form = parse_elicit_request_params(_form_params_dict())
    url = parse_elicit_request_params(_url_params_dict())
    assert isinstance(form, ElicitRequestFormParams)
    assert isinstance(url, ElicitRequestURLParams)
