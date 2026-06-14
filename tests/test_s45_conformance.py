"""Tests for S45 — Conformance Requirements & References (§29–§30).

Exercises the authoritative conformance catalog assembled in
``mcp_sdk_py.conformance``: the three conformance axes, the §29.2 baseline-server
request disposition, the §29.3 baseline-client envelope and retry discipline, the
§29.4 capability-conditioned obligation map, the §29.5 optionality of extensions
and deprecated features, the §29.6 robustness rules, the §29.7 stateless
invariants, the §29.8 transport conformance points, the §29.9 determination
procedure and conformance profile, and the §30 provenance-only citation status.

AC -> test coverage map:
  AC-45.1  (R-29.1-a, R-29.1-b)                          -> test_ac_45_1_*
  AC-45.2  (R-29.1-c, R-29.1-d)                          -> test_ac_45_2_*
  AC-45.3  (R-29.1-e)                                    -> test_ac_45_3_*
  AC-45.4  (R-29.1-f, R-29.9-a)                          -> test_ac_45_4_*
  AC-45.5  (R-29.2-a, R-29.2-b)                          -> test_ac_45_5_*
  AC-45.6  (R-29.2-c, R-29.2-d)                          -> test_ac_45_6_*
  AC-45.7  (R-29.2-e, R-29.2-f, R-29.2-g)                -> test_ac_45_7_*
  AC-45.8  (R-29.2-h)                                    -> test_ac_45_8_*
  AC-45.9  (R-29.2-i, R-29.4-k)                          -> test_ac_45_9_*
  AC-45.10 (R-29.2-j)                                    -> test_ac_45_10_*
  AC-45.11 (R-29.2-k, R-29.2-l)                          -> test_ac_45_11_*
  AC-45.12 (R-29.2-m, R-29.2-n)                          -> test_ac_45_12_*
  AC-45.13 (R-29.3-a)                                    -> test_ac_45_13_*
  AC-45.14 (R-29.3-b, R-29.3-c)                          -> test_ac_45_14_*
  AC-45.15 (R-29.3-d, R-29.3-e, R-29.3-f)                -> test_ac_45_15_*
  AC-45.16 (R-29.3-g, R-29.3-h, R-29.3-i)                -> test_ac_45_16_*
  AC-45.17 (R-29.3-j)                                    -> test_ac_45_17_*
  AC-45.18 (R-29.3-k)                                    -> test_ac_45_18_*
  AC-45.19 (R-29.4-a..g)                                 -> test_ac_45_19_*
  AC-45.20 (R-29.4-h, R-29.4-i)                          -> test_ac_45_20_*
  AC-45.21 (R-29.4-j)                                    -> test_ac_45_21_*
  AC-45.22 (R-29.4-l)                                    -> test_ac_45_22_*
  AC-45.23 (R-29.4-m, R-29.4-n)                          -> test_ac_45_23_*
  AC-45.24 (R-29.5-a)                                    -> test_ac_45_24_*
  AC-45.25 (R-29.5-b, R-29.5-c, R-29.5-d)                -> test_ac_45_25_*
  AC-45.26 (R-29.5-e, R-29.5-f)                          -> test_ac_45_26_*
  AC-45.27 (R-29.6-a..d)                                 -> test_ac_45_27_*
  AC-45.28 (R-29.6-e)                                    -> test_ac_45_28_*
  AC-45.29 (R-29.6-f, R-29.6-g, R-29.6-h)                -> test_ac_45_29_*
  AC-45.30 (R-29.6-i)                                    -> test_ac_45_30_*
  AC-45.31 (R-29.7-a, R-29.7-b)                          -> test_ac_45_31_*
  AC-45.32 (R-29.7-c)                                    -> test_ac_45_32_*
  AC-45.33 (R-29.7-d, R-29.7-e)                          -> test_ac_45_33_*
  AC-45.34 (R-29.8-a, R-29.8-b)                          -> test_ac_45_34_*
  AC-45.35 (R-29.8-c)                                    -> test_ac_45_35_*
  AC-45.36 (R-29.8-d, R-29.8-e)                          -> test_ac_45_36_*
  AC-45.37 (R-29.8-f, R-29.8-g)                          -> test_ac_45_37_*
  AC-45.38 (R-29.9-b, R-29.9-c)                          -> test_ac_45_38_*
  AC-45.39 (R-30-a)                                      -> test_ac_45_39_*
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.conformance import (
  CAPABILITY_OBLIGATIONS,
  CITATIONS_ARE_PROVENANCE_ONLY,
  CONFORMANCE_REQUIREMENTS,
  CONFORMANCE_TRANSPORTS,
  DISPOSITION_ERROR_CODE,
  INVALID_PARAMS_CODE,
  REQUIRED_ENVELOPE_FIELDS,
  TRANSPORT_ERROR_HTTP_STATUS,
  WIRE_PROTOCOL_REVISION,
  CapabilityObligation,
  ConformanceAxis,
  ConformanceProfile,
  ConformanceRequirement,
  ConformanceRole,
  ConformanceViolation,
  DispositionResult,
  RetryEnvelope,
  ServerDisposition,
  assert_at_least_one_transport,
  assert_input_request_kind_declared,
  assert_no_partial_feature,
  assert_request_independent_of_connection,
  assert_result_type_advertised,
  assert_transports_independent,
  build_input_required_retry,
  citation_is_load_bearing,
  classify_unknown_error_code,
  dispose_server_request,
  echo_opaque_value,
  http_status_for_protocol_error,
  ignore_unknown_fields,
  is_result_type_actionable,
  make_request_state,
  mandatory_requirements,
  obligations_for_capabilities,
  requirement,
  requirements_for_axis,
  requirements_for_role,
  requires_explicit_continuation,
  resolve_absent_result_type,
  select_retry_revision,
  tolerate_unknown_capabilities,
  tolerate_unknown_extensions,
  transport_authorization_applies,
  validate_client_request_envelope,
  verify_request_state,
)
from mcp_sdk_py.extension_mechanism import CORE_RESULT_TYPES
from mcp_sdk_py.foundations import RequirementLevel
from mcp_sdk_py.multi_round_trip import (
  INPUT_REQUEST_ELICITATION,
  InvalidRequestStateError,
)
from mcp_sdk_py.negotiation import (
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
)
from mcp_sdk_py.transport import TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP


# A complete §4 envelope reused across the disposition tests.
def _full_envelope() -> dict[str, str]:
  return {f: "value" for f in REQUIRED_ENVELOPE_FIELDS}


# ---------------------------------------------------------------------------
# AC-45.1 — both-roles satisfies each role's requirements (R-29.1-a, R-29.1-b)
# ---------------------------------------------------------------------------

def test_ac_45_1_both_roles_profile_binds_each_role():
  profile = ConformanceProfile(
    roles=frozenset({ConformanceRole.CLIENT, ConformanceRole.SERVER}),
    revisions=(WIRE_PROTOCOL_REVISION,),
  )
  assert profile.is_both_roles
  atoms = {r.atom for r in profile.binding_requirements()}
  # A server-only atom and a client-only atom both bind a both-roles party.
  assert "R-29.2-a" in atoms  # server: implement server/discover
  assert "R-29.3-a" in atoms  # client: per-request envelope


def test_ac_45_1_single_role_excludes_the_other_roles_atoms():
  client_atoms = {r.atom for r in requirements_for_role(ConformanceRole.CLIENT)}
  server_atoms = {r.atom for r in requirements_for_role(ConformanceRole.SERVER)}
  # Client-role is not bound by the server-only discovery obligation, and vice versa.
  assert "R-29.2-a" not in client_atoms
  assert "R-29.3-a" not in server_atoms
  # A both-roles atom binds either role.
  assert "R-29.1-b" in client_atoms and "R-29.1-b" in server_atoms


# ---------------------------------------------------------------------------
# AC-45.2 — §3 base format + self-contained §4 envelope (R-29.1-c, R-29.1-d)
# ---------------------------------------------------------------------------

def test_ac_45_2_base_format_and_stateless_atoms_are_role_agnostic_musts():
  base = requirement("R-29.1-c")
  stateless = requirement("R-29.1-d")
  assert base.level is RequirementLevel.MUST and base.section == "§3"
  assert stateless.level is RequirementLevel.MUST and stateless.section == "§4"
  # Both bind every party regardless of role (empty roles == binds all).
  assert base.binds_role(ConformanceRole.CLIENT)
  assert stateless.binds_role(ConformanceRole.SERVER)


# ---------------------------------------------------------------------------
# AC-45.3 — deriving state from connection identity is non-conformant (R-29.1-e)
# ---------------------------------------------------------------------------

def test_ac_45_3_second_request_judged_on_own_envelope_not_first():
  # The second request omits a field present in the first; it is judged on its
  # own envelope (rejected), never by reusing the first's value.
  first = _full_envelope()
  assert dispose_server_request(
    request_revision=WIRE_PROTOCOL_REVISION,
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=first,
  ).is_success
  second = _full_envelope()
  del second[REQUIRED_ENVELOPE_FIELDS[0]]
  result = dispose_server_request(
    request_revision=WIRE_PROTOCOL_REVISION,
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=second,
  )
  assert result.disposition is ServerDisposition.REJECT_MALFORMED_ENVELOPE


def test_ac_45_3_deriving_from_connection_raises():
  assert_request_independent_of_connection(derived_from_connection=False)
  with pytest.raises(ConformanceViolation) as exc:
    assert_request_independent_of_connection(derived_from_connection=True)
  assert exc.value.atom == "R-29.1-e"


# ---------------------------------------------------------------------------
# AC-45.4 — observable basis: language/architecture irrelevant (R-29.1-f, R-29.9-a)
# ---------------------------------------------------------------------------

def test_ac_45_4_identical_inputs_identical_disposition():
  env = _full_envelope()
  a = dispose_server_request(
    request_revision=WIRE_PROTOCOL_REVISION,
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=dict(env),
  )
  b = dispose_server_request(
    request_revision=WIRE_PROTOCOL_REVISION,
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=dict(env),
  )
  assert a.disposition is b.disposition is ServerDisposition.SUCCESS


def test_ac_45_4_observable_basis_atoms_are_discretionary():
  assert requirement("R-29.1-f").level is RequirementLevel.MAY
  assert requirement("R-29.9-a").level is RequirementLevel.MAY


# ---------------------------------------------------------------------------
# AC-45.5 — server/discover unconditional; client MAY call first (R-29.2-a/b)
# ---------------------------------------------------------------------------

def test_ac_45_5_discover_is_unconditional_must_for_server():
  discover = requirement("R-29.2-a")
  assert discover.level is RequirementLevel.MUST
  assert discover.binds_role(ConformanceRole.SERVER)
  assert not discover.binds_role(ConformanceRole.CLIENT)


def test_ac_45_5_client_may_call_discover_first():
  may = requirement("R-29.2-b")
  assert may.level is RequirementLevel.MAY
  assert may.binds_role(ConformanceRole.CLIENT)


# ---------------------------------------------------------------------------
# AC-45.6 — advertise revisions/capabilities consistent with §6 (R-29.2-c/d)
# ---------------------------------------------------------------------------

def test_ac_45_6_advertise_atoms_levels_and_sections():
  advertise = requirement("R-29.2-c")
  never = requirement("R-29.2-d")
  assert advertise.level is RequirementLevel.MUST and "§6" in advertise.section
  assert never.level is RequirementLevel.MUST_NOT


def test_ac_45_6_no_partial_feature_means_unimplemented_not_advertised():
  # Advertising a revision/capability not implemented is non-conformant (R-29.2-d
  # ties to R-29.9-b: advertise only when fully implemented).
  assert_no_partial_feature(advertised=True, fully_implemented=True, feature="tools")
  with pytest.raises(ConformanceViolation):
    assert_no_partial_feature(advertised=True, fully_implemented=False, feature="tools")


# ---------------------------------------------------------------------------
# AC-45.7 — honor envelope, infer no state, no connection reuse (R-29.2-e/f/g)
# ---------------------------------------------------------------------------

def test_ac_45_7_well_formed_request_succeeds_on_its_own_envelope():
  result = dispose_server_request(
    request_revision=WIRE_PROTOCOL_REVISION,
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=_full_envelope(),
  )
  assert result.is_success


def test_ac_45_7_no_connection_reuse_atoms_are_prohibitions():
  assert requirement("R-29.2-f").level is RequirementLevel.MUST_NOT
  assert requirement("R-29.2-g").level is RequirementLevel.MUST_NOT


# ---------------------------------------------------------------------------
# AC-45.8 — unsupported revision -> -32004 {supported, requested} (R-29.2-h)
# ---------------------------------------------------------------------------

def test_ac_45_8_unsupported_revision_rejected_with_32004_data():
  result = dispose_server_request(
    request_revision="2025-01-01",
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=_full_envelope(),
  )
  assert result.disposition is ServerDisposition.REJECT_UNSUPPORTED_REVISION
  assert result.error.code == UNSUPPORTED_PROTOCOL_VERSION_CODE
  assert result.error.data["supported"] == [WIRE_PROTOCOL_REVISION]
  assert result.error.data["requested"] == "2025-01-01"
  assert DISPOSITION_ERROR_CODE[result.disposition] == UNSUPPORTED_PROTOCOL_VERSION_CODE


# ---------------------------------------------------------------------------
# AC-45.9 — missing capability -> -32003 requiredCapabilities (R-29.2-i, R-29.4-k)
# ---------------------------------------------------------------------------

def test_ac_45_9_missing_capability_rejected_with_32003_required_capabilities():
  result = dispose_server_request(
    request_revision=WIRE_PROTOCOL_REVISION,
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=_full_envelope(),
    required_capabilities=["elicitation"],
    declared_client_capabilities={},
  )
  assert result.disposition is ServerDisposition.REJECT_MISSING_CAPABILITY
  assert result.error.code == MISSING_REQUIRED_CLIENT_CAPABILITY_CODE
  assert result.error.data["requiredCapabilities"] == {"elicitation": {}}


def test_ac_45_9_declared_capability_is_not_rejected():
  result = dispose_server_request(
    request_revision=WIRE_PROTOCOL_REVISION,
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=_full_envelope(),
    required_capabilities=["elicitation"],
    declared_client_capabilities={"elicitation": {}},
  )
  assert result.is_success


# ---------------------------------------------------------------------------
# AC-45.10 — missing §4-required field -> -32602 (R-29.2-j)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("missing", list(REQUIRED_ENVELOPE_FIELDS))
def test_ac_45_10_malformed_envelope_rejected_with_32602(missing):
  env = _full_envelope()
  del env[missing]
  result = dispose_server_request(
    request_revision=WIRE_PROTOCOL_REVISION,
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=env,
  )
  assert result.disposition is ServerDisposition.REJECT_MALFORMED_ENVELOPE
  assert result.error.code == INVALID_PARAMS_CODE


# ---------------------------------------------------------------------------
# AC-45.11 — resultType present, from core + advertised extensions (R-29.2-k/l)
# ---------------------------------------------------------------------------

def test_ac_45_11_core_result_type_is_accepted():
  for rt in CORE_RESULT_TYPES:
    assert assert_result_type_advertised(rt) == rt


def test_ac_45_11_missing_result_type_violates_k():
  with pytest.raises(ConformanceViolation) as exc:
    assert_result_type_advertised("")
  assert exc.value.atom == "R-29.2-k"


def test_ac_45_11_extension_result_type_only_when_advertised():
  assert assert_result_type_advertised("task", advertised_extension_result_types={"task"}) == "task"
  with pytest.raises(ConformanceViolation) as exc:
    assert_result_type_advertised("task")  # not advertised
  assert exc.value.atom == "R-29.2-l"


# ---------------------------------------------------------------------------
# AC-45.12 — unadvertised feature is gated/refused (R-29.2-m, R-29.2-n)
# ---------------------------------------------------------------------------

def test_ac_45_12_unadvertised_feature_refused():
  result = dispose_server_request(
    request_revision=WIRE_PROTOCOL_REVISION,
    supported_revisions=[WIRE_PROTOCOL_REVISION],
    envelope_fields=_full_envelope(),
    feature_advertised=False,
  )
  assert result.disposition is ServerDisposition.REFUSE_UNADVERTISED_FEATURE
  assert result.error is None
  assert requirement("R-29.2-n").level is RequirementLevel.MUST_NOT


# ---------------------------------------------------------------------------
# AC-45.13 — client request carries revision, identity, capabilities (R-29.3-a)
# ---------------------------------------------------------------------------

def test_ac_45_13_complete_client_envelope_validates():
  validate_client_request_envelope(_full_envelope())  # no raise


@pytest.mark.parametrize("missing", list(REQUIRED_ENVELOPE_FIELDS))
def test_ac_45_13_missing_field_raises(missing):
  env = _full_envelope()
  del env[missing]
  with pytest.raises(ConformanceViolation) as exc:
    validate_client_request_envelope(env)
  assert exc.value.atom == "R-29.3-a"


# ---------------------------------------------------------------------------
# AC-45.14 — revision selection + -32004 retry (R-29.3-b, R-29.3-c)
# ---------------------------------------------------------------------------

def test_ac_45_14_select_first_mutually_supported_revision():
  chosen = select_retry_revision(
    client_supported=["2099-01-01", WIRE_PROTOCOL_REVISION],
    server_supported=[WIRE_PROTOCOL_REVISION],
  )
  assert chosen == WIRE_PROTOCOL_REVISION


def test_ac_45_14_no_overlap_returns_none():
  assert select_retry_revision(
    client_supported=["2099-01-01"],
    server_supported=[WIRE_PROTOCOL_REVISION],
  ) is None
  assert requirement("R-29.3-c").level is RequirementLevel.SHOULD


# ---------------------------------------------------------------------------
# AC-45.15 — opaque values echoed unchanged, never inspected (R-29.3-d/e/f)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
  "value",
  ["cursor-abc", {"opaque": "handle"}, ["s", "u", "b"], "OPAQUE-ECHOED-EXACTLY"],
)
def test_ac_45_15_opaque_value_echoed_identically(value):
  echoed = echo_opaque_value(value)
  assert echoed == value
  # The exact same object is returned (no parsing/transforming/copying).
  assert echoed is value


# ---------------------------------------------------------------------------
# AC-45.16 — input_required fulfillment & immediate-retry (R-29.3-g/h/i)
# ---------------------------------------------------------------------------

def test_ac_45_16_retry_with_constructed_inputs():
  retry = build_input_required_retry(
    original_request_id="req-3", new_request_id="req-3-retry", request_state="S"
  )
  assert retry.request_id == "req-3-retry"
  assert retry.request_state == "S"


def test_ac_45_16_immediate_retry_when_no_input_requests():
  # No requestState supplied => retry rides no requestState (MAY retry immediately).
  retry = build_input_required_retry(
    original_request_id="req-3", new_request_id="req-3-retry"
  )
  assert retry.request_state is None
  assert requirement("R-29.3-i").level is RequirementLevel.MAY


# ---------------------------------------------------------------------------
# AC-45.17 — retry: fresh id, requestState echoed/omitted (R-29.3-j)
# ---------------------------------------------------------------------------

def test_ac_45_17_retry_requires_fresh_id():
  with pytest.raises(ConformanceViolation) as exc:
    build_input_required_retry(original_request_id="x", new_request_id="x")
  assert exc.value.atom == "R-29.3-j"


def test_ac_45_17_request_state_echoed_when_provided_omitted_when_not():
  with_state = build_input_required_retry(
    original_request_id="a", new_request_id="b", request_state="OPAQUE"
  )
  assert with_state.to_meta() == {"requestState": "OPAQUE"}
  assert with_state.includes_request_state
  without_state = build_input_required_retry(
    original_request_id="a", new_request_id="b"
  )
  assert without_state.to_meta() == {}
  assert not without_state.includes_request_state


# ---------------------------------------------------------------------------
# AC-45.18 — interpret by resultType + §29.6 robustness (R-29.3-k)
# ---------------------------------------------------------------------------

def test_ac_45_18_recognized_result_type_actionable_unrecognized_not():
  assert is_result_type_actionable("complete")
  assert not is_result_type_actionable("totally-unknown")
  assert requirement("R-29.3-k").section == "§3/§29.6"


# ---------------------------------------------------------------------------
# AC-45.19 — capability -> section obligation map (R-29.4-a..g)
# ---------------------------------------------------------------------------

def test_ac_45_19_obligation_map_sections():
  assert CAPABILITY_OBLIGATIONS["tools"].sections == ("§16",)
  assert CAPABILITY_OBLIGATIONS["resources"].sections == ("§17",)
  assert CAPABILITY_OBLIGATIONS["resourceSubscriptions"].sections == ("§17", "§10")
  assert CAPABILITY_OBLIGATIONS["prompts"].sections == ("§18",)
  assert CAPABILITY_OBLIGATIONS["completions"].sections == ("§19",)
  assert CAPABILITY_OBLIGATIONS["elicitation"].sections == ("§20",)
  assert CAPABILITY_OBLIGATIONS["subscriptions"].sections == ("§10",)


def test_ac_45_19_elicitation_is_a_client_obligation():
  assert CAPABILITY_OBLIGATIONS["elicitation"].role is ConformanceRole.CLIENT
  assert CAPABILITY_OBLIGATIONS["tools"].role is ConformanceRole.SERVER


def test_ac_45_19_obligations_for_capabilities_dedupes_and_orders():
  obligations = obligations_for_capabilities(["tools", "prompts", "tools"])
  assert [o.capability for o in obligations] == ["tools", "prompts"]


# ---------------------------------------------------------------------------
# AC-45.20 — never depend on an unadvertised feature (R-29.4-h, R-29.4-i)
# ---------------------------------------------------------------------------

def test_ac_45_20_unadvertised_result_type_rejected():
  # A result type contributed by an extension the server did NOT advertise is
  # outside what it may return (R-29.4-i via R-29.2-l).
  with pytest.raises(ConformanceViolation) as exc:
    assert_result_type_advertised("ext-only-type")
  assert exc.value.atom == "R-29.2-l"
  assert requirement("R-29.4-h").level is RequirementLevel.MUST_NOT
  assert requirement("R-29.4-i").level is RequirementLevel.MUST_NOT


# ---------------------------------------------------------------------------
# AC-45.21 — advertising binds full conformance (R-29.4-j)
# ---------------------------------------------------------------------------

def test_ac_45_21_advertised_but_partial_is_non_conformant():
  with pytest.raises(ConformanceViolation) as exc:
    assert_no_partial_feature(
      advertised=True, fully_implemented=False, feature="completions"
    )
  assert exc.value.atom == "R-29.9-b"
  assert requirement("R-29.4-j").level is RequirementLevel.MUST_NOT


# ---------------------------------------------------------------------------
# AC-45.22 — no undeclared-kind input request (R-29.4-l)
# ---------------------------------------------------------------------------

def test_ac_45_22_elicitation_input_request_requires_declared_capability():
  with pytest.raises(ConformanceViolation) as exc:
    assert_input_request_kind_declared(INPUT_REQUEST_ELICITATION, declared_client_capabilities={})
  assert exc.value.atom == "R-29.4-l"


def test_ac_45_22_declared_elicitation_permits_the_input_request():
  # No raise when the client declared the capability.
  assert_input_request_kind_declared(
    INPUT_REQUEST_ELICITATION, declared_client_capabilities={"elicitation"}
  )
  assert_input_request_kind_declared(
    INPUT_REQUEST_ELICITATION, declared_client_capabilities={"elicitation": {}}
  )


# ---------------------------------------------------------------------------
# AC-45.23 — deprecated client-provided capabilities bidirectional (R-29.4-m/n)
# ---------------------------------------------------------------------------

def test_ac_45_23_deprecated_capability_bidirectional_atoms():
  advertise = requirement("R-29.4-m")
  no_reliance = requirement("R-29.4-n")
  assert advertise.level is RequirementLevel.MUST and advertise.section == "§21"
  assert no_reliance.level is RequirementLevel.MUST_NOT and no_reliance.section == "§21"


# ---------------------------------------------------------------------------
# AC-45.24 — zero extensions is fully conformant (R-29.5-a)
# ---------------------------------------------------------------------------

def test_ac_45_24_zero_extensions_profile_is_conformant():
  profile = ConformanceProfile(
    roles=frozenset({ConformanceRole.SERVER}),
    revisions=(WIRE_PROTOCOL_REVISION,),
    extensions=(),
  )
  assert profile.advertises_zero_extensions
  assert requirement("R-29.5-a").level is RequirementLevel.OPTIONAL


# ---------------------------------------------------------------------------
# AC-45.25 — extension obligations, naming, one-sided fallback (R-29.5-b/c/d)
# ---------------------------------------------------------------------------

def test_ac_45_25_extension_atoms_levels_and_sections():
  assert requirement("R-29.5-b").level is RequirementLevel.MUST
  assert requirement("R-29.5-c").section == "§6"
  assert requirement("R-29.5-d").level is RequirementLevel.MUST


# ---------------------------------------------------------------------------
# AC-45.26 — deprecated features optional, full if implemented (R-29.5-e/f)
# ---------------------------------------------------------------------------

def test_ac_45_26_deprecated_optional_but_full_when_implemented():
  assert requirement("R-29.5-e").level is RequirementLevel.OPTIONAL
  assert requirement("R-29.5-f").level is RequirementLevel.MUST
  # A Deprecated feature implemented only partially is non-conformant.
  assert_no_partial_feature(advertised=False, fully_implemented=False, feature="roots")
  with pytest.raises(ConformanceViolation):
    assert_no_partial_feature(advertised=True, fully_implemented=False, feature="roots")


# ---------------------------------------------------------------------------
# AC-45.27 — tolerate unknown fields/capabilities/extensions (R-29.6-a..d)
# ---------------------------------------------------------------------------

def test_ac_45_27_unknown_fields_ignored_known_kept():
  obj = {"name": "search", "arguments": {"q": "x"}, "futureField": {"any": True}}
  kept = ignore_unknown_fields(obj, {"name", "arguments"})
  assert kept == {"name": "search", "arguments": {"q": "x"}}
  assert "futureField" not in kept


def test_ac_45_27_unknown_capabilities_and_extensions_ignored():
  caps = tolerate_unknown_capabilities(["tools", "unknownCap"], {"tools"})
  assert caps == ("tools",)
  exts = tolerate_unknown_extensions(["io.example/ext", "unknown/ext"], {"io.example/ext"})
  assert exts == ("io.example/ext",)


# ---------------------------------------------------------------------------
# AC-45.28 — unrecognized error code is a failure, not a crash (R-29.6-e)
# ---------------------------------------------------------------------------

def test_ac_45_28_unknown_error_code_classified_as_failure():
  assert classify_unknown_error_code(-31999) == "failure"
  assert classify_unknown_error_code(42) == "failure"
  assert requirement("R-29.6-e").binds_role(ConformanceRole.CLIENT)


# ---------------------------------------------------------------------------
# AC-45.29 — unrecognized/absent resultType (R-29.6-f/g/h)
# ---------------------------------------------------------------------------

def test_ac_45_29_unrecognized_result_type_not_actionable():
  assert not is_result_type_actionable("mystery")
  assert not is_result_type_actionable(None)


def test_ac_45_29_absent_result_type_applies_section3_default():
  assert resolve_absent_result_type({"resultType": "input_required"}) == "input_required"
  assert resolve_absent_result_type({}) == "complete"
  assert requirement("R-29.6-h").section == "§3"


# ---------------------------------------------------------------------------
# AC-45.30 — understood content not discarded (R-29.6-i)
# ---------------------------------------------------------------------------

def test_ac_45_30_understood_content_survives_unknown_fields():
  obj = {"name": "search", "arguments": {"q": "x"}, "futureField": 1}
  kept = ignore_unknown_fields(obj, {"name", "arguments"})
  # Required understood content is retained; only the unknown is dropped.
  assert kept["name"] == "search"
  assert kept["arguments"] == {"q": "x"}
  assert requirement("R-29.6-i").level is RequirementLevel.MUST_NOT


# ---------------------------------------------------------------------------
# AC-45.31 — independent processing via explicit continuation (R-29.7-a/b)
# ---------------------------------------------------------------------------

def test_ac_45_31_independent_requests_across_separate_connections():
  # Each request judged on its own envelope, regardless of which "connection".
  for _ in range(2):
    assert dispose_server_request(
      request_revision=WIRE_PROTOCOL_REVISION,
      supported_revisions=[WIRE_PROTOCOL_REVISION],
      envelope_fields=_full_envelope(),
    ).is_success
  with pytest.raises(ConformanceViolation):
    assert_request_independent_of_connection(
      derived_from_connection=True, atom="R-29.7-a"
    )


def test_ac_45_31_spanning_state_requires_explicit_continuation():
  assert requires_explicit_continuation(True) is True
  assert requires_explicit_continuation(False) is False


# ---------------------------------------------------------------------------
# AC-45.32 — connection is not the lifetime boundary (R-29.7-c)
# ---------------------------------------------------------------------------

def test_ac_45_32_connection_is_not_lifetime_boundary():
  # Treating the connection/process as the lifetime boundary is non-conformant.
  with pytest.raises(ConformanceViolation) as exc:
    assert_request_independent_of_connection(
      derived_from_connection=True, atom="R-29.7-c"
    )
  assert exc.value.atom == "R-29.7-c"


# ---------------------------------------------------------------------------
# AC-45.33 — tampered requestState rejected (R-29.7-d/e)
# ---------------------------------------------------------------------------

def test_ac_45_33_request_state_round_trips_and_rejects_tampering():
  secret = b"server-secret"
  token = make_request_state("trust-context", secret)
  assert verify_request_state(token, secret) == "trust-context"
  with pytest.raises(InvalidRequestStateError):
    verify_request_state(token + "tamper", secret)


def test_ac_45_33_attacker_controlled_atoms_are_musts():
  assert requirement("R-29.7-d").level is RequirementLevel.MUST
  assert requirement("R-29.7-e").level is RequirementLevel.MUST


# ---------------------------------------------------------------------------
# AC-45.34 — at least one transport, each upholds its rules (R-29.8-a/b)
# ---------------------------------------------------------------------------

def test_ac_45_34_at_least_one_transport_required():
  assert assert_at_least_one_transport([TRANSPORT_STDIO]) == (TRANSPORT_STDIO,)
  with pytest.raises(ConformanceViolation) as exc:
    assert_at_least_one_transport([])
  assert exc.value.atom == "R-29.8-a"


def test_ac_45_34_unknown_transport_rejected():
  with pytest.raises(ConformanceViolation):
    assert_at_least_one_transport(["smoke-signal"])
  assert CONFORMANCE_TRANSPORTS == {TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP}


# ---------------------------------------------------------------------------
# AC-45.35 — protocol error -> prescribed HTTP status (R-29.8-c)
# ---------------------------------------------------------------------------

def test_ac_45_35_invalid_params_and_missing_capability_map_to_400():
  assert http_status_for_protocol_error(INVALID_PARAMS_CODE) == 400
  assert http_status_for_protocol_error(MISSING_REQUIRED_CLIENT_CAPABILITY_CODE) == 400
  assert TRANSPORT_ERROR_HTTP_STATUS[INVALID_PARAMS_CODE] == 400


# ---------------------------------------------------------------------------
# AC-45.36 — HTTP applies §23, stdio does not (R-29.8-d/e)
# ---------------------------------------------------------------------------

def test_ac_45_36_authorization_applicability_by_transport():
  assert transport_authorization_applies(TRANSPORT_STREAMABLE_HTTP) is True
  assert transport_authorization_applies(TRANSPORT_STDIO) is False
  assert requirement("R-29.8-d").level is RequirementLevel.SHOULD
  assert requirement("R-29.8-e").level is RequirementLevel.SHOULD_NOT


# ---------------------------------------------------------------------------
# AC-45.37 — transports independent, concurrency permitted (R-29.8-f/g)
# ---------------------------------------------------------------------------

def test_ac_45_37_concurrent_transports_with_no_cross_contingency():
  assert_transports_independent(
    [TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP],
    cross_transport_contingency=False,
  )
  assert requirement("R-29.8-g").level is RequirementLevel.MAY


def test_ac_45_37_cross_transport_contingency_rejected():
  with pytest.raises(ConformanceViolation) as exc:
    assert_transports_independent(
      [TRANSPORT_STDIO, TRANSPORT_STREAMABLE_HTTP],
      cross_transport_contingency=True,
    )
  assert exc.value.atom == "R-29.8-f"


# ---------------------------------------------------------------------------
# AC-45.38 — no partial feature; exact registry values (R-29.9-b/c)
# ---------------------------------------------------------------------------

def test_ac_45_38_profile_always_includes_wire_revision_and_registry_codes():
  profile = ConformanceProfile(
    roles=frozenset({ConformanceRole.SERVER}),
    revisions=(),  # omitted on purpose
    capabilities=("tools",),
  )
  # R-29.9-c: the revision catalog always includes the exact wire value.
  assert WIRE_PROTOCOL_REVISION in profile.revisions
  # Exact Appendix B codes are reused, not redefined.
  assert DISPOSITION_ERROR_CODE[ServerDisposition.REJECT_MALFORMED_ENVELOPE] == INVALID_PARAMS_CODE
  assert profile.capability_obligations()[0].capability == "tools"


def test_ac_45_38_no_partial_feature_passes_when_full():
  assert_no_partial_feature(advertised=True, fully_implemented=True, feature="tools")
  assert requirement("R-29.9-b").level is RequirementLevel.MUST
  assert requirement("R-29.9-c").level is RequirementLevel.MUST


# ---------------------------------------------------------------------------
# AC-45.39 — citations are provenance only (R-30-a)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("marker", ["[MCP]", "[RFC2119]", "[SEP-2575]", "[OAUTH21]"])
def test_ac_45_39_no_citation_is_load_bearing(marker):
  assert citation_is_load_bearing(marker) is False


def test_ac_45_39_citations_are_provenance_only_constant():
  assert CITATIONS_ARE_PROVENANCE_ONLY is True
  assert requirement("R-30-a").level is RequirementLevel.MAY


# ---------------------------------------------------------------------------
# Catalog integrity — every traceability atom is present with its level
# ---------------------------------------------------------------------------

def test_catalog_covers_every_traceability_atom():
  # The §10 traceability table of the story lists exactly these atoms.
  expected = {
    "R-29.1-a", "R-29.1-b", "R-29.1-c", "R-29.1-d", "R-29.1-e", "R-29.1-f",
    "R-29.2-a", "R-29.2-b", "R-29.2-c", "R-29.2-d", "R-29.2-e", "R-29.2-f",
    "R-29.2-g", "R-29.2-h", "R-29.2-i", "R-29.2-j", "R-29.2-k", "R-29.2-l",
    "R-29.2-m", "R-29.2-n",
    "R-29.3-a", "R-29.3-b", "R-29.3-c", "R-29.3-d", "R-29.3-e", "R-29.3-f",
    "R-29.3-g", "R-29.3-h", "R-29.3-i", "R-29.3-j", "R-29.3-k",
    "R-29.4-a", "R-29.4-b", "R-29.4-c", "R-29.4-d", "R-29.4-e", "R-29.4-f",
    "R-29.4-g", "R-29.4-h", "R-29.4-i", "R-29.4-j", "R-29.4-k", "R-29.4-l",
    "R-29.4-m", "R-29.4-n",
    "R-29.5-a", "R-29.5-b", "R-29.5-c", "R-29.5-d", "R-29.5-e", "R-29.5-f",
    "R-29.6-a", "R-29.6-b", "R-29.6-c", "R-29.6-d", "R-29.6-e", "R-29.6-f",
    "R-29.6-g", "R-29.6-h", "R-29.6-i",
    "R-29.7-a", "R-29.7-b", "R-29.7-c", "R-29.7-d", "R-29.7-e",
    "R-29.8-a", "R-29.8-b", "R-29.8-c", "R-29.8-d", "R-29.8-e", "R-29.8-f",
    "R-29.8-g",
    "R-29.9-a", "R-29.9-b", "R-29.9-c",
    "R-30-a",
  }
  assert set(CONFORMANCE_REQUIREMENTS) == expected


def test_catalog_entries_are_well_formed():
  for atom, req in CONFORMANCE_REQUIREMENTS.items():
    assert isinstance(req, ConformanceRequirement)
    assert req.atom == atom
    assert isinstance(req.level, RequirementLevel)
    assert isinstance(req.axis, ConformanceAxis)
    assert req.section


def test_mandatory_requirements_are_absolute_only():
  for req in mandatory_requirements():
    assert req.is_mandatory
    assert req.level.is_absolute_requirement or req.level.is_absolute_prohibition


def test_requirements_for_axis_partitions_the_catalog():
  total = sum(len(requirements_for_axis(a)) for a in ConformanceAxis)
  assert total == len(CONFORMANCE_REQUIREMENTS)


# ---------------------------------------------------------------------------
# ConformanceProfile validation
# ---------------------------------------------------------------------------

def test_profile_requires_at_least_one_role():
  with pytest.raises(ConformanceViolation) as exc:
    ConformanceProfile(roles=frozenset(), revisions=(WIRE_PROTOCOL_REVISION,))
  assert exc.value.atom == "R-29.1-a"


def test_profile_requires_at_least_one_transport():
  with pytest.raises(ConformanceViolation) as exc:
    ConformanceProfile(
      roles=frozenset({ConformanceRole.SERVER}),
      revisions=(WIRE_PROTOCOL_REVISION,),
      transports=(),
    )
  assert exc.value.atom == "R-29.8-a"


def test_dataclass_helper_types_are_frozen():
  result = DispositionResult(ServerDisposition.SUCCESS, None, "R-29.2-k")
  retry = RetryEnvelope(request_id="x", request_state=None)
  obligation = CapabilityObligation("tools", ConformanceRole.SERVER, ("§16",), "R-29.4-b")
  with pytest.raises(Exception):
    result.disposition = ServerDisposition.SUCCESS  # type: ignore[misc]
  with pytest.raises(Exception):
    retry.request_id = "y"  # type: ignore[misc]
  with pytest.raises(Exception):
    obligation.capability = "prompts"  # type: ignore[misc]
