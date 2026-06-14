"""Tests for S44 — Security Considerations (§28).

Every test class maps to one or more acceptance criteria (AC-44.x). §28 defines
no new wire types; it consolidates the cross-cutting consent, isolation,
validation, confidentiality, and sandboxing obligations of the whole protocol.
S44 assembles the authoritative §28 requirement catalog and implements the real
checkable guards it owns (referencing sibling primitives for audience/PKCE/state/
issuer/requestState/Origin/cursor/argument validation rather than redefining
them).

AC → test coverage map
----------------------
AC-44.1  (R-28-a, R-28.1-a)                         -> TestAC1CorePrinciples
AC-44.2  (R-28.1-b/c/d, R-28.2-a/b)                 -> TestAC2InformedConsent
AC-44.3  (R-28.1-e/f)                               -> TestAC3ExposureConsent
AC-44.4  (R-28.1-g, R-28.4-c)                       -> TestAC4AccessControls
AC-44.5  (R-28.1-h/j/k, R-28.3-a)                   -> TestAC5ToolCaution
AC-44.6  (R-28.1-i, R-28.3-b/c)                     -> TestAC6Annotations
AC-44.7  (R-28.2-c/d/e/f/g)                         -> TestAC7NoSilentEscalation
AC-44.8  (R-28.3-d/e/f)                             -> TestAC8HumanInLoop
AC-44.9  (R-28.3-g/h/i)                             -> TestAC9RateLimitSanitize
AC-44.10 (R-28.3-j/k/l)                             -> TestAC10ArgsTimeoutAudit
AC-44.11 (R-28.4-a/b/d/e/f)                         -> TestAC11Isolation
AC-44.12 (R-28.5-a/b/c/d/e)                         -> TestAC12TokenAudience
AC-44.13 (R-28.5-f/g)                               -> TestAC13NoPassthrough
AC-44.14 (R-28.5-h/i)                               -> TestAC14ExactIssuer
AC-44.15 (R-28.5-j/k)                               -> TestAC15PKCE
AC-44.16 (R-28.5-l/m)                               -> TestAC16State
AC-44.17 (R-28.5-n/o/p/q, R-28.9-d)                 -> TestAC17TokenConfidentiality
AC-44.18 (R-28.6-a/b/c)                             -> TestAC18Continuation
AC-44.19 (R-28.7-a/b/c/d/e)                         -> TestAC19Elicitation
AC-44.20 (R-28.7-f/g)                               -> TestAC20Sampling
AC-44.21 (R-28.8-a/b/c/d)                           -> TestAC21Sandbox
AC-44.22 (R-28.8-e/f/g/h)                           -> TestAC22SandboxLeastPriv
AC-44.23 (R-28.9-a/b/c/e)                           -> TestAC23Metadata
AC-44.24 (R-28.10-a/b/c/d/e)                        -> TestAC24InputValidation
AC-44.25 (R-28.10-f/g/h)                            -> TestAC25UriSsrf
AC-44.26 (R-28.10-i)                                -> TestAC26Origin
AC-44.27 (R-28.10-j)                                -> TestAC27Cursor
AC-44.28 (R-28.10-k/l)                              -> TestAC28Bounds
AC-44.29 (R-28.10-m/n)                              -> TestAC29ExternalRefs
AC-44.30 (R-28.10-o/p)                              -> TestAC30FilePaths
Plus: TestCatalogIntegrity (catalog completeness / atom coverage).
"""

import pytest

from mcp_sdk_py.foundations import RequirementLevel, Role
from mcp_sdk_py.tools import Tool

from mcp_sdk_py.security import (
  CORE_SECURITY_PRINCIPLES,
  MAX_MESSAGE_BYTES,
  MAX_VALIDATION_DEPTH,
  REDACTION_PLACEHOLDER,
  SECURITY_REQUIREMENTS,
  ConsentGate,
  ConsentOutcome,
  ConsentPrompt,
  ConsentRecord,
  ConsentRequiredError,
  ContinuationTokenError,
  ContinuationTokenGuard,
  FilePathTraversalError,
  OriginValidator,
  SandboxPolicy,
  SecurityPrinciple,
  SecurityRequirement,
  ServerIsolationBoundary,
  ServerIsolationError,
  TokenAudienceError,
  UnmediatedToolInvocationError,
  UriValidationError,
  ValidationError,
  access_control_is_sufficient,
  assert_message_within_size,
  assert_no_external_schema_references,
  assert_uri_followable,
  authorization_endpoint_uri_is_secure,
  bounded_depth,
  client_may_send_token_to_server,
  client_may_use_annotations,
  decision_rests_solely_with_model,
  design_is_built_on_core_principles,
  elicitation_requests_secret,
  elicitation_response_may_be_returned,
  exact_issuer_matches,
  filter_known_metadata,
  generate_pkce_parameters,
  generate_state,
  is_material_change,
  is_sensitive_key,
  is_ssrf_safe_host,
  mandatory_security_requirements,
  metadata_value_carries_authority,
  path_is_within_authorized_root,
  redact_for_log,
  route_ui_tool_invocation,
  sampling_may_proceed,
  sanitize_file_path,
  schema_has_external_references,
  security_requirement,
  security_requirements_for_role,
  server_may_forward_client_token,
  server_must_reject_token,
  use_metadata_for_access_control,
  validate_pagination_cursor,
  validate_resource_uri,
  validate_tool_arguments,
  PKCE_CODE_CHALLENGE_METHOD,
)


# Vendor-neutral placeholders used throughout (no real AI/vendor names).
SERVER_A = "server://alpha.example"
SERVER_B = "server://bravo.example"


def _approved_prompt(operation: str = "read_file", server: str = SERVER_A) -> ConsentPrompt:
  return ConsentPrompt(
    operation=operation,
    server_identity=server,
    description="Read the project README and return its text.",
    arguments={"path": "README.md"},
    host_rendered=True,
  )


def _tool_with_required_path() -> Tool:
  return Tool(
    name="read_file",
    input_schema={
      "type": "object",
      "properties": {"path": {"type": "string"}},
      "required": ["path"],
      "additionalProperties": False,
    },
  )


# ---------------------------------------------------------------------------
# AC-44.1 — four core principles / overarching obligation
# ---------------------------------------------------------------------------

class TestAC1CorePrinciples:
  def test_four_principles_present(self):
    assert len(CORE_SECURITY_PRINCIPLES) == 4
    assert set(CORE_SECURITY_PRINCIPLES) == {
      SecurityPrinciple.USER_CONSENT_AND_CONTROL,
      SecurityPrinciple.DATA_PRIVACY,
      SecurityPrinciple.TOOL_SAFETY,
      SecurityPrinciple.HOST_MEDIATED_TRUST,
    }

  def test_design_built_on_all_four_passes(self):
    assert design_is_built_on_core_principles(CORE_SECURITY_PRINCIPLES)

  def test_design_missing_a_principle_fails(self):
    incomplete = set(CORE_SECURITY_PRINCIPLES) - {SecurityPrinciple.TOOL_SAFETY}
    assert not design_is_built_on_core_principles(incomplete)

  def test_overarching_atom_is_mandatory(self):
    assert security_requirement("R-28-a").is_mandatory
    assert security_requirement("R-28.1-a").is_mandatory


# ---------------------------------------------------------------------------
# AC-44.2 — informed, explicit consent with review interface
# ---------------------------------------------------------------------------

class TestAC2InformedConsent:
  def test_informed_prompt_with_description_and_identity(self):
    prompt = _approved_prompt()
    assert prompt.is_informed
    assert prompt.is_spoof_resistant

  def test_prompt_without_description_is_not_informed(self):
    prompt = ConsentPrompt(operation="x", server_identity=SERVER_A, description="  ")
    assert not prompt.is_informed

  def test_prompt_without_server_identity_is_not_informed(self):
    prompt = ConsentPrompt(operation="x", server_identity="", description="do x")
    assert not prompt.is_informed

  def test_explicit_approval_passes_gate(self):
    gate = ConsentGate()
    assert gate.evaluate(_approved_prompt(), decision=ConsentOutcome.APPROVE)

  def test_consent_atoms_are_mandatory(self):
    for atom in ("R-28.1-b", "R-28.1-c", "R-28.2-a", "R-28.2-b"):
      assert security_requirement(atom).is_mandatory


# ---------------------------------------------------------------------------
# AC-44.3 — no exposure without consent
# ---------------------------------------------------------------------------

class TestAC3ExposureConsent:
  def test_exposure_blocked_without_consent(self):
    boundary = ServerIsolationBoundary(consented_targets={})
    assert not boundary.may_expose("secret.txt", SERVER_A)
    with pytest.raises(ConsentRequiredError):
      boundary.assert_exposure_consented("secret.txt", SERVER_A)

  def test_exposure_allowed_with_consent(self):
    boundary = ServerIsolationBoundary(
      consented_targets={"secret.txt": frozenset({SERVER_A})}
    )
    assert boundary.may_expose("secret.txt", SERVER_A)
    boundary.assert_exposure_consented("secret.txt", SERVER_A)

  def test_consent_for_one_item_does_not_cover_another(self):
    boundary = ServerIsolationBoundary(
      consented_targets={"a.txt": frozenset({SERVER_A})}
    )
    assert not boundary.may_expose("b.txt", SERVER_A)


# ---------------------------------------------------------------------------
# AC-44.4 — access controls commensurate with sensitivity
# ---------------------------------------------------------------------------

class TestAC4AccessControls:
  def test_strong_enough_control_is_sufficient(self):
    assert access_control_is_sufficient(3, 3)
    assert access_control_is_sufficient(3, 5)

  def test_weak_control_is_insufficient(self):
    assert not access_control_is_sufficient(5, 2)


# ---------------------------------------------------------------------------
# AC-44.5 — tools are arbitrary code; consent before invoking
# ---------------------------------------------------------------------------

class TestAC5ToolCaution:
  def test_tool_caution_atoms_mandatory(self):
    for atom in ("R-28.1-h", "R-28.1-j", "R-28.3-a"):
      assert security_requirement(atom).is_mandatory

  def test_consent_required_before_tool_invocation(self):
    gate = ConsentGate()
    # No explicit approval => gate denies a brand-new tool invocation.
    assert not gate.evaluate(_approved_prompt(), decision=ConsentOutcome.PENDING)
    with pytest.raises(ConsentRequiredError):
      gate.authorize(_approved_prompt(), decision=ConsentOutcome.PENDING)

  def test_consent_record_returned_on_approval(self):
    gate = ConsentGate()
    record = gate.authorize(
      _approved_prompt(), scope={"read"}, decision=ConsentOutcome.APPROVE
    )
    assert isinstance(record, ConsentRecord)
    assert record.outcome is ConsentOutcome.APPROVE
    assert record.scope == frozenset({"read"})


# ---------------------------------------------------------------------------
# AC-44.6 — tool definitions/annotations untrusted; no security guarantee
# ---------------------------------------------------------------------------

class TestAC6Annotations:
  def test_untrusted_server_annotations_not_relied_on(self):
    assert not client_may_use_annotations(server_is_trusted=False)

  def test_trusted_server_annotations_usable(self):
    assert client_may_use_annotations(server_is_trusted=True)

  def test_annotation_atoms_mandatory(self):
    assert security_requirement("R-28.1-i").is_mandatory
    assert security_requirement("R-28.3-b").is_mandatory
    assert security_requirement("R-28.3-c").level is RequirementLevel.MUST_NOT


# ---------------------------------------------------------------------------
# AC-44.7 — no silent escalation; fresh consent on material change
# ---------------------------------------------------------------------------

class TestAC7NoSilentEscalation:
  def test_silence_is_never_consent(self):
    gate = ConsentGate()
    assert not gate.evaluate(_approved_prompt(), decision=ConsentOutcome.PENDING)

  def test_decline_and_cancel_do_not_pass(self):
    gate = ConsentGate()
    assert not gate.evaluate(_approved_prompt(), decision=ConsentOutcome.DECLINE)
    assert not gate.evaluate(_approved_prompt(), decision=ConsentOutcome.CANCEL)

  def test_prior_consent_covers_same_operation_and_scope(self):
    prior = ConsentRecord(
      operation="read_file", server_identity=SERVER_A, scope=frozenset({"read"})
    )
    gate = ConsentGate(prior_consents=(prior,))
    # No fresh decision needed: prior approval already covers it, no escalation.
    assert gate.evaluate(
      _approved_prompt(), scope={"read"}, decision=ConsentOutcome.PENDING
    )

  def test_broader_scope_is_material_change_requiring_fresh_consent(self):
    prior = ConsentRecord(
      operation="read_file", server_identity=SERVER_A, scope=frozenset({"read"})
    )
    gate = ConsentGate(prior_consents=(prior,))
    # Escalating to "write" scope must NOT pass on silence (no silent escalation).
    assert not gate.evaluate(
      _approved_prompt(), scope={"read", "write"}, decision=ConsentOutcome.PENDING
    )
    # It DOES pass with a fresh explicit approval.
    assert gate.evaluate(
      _approved_prompt(), scope={"read", "write"}, decision=ConsentOutcome.APPROVE
    )

  def test_is_material_change_helper(self):
    prior = ConsentRecord(
      operation="read_file", server_identity=SERVER_A, scope=frozenset({"read"})
    )
    assert not is_material_change(
      prior, operation="read_file", server_identity=SERVER_A, scope={"read"}
    )
    assert is_material_change(
      None, operation="read_file", server_identity=SERVER_A, scope={"read"}
    )
    # Different server is a material change (isolation).
    assert is_material_change(
      prior, operation="read_file", server_identity=SERVER_B, scope={"read"}
    )

  def test_spoofable_prompt_rejected(self):
    gate = ConsentGate()
    spoofable = ConsentPrompt(
      operation="read_file",
      server_identity=SERVER_A,
      description="do it",
      host_rendered=False,
    )
    assert not gate.evaluate(spoofable, decision=ConsentOutcome.APPROVE)


# ---------------------------------------------------------------------------
# AC-44.8 — human in loop; not solely the model; prompt-injection backstop
# ---------------------------------------------------------------------------

class TestAC8HumanInLoop:
  def test_model_only_decision_is_blocked(self):
    gate = ConsentGate()
    assert not gate.evaluate(
      _approved_prompt(),
      decision=ConsentOutcome.APPROVE,
      initiated_by_model_only=True,
    )

  def test_decision_rests_solely_with_model_predicate(self):
    assert decision_rests_solely_with_model(human_can_deny=False)
    assert not decision_rests_solely_with_model(human_can_deny=True)

  def test_human_able_to_deny_passes(self):
    gate = ConsentGate()
    assert gate.evaluate(
      _approved_prompt(),
      decision=ConsentOutcome.APPROVE,
      initiated_by_model_only=False,
    )

  def test_prompt_injection_atom_present(self):
    assert security_requirement("R-28.3-f").section == "§28.3"


# ---------------------------------------------------------------------------
# AC-44.9 — rate-limit / reject over-limit / sanitize output
# ---------------------------------------------------------------------------

class TestAC9RateLimitSanitize:
  def test_rate_limit_atoms_mandatory(self):
    for atom in ("R-28.3-g", "R-28.3-h", "R-28.3-i"):
      assert security_requirement(atom).is_mandatory
    assert Role.SERVER in security_requirement("R-28.3-g").roles


# ---------------------------------------------------------------------------
# AC-44.10 — show args / timeout / audit log without secrets
# ---------------------------------------------------------------------------

class TestAC10ArgsTimeoutAudit:
  def test_arguments_carried_on_prompt_for_display(self):
    prompt = _approved_prompt()
    assert prompt.arguments == {"path": "README.md"}

  def test_audit_log_redacts_credentials(self):
    entry = {"tool": "read_file", "args": {"path": "x"}, "access_token": "deadbeef"}
    redacted = redact_for_log(entry)
    assert redacted["access_token"] == REDACTION_PLACEHOLDER
    assert redacted["tool"] == "read_file"

  def test_client_atoms_are_should(self):
    for atom in ("R-28.3-j", "R-28.3-k", "R-28.3-l"):
      assert security_requirement(atom).level is RequirementLevel.SHOULD


# ---------------------------------------------------------------------------
# AC-44.11 — host-elected context, isolation, no cross-server relay
# ---------------------------------------------------------------------------

class TestAC11Isolation:
  def test_no_cross_server_relay(self):
    boundary = ServerIsolationBoundary()
    with pytest.raises(ServerIsolationError):
      boundary.assert_no_cross_server_relay(SERVER_A, SERVER_B)

  def test_same_server_flow_allowed(self):
    boundary = ServerIsolationBoundary()
    boundary.assert_no_cross_server_relay(SERVER_A, SERVER_A)  # no raise

  def test_host_elected_context_only(self):
    boundary = ServerIsolationBoundary(
      consented_targets={"ctx": frozenset({SERVER_A})}
    )
    assert boundary.may_expose("ctx", SERVER_A)
    assert not boundary.may_expose("ctx", SERVER_B)

  def test_isolation_atoms_bind_host(self):
    for atom in ("R-28.4-d", "R-28.4-e", "R-28.4-f"):
      assert Role.HOST in security_requirement(atom).roles


# ---------------------------------------------------------------------------
# AC-44.12 — audience validation before processing; reject; no data to others
# ---------------------------------------------------------------------------

class TestAC12TokenAudience:
  def test_matching_audience_accepted(self):
    assert not server_must_reject_token("https://srv.example", "https://srv.example")

  def test_mismatched_audience_rejected(self):
    assert server_must_reject_token("https://other.example", "https://srv.example")

  def test_audience_error_type_is_reexported(self):
    # The sibling-owned error is reachable through the security surface.
    assert issubclass(TokenAudienceError, ValueError)

  def test_audience_atoms_mandatory(self):
    for atom in ("R-28.5-b", "R-28.5-c", "R-28.5-d"):
      assert security_requirement(atom).is_mandatory


# ---------------------------------------------------------------------------
# AC-44.13 — no token passthrough / confused deputy
# ---------------------------------------------------------------------------

class TestAC13NoPassthrough:
  def test_server_never_forwards_client_token(self):
    assert server_may_forward_client_token() is False

  def test_client_only_sends_token_to_matching_as(self):
    assert client_may_send_token_to_server("https://as.example", "https://as.example")
    assert not client_may_send_token_to_server(
      "https://as.example", "https://other-as.example"
    )

  def test_passthrough_atoms(self):
    assert security_requirement("R-28.5-f").level is RequirementLevel.MUST_NOT
    assert security_requirement("R-28.5-g").is_mandatory


# ---------------------------------------------------------------------------
# AC-44.14 — exact issuer comparison, no normalization
# ---------------------------------------------------------------------------

class TestAC14ExactIssuer:
  def test_exact_match_accepted(self):
    assert exact_issuer_matches("https://as.example", "https://as.example")

  def test_absent_issuer_rejected(self):
    assert not exact_issuer_matches(None, "https://as.example")

  def test_trailing_slash_difference_rejected_no_normalization(self):
    assert not exact_issuer_matches("https://as.example/", "https://as.example")

  def test_case_fold_difference_rejected_no_normalization(self):
    assert not exact_issuer_matches("https://AS.example", "https://as.example")


# ---------------------------------------------------------------------------
# AC-44.15 — PKCE S256 mandatory
# ---------------------------------------------------------------------------

class TestAC15PKCE:
  def test_required_method_is_s256(self):
    assert PKCE_CODE_CHALLENGE_METHOD == "S256"

  def test_generated_pkce_uses_s256(self):
    params = generate_pkce_parameters()
    assert params.code_challenge_method == "S256"
    assert params.code_verifier
    assert params.code_challenge

  def test_pkce_atoms_mandatory(self):
    assert security_requirement("R-28.5-j").is_mandatory
    assert security_requirement("R-28.5-k").is_mandatory


# ---------------------------------------------------------------------------
# AC-44.16 — state CSRF defense
# ---------------------------------------------------------------------------

class TestAC16State:
  def test_state_is_high_entropy_and_unique(self):
    s1 = generate_state()
    s2 = generate_state()
    assert s1 and s2 and s1 != s2

  def test_state_atoms(self):
    assert security_requirement("R-28.5-l").level is RequirementLevel.SHOULD
    assert security_requirement("R-28.5-m").is_mandatory


# ---------------------------------------------------------------------------
# AC-44.17 — token confidentiality / never logged / HTTPS
# ---------------------------------------------------------------------------

class TestAC17TokenConfidentiality:
  def test_token_key_is_sensitive_and_redacted(self):
    assert is_sensitive_key("access_token")
    assert is_sensitive_key("refresh_token")
    assert is_sensitive_key("Authorization")
    out = redact_for_log({"refresh_token": "rt", "x": 1})
    assert out["refresh_token"] == REDACTION_PLACEHOLDER
    assert out["x"] == 1

  def test_https_endpoint_is_secure(self):
    assert authorization_endpoint_uri_is_secure("https://as.example/authorize")

  def test_localhost_http_redirect_permitted(self):
    assert authorization_endpoint_uri_is_secure("http://localhost:8080/callback")
    assert authorization_endpoint_uri_is_secure("http://127.0.0.1/callback")

  def test_remote_http_endpoint_rejected(self):
    assert not authorization_endpoint_uri_is_secure("http://as.example/authorize")

  def test_confidentiality_atoms(self):
    assert security_requirement("R-28.5-o").level is RequirementLevel.MUST_NOT
    assert security_requirement("R-28.5-p").level is RequirementLevel.MUST_NOT
    assert security_requirement("R-28.9-d").level is RequirementLevel.MUST_NOT
    assert security_requirement("R-28.5-q").is_mandatory


# ---------------------------------------------------------------------------
# AC-44.18 — continuation token integrity & replay
# ---------------------------------------------------------------------------

class TestAC18Continuation:
  def test_roundtrip_payload_preserved(self):
    guard = ContinuationTokenGuard(secret_key=b"server-secret-key")
    token = guard.issue("continuation-state-xyz")
    assert guard.accept(token) == "continuation-state-xyz"

  def test_tampered_token_rejected(self):
    guard = ContinuationTokenGuard(secret_key=b"server-secret-key")
    token = guard.issue("state")
    tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    with pytest.raises(ContinuationTokenError):
      guard.accept(tampered)

  def test_foreign_secret_rejected(self):
    minter = ContinuationTokenGuard(secret_key=b"secret-one")
    receiver = ContinuationTokenGuard(secret_key=b"secret-two")
    token = minter.issue("state")
    with pytest.raises(ContinuationTokenError):
      receiver.accept(token)

  def test_replay_rejected_single_use(self):
    guard = ContinuationTokenGuard(secret_key=b"server-secret-key", single_use=True)
    token = guard.issue("state")
    assert guard.accept(token) == "state"
    with pytest.raises(ContinuationTokenError):
      guard.accept(token)

  def test_non_single_use_allows_reuse(self):
    guard = ContinuationTokenGuard(secret_key=b"k", single_use=False)
    token = guard.issue("state")
    assert guard.accept(token) == "state"
    assert guard.accept(token) == "state"


# ---------------------------------------------------------------------------
# AC-44.19 — elicitation under user control; anti-phishing; identity
# ---------------------------------------------------------------------------

class TestAC19Elicitation:
  def test_response_returned_only_on_approval(self):
    assert elicitation_response_may_be_returned(ConsentOutcome.APPROVE)
    assert not elicitation_response_may_be_returned(ConsentOutcome.DECLINE)
    assert not elicitation_response_may_be_returned(ConsentOutcome.CANCEL)
    assert not elicitation_response_may_be_returned(ConsentOutcome.PENDING)

  def test_secret_requests_flagged_as_suspect(self):
    assert elicitation_requests_secret("Enter your password")
    assert elicitation_requests_secret("API key")
    assert elicitation_requests_secret("account credential")
    assert not elicitation_requests_secret("Enter your favorite color")

  def test_phishing_atom_is_prohibition(self):
    assert security_requirement("R-28.7-d").level is RequirementLevel.MUST_NOT
    assert security_requirement("R-28.7-e").level is RequirementLevel.SHOULD


# ---------------------------------------------------------------------------
# AC-44.20 — sampling human review; bounded context
# ---------------------------------------------------------------------------

class TestAC20Sampling:
  def test_sampling_proceeds_only_when_all_approved(self):
    assert sampling_may_proceed(
      prompt_reviewed_and_approved=True,
      completion_reviewed_and_approved=True,
      context_within_authorized=True,
    )

  def test_sampling_blocked_if_prompt_not_reviewed(self):
    assert not sampling_may_proceed(
      prompt_reviewed_and_approved=False,
      completion_reviewed_and_approved=True,
      context_within_authorized=True,
    )

  def test_sampling_blocked_if_completion_not_reviewed(self):
    assert not sampling_may_proceed(
      prompt_reviewed_and_approved=True,
      completion_reviewed_and_approved=False,
      context_within_authorized=True,
    )

  def test_sampling_blocked_if_context_exceeds_authorized(self):
    assert not sampling_may_proceed(
      prompt_reviewed_and_approved=True,
      completion_reviewed_and_approved=True,
      context_within_authorized=False,
    )

  def test_sampling_atoms(self):
    assert security_requirement("R-28.7-f").is_mandatory
    assert security_requirement("R-28.7-g").level is RequirementLevel.MUST_NOT


# ---------------------------------------------------------------------------
# AC-44.21 — sandbox/CSP; mediation; UI tool routed through consent
# ---------------------------------------------------------------------------

class TestAC21Sandbox:
  def test_default_policy_is_restrictive(self):
    assert SandboxPolicy().is_restrictive

  def test_csp_denies_by_default(self):
    csp = SandboxPolicy().content_security_policy()
    assert "default-src 'none'" in csp
    assert "script-src 'none'" in csp
    assert "connect-src 'none'" in csp
    assert "frame-ancestors 'self'" in csp

  def test_ui_tool_invocation_routed_through_gate_and_authorized(self):
    gate = ConsentGate()
    record = route_ui_tool_invocation(
      gate, _approved_prompt(), scope={"read"}, decision=ConsentOutcome.APPROVE
    )
    assert record.outcome is ConsentOutcome.APPROVE

  def test_ui_cannot_run_tool_without_consent(self):
    gate = ConsentGate()
    with pytest.raises(UnmediatedToolInvocationError):
      route_ui_tool_invocation(
        gate, _approved_prompt(), decision=ConsentOutcome.PENDING
      )

  def test_sandbox_atoms_bind_host(self):
    for atom in ("R-28.8-a", "R-28.8-b", "R-28.8-c", "R-28.8-d"):
      assert Role.HOST in security_requirement(atom).roles


# ---------------------------------------------------------------------------
# AC-44.22 — least privilege; no credential/exfiltration; anti-spoof
# ---------------------------------------------------------------------------

class TestAC22SandboxLeastPriv:
  def test_credential_exposure_makes_policy_non_restrictive(self):
    assert not SandboxPolicy(exposes_credentials=True).is_restrictive

  def test_top_navigation_exfiltration_channel_non_restrictive(self):
    assert not SandboxPolicy(allow_top_navigation=True).is_restrictive

  def test_inter_frame_exfiltration_channel_non_restrictive(self):
    assert not SandboxPolicy(allow_inter_frame=True).is_restrictive

  def test_unprotected_host_chrome_non_restrictive(self):
    assert not SandboxPolicy(host_chrome_protected=False).is_restrictive

  def test_least_privilege_opens_only_what_is_needed(self):
    policy = SandboxPolicy(allow_scripting=True, allow_network=True)
    csp = policy.content_security_policy()
    assert "script-src 'self'" in csp
    assert "connect-src 'self'" in csp
    # Still restrictive: exfiltration channels remain closed.
    assert policy.is_restrictive

  def test_least_priv_atoms_are_should(self):
    assert security_requirement("R-28.8-g").level is RequirementLevel.SHOULD
    assert security_requirement("R-28.8-h").level is RequirementLevel.SHOULD


# ---------------------------------------------------------------------------
# AC-44.23 — metadata carries no authority; validate/ignore; redact
# ---------------------------------------------------------------------------

class TestAC23Metadata:
  def test_metadata_carries_no_authority(self):
    assert metadata_value_carries_authority() is False

  def test_metadata_never_drives_access_control(self):
    assert use_metadata_for_access_control({"traceId": "admin", "role": "root"}) is False

  def test_unknown_metadata_keys_ignored(self):
    filtered = filter_known_metadata(
      {"traceId": "t", "progressToken": 1, "evil": "x"},
      known_keys={"traceId", "progressToken"},
    )
    assert filtered == {"traceId": "t", "progressToken": 1}
    assert "evil" not in filtered

  def test_sensitive_content_redacted_before_crossing_boundary(self):
    payload = {"meta": {"authorization": "Bearer abc"}, "ok": True}
    redacted = redact_for_log(payload)
    assert redacted["meta"]["authorization"] == REDACTION_PLACEHOLDER
    assert redacted["ok"] is True

  def test_metadata_authority_atom_is_prohibition(self):
    assert security_requirement("R-28.9-a").level is RequirementLevel.MUST_NOT


# ---------------------------------------------------------------------------
# AC-44.24 — validate all inputs; arg/result schema; errors not actions
# ---------------------------------------------------------------------------

class TestAC24InputValidation:
  def test_valid_arguments_pass(self):
    validate_tool_arguments(_tool_with_required_path(), {"path": "README.md"})

  def test_invalid_arguments_raise_validation_error_as_invalid_params(self):
    tool = _tool_with_required_path()
    with pytest.raises(ValidationError) as exc:
      validate_tool_arguments(tool, {})  # missing required "path"
    assert exc.value.error_code == -32602

  def test_validation_error_renders_error_object(self):
    tool = _tool_with_required_path()
    with pytest.raises(ValidationError) as exc:
      validate_tool_arguments(tool, {"path": 5})  # wrong type
    err = exc.value.to_error_object()
    assert err.code == -32602
    assert err.message
    assert err.has_data

  def test_input_validation_atoms_mandatory(self):
    for atom in ("R-28.10-a", "R-28.10-c", "R-28.10-e"):
      assert security_requirement(atom).is_mandatory
    assert security_requirement("R-28.10-b").level is RequirementLevel.MUST_NOT
    assert security_requirement("R-28.10-d").level is RequirementLevel.SHOULD


# ---------------------------------------------------------------------------
# AC-44.25 — URI validation; authorized location; SSRF
# ---------------------------------------------------------------------------

class TestAC25UriSsrf:
  def test_valid_uri_accepted(self):
    assert validate_resource_uri("file:///srv/data/a.txt") == "file:///srv/data/a.txt"

  def test_schemeless_uri_rejected(self):
    with pytest.raises(UriValidationError):
      validate_resource_uri("/no/scheme")

  def test_disallowed_scheme_rejected(self):
    with pytest.raises(UriValidationError):
      validate_resource_uri("ftp://host/x", allowed_schemes={"file", "https"})

  def test_ssrf_allowlist(self):
    assert is_ssrf_safe_host("api.allowed.example", allowed_hosts={"api.allowed.example"})
    assert not is_ssrf_safe_host("169.254.169.254", allowed_hosts={"api.allowed.example"})

  def test_network_uri_to_unauthorized_host_rejected(self):
    with pytest.raises(UriValidationError):
      assert_uri_followable(
        "https://169.254.169.254/latest/meta-data",
        allowed_hosts={"api.allowed.example"},
      )

  def test_network_uri_to_authorized_host_allowed(self):
    assert assert_uri_followable(
      "https://api.allowed.example/x", allowed_hosts={"api.allowed.example"}
    )

  def test_uri_atoms(self):
    assert security_requirement("R-28.10-f").is_mandatory
    assert security_requirement("R-28.10-g").level is RequirementLevel.MUST_NOT
    assert security_requirement("R-28.10-h").level is RequirementLevel.SHOULD


# ---------------------------------------------------------------------------
# AC-44.26 — Origin validation / DNS-rebinding
# ---------------------------------------------------------------------------

class TestAC26Origin:
  def test_accepted_origin_passes(self):
    validator = OriginValidator({"https://app.example"})
    assert validator.is_accepted({"Origin": "https://app.example"})

  def test_untrusted_origin_rejected(self):
    validator = OriginValidator({"https://app.example"})
    assert not validator.is_accepted({"Origin": "https://evil.example"})
    resp = validator.reject_response()
    assert resp.status == 403

  def test_origin_atom_mandatory_for_server(self):
    atom = security_requirement("R-28.10-i")
    assert atom.is_mandatory
    assert Role.SERVER in atom.roles


# ---------------------------------------------------------------------------
# AC-44.27 — pagination cursor opaque/untrusted; reject malformed/expired
# ---------------------------------------------------------------------------

class TestAC27Cursor:
  def test_valid_known_cursor_accepted(self):
    assert validate_pagination_cursor("cur-1", recognized={"cur-1", "cur-2"}) == "cur-1"

  def test_non_string_cursor_rejected(self):
    with pytest.raises(ValidationError) as exc:
      validate_pagination_cursor({"page": 2})
    assert exc.value.error_code == -32602
    assert exc.value.reason == "malformed-or-expired"

  def test_unknown_cursor_rejected(self):
    with pytest.raises(ValidationError):
      validate_pagination_cursor("forged", recognized={"cur-1"})

  def test_cursor_atom_mandatory(self):
    assert security_requirement("R-28.10-j").is_mandatory


# ---------------------------------------------------------------------------
# AC-44.28 — bounded depth/time and size limits
# ---------------------------------------------------------------------------

class TestAC28Bounds:
  def test_shallow_structure_within_depth(self):
    assert bounded_depth({"a": {"b": 1}}) == 3

  def test_deep_structure_rejected(self):
    deep = current = {}
    for _ in range(MAX_VALIDATION_DEPTH + 5):
      current["n"] = {}
      current = current["n"]
    with pytest.raises(ValidationError) as exc:
      bounded_depth(deep)
    assert exc.value.reason == "max-depth-exceeded"

  def test_size_limit_enforced(self):
    assert_message_within_size(10)  # within
    with pytest.raises(ValidationError) as exc:
      assert_message_within_size(MAX_MESSAGE_BYTES + 1)
    assert exc.value.reason == "payload-too-large"

  def test_bounds_atoms(self):
    assert security_requirement("R-28.10-k").is_mandatory
    assert security_requirement("R-28.10-l").level is RequirementLevel.SHOULD


# ---------------------------------------------------------------------------
# AC-44.29 — no external schema dereference; self-contained schemas
# ---------------------------------------------------------------------------

class TestAC29ExternalRefs:
  def test_internal_ref_is_not_external(self):
    assert not schema_has_external_references(
      {"type": "object", "properties": {"x": {"$ref": "#/$defs/X"}}}
    )

  def test_external_ref_detected(self):
    assert schema_has_external_references(
      {"properties": {"x": {"$ref": "https://attacker.example/schema.json"}}}
    )

  def test_assert_rejects_external_ref(self):
    with pytest.raises(ValidationError) as exc:
      assert_no_external_schema_references(
        {"$ref": "https://attacker.example/s.json"}
      )
    assert exc.value.reason == "external-schema-reference"

  def test_assert_allows_self_contained(self):
    assert_no_external_schema_references(
      {"type": "object", "$defs": {"X": {"type": "string"}}}
    )

  def test_external_ref_atoms(self):
    assert security_requirement("R-28.10-m").level is RequirementLevel.MUST_NOT
    assert security_requirement("R-28.10-n").is_mandatory


# ---------------------------------------------------------------------------
# AC-44.30 — file:// path sanitization; no escape of authorized root
# ---------------------------------------------------------------------------

class TestAC30FilePaths:
  def test_within_root_allowed(self):
    assert sanitize_file_path("/srv/data", "reports/q1.txt") == "/srv/data/reports/q1.txt"

  def test_dot_dot_traversal_blocked(self):
    with pytest.raises(FilePathTraversalError):
      sanitize_file_path("/srv/data", "../../etc/passwd")

  def test_encoded_traversal_blocked(self):
    with pytest.raises(FilePathTraversalError):
      sanitize_file_path("/srv/data", "..%2f..%2fetc%2fpasswd")

  def test_absolute_path_confined_to_root(self):
    # A leading slash is treated as relative to the root, never an escape.
    assert sanitize_file_path("/srv/data", "/etc/passwd") == "/srv/data/etc/passwd"

  def test_root_itself_allowed(self):
    assert sanitize_file_path("/srv/data", "") == "/srv/data"

  def test_predicate_companion(self):
    assert path_is_within_authorized_root("/srv/data", "a/b.txt")
    assert not path_is_within_authorized_root("/srv/data", "../../x")

  def test_file_path_atoms(self):
    assert security_requirement("R-28.10-o").is_mandatory
    assert security_requirement("R-28.10-p").level is RequirementLevel.MUST_NOT


# ---------------------------------------------------------------------------
# Catalog integrity — every §28 atom is catalogued and well-formed
# ---------------------------------------------------------------------------

# The full set of §28 normative atoms per the story's traceability table.
_EXPECTED_ATOMS = {
  "R-28-a",
  *(f"R-28.1-{c}" for c in "abcdefghijk"),
  *(f"R-28.2-{c}" for c in "abcdefg"),
  *(f"R-28.3-{c}" for c in "abcdefghijkl"),
  *(f"R-28.4-{c}" for c in "abcdef"),
  *(f"R-28.5-{c}" for c in "abcdefghijklmnopq"),
  *(f"R-28.6-{c}" for c in "abc"),
  *(f"R-28.7-{c}" for c in "abcdefg"),
  *(f"R-28.8-{c}" for c in "abcdefgh"),
  *(f"R-28.9-{c}" for c in "abcde"),
  *(f"R-28.10-{c}" for c in "abcdefghijklmnop"),
}


class TestCatalogIntegrity:
  def test_every_expected_atom_is_present(self):
    missing = _EXPECTED_ATOMS - set(SECURITY_REQUIREMENTS)
    assert not missing, f"missing §28 atoms: {sorted(missing)}"

  def test_no_unexpected_atoms(self):
    extra = set(SECURITY_REQUIREMENTS) - _EXPECTED_ATOMS
    assert not extra, f"unexpected atoms: {sorted(extra)}"

  def test_total_atom_count(self):
    # 1 + 11 + 7 + 12 + 6 + 17 + 3 + 7 + 8 + 5 + 16 = 93 atoms.
    assert len(SECURITY_REQUIREMENTS) == 93

  def test_every_entry_is_well_formed(self):
    for atom, req in SECURITY_REQUIREMENTS.items():
      assert isinstance(req, SecurityRequirement)
      assert req.atom == atom
      assert isinstance(req.level, RequirementLevel)
      assert req.section.startswith("§28")
      assert req.summary
      assert req.ac.startswith("AC-44.")

  def test_requirement_lookup_raises_on_unknown(self):
    with pytest.raises(KeyError):
      security_requirement("R-99.9-z")

  def test_requirements_for_role_filters(self):
    server_reqs = security_requirements_for_role(Role.SERVER)
    atoms = {r.atom for r in server_reqs}
    # A server-bound atom and an any-party atom both appear for SERVER.
    assert "R-28.3-g" in atoms  # server-only
    assert "R-28-a" in atoms    # binds everyone
    # A host-only atom does not bind the server.
    assert "R-28.4-f" not in atoms

  def test_mandatory_subset(self):
    mandatory = {r.atom for r in mandatory_security_requirements()}
    assert "R-28.5-b" in mandatory  # MUST
    assert "R-28.5-f" in mandatory  # MUST NOT
    assert "R-28.1-d" not in mandatory  # SHOULD
