"""Tests for S36 — Authorization II: Auth-Code+PKCE Flow, Tokens & Worked Examples.

Covers every normative atom of §23.4–§23.10 in scope for S36 and every numbered
acceptance criterion AC-36.1 .. AC-36.66, plus the §23.10 worked HTTP examples.

AC → test coverage map:
  AC-36.1  (R-23.4-a)        → TestObtainClientIdMechanisms::test_obtains_one_mechanism_or_prompts
  AC-36.2  (R-23.4-b)        → TestObtainClientIdMechanisms::test_priority_order
  AC-36.3  (R-23.4-c)        → TestPreRegistrationMismatch
  AC-36.4  (R-23.4-d)        → TestCIMDFormation::test_https_url_resolving_to_json_doc
  AC-36.5  (R-23.4-e)        → TestCIMDFormation::test_https_scheme_and_path_component
  AC-36.6  (R-23.4-f)        → TestCIMDDocument::test_requires_minimum_fields
  AC-36.7  (R-23.4-g)        → TestCIMDDocument::test_client_id_equals_url
  AC-36.8  (R-23.4-h)        → TestAuthorizationServerCIMD::test_fetches_url_client_id
  AC-36.9  (R-23.4-i)        → TestAuthorizationServerCIMD::test_validates_client_id_matches_url
  AC-36.10 (R-23.4-j)        → TestAuthorizationServerCIMD::test_validates_redirect_uri
  AC-36.11 (R-23.4-k)        → TestAuthorizationServerCIMD::test_validates_valid_json_required_fields
  AC-36.12 (R-23.4-l)        → TestCIMDCaching
  AC-36.13 (R-23.4-m)        → TestDCRApplicationType::test_includes_application_type
  AC-36.14 (R-23.4-n)        → TestDCRApplicationType::test_native
  AC-36.15 (R-23.4-o)        → TestDCRApplicationType::test_web
  AC-36.16 (R-23.4-p)        → TestDCRFailureHandling::test_handles_redirect_uri_failure
  AC-36.17 (R-23.4-q)        → TestDCRFailureHandling::test_surfaces_meaningful_error
  AC-36.18 (R-23.4-r)        → TestDCRRetry
  AC-36.19 (R-23.4-s)        → TestDCRPersistence::test_keyed_by_issuer
  AC-36.20 (R-23.4-t)        → TestDCRPersistence::test_reregister_on_as_change
  AC-36.21 (R-23.5-a)        → TestPKCE::test_uses_s256
  AC-36.22 (R-23.5-b)        → TestPKCE::test_high_entropy_verifier_and_s256_challenge
  AC-36.23 (R-23.5-c)        → TestRecordIssuer
  AC-36.24 (R-23.5-d)        → TestAuthorizationRequest::test_response_type_code
  AC-36.25 (R-23.5-e)        → TestAuthorizationRequest::test_redirect_uri_registered
  AC-36.26 (R-23.5-f)        → TestScopePriority
  AC-36.27 (R-23.5-g)        → TestAuthorizationRequest::test_opaque_state
  AC-36.28 (R-23.5-i)        → TestAuthorizationRequest::test_code_challenge_method_s256
  AC-36.29 (R-23.5-j)        → TestAuthorizationRequest::test_resource_parameter
  AC-36.30 (R-23.5-k)        → TestRedirectIssuerParameter
  AC-36.31 (R-23.5-h)        → TestStateVerification::test_verifies_returned_state
  AC-36.32 (R-23.5-l)        → TestStateVerification::test_state_matches_before_redeeming
  AC-36.33 (R-23.5-m)        → TestRedirectValidation::test_validates_iss_before_redeeming
  AC-36.34 (R-23.5-n)        → TestTokenRequest::test_grant_type_authorization_code
  AC-36.35 (R-23.5-o)        → TestTokenRequest::test_redirect_uri_identical
  AC-36.36 (R-23.5-p)        → TestTokenRequest::test_resource_identical
  AC-36.37 (R-23.6-a)        → TestResourceIndicators::test_implements_resource_indicators
  AC-36.38 (R-23.6-b)        → TestResourceIndicators::test_resource_in_both_requests
  AC-36.39 (R-23.6-c)        → TestResourceIndicators::test_resource_identifies_server
  AC-36.40 (R-23.6-d)        → TestResourceIndicators::test_resource_is_canonical_identifier
  AC-36.41 (R-23.6-e)        → TestResourceIndicators::test_sends_resource_regardless_of_support
  AC-36.42 (R-23.6-f)        → TestAudienceBinding::test_server_validates_audience
  AC-36.43 (R-23.6-g)        → TestAudienceBinding::test_server_rejects_wrong_audience
  AC-36.44 (R-23.6-h)        → TestAudienceBinding::test_server_only_own_resources
  AC-36.45 (R-23.6-i)        → TestAudienceBinding::test_client_sends_only_bound_token
  AC-36.46 (R-23.7-a)        → TestIssValidation::test_validates_before_token_endpoint
  AC-36.47 (R-23.7-b)        → TestIssAdvertised::test_iss_included_in_responses
  AC-36.48 (R-23.7-c)        → TestIssAdvertised::test_advertises_supported_flag
  AC-36.49 (R-23.7-d)        → TestIssValidationTable
  AC-36.50 (R-23.7-e)        → TestIssValidation::test_supported_true_iss_absent_rejected
  AC-36.51 (R-23.7-f)        → TestIssValidation::test_compares_iss_regardless_of_advertisement
  AC-36.52 (R-23.7-g)        → TestIssExactMatch
  AC-36.53 (R-23.7-h)        → TestErrorResponseSuppression
  AC-36.54 (R-23.8-a)        → TestAccessTokenUsage::test_authorization_on_every_request
  AC-36.55 (R-23.8-b)        → TestAccessTokenUsage::test_bearer_header
  AC-36.56 (R-23.8-c)        → TestAccessTokenUsage::test_not_in_query_string
  AC-36.57 (R-23.8-d)        → TestServerTokenValidation::test_validates_all_aspects
  AC-36.58 (R-23.8-e)        → TestServerTokenValidation::test_401_for_invalid
  AC-36.59 (R-23.8-f)        → TestServerTokenValidation::test_403_insufficient_scope
  AC-36.60 (R-23.9-a)        → TestRefreshTokens::test_includes_refresh_token_grant_type
  AC-36.61 (R-23.9-b)        → TestRefreshTokens::test_offline_access_when_supported
  AC-36.62 (R-23.9-c)        → TestRefreshTokens::test_refresh_token_confidential
  AC-36.63 (R-23.9-d)        → TestRefreshTokens::test_does_not_assume_refresh_token
  AC-36.64 (R-23.9-e)        → TestRefreshTokens::test_refresh_request_audience_bound
  AC-36.65 (R-23.9-f)        → TestRefreshTokens::test_refresh_may_narrow_scope
  AC-36.66 (R-23.9-g)        → TestRefreshTokens::test_offline_access_excluded_from_resource

Worked HTTP examples (§23.10): TestWorkedExamples.
"""

import base64
import hashlib

import pytest

from mcp_sdk_py.authorization import (
  AuthorizationServerMetadata,
  BearerChallenge,
  ProtectedResourceMetadata,
  build_canonical_resource_identifier,
)
from mcp_sdk_py.oauth_flow import (
  AUTHORIZATION_HEADER,
  CLIENT_ID_MECHANISM_PRIORITY,
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_REFRESH_TOKEN,
  OFFLINE_ACCESS_SCOPE,
  PKCE_CODE_CHALLENGE_METHOD,
  RESOURCE_PARAMETER,
  RESPONSE_TYPE_CODE,
  ApplicationType,
  AudienceMismatchError,
  AuthorizationRecord,
  AuthorizationRequest,
  AuthorizationResponse,
  AuthorizationServerMismatchError,
  CIMDCache,
  CIMDValidationError,
  ClientIdMechanism,
  ClientIdMetadataDocument,
  DCRCredentialStore,
  DCRRegistrationError,
  DynamicClientRegistrationRequest,
  DynamicClientRegistrationResponse,
  IssValidationAction,
  IssValidationError,
  PKCEParameters,
  PreRegisteredCredentials,
  StateMismatchError,
  TokenInQueryStringError,
  TokenRequest,
  TokenResponse,
  TokenValidationError,
  TokenValidationOutcome,
  add_offline_access_scope,
  application_type_for_client,
  authorization_and_token_resource_match,
  authorization_server_fetch_cimd,
  authorization_server_validate_cimd,
  build_authorization_header,
  build_authorization_request,
  build_authorization_request_url,
  build_dcr_request,
  build_refresh_token_request,
  build_token_request,
  client_may_send_token,
  client_wants_refresh_grant_types,
  derive_code_challenge,
  encode_token_request_body,
  error_response_is_actionable,
  generate_code_verifier,
  generate_pkce_parameters,
  generate_state,
  is_url_formatted_client_id,
  iss_validation_action,
  may_request_offline_access,
  metadata_excludes_offline_access,
  parse_authorization_response,
  parse_client_id_metadata_document,
  parse_dcr_response,
  parse_token_response,
  pre_registration_matches,
  record_authorization_request,
  resource_indicator_for,
  retry_dcr_with_adjustment,
  select_client_id_mechanism,
  select_request_scope,
  server_accepts_token,
  token_in_query_string,
  token_is_audience_bound,
  token_validation_status,
  validate_access_token,
  validate_client_id_metadata_document,
  validate_iss,
  validate_redirect,
  verify_state,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

MCP_SERVER = "https://mcp.example.com"
AUTH_ISSUER = "https://auth.example.com"
CIMD_URL = "https://app.example.com/oauth/client-metadata.json"
REDIRECT_URI = "http://localhost:3000/callback"


def _as_metadata(**overrides) -> AuthorizationServerMetadata:
  defaults = dict(
    issuer=AUTH_ISSUER,
    authorization_endpoint=f"{AUTH_ISSUER}/authorize",
    token_endpoint=f"{AUTH_ISSUER}/token",
  )
  defaults.update(overrides)
  return AuthorizationServerMetadata(**defaults)


def _prm(**overrides) -> ProtectedResourceMetadata:
  defaults = dict(
    resource=MCP_SERVER,
    authorization_servers=[AUTH_ISSUER],
    scopes_supported=["files:read", "files:write"],
    bearer_methods_supported=["header"],
  )
  defaults.update(overrides)
  return ProtectedResourceMetadata(**defaults)


def _cimd_doc() -> dict:
  return {
    "client_id": CIMD_URL,
    "client_name": "Example MCP Client",
    "client_uri": "https://app.example.com",
    "logo_uri": "https://app.example.com/logo.png",
    "redirect_uris": [
      "http://127.0.0.1:3000/callback",
      "http://localhost:3000/callback",
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
  }


# ===========================================================================
# §23.4  Obtaining a client_id
# ===========================================================================


class TestObtainClientIdMechanisms:
  """AC-36.1 / AC-36.2 — obtaining a client_id and the priority order."""

  def test_obtains_one_mechanism_or_prompts(self):
    # AC-36.1 (R-23.4-a): always resolves to exactly one mechanism, with the
    # user-prompt fallback always available.
    chosen = select_client_id_mechanism([])
    assert chosen is ClientIdMechanism.USER_PROMPT
    chosen = select_client_id_mechanism({ClientIdMechanism.DYNAMIC_CLIENT_REGISTRATION})
    assert chosen is ClientIdMechanism.DYNAMIC_CLIENT_REGISTRATION

  def test_priority_order(self):
    # AC-36.2 (R-23.4-b): pre-registration → CIMD → DCR → user prompt.
    assert CLIENT_ID_MECHANISM_PRIORITY == (
      ClientIdMechanism.PRE_REGISTRATION,
      ClientIdMechanism.CLIENT_ID_METADATA_DOCUMENT,
      ClientIdMechanism.DYNAMIC_CLIENT_REGISTRATION,
      ClientIdMechanism.USER_PROMPT,
    )
    all_three = {
      ClientIdMechanism.DYNAMIC_CLIENT_REGISTRATION,
      ClientIdMechanism.CLIENT_ID_METADATA_DOCUMENT,
      ClientIdMechanism.PRE_REGISTRATION,
    }
    assert select_client_id_mechanism(all_three) is ClientIdMechanism.PRE_REGISTRATION
    without_pre = {
      ClientIdMechanism.DYNAMIC_CLIENT_REGISTRATION,
      ClientIdMechanism.CLIENT_ID_METADATA_DOCUMENT,
    }
    assert (
      select_client_id_mechanism(without_pre)
      is ClientIdMechanism.CLIENT_ID_METADATA_DOCUMENT
    )


class TestPreRegistrationMismatch:
  """AC-36.3 (R-23.4-c) — surfacing a mismatched-AS error for pre-registration."""

  def test_match_returns_true(self):
    creds = PreRegisteredCredentials(issuer=AUTH_ISSUER, client_id="abc")
    assert pre_registration_matches(creds, AUTH_ISSUER) is True

  def test_mismatch_surfaces_error(self):
    creds = PreRegisteredCredentials(issuer="https://other.example.com", client_id="abc")
    with pytest.raises(AuthorizationServerMismatchError) as exc:
      pre_registration_matches(creds, AUTH_ISSUER)
    assert exc.value.credential_issuer == "https://other.example.com"
    assert exc.value.indicated_issuer == AUTH_ISSUER


class TestCIMDFormation:
  """AC-36.4 / AC-36.5 — the CIMD client_id is an HTTPS URL with a path."""

  def test_https_url_resolving_to_json_doc(self):
    # AC-36.4 (R-23.4-d): the client_id is an HTTPS URL resolving to a JSON doc.
    assert is_url_formatted_client_id(CIMD_URL) is True
    doc = parse_client_id_metadata_document(_cimd_doc())
    assert doc.client_id == CIMD_URL
    assert doc.client_name == "Example MCP Client"

  def test_https_scheme_and_path_component(self):
    # AC-36.5 (R-23.4-e): https scheme + path component required.
    assert is_url_formatted_client_id("https://app.example.com/oauth/meta.json") is True
    assert is_url_formatted_client_id("http://app.example.com/meta.json") is False
    assert is_url_formatted_client_id("https://app.example.com") is False
    assert is_url_formatted_client_id("https://app.example.com/") is False


class TestCIMDDocument:
  """AC-36.6 / AC-36.7 — required CIMD fields and the client_id == URL rule."""

  def test_requires_minimum_fields(self):
    # AC-36.6 (R-23.4-f): client_id, client_name, redirect_uris required.
    for missing in ("client_id", "client_name", "redirect_uris"):
      raw = _cimd_doc()
      del raw[missing]
      with pytest.raises(CIMDValidationError):
        parse_client_id_metadata_document(raw)

  def test_client_id_equals_url(self):
    # AC-36.7 (R-23.4-g): client_id field exactly equals the document URL.
    doc = parse_client_id_metadata_document(_cimd_doc())
    validate_client_id_metadata_document(doc, CIMD_URL)  # exact match: OK
    with pytest.raises(CIMDValidationError):
      validate_client_id_metadata_document(doc, "https://app.example.com/other.json")


class TestAuthorizationServerCIMD:
  """AC-36.8 .. AC-36.11 — the authorization server's CIMD duties."""

  def test_fetches_url_client_id(self):
    # AC-36.8 (R-23.4-h): a URL-formatted client_id is fetched.
    calls = []

    def resolver(url):
      calls.append(url)
      return _cimd_doc()

    doc = authorization_server_fetch_cimd(CIMD_URL, resolver)
    assert calls == [CIMD_URL]
    assert doc.client_id == CIMD_URL

  def test_validates_client_id_matches_url(self):
    # AC-36.9 (R-23.4-i): the fetched document's client_id must match the URL.
    raw = _cimd_doc()
    raw["client_id"] = "https://attacker.example.com/meta.json"
    with pytest.raises(CIMDValidationError):
      authorization_server_validate_cimd(CIMD_URL, raw)

  def test_validates_redirect_uri(self):
    # AC-36.10 (R-23.4-j): the presented redirect URI is validated against the doc.
    raw = _cimd_doc()
    # A listed redirect URI is accepted.
    authorization_server_validate_cimd(
      CIMD_URL, raw, presented_redirect_uri="http://localhost:3000/callback"
    )
    # An unlisted one is rejected.
    with pytest.raises(CIMDValidationError):
      authorization_server_validate_cimd(
        CIMD_URL, raw, presented_redirect_uri="http://evil.example.com/cb"
      )

  def test_validates_valid_json_required_fields(self):
    # AC-36.11 (R-23.4-k): body must be valid JSON with the required fields.
    with pytest.raises(CIMDValidationError):
      authorization_server_validate_cimd(CIMD_URL, "not-a-json-object")
    raw = _cimd_doc()
    del raw["redirect_uris"]
    with pytest.raises(CIMDValidationError):
      authorization_server_validate_cimd(CIMD_URL, raw)


class TestCIMDCaching:
  """AC-36.12 (R-23.4-l) — caching the CIMD respecting HTTP cache headers."""

  def test_caches_and_serves_from_cache(self):
    cache = CIMDCache()
    calls = []

    def resolver(url):
      calls.append(url)
      return _cimd_doc()

    first = authorization_server_fetch_cimd(CIMD_URL, resolver, cache=cache)
    second = authorization_server_fetch_cimd(CIMD_URL, resolver, cache=cache)
    assert calls == [CIMD_URL]  # fetched once; second served from cache
    assert first == second

  def test_no_store_is_not_cached(self):
    cache = CIMDCache()
    calls = []

    def resolver(url):
      calls.append(url)
      return _cimd_doc()

    authorization_server_fetch_cimd(
      CIMD_URL, resolver, cache=cache, cache_headers={"Cache-Control": "no-store"}
    )
    authorization_server_fetch_cimd(
      CIMD_URL, resolver, cache=cache, cache_headers={"Cache-Control": "no-store"}
    )
    assert calls == [CIMD_URL, CIMD_URL]  # never cached → fetched twice
    assert cache.get(CIMD_URL) is None


class TestDCRApplicationType:
  """AC-36.13 / AC-36.14 / AC-36.15 — the DCR application_type requirement."""

  def test_includes_application_type(self):
    # AC-36.13 (R-23.4-m): the registration includes an application_type.
    req = build_dcr_request([REDIRECT_URI], is_native=True)
    body = req.to_body()
    assert body["application_type"] == "native"
    assert "application_type" in body

  def test_native(self):
    # AC-36.14 (R-23.4-n): native client → "native".
    assert application_type_for_client(is_native=True) is ApplicationType.NATIVE
    req = build_dcr_request([REDIRECT_URI], is_native=True)
    assert req.application_type is ApplicationType.NATIVE

  def test_web(self):
    # AC-36.15 (R-23.4-o): remote browser-based client → "web".
    assert application_type_for_client(is_native=False) is ApplicationType.WEB
    req = build_dcr_request([REDIRECT_URI], is_native=False)
    assert req.application_type is ApplicationType.WEB


class TestDCRFailureHandling:
  """AC-36.16 / AC-36.17 — handling redirect-URI failures with a meaningful error."""

  def test_handles_redirect_uri_failure(self):
    # AC-36.16 (R-23.4-p): a redirect-URI failure is handled, not crashed on.
    error_body = {
      "error": "invalid_redirect_uri",
      "error_description": "redirect_uri must use https",
    }
    with pytest.raises(DCRRegistrationError) as exc:
      parse_dcr_response(error_body)
    assert exc.value.recoverable is True  # may retry with conforming URIs

  def test_surfaces_meaningful_error(self):
    # AC-36.17 (R-23.4-q): a rejection surfaces a meaningful error.
    with pytest.raises(DCRRegistrationError) as exc:
      parse_dcr_response({"error": "access_denied", "error_description": "nope"})
    assert "nope" in str(exc.value)
    # Missing client_id on a "success" is also surfaced.
    with pytest.raises(DCRRegistrationError):
      parse_dcr_response({})

  def test_success_parses(self):
    resp = parse_dcr_response({"client_id": "generated-id", "client_secret": "s3cret"})
    assert isinstance(resp, DynamicClientRegistrationResponse)
    assert resp.client_id == "generated-id"
    assert resp.client_secret == "s3cret"


class TestDCRRetry:
  """AC-36.18 (R-23.4-r) — retrying with an adjusted application_type or URIs."""

  def test_retry_adjusts_application_type(self):
    req = build_dcr_request([REDIRECT_URI], is_native=False)
    err = DCRRegistrationError("invalid_redirect_uri", recoverable=True)
    retried = retry_dcr_with_adjustment(
      req, err, adjusted_application_type=ApplicationType.NATIVE
    )
    assert retried.application_type is ApplicationType.NATIVE

  def test_retry_with_conforming_redirect_uris(self):
    req = build_dcr_request(["http://evil/cb"], is_native=True)
    err = DCRRegistrationError("invalid_redirect_uri", recoverable=True)
    retried = retry_dcr_with_adjustment(
      req, err, conforming_redirect_uris=["http://localhost:3000/callback"]
    )
    assert retried.redirect_uris == ["http://localhost:3000/callback"]

  def test_non_recoverable_cannot_retry(self):
    req = build_dcr_request([REDIRECT_URI], is_native=True)
    err = DCRRegistrationError("access_denied", recoverable=False)
    with pytest.raises(DCRRegistrationError):
      retry_dcr_with_adjustment(req, err, adjusted_application_type=ApplicationType.WEB)


class TestDCRPersistence:
  """AC-36.19 / AC-36.20 — DCR credentials keyed by issuer; re-register on change."""

  def test_keyed_by_issuer(self):
    # AC-36.19 (R-23.4-s): each credential is keyed by the issuing AS issuer.
    store = DCRCredentialStore()
    resp = DynamicClientRegistrationResponse(client_id="cid-a")
    store.store(AUTH_ISSUER, resp)
    assert store.get(AUTH_ISSUER) == resp
    # Never returns another issuer's credentials.
    assert store.get("https://other.example.com") is None

  def test_reregister_on_as_change(self):
    # AC-36.20 (R-23.4-t): re-register when the authorization server changes.
    store = DCRCredentialStore()
    store.store(AUTH_ISSUER, DynamicClientRegistrationResponse(client_id="cid-a"))
    assert store.must_reregister(AUTH_ISSUER) is False
    assert store.must_reregister("https://new-as.example.com") is True


# ===========================================================================
# §23.5  PKCE & the authorization-code flow
# ===========================================================================


class TestPKCE:
  """AC-36.21 / AC-36.22 — S256 PKCE generation."""

  def test_uses_s256(self):
    # AC-36.21 (R-23.5-a): code_challenge_method is S256.
    assert PKCE_CODE_CHALLENGE_METHOD == "S256"
    pkce = generate_pkce_parameters()
    assert pkce.code_challenge_method == "S256"

  def test_high_entropy_verifier_and_s256_challenge(self):
    # AC-36.22 (R-23.5-b): high-entropy verifier; challenge = BASE64URL(SHA256(v)).
    v1 = generate_code_verifier()
    v2 = generate_code_verifier()
    assert v1 != v2  # high entropy: distinct each call
    assert len(v1) >= 43  # RFC 7636 minimum length
    # Real S256 derivation, verified independently.
    expected = (
      base64.urlsafe_b64encode(hashlib.sha256(v1.encode("ascii")).digest())
      .rstrip(b"=")
      .decode("ascii")
    )
    assert derive_code_challenge(v1) == expected
    assert "=" not in derive_code_challenge(v1)  # no padding

  def test_known_rfc7636_vector(self):
    # RFC 7636 Appendix B test vector: verifier → challenge.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert derive_code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class TestRecordIssuer:
  """AC-36.23 (R-23.5-c) — recording the issuer keyed to verifier/state in Step 1."""

  def test_records_issuer_keyed_to_verifier_and_state(self):
    pkce = generate_pkce_parameters()
    state = generate_state()
    record = record_authorization_request(pkce, _as_metadata(), state=state)
    assert record.code_verifier == pkce.code_verifier
    assert record.recorded_issuer == AUTH_ISSUER
    assert record.state == state

  def test_records_without_state(self):
    pkce = generate_pkce_parameters()
    record = record_authorization_request(pkce, _as_metadata())
    assert record.state is None
    assert record.recorded_issuer == AUTH_ISSUER


def _pkce_fixed() -> PKCEParameters:
  verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  return PKCEParameters(
    code_verifier=verifier, code_challenge=derive_code_challenge(verifier)
  )


class TestAuthorizationRequest:
  """AC-36.24 / AC-36.25 / AC-36.27 / AC-36.28 / AC-36.29 — Step-2 parameters."""

  def _build(self, **overrides):
    params = dict(
      client_id=CIMD_URL,
      redirect_uri=REDIRECT_URI,
      resource=MCP_SERVER,
      pkce=_pkce_fixed(),
      scope="files:read",
      state="af0ifjsldkj",
    )
    params.update(overrides)
    return build_authorization_request(**params)

  def test_response_type_code(self):
    # AC-36.24 (R-23.5-d): response_type=code.
    req = self._build()
    assert req.response_type == "code"
    assert RESPONSE_TYPE_CODE == "code"
    assert req.to_query_parameters()["response_type"] == "code"

  def test_redirect_uri_registered(self):
    # AC-36.25 (R-23.5-e): redirect_uri carried (must be one registered).
    req = self._build(redirect_uri=REDIRECT_URI)
    assert req.redirect_uri == REDIRECT_URI
    assert req.to_query_parameters()["redirect_uri"] == REDIRECT_URI

  def test_opaque_state(self):
    # AC-36.27 (R-23.5-g): includes an opaque, unguessable state.
    req = self._build(state="af0ifjsldkj")
    assert req.state == "af0ifjsldkj"
    assert req.to_query_parameters()["state"] == "af0ifjsldkj"
    # Generated state is high-entropy and unguessable.
    assert generate_state() != generate_state()

  def test_code_challenge_method_s256(self):
    # AC-36.28 (R-23.5-i): code_challenge_method=S256.
    req = self._build()
    assert req.code_challenge_method == "S256"
    assert req.to_query_parameters()["code_challenge_method"] == "S256"

  def test_resource_parameter(self):
    # AC-36.29 (R-23.5-j): includes resource == canonical resource identifier.
    req = self._build(resource=MCP_SERVER)
    assert req.resource == MCP_SERVER
    assert req.to_query_parameters()["resource"] == MCP_SERVER

  def test_resource_required(self):
    with pytest.raises(ValueError):
      self._build(resource="")


class TestScopePriority:
  """AC-36.26 (R-23.5-f) — scope priority: challenge > scopes_supported > omit."""

  def test_challenge_scope_wins(self):
    challenge = BearerChallenge(scope="files:read")
    assert select_request_scope(challenge, _prm()) == "files:read"

  def test_falls_back_to_scopes_supported(self):
    assert select_request_scope(None, _prm()) == "files:read files:write"

  def test_omits_when_scopes_supported_absent(self):
    prm = _prm(scopes_supported=None)
    assert select_request_scope(None, prm) is None
    assert select_request_scope(BearerChallenge(scope=None), prm) is None


class TestRedirectIssuerParameter:
  """AC-36.30 (R-23.5-k) — the redirect SHOULD include an iss parameter."""

  def test_iss_parsed_from_redirect(self):
    response = parse_authorization_response(
      "http://localhost:3000/callback?code=abc&state=s&iss=https%3A%2F%2Fauth.example.com"
    )
    assert response.iss == AUTH_ISSUER
    assert response.code == "abc"


class TestStateVerification:
  """AC-36.31 / AC-36.32 — verifying returned state before redeeming the code."""

  def test_verifies_returned_state(self):
    # AC-36.31 (R-23.5-h): the returned state is verified when one was sent.
    record = AuthorizationRecord(
      code_verifier="v", recorded_issuer=AUTH_ISSUER, state="sent-state"
    )
    verify_state(record, AuthorizationResponse(code="c", state="sent-state"))
    with pytest.raises(StateMismatchError):
      verify_state(record, AuthorizationResponse(code="c", state="other"))

  def test_state_matches_before_redeeming(self):
    # AC-36.32 (R-23.5-l): state must match before redeeming; a missing echoed
    # state when one was sent is a mismatch.
    record = AuthorizationRecord(
      code_verifier="v", recorded_issuer=AUTH_ISSUER, state="sent"
    )
    with pytest.raises(StateMismatchError):
      verify_state(record, AuthorizationResponse(code="c", state=None))

  def test_no_state_nothing_to_verify(self):
    record = AuthorizationRecord(code_verifier="v", recorded_issuer=AUTH_ISSUER)
    verify_state(record, AuthorizationResponse(code="c"))  # no raise


class TestRedirectValidation:
  """AC-36.33 (R-23.5-m) — validating iss per §23.7 before redeeming the code."""

  def test_validates_iss_before_redeeming(self):
    record = AuthorizationRecord(
      code_verifier="v", recorded_issuer=AUTH_ISSUER, state="s"
    )
    good = AuthorizationResponse(code="thecode", state="s", iss=AUTH_ISSUER)
    code = validate_redirect(record, good, iss_parameter_supported=True)
    assert code == "thecode"

    bad = AuthorizationResponse(code="thecode", state="s", iss="https://evil.example.com")
    with pytest.raises(IssValidationError):
      validate_redirect(record, bad, iss_parameter_supported=True)


class TestTokenRequest:
  """AC-36.34 / AC-36.35 / AC-36.36 — the Step-4 token request body."""

  def _auth_req(self):
    return build_authorization_request(
      client_id=CIMD_URL,
      redirect_uri=REDIRECT_URI,
      resource=MCP_SERVER,
      pkce=_pkce_fixed(),
      scope="files:read",
      state="af0ifjsldkj",
    )

  def test_grant_type_authorization_code(self):
    # AC-36.34 (R-23.5-n): grant_type=authorization_code.
    req = build_token_request(
      client_id=CIMD_URL,
      authorization_request=self._auth_req(),
      code="thecode",
      code_verifier=_pkce_fixed().code_verifier,
    )
    assert req.grant_type == "authorization_code"
    assert req.to_form_fields()["grant_type"] == "authorization_code"
    assert req.to_form_fields()["code"] == "thecode"

  def test_redirect_uri_identical(self):
    # AC-36.35 (R-23.5-o): redirect_uri byte-identical to Step 2.
    auth = self._auth_req()
    req = build_token_request(
      client_id=CIMD_URL,
      authorization_request=auth,
      code="thecode",
      code_verifier=_pkce_fixed().code_verifier,
    )
    assert req.redirect_uri == auth.redirect_uri == REDIRECT_URI

  def test_resource_identical(self):
    # AC-36.36 (R-23.5-p): resource present and identical to Step 2.
    auth = self._auth_req()
    req = build_token_request(
      client_id=CIMD_URL,
      authorization_request=auth,
      code="thecode",
      code_verifier=_pkce_fixed().code_verifier,
    )
    assert req.resource == auth.resource == MCP_SERVER
    assert req.to_form_fields()[RESOURCE_PARAMETER] == MCP_SERVER

  def test_token_response_parsing(self):
    resp = parse_token_response(
      {
        "access_token": "tok",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "r",
        "scope": "files:read",
      }
    )
    assert isinstance(resp, TokenResponse)
    assert resp.access_token == "tok"
    assert resp.has_refresh_token is True
    with pytest.raises(ValueError):
      parse_token_response({"token_type": "Bearer"})  # missing access_token


# ===========================================================================
# §23.6  Resource Indicators & audience binding
# ===========================================================================


class TestResourceIndicators:
  """AC-36.37 .. AC-36.41 — the resource parameter on both legs."""

  def _auth_and_token(self, resource=MCP_SERVER):
    auth = build_authorization_request(
      client_id=CIMD_URL,
      redirect_uri=REDIRECT_URI,
      resource=resource,
      pkce=_pkce_fixed(),
    )
    token = build_token_request(
      client_id=CIMD_URL,
      authorization_request=auth,
      code="c",
      code_verifier=_pkce_fixed().code_verifier,
    )
    return auth, token

  def test_implements_resource_indicators(self):
    # AC-36.37 (R-23.6-a): Resource Indicators are implemented (resource param).
    assert RESOURCE_PARAMETER == "resource"
    assert resource_indicator_for(MCP_SERVER) == MCP_SERVER
    with pytest.raises(ValueError):
      resource_indicator_for("")

  def test_resource_in_both_requests(self):
    # AC-36.38 (R-23.6-b): resource is in both the authz and token requests.
    auth, token = self._auth_and_token()
    assert auth.to_query_parameters()["resource"] == MCP_SERVER
    assert token.to_form_fields()["resource"] == MCP_SERVER
    assert authorization_and_token_resource_match(auth, token) is True

  def test_resource_identifies_server(self):
    # AC-36.39 (R-23.6-c): the resource identifies the MCP server.
    auth, _ = self._auth_and_token(resource=MCP_SERVER)
    assert auth.resource == MCP_SERVER

  def test_resource_is_canonical_identifier(self):
    # AC-36.40 (R-23.6-d): the value is the canonical resource identifier.
    canonical = build_canonical_resource_identifier("https://MCP.Example.com/")
    auth, token = self._auth_and_token(resource=canonical)
    assert auth.resource == canonical == "https://mcp.example.com"
    assert token.resource == canonical

  def test_sends_resource_regardless_of_support(self):
    # AC-36.41 (R-23.6-e): resource sent even if the AS does not advertise it.
    # No metadata flag is consulted when building the request; resource is always
    # present.
    auth, token = self._auth_and_token()
    assert "resource" in auth.to_query_parameters()
    assert "resource" in token.to_form_fields()


class TestAudienceBinding:
  """AC-36.42 .. AC-36.45 — server audience validation and the client send rule."""

  def test_server_validates_audience(self):
    # AC-36.42 (R-23.6-f): the server validates the token was issued for it.
    assert server_accepts_token(MCP_SERVER, MCP_SERVER) is True
    assert server_accepts_token([MCP_SERVER], MCP_SERVER) is True
    assert token_is_audience_bound([MCP_SERVER, "https://x"], MCP_SERVER) is True

  def test_server_rejects_wrong_audience(self):
    # AC-36.43 (R-23.6-g): a token for another server is rejected.
    with pytest.raises(AudienceMismatchError):
      server_accepts_token("https://other.example.com", MCP_SERVER)

  def test_server_only_own_resources(self):
    # AC-36.44 (R-23.6-h): only tokens valid for its own resources; never forward.
    with pytest.raises(AudienceMismatchError):
      server_accepts_token(["https://a", "https://b"], MCP_SERVER)
    assert token_is_audience_bound(None, MCP_SERVER) is False

  def test_client_sends_only_bound_token(self):
    # AC-36.45 (R-23.6-i): the client sends only an audience-bound token.
    assert client_may_send_token(MCP_SERVER, MCP_SERVER) is True
    assert client_may_send_token("https://other.example.com", MCP_SERVER) is False


# ===========================================================================
# §23.7  Issuer identification
# ===========================================================================


def _record(issuer=AUTH_ISSUER, state="s"):
  return AuthorizationRecord(code_verifier="v", recorded_issuer=issuer, state=state)


class TestIssValidation:
  """AC-36.46 / AC-36.50 / AC-36.51 — iss validation behaviors."""

  def test_validates_before_token_endpoint(self):
    # AC-36.46 (R-23.7-a): iss validated against the recorded issuer.
    record = _record()
    validate_iss(
      record,
      AuthorizationResponse(code="c", state="s", iss=AUTH_ISSUER),
      iss_parameter_supported=True,
    )
    with pytest.raises(IssValidationError):
      validate_iss(
        record,
        AuthorizationResponse(code="c", state="s", iss="https://evil.example.com"),
        iss_parameter_supported=True,
      )

  def test_supported_true_iss_absent_rejected(self):
    # AC-36.50 (R-23.7-e): supported=true + iss absent → reject.
    with pytest.raises(IssValidationError):
      validate_iss(
        _record(),
        AuthorizationResponse(code="c", state="s", iss=None),
        iss_parameter_supported=True,
      )

  def test_compares_iss_regardless_of_advertisement(self):
    # AC-36.51 (R-23.7-f): a present iss is compared even when not advertised.
    record = _record()
    # supported absent/false but iss present and matching → OK.
    validate_iss(
      record,
      AuthorizationResponse(code="c", state="s", iss=AUTH_ISSUER),
      iss_parameter_supported=None,
    )
    # supported false but iss present and mismatching → reject.
    with pytest.raises(IssValidationError):
      validate_iss(
        record,
        AuthorizationResponse(code="c", state="s", iss="https://evil.example.com"),
        iss_parameter_supported=False,
      )


class TestIssAdvertised:
  """AC-36.47 / AC-36.48 — the AS SHOULD emit iss and MUST advertise the flag."""

  def test_iss_included_in_responses(self):
    # AC-36.47 (R-23.7-b): iss is honored in both success and error responses.
    success = parse_authorization_response(
      {"code": "c", "state": "s", "iss": AUTH_ISSUER}
    )
    assert success.iss == AUTH_ISSUER
    error = parse_authorization_response(
      {"error": "access_denied", "iss": AUTH_ISSUER}
    )
    assert error.iss == AUTH_ISSUER and error.is_error

  def test_advertises_supported_flag(self):
    # AC-36.48 (R-23.7-c): an AS that includes iss sets the flag true; the table
    # treats a true flag as "iss required".
    metadata = _as_metadata(authorization_response_iss_parameter_supported=True)
    assert metadata.authorization_response_iss_parameter_supported is True
    # With the flag true, an absent iss is rejected (the flag's normative effect).
    assert (
      iss_validation_action(iss_parameter_supported=True, iss_present=False)
      is IssValidationAction.REJECT
    )


class TestIssValidationTable:
  """AC-36.49 (R-23.7-d) — the four-row iss-validation decision table."""

  def test_all_four_rows(self):
    assert (
      iss_validation_action(iss_parameter_supported=True, iss_present=True)
      is IssValidationAction.COMPARE
    )
    assert (
      iss_validation_action(iss_parameter_supported=True, iss_present=False)
      is IssValidationAction.REJECT
    )
    assert (
      iss_validation_action(iss_parameter_supported=False, iss_present=True)
      is IssValidationAction.COMPARE
    )
    assert (
      iss_validation_action(iss_parameter_supported=False, iss_present=False)
      is IssValidationAction.PROCEED
    )
    # "absent" flag behaves like false.
    assert (
      iss_validation_action(iss_parameter_supported=None, iss_present=False)
      is IssValidationAction.PROCEED
    )

  def test_proceed_does_not_raise(self):
    validate_iss(
      _record(),
      AuthorizationResponse(code="c", state="s", iss=None),
      iss_parameter_supported=None,
    )


class TestIssExactMatch:
  """AC-36.52 (R-23.7-g) — exact string match, no normalization."""

  def test_no_case_folding(self):
    record = _record(issuer="https://auth.example.com")
    with pytest.raises(IssValidationError):
      validate_iss(
        record,
        AuthorizationResponse(code="c", state="s", iss="https://AUTH.example.com"),
        iss_parameter_supported=True,
      )

  def test_no_trailing_slash_normalization(self):
    record = _record(issuer="https://auth.example.com")
    with pytest.raises(IssValidationError):
      validate_iss(
        record,
        AuthorizationResponse(code="c", state="s", iss="https://auth.example.com/"),
        iss_parameter_supported=True,
      )

  def test_no_default_port_elision(self):
    record = _record(issuer="https://auth.example.com")
    with pytest.raises(IssValidationError):
      validate_iss(
        record,
        AuthorizationResponse(
          code="c", state="s", iss="https://auth.example.com:443"
        ),
        iss_parameter_supported=True,
      )

  def test_exact_match_passes_with_decoded_value(self):
    # The form-urlencoded iss is decoded, then compared exactly.
    record = _record(issuer=AUTH_ISSUER)
    response = parse_authorization_response(
      "callback?code=c&state=s&iss=https%3A%2F%2Fauth.example.com"
    )
    validate_iss(record, response, iss_parameter_supported=True)  # no raise


class TestErrorResponseSuppression:
  """AC-36.53 (R-23.7-h) — suppress error fields on an iss mismatch."""

  def test_error_suppressed_on_mismatch(self):
    record = _record()
    bad_error = AuthorizationResponse(
      error="access_denied",
      error_description="user said no",
      iss="https://evil.example.com",
      state="s",
    )
    assert (
      error_response_is_actionable(record, bad_error, iss_parameter_supported=True)
      is False
    )

  def test_error_actionable_when_iss_matches(self):
    record = _record()
    good_error = AuthorizationResponse(
      error="access_denied", iss=AUTH_ISSUER, state="s"
    )
    assert (
      error_response_is_actionable(record, good_error, iss_parameter_supported=True)
      is True
    )


# ===========================================================================
# §23.8  Access-token usage
# ===========================================================================


class TestAccessTokenUsage:
  """AC-36.54 / AC-36.55 / AC-36.56 — bearer header on every request, never in query."""

  def test_authorization_on_every_request(self):
    # AC-36.54 (R-23.8-a): authorization header is produced for each request.
    header = build_authorization_header("eyJtoken")
    assert header == {AUTHORIZATION_HEADER: "Bearer eyJtoken"}

  def test_bearer_header(self):
    # AC-36.55 (R-23.8-b): Authorization: Bearer <token>.
    header = build_authorization_header("abc.def.ghi")
    assert header["Authorization"] == "Bearer abc.def.ghi"
    with pytest.raises(ValueError):
      build_authorization_header("")

  def test_not_in_query_string(self):
    # AC-36.56 (R-23.8-c): the access token MUST NOT be in the URI query string.
    assert token_in_query_string("https://mcp.example.com/mcp") is False
    with pytest.raises(TokenInQueryStringError):
      token_in_query_string("https://mcp.example.com/mcp?access_token=abc")


class TestServerTokenValidation:
  """AC-36.57 / AC-36.58 / AC-36.59 — per-request validation and 401/403 outcomes."""

  def test_validates_all_aspects(self):
    # AC-36.57 (R-23.8-d): signature, expiry, audience, and scope are validated.
    outcome = validate_access_token(
      token_present=True,
      signature_valid=True,
      not_expired=True,
      audience_matches=True,
      granted_scopes=["files:read", "files:write"],
      required_scopes=["files:read"],
    )
    assert outcome is TokenValidationOutcome.VALID
    assert token_validation_status(outcome) is None

  def test_401_for_invalid(self):
    # AC-36.58 (R-23.8-e): missing/invalid/expired/wrong-audience → 401.
    for kwargs in (
      dict(token_present=False),
      dict(signature_valid=False),
      dict(not_expired=False),
      dict(audience_matches=False),
    ):
      base = dict(
        token_present=True,
        signature_valid=True,
        not_expired=True,
        audience_matches=True,
        granted_scopes=["files:read"],
        required_scopes=["files:read"],
      )
      base.update(kwargs)
      outcome = validate_access_token(**base)
      assert outcome is TokenValidationOutcome.UNAUTHORIZED
      assert token_validation_status(outcome) == 401

  def test_403_insufficient_scope(self):
    # AC-36.59 (R-23.8-f): valid token lacking required scope → 403.
    outcome = validate_access_token(
      token_present=True,
      signature_valid=True,
      not_expired=True,
      audience_matches=True,
      granted_scopes=["files:read"],
      required_scopes=["files:write"],
    )
    assert outcome is TokenValidationOutcome.INSUFFICIENT_SCOPE
    assert token_validation_status(outcome) == 403
    err = TokenValidationError(outcome)
    assert err.status == 403


# ===========================================================================
# §23.9  Refresh tokens
# ===========================================================================


class TestRefreshTokens:
  """AC-36.60 .. AC-36.66 — refresh grant, offline_access, and audience binding."""

  def test_includes_refresh_token_grant_type(self):
    # AC-36.60 (R-23.9-a): refresh-capable client lists refresh_token in grant_types.
    assert client_wants_refresh_grant_types() == [
      "authorization_code",
      "refresh_token",
    ]
    assert client_wants_refresh_grant_types(["authorization_code"]) == [
      "authorization_code",
      "refresh_token",
    ]
    # idempotent
    assert client_wants_refresh_grant_types(["refresh_token"]) == ["refresh_token"]

  def test_offline_access_when_supported(self):
    # AC-36.61 (R-23.9-b): may add offline_access when scopes_supported lists it.
    with_offline = _as_metadata(scopes_supported=["files:read", "offline_access"])
    without = _as_metadata(scopes_supported=["files:read"])
    assert may_request_offline_access(with_offline) is True
    assert may_request_offline_access(without) is False
    assert add_offline_access_scope("files:read", with_offline) == (
      "files:read offline_access"
    )
    assert add_offline_access_scope("files:read", without) == "files:read"

  def test_refresh_token_confidential(self):
    # AC-36.62 (R-23.9-c): a refresh request keeps the refresh token in the body,
    # not the URL — it never leaks into a query string.
    req = build_refresh_token_request(
      client_id=CIMD_URL, refresh_token="secret-refresh", resource=MCP_SERVER
    )
    body = encode_token_request_body(req)
    assert "refresh_token=secret-refresh" in body
    # The token is carried in the form body; no query-string exposure.
    assert token_in_query_string("https://auth.example.com/token") is False

  def test_does_not_assume_refresh_token(self):
    # AC-36.63 (R-23.9-d): a token response without a refresh token is valid.
    resp = parse_token_response({"access_token": "a", "token_type": "Bearer"})
    assert resp.has_refresh_token is False
    assert resp.refresh_token is None

  def test_refresh_request_audience_bound(self):
    # AC-36.64 (R-23.9-e): grant_type=refresh_token + refresh_token + same resource.
    req = build_refresh_token_request(
      client_id=CIMD_URL, refresh_token="tGzv3JOkF0XG5Qx2TlKWIA", resource=MCP_SERVER
    )
    fields = req.to_form_fields()
    assert fields["grant_type"] == GRANT_TYPE_REFRESH_TOKEN == "refresh_token"
    assert fields["refresh_token"] == "tGzv3JOkF0XG5Qx2TlKWIA"
    assert fields["resource"] == MCP_SERVER  # keeps audience binding
    with pytest.raises(ValueError):
      build_refresh_token_request(
        client_id=CIMD_URL, refresh_token="r", resource=""
      )

  def test_refresh_may_narrow_scope(self):
    # AC-36.65 (R-23.9-f): a refresh request may include a narrower scope.
    req = build_refresh_token_request(
      client_id=CIMD_URL,
      refresh_token="r",
      resource=MCP_SERVER,
      scope="files:read",
    )
    assert req.to_form_fields()["scope"] == "files:read"
    # Without a scope, the field is omitted.
    req2 = build_refresh_token_request(
      client_id=CIMD_URL, refresh_token="r", resource=MCP_SERVER
    )
    assert "scope" not in req2.to_form_fields()

  def test_offline_access_excluded_from_resource(self):
    # AC-36.66 (R-23.9-g): neither WWW-Authenticate scope nor scopes_supported
    # includes offline_access.
    assert (
      metadata_excludes_offline_access(
        www_authenticate_scope="files:read",
        protected_resource_metadata=_prm(scopes_supported=["files:read"]),
      )
      is True
    )
    assert (
      metadata_excludes_offline_access(www_authenticate_scope="files:read offline_access")
      is False
    )
    assert (
      metadata_excludes_offline_access(
        protected_resource_metadata=_prm(
          scopes_supported=["files:read", "offline_access"]
        )
      )
      is False
    )


# ===========================================================================
# §23.10  Worked HTTP examples
# ===========================================================================


class TestWorkedExamples:
  """The §23.10 worked HTTP examples, exercised end-to-end."""

  def test_authorization_request_url(self):
    # The §23.10 authorization-request URL (with PKCE and resource).
    pkce = PKCEParameters(
      code_verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    )
    request = build_authorization_request(
      client_id=CIMD_URL,
      redirect_uri=REDIRECT_URI,
      resource=MCP_SERVER,
      pkce=pkce,
      scope="files:read",
      state="af0ifjsldkj",
    )
    url = build_authorization_request_url(f"{AUTH_ISSUER}/authorize", request)
    assert url.startswith("https://auth.example.com/authorize?")
    assert "response_type=code" in url
    assert "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" in url
    assert "code_challenge_method=S256" in url
    assert "resource=https%3A%2F%2Fmcp.example.com" in url
    assert "state=af0ifjsldkj" in url

  def test_redirect_and_iss_comparison(self):
    # The §23.10 redirect: code + state + iss, validated by exact match.
    record = AuthorizationRecord(
      code_verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      recorded_issuer=AUTH_ISSUER,
      state="af0ifjsldkj",
    )
    redirect = (
      "http://localhost:3000/callback"
      "?code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj&iss=https%3A%2F%2Fauth.example.com"
    )
    response = parse_authorization_response(redirect)
    code = validate_redirect(record, response, iss_parameter_supported=True)
    assert code == "SplxlOBeZQQYbYS6WxSbIA"

  def test_token_request_body(self):
    # The §23.10 token request body (authorization_code).
    auth = build_authorization_request(
      client_id=CIMD_URL,
      redirect_uri=REDIRECT_URI,
      resource=MCP_SERVER,
      pkce=PKCEParameters(
        code_verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      ),
    )
    req = build_token_request(
      client_id=CIMD_URL,
      authorization_request=auth,
      code="SplxlOBeZQQYbYS6WxSbIA",
      code_verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    )
    body = encode_token_request_body(req)
    assert "grant_type=authorization_code" in body
    assert "code=SplxlOBeZQQYbYS6WxSbIA" in body
    assert "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" in body
    assert "resource=https%3A%2F%2Fmcp.example.com" in body

  def test_token_response(self):
    # The §23.10 token response.
    resp = parse_token_response(
      {
        "access_token": "eyJhbGciOiJIUzI1NiIs...",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
        "scope": "files:read",
      }
    )
    assert resp.access_token == "eyJhbGciOiJIUzI1NiIs..."
    assert resp.token_type == "Bearer"
    assert resp.expires_in == 3600
    assert resp.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"

  def test_authorized_request_header(self):
    # The §23.10 authorized MCP request carrying the bearer token.
    header = build_authorization_header("eyJhbGciOiJIUzI1NiIs...")
    assert header["Authorization"] == "Bearer eyJhbGciOiJIUzI1NiIs..."

  def test_refresh_token_request_body(self):
    # The §23.10 refresh-token request (same resource keeps audience binding).
    req = build_refresh_token_request(
      client_id=CIMD_URL,
      refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
      resource=MCP_SERVER,
    )
    body = encode_token_request_body(req)
    assert "grant_type=refresh_token" in body
    assert "refresh_token=tGzv3JOkF0XG5Qx2TlKWIA" in body
    assert "client_id=https%3A%2F%2Fapp.example.com%2Foauth%2Fclient-metadata.json" in body
    assert "resource=https%3A%2F%2Fmcp.example.com" in body
