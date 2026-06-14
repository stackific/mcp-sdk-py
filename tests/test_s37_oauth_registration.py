"""Tests for S37 — Authorization III: Registration Mechanisms, Scopes & Security.

Covers every normative atom of §23.11–§23.19 in scope for S37 and every numbered
acceptance criterion AC-37.1 .. AC-37.38, plus the §9 worked examples.

AC → test coverage map:
  AC-37.1  (R-23.11-a)                  → TestObtainClientId
  AC-37.2  (R-23.11-b)                  → TestMechanismSelection::test_priority_order
  AC-37.3  (R-23.11-c)                  → TestMechanismSelection::test_inspects_metadata_first
  AC-37.4  (R-23.11-d)                  → TestMechanismSelection::test_no_cimd_without_support
  AC-37.5  (R-23.11-e)                  → TestMechanismSelection::test_no_dcr_without_endpoint
  AC-37.6  (R-23.12-a)                  → TestCimdSupport
  AC-37.7  (R-23.12-b,c)                → TestCimdUrl
  AC-37.8  (R-23.12-d,e)                → TestCimdDocument
  AC-37.9  (R-23.12-f)                  → TestCimdPrivateKeyJwt
  AC-37.10 (R-23.12-g,h,i,j)           → TestAuthorizationServerCimd
  AC-37.11 (R-23.12-k,l)               → TestCimdCachingAndTrust
  AC-37.12 (R-23.13-a)                 → TestPreRegistration
  AC-37.13 (R-23.14-a,b)               → TestDcrDeprecated
  AC-37.14 (R-23.14-c,d,e)             → TestDcrRequiredFields
  AC-37.15 (R-23.15-a,b,c)             → TestApplicationType
  AC-37.16 (R-23.15-d,e,f)             → TestDcrFailureHandling
  AC-37.17 (R-23.16-a,b)               → TestIssuerBinding::test_keyed_by_issuer
  AC-37.18 (R-23.16-c,d,e)             → TestIssuerBinding::test_no_cross_as_reuse
  AC-37.19 (R-23.16-f,g)               → TestIssuerExactMatch
  AC-37.20 (R-23.17-a,b)               → TestProtectedResourceDiscovery
  AC-37.21 (R-23.17-c,d)               → TestAuthorizationServersField
  AC-37.22 (R-23.17-e,f,g)             → TestAuthorizationServerWellKnown
  AC-37.23 (R-23.17-h,i)               → TestAuthorizationServerIssuerSelfConsistency
  AC-37.24 (R-23.18-a,b,c,d)           → TestScopeSelection
  AC-37.25 (R-23.18-e,f,g,h,i)         → TestInsufficientScopeChallenge::test_shape
  AC-37.26 (R-23.18-j,k)               → TestInsufficientScopeChallenge::test_single_challenge
  AC-37.27 (R-23.18-l,m,n / R-23.1-ae) → TestStepUpActor
  AC-37.28 (R-23.18-o,p)               → TestScopeUnion
  AC-37.29 (R-23.18-q,r / R-23.1-af,ag)→ TestStepUpRetry
  AC-37.30 (R-23.19-a)                 → TestResourceIndicator
  AC-37.31 (R-23.19-b,c,d)             → TestAudienceBinding
  AC-37.32 (R-23.19-e,j)               → TestPerRequestRecord
  AC-37.33 (R-23.19-f,g,h,i)           → TestIssValidation
  AC-37.34 (R-23.19-k)                 → TestPkce
  AC-37.35 (R-23.19-l)                 → TestState
  AC-37.36 (R-23.19-m,n,o,p)           → TestTokenConfidentiality
  AC-37.37 (R-23.19-q,r,s,t)           → TestRefreshTokens
  AC-37.38 (R-23.19-u)                 → TestResourceServerOfflineAccess

Worked examples (§9 / §23.18): TestWorkedExamples.
"""

import pytest

from mcp_sdk_py.authorization import (
  AuthorizationServerMetadata,
  BearerChallenge,
  IssuerMismatchError,
  ProtectedResourceMetadata,
)
from mcp_sdk_py.oauth_registration import (
  AUTHORIZATION_CONDITION_BY_STATUS,
  BEARER_AUTHORIZATION_HEADER,
  CIMD_REQUIRED_DOCUMENT_FIELDS,
  CIMD_VALIDATION_FAILURE_ERRORS,
  DCR_DEPRECATED,
  DEFAULT_STEP_UP_RETRY_LIMIT,
  OFFLINE_ACCESS_SCOPE_NAME,
  OIDC_DEFAULT_APPLICATION_TYPE,
  PRE_REGISTRATION_CREDENTIAL_SOURCES,
  REFRESH_TOKEN_GRANT,
  REGISTRATION_MECHANISM_PRIORITY,
  REQUIRED_PKCE_METHOD,
  RESOURCE_INDICATOR_PARAMETER,
  CimdDocument,
  CimdDocumentCache,
  CimdDocumentError,
  ClientRegistrationError,
  ClientRegistrationRequest,
  ClientRegistrationResponse,
  InsufficientScopeChallenge,
  IssuerBoundCredentialStore,
  IssuerCredentialMismatchError,
  PermanentAuthorizationFailureError,
  PerRequestAuthorizationRecord,
  PreRegisteredClientInformation,
  RegistrationApplicationType,
  RegistrationMechanism,
  RegistrationMechanismUnavailableError,
  ResponseIssMismatchError,
  ScopeUpgradeTracker,
  StepUpActorKind,
  TokenAudienceError,
  TokenConfidentialityError,
  add_offline_access_scope,
  assert_token_not_forwarded,
  assert_token_not_in_query_string,
  authorization_response_is_actionable,
  authorization_server_fetch_cimd_document,
  authorization_server_supports_cimd,
  authorization_server_supports_dcr,
  authorization_server_validate_cimd_document,
  bind_credentials_to_issuer,
  build_authorization_server_metadata_urls,
  build_bearer_authorization_header,
  build_client_registration_request,
  challenged_scopes_are_authoritative,
  cimd_credentials_exempt_from_reregistration,
  client_id_obtained,
  client_may_send_token_to_server,
  client_supports_pre_registration,
  client_wants_refresh_grant_types,
  default_cimd_domain_trust_policy,
  is_cimd_client_id,
  issuers_match,
  locate_protected_resource_metadata_urls,
  may_add_offline_access,
  parse_cimd_document,
  parse_client_registration_response,
  parse_insufficient_scope_challenge,
  pkce_is_required,
  plan_step_up_reauthorization,
  protected_resource_authorization_servers,
  record_per_request_authorization,
  redact_token_for_logging,
  refresh_token_is_guaranteed,
  refresh_token_must_be_kept_confidential,
  registration_application_type_for,
  resource_parameters_for_flow,
  resource_server_should_exclude_offline_access,
  retry_client_registration,
  select_initial_scope,
  select_registration_mechanism,
  server_accepts_audience_bound_token,
  should_attempt_step_up,
  state_is_recommended,
  surface_registration_error,
  union_scopes,
  validate_authorization_server_metadata_issuer,
  validate_cimd_document,
  validate_response_iss,
)

# Vendor-neutral test fixtures (no real AS/vendor/model names).
ISSUER = "https://auth.example.com"
ISSUER_PATH = "https://auth.example.com/tenant1"
MCP_ENDPOINT = "https://example.com/public/mcp"
RESOURCE = "https://mcp.example.com/mcp"
CIMD_URL = "https://app.example.com/oauth/client-metadata.json"
REDIRECTS = ["http://127.0.0.1:3000/callback", "http://localhost:3000/callback"]


def as_metadata(**overrides):
  base = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
  }
  base.update(overrides)
  return AuthorizationServerMetadata(**base)


def pr_metadata(**overrides):
  base = {
    "resource": RESOURCE,
    "authorization_servers": [ISSUER],
  }
  base.update(overrides)
  return ProtectedResourceMetadata(**base)


def cimd_dict(**overrides):
  base = {
    "client_id": CIMD_URL,
    "client_name": "Example MCP Client",
    "redirect_uris": list(REDIRECTS),
  }
  base.update(overrides)
  return base


# ---------------------------------------------------------------------------
# §23.11 — Obtaining a client_id and mechanism selection
# ---------------------------------------------------------------------------


class TestObtainClientId:
  """AC-37.1 (R-23.11-a): a client_id is obtained before the flow begins."""

  def test_requires_client_id_before_flow(self):
    assert client_id_obtained("s6BhdRkqt3") is True
    assert client_id_obtained(CIMD_URL) is True

  def test_no_client_id_means_not_ready(self):
    assert client_id_obtained(None) is False
    assert client_id_obtained("") is False


class TestMechanismSelection:
  """AC-37.2..5 (R-23.11-b..e): priority order and the metadata gates."""

  def test_priority_order(self):
    # The declared priority order is pre-registration → CIMD → DCR → user prompt.
    assert REGISTRATION_MECHANISM_PRIORITY == (
      RegistrationMechanism.PRE_REGISTRATION,
      RegistrationMechanism.CLIENT_ID_METADATA_DOCUMENT,
      RegistrationMechanism.DYNAMIC_CLIENT_REGISTRATION,
      RegistrationMechanism.USER_PROMPT,
    )
    # Pre-registration wins when held, even if CIMD+DCR are advertised.
    md = as_metadata(
      client_id_metadata_document_supported=True,
      registration_endpoint=f"{ISSUER}/register",
    )
    assert (
      select_registration_mechanism(md, has_pre_registered_credentials=True)
      is RegistrationMechanism.PRE_REGISTRATION
    )
    # Without pre-registration, CIMD beats DCR.
    assert (
      select_registration_mechanism(md)
      is RegistrationMechanism.CLIENT_ID_METADATA_DOCUMENT
    )
    # DCR is the fallback when CIMD is not advertised but a reg endpoint is.
    dcr_only = as_metadata(registration_endpoint=f"{ISSUER}/register")
    assert (
      select_registration_mechanism(dcr_only)
      is RegistrationMechanism.DYNAMIC_CLIENT_REGISTRATION
    )
    # Nothing advertised → prompt the user.
    assert (
      select_registration_mechanism(as_metadata())
      is RegistrationMechanism.USER_PROMPT
    )

  def test_inspects_metadata_first(self):
    # The selection consults the AS metadata gates; advertising CIMD selects CIMD.
    md = as_metadata(client_id_metadata_document_supported=True)
    assert authorization_server_supports_cimd(md) is True
    assert (
      select_registration_mechanism(md)
      is RegistrationMechanism.CLIENT_ID_METADATA_DOCUMENT
    )

  def test_no_cimd_without_support(self):
    md = as_metadata()  # client_id_metadata_document_supported absent.
    assert authorization_server_supports_cimd(md) is False
    # Auto selection never returns CIMD when not advertised.
    assert (
      select_registration_mechanism(md, supports_dcr=False)
      is RegistrationMechanism.USER_PROMPT
    )
    # Forcing CIMD without the gate is refused (R-23.11-d).
    with pytest.raises(RegistrationMechanismUnavailableError):
      select_registration_mechanism(
        md, forced=RegistrationMechanism.CLIENT_ID_METADATA_DOCUMENT
      )
    # An explicit false flag is still not support.
    assert (
      authorization_server_supports_cimd(
        as_metadata(client_id_metadata_document_supported=False)
      )
      is False
    )

  def test_no_dcr_without_endpoint(self):
    md = as_metadata()  # no registration_endpoint.
    assert authorization_server_supports_dcr(md) is False
    assert (
      select_registration_mechanism(md, supports_cimd=False)
      is RegistrationMechanism.USER_PROMPT
    )
    with pytest.raises(RegistrationMechanismUnavailableError):
      select_registration_mechanism(
        md, forced=RegistrationMechanism.DYNAMIC_CLIENT_REGISTRATION
      )


# ---------------------------------------------------------------------------
# §23.12 — Client ID Metadata Documents
# ---------------------------------------------------------------------------


class TestCimdSupport:
  """AC-37.6 (R-23.12-a): CIMD is the preferred path both sides advertise/use."""

  def test_cimd_preferred_over_dcr(self):
    md = as_metadata(
      client_id_metadata_document_supported=True,
      registration_endpoint=f"{ISSUER}/register",
    )
    # Both are available, CIMD is chosen as the preferred registration path.
    assert (
      select_registration_mechanism(md)
      is RegistrationMechanism.CLIENT_ID_METADATA_DOCUMENT
    )


class TestCimdUrl:
  """AC-37.7 (R-23.12-b,c): HTTPS URL with the https scheme and a path component."""

  def test_https_url_with_path_is_cimd(self):
    assert is_cimd_client_id(CIMD_URL) is True
    assert is_cimd_client_id("https://app.example.com/oauth/x") is True

  def test_http_or_no_path_is_not_cimd(self):
    assert is_cimd_client_id("http://app.example.com/x") is False  # not https
    assert is_cimd_client_id("https://app.example.com") is False  # no path
    assert is_cimd_client_id("https://app.example.com/") is False  # bare root
    assert is_cimd_client_id("s6BhdRkqt3") is False  # opaque id

  def test_validate_rejects_non_https_or_pathless_url(self):
    doc = parse_cimd_document(cimd_dict(client_id="http://app.example.com/x"))
    with pytest.raises(CimdDocumentError):
      validate_cimd_document(doc, "http://app.example.com/x")


class TestCimdDocument:
  """AC-37.8 (R-23.12-d,e): valid JSON object, required fields, client_id == URL."""

  def test_requires_minimum_fields(self):
    assert CIMD_REQUIRED_DOCUMENT_FIELDS == ("client_id", "client_name", "redirect_uris")
    for missing in CIMD_REQUIRED_DOCUMENT_FIELDS:
      raw = cimd_dict()
      del raw[missing]
      with pytest.raises(CimdDocumentError):
        parse_cimd_document(raw)

  def test_rejects_non_object(self):
    with pytest.raises(CimdDocumentError):
      parse_cimd_document(["not", "an", "object"])

  def test_client_id_must_equal_url_byte_for_byte(self):
    doc = parse_cimd_document(cimd_dict())
    validate_cimd_document(doc, CIMD_URL)  # exact match passes.
    # A trailing slash difference is NOT normalized away → mismatch.
    with pytest.raises(CimdDocumentError):
      validate_cimd_document(doc, CIMD_URL + "/")
    # Differing in the document body is rejected too.
    other = parse_cimd_document(
      cimd_dict(client_id="https://app.example.com/oauth/other.json")
    )
    with pytest.raises(CimdDocumentError):
      validate_cimd_document(other, CIMD_URL)

  def test_preserves_optional_and_additional_fields(self):
    doc = parse_cimd_document(
      cimd_dict(
        client_uri="https://app.example.com",
        logo_uri="https://app.example.com/logo.png",
        grant_types=["authorization_code"],
        response_types=["code"],
        token_endpoint_auth_method="none",
        software_id="vendor-neutral-id",
      )
    )
    assert doc.client_uri == "https://app.example.com"
    assert doc.grant_types == ["authorization_code"]
    assert doc.additional == {"software_id": "vendor-neutral-id"}


class TestCimdPrivateKeyJwt:
  """AC-37.9 (R-23.12-f): a CIMD client MAY use private_key_jwt token auth."""

  def test_private_key_jwt_flagged(self):
    doc = parse_cimd_document(
      cimd_dict(token_endpoint_auth_method="private_key_jwt", jwks_uri="https://app.example.com/jwks")
    )
    assert doc.uses_private_key_jwt() is True
    # The key material (e.g. jwks_uri) rides along in the document.
    assert doc.additional["jwks_uri"] == "https://app.example.com/jwks"

  def test_none_auth_is_not_private_key_jwt(self):
    doc = parse_cimd_document(cimd_dict(token_endpoint_auth_method="none"))
    assert doc.uses_private_key_jwt() is False


class TestAuthorizationServerCimd:
  """AC-37.10 (R-23.12-g,h,i,j): AS fetch + the three validations."""

  def test_fetches_url_client_id(self):
    calls = []

    def resolver(url):
      calls.append(url)
      return cimd_dict()

    doc = authorization_server_fetch_cimd_document(CIMD_URL, resolver)
    assert calls == [CIMD_URL]
    assert doc.client_id == CIMD_URL

  def test_validates_client_id_matches_url_exactly(self):
    # Document client_id differs from the fetch URL → rejected (R-23.12-h).
    bad = cimd_dict(client_id="https://attacker.example/x")
    with pytest.raises(CimdDocumentError):
      authorization_server_validate_cimd_document(CIMD_URL, bad)

  def test_validates_valid_json_required_fields(self):
    with pytest.raises(CimdDocumentError):
      authorization_server_validate_cimd_document(CIMD_URL, {"client_id": CIMD_URL})

  def test_validates_redirect_uri_listed(self):
    # Presented redirect URI must be in redirect_uris (R-23.12-j).
    doc = authorization_server_validate_cimd_document(
      CIMD_URL, cimd_dict(), presented_redirect_uri=REDIRECTS[0]
    )
    assert doc.client_id == CIMD_URL
    with pytest.raises(CimdDocumentError):
      authorization_server_validate_cimd_document(
        CIMD_URL, cimd_dict(), presented_redirect_uri="https://evil.example/cb"
      )

  def test_validation_failure_error_codes_referenced(self):
    assert set(CIMD_VALIDATION_FAILURE_ERRORS) == {"invalid_client", "invalid_request"}


class TestCimdCachingAndTrust:
  """AC-37.11 (R-23.12-k,l): caching honoring headers + a host-domain trust policy."""

  def test_caches_and_avoids_refetch(self):
    cache = CimdDocumentCache()
    calls = []

    def resolver(url):
      calls.append(url)
      return cimd_dict()

    authorization_server_fetch_cimd_document(CIMD_URL, resolver, cache=cache)
    authorization_server_fetch_cimd_document(CIMD_URL, resolver, cache=cache)
    assert calls == [CIMD_URL]  # fetched once.
    assert cache.get(CIMD_URL) is not None

  def test_no_store_is_not_cached(self):
    cache = CimdDocumentCache()
    calls = []

    def resolver(url):
      calls.append(url)
      return cimd_dict()

    headers = {"Cache-Control": "no-store"}
    authorization_server_fetch_cimd_document(
      CIMD_URL, resolver, cache=cache, cache_headers=headers
    )
    authorization_server_fetch_cimd_document(
      CIMD_URL, resolver, cache=cache, cache_headers=headers
    )
    assert calls == [CIMD_URL, CIMD_URL]  # re-fetched; nothing cached.
    assert cache.get(CIMD_URL) is None

  def test_domain_trust_policy(self):
    allowed = frozenset({"app.example.com"})
    assert default_cimd_domain_trust_policy(CIMD_URL, allowed) is True
    assert (
      default_cimd_domain_trust_policy("https://evil.example/x", allowed) is False
    )
    # None means unrestricted.
    assert default_cimd_domain_trust_policy("https://anything.example/x", None) is True

  def test_fetch_rejects_disallowed_host(self):
    with pytest.raises(CimdDocumentError):
      authorization_server_fetch_cimd_document(
        "https://evil.example/x",
        lambda url: cimd_dict(client_id="https://evil.example/x"),
        allowed_domains=frozenset({"app.example.com"}),
      )


# ---------------------------------------------------------------------------
# §23.13 — Pre-registration
# ---------------------------------------------------------------------------


class TestPreRegistration:
  """AC-37.12 (R-23.13-a): support static credentials supplied out of band."""

  def test_supported_sources(self):
    assert set(PRE_REGISTRATION_CREDENTIAL_SOURCES) == {
      "hardcoded_for_authorization_server",
      "entered_via_configuration_interface",
    }
    assert client_supports_pre_registration("hardcoded_for_authorization_server")
    assert client_supports_pre_registration("entered_via_configuration_interface")
    assert not client_supports_pre_registration("dynamic_client_registration")

  def test_credentials_carry_issuer(self):
    creds = PreRegisteredClientInformation(
      issuer=ISSUER, client_id="s6BhdRkqt3", client_secret="secret"
    )
    assert creds.issuer == ISSUER


# ---------------------------------------------------------------------------
# §23.14 / §23.15 — Dynamic Client Registration (Deprecated)
# ---------------------------------------------------------------------------


class TestDcrDeprecated:
  """AC-37.13 (R-23.14-a,b): prefer CIMD; DCR MAY still be supported."""

  def test_dcr_marked_deprecated(self):
    assert DCR_DEPRECATED is True

  def test_dcr_round_trip_obtains_client_id(self):
    req = build_client_registration_request(REDIRECTS, is_native=True)
    body = req.to_body()
    assert body["redirect_uris"] == REDIRECTS
    resp = parse_client_registration_response({"client_id": "s6BhdRkqt3"})
    assert resp.client_id == "s6BhdRkqt3"


class TestDcrRequiredFields:
  """AC-37.14 (R-23.14-c,d,e): redirect_uris + application_type in; client_id out."""

  def test_request_includes_required_fields(self):
    req = build_client_registration_request(REDIRECTS, is_native=True)
    body = req.to_body()
    assert body["redirect_uris"] == REDIRECTS  # REQUIRED (R-23.14-c)
    assert body["application_type"] == "native"  # REQUIRED for MCP (R-23.14-d)

  def test_request_rejects_empty_redirect_uris(self):
    with pytest.raises(ValueError):
      build_client_registration_request([], is_native=True)

  def test_response_requires_client_id(self):
    resp = parse_client_registration_response(
      {
        "client_id": "s6BhdRkqt3",
        "client_id_issued_at": 1769555200,
        "application_type": "native",
        "redirect_uris": REDIRECTS,
      }
    )
    assert resp.client_id == "s6BhdRkqt3"  # REQUIRED (R-23.14-e)
    assert resp.client_id_issued_at == 1769555200
    assert resp.echoed_metadata["application_type"] == "native"
    with pytest.raises(ClientRegistrationError):
      parse_client_registration_response({"application_type": "native"})


class TestApplicationType:
  """AC-37.15 (R-23.15-a,b,c): native vs web consistent with redirect URIs."""

  def test_native_for_loopback(self):
    assert registration_application_type_for(is_native=True) is (
      RegistrationApplicationType.NATIVE
    )
    req = build_client_registration_request(REDIRECTS, is_native=True)
    assert req.application_type is RegistrationApplicationType.NATIVE

  def test_web_for_remote(self):
    assert registration_application_type_for(is_native=False) is (
      RegistrationApplicationType.WEB
    )
    req = build_client_registration_request(
      ["https://app.example.com/cb"], is_native=False
    )
    assert req.application_type is RegistrationApplicationType.WEB

  def test_oidc_default_is_web(self):
    assert OIDC_DEFAULT_APPLICATION_TYPE is RegistrationApplicationType.WEB


class TestDcrFailureHandling:
  """AC-37.16 (R-23.15-d,e,f): handle OIDC redirect-URI failure; surface; retry."""

  def test_redirect_uri_rejection_is_recoverable(self):
    with pytest.raises(ClientRegistrationError) as exc:
      parse_client_registration_response(
        {
          "error": "invalid_redirect_uri",
          "error_description": "redirect URIs not allowed for application_type web",
        }
      )
    assert exc.value.recoverable is True  # R-23.15-f
    assert exc.value.error == "invalid_redirect_uri"

  def test_surfaces_meaningful_error(self):
    err = ClientRegistrationError(
      "redirect URI not permitted", error="invalid_redirect_uri", recoverable=True
    )
    message = surface_registration_error(err)
    assert "invalid_redirect_uri" in message
    assert "redirect URI not permitted" in message

  def test_retry_with_adjusted_application_type(self):
    req = build_client_registration_request(REDIRECTS, is_native=False)
    err = ClientRegistrationError(
      "redirect URI mismatch", error="invalid_redirect_uri", recoverable=True
    )
    retried = retry_client_registration(
      req, err, adjusted_application_type=RegistrationApplicationType.NATIVE
    )
    assert retried.application_type is RegistrationApplicationType.NATIVE
    # Retry with conforming redirect URIs is also supported.
    conforming = ["http://127.0.0.1:7777/callback"]
    retried2 = retry_client_registration(
      req, err, conforming_redirect_uris=conforming
    )
    assert retried2.redirect_uris == conforming

  def test_non_recoverable_error_cannot_retry(self):
    req = build_client_registration_request(REDIRECTS, is_native=True)
    err = ClientRegistrationError("bad request", error="invalid_request")
    with pytest.raises(ClientRegistrationError):
      retry_client_registration(
        req, err, adjusted_application_type=RegistrationApplicationType.WEB
      )

  def test_retry_requires_an_adjustment(self):
    req = build_client_registration_request(REDIRECTS, is_native=True)
    err = ClientRegistrationError(
      "x", error="invalid_redirect_uri", recoverable=True
    )
    with pytest.raises(ValueError):
      retry_client_registration(req, err)


# ---------------------------------------------------------------------------
# §23.16 — Credential binding to the issuer
# ---------------------------------------------------------------------------


class TestIssuerBinding:
  """AC-37.17/18 (R-23.16-a..e): issuer-keyed storage, no cross-AS reuse."""

  def test_keyed_by_issuer(self):
    store = IssuerBoundCredentialStore()
    creds = ClientRegistrationResponse(client_id="s6BhdRkqt3")
    store.store(ISSUER, creds)
    assert store.get(ISSUER) is creds
    # A different issuer never returns these credentials.
    assert store.get("https://auth.other.example") is None

  def test_empty_issuer_key_rejected(self):
    store = IssuerBoundCredentialStore()
    with pytest.raises(ValueError):
      store.store("", ClientRegistrationResponse(client_id="x"))

  def test_no_cross_as_reuse(self):
    store = IssuerBoundCredentialStore()
    store.store(ISSUER, ClientRegistrationResponse(client_id="A"))
    other = "https://auth.other.example"
    # Credentials for A are not visible to B and B must re-register.
    assert store.get(other) is None
    assert store.must_reregister(other) is True
    assert store.must_reregister(ISSUER) is False
    # Reusing A's credentials against B is refused.
    with pytest.raises(IssuerCredentialMismatchError):
      bind_credentials_to_issuer(ISSUER, other)

  def test_bind_passes_on_match(self):
    bind_credentials_to_issuer(ISSUER, ISSUER)  # no raise.

  def test_cimd_exempt_from_reregistration(self):
    assert cimd_credentials_exempt_from_reregistration() is True


class TestIssuerExactMatch:
  """AC-37.19 (R-23.16-f,g): exact-string comparison; surface mismatch error."""

  @pytest.mark.parametrize(
    "a,b",
    [
      ("https://auth.example.com", "https://AUTH.EXAMPLE.COM"),  # case
      ("https://auth.example.com", "https://auth.example.com:443"),  # default port
      ("https://auth.example.com", "https://auth.example.com/"),  # trailing slash
      ("https://auth.example.com/a b", "https://auth.example.com/a%20b"),  # pct
    ],
  )
  def test_normalization_variants_are_different(self, a, b):
    assert issuers_match(a, b) is False
    with pytest.raises(IssuerCredentialMismatchError):
      bind_credentials_to_issuer(a, b)

  def test_identical_strings_match(self):
    assert issuers_match(ISSUER, ISSUER) is True

  def test_mismatch_surfaces_error_rather_than_silent_use(self):
    creds = PreRegisteredClientInformation(issuer=ISSUER, client_id="x")
    discovered = pr_metadata(authorization_servers=["https://auth.other.example"])
    with pytest.raises(IssuerCredentialMismatchError):
      bind_credentials_to_issuer(
        creds.issuer, discovered.authorization_servers[0]
      )


# ---------------------------------------------------------------------------
# §23.17 — Discovery robustness
# ---------------------------------------------------------------------------


class TestProtectedResourceDiscovery:
  """AC-37.20 (R-23.17-a,b): header URL takes priority, else well-known order."""

  def test_uses_resource_metadata_header(self):
    header = (
      'Bearer resource_metadata='
      '"https://mcp.example.com/.well-known/oauth-protected-resource"'
    )
    urls = locate_protected_resource_metadata_urls(
      MCP_ENDPOINT, www_authenticate=header
    )
    assert urls == [
      "https://mcp.example.com/.well-known/oauth-protected-resource"
    ]

  def test_well_known_fallback_order(self):
    urls = locate_protected_resource_metadata_urls(MCP_ENDPOINT)
    assert urls == [
      "https://example.com/.well-known/oauth-protected-resource/public/mcp",
      "https://example.com/.well-known/oauth-protected-resource",
    ]


class TestAuthorizationServersField:
  """AC-37.21 (R-23.17-c,d): authorization_servers present; separate state per AS."""

  def test_authorization_servers_required(self):
    servers = protected_resource_authorization_servers(pr_metadata())
    assert servers == [ISSUER]

  def test_empty_authorization_servers_rejected(self):
    md = ProtectedResourceMetadata(resource=RESOURCE, authorization_servers=[])
    with pytest.raises(ValueError):
      protected_resource_authorization_servers(md)

  def test_separate_registration_state_per_as(self):
    a, b = "https://auth.a.example", "https://auth.b.example"
    md = pr_metadata(authorization_servers=[a, b])
    assert protected_resource_authorization_servers(md) == [a, b]
    store = IssuerBoundCredentialStore()
    store.store(a, ClientRegistrationResponse(client_id="A"))
    # B has its own (absent) state, independent of A.
    assert store.get(a) is not None
    assert store.get(b) is None
    assert store.must_reregister(b) is True


class TestAuthorizationServerWellKnown:
  """AC-37.22 (R-23.17-e,f,g): path vs non-path issuer well-known ordering."""

  def test_issuer_with_path(self):
    urls = build_authorization_server_metadata_urls(ISSUER_PATH)
    assert urls == [
      "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
      "https://auth.example.com/.well-known/openid-configuration/tenant1",
      "https://auth.example.com/tenant1/.well-known/openid-configuration",
    ]

  def test_issuer_without_path(self):
    urls = build_authorization_server_metadata_urls(ISSUER)
    assert urls == [
      "https://auth.example.com/.well-known/oauth-authorization-server",
      "https://auth.example.com/.well-known/openid-configuration",
    ]


class TestAuthorizationServerIssuerSelfConsistency:
  """AC-37.23 (R-23.17-h,i): document issuer must equal the construction value."""

  def test_matching_issuer_accepted(self):
    md = as_metadata(issuer="https://honest.example")
    validate_authorization_server_metadata_issuer(md, "https://honest.example")

  def test_mismatched_issuer_rejected(self):
    md = as_metadata(issuer="https://attacker.example")
    with pytest.raises(IssuerMismatchError):
      validate_authorization_server_metadata_issuer(md, "https://honest.example")


# ---------------------------------------------------------------------------
# §23.18 — Scope selection and step-up
# ---------------------------------------------------------------------------


class TestScopeSelection:
  """AC-37.24 (R-23.18-a,b,c,d): challenge scope wins, else scopes_supported, else omit."""

  def test_challenge_scope_is_authoritative(self):
    challenge = BearerChallenge(scope="files:read")
    md = pr_metadata(scopes_supported=["files:read", "files:write", "admin"])
    assert select_initial_scope(challenge, md) == "files:read"
    # The challenged set is returned verbatim, independent of scopes_supported.
    assert challenged_scopes_are_authoritative(
      challenge, scopes_supported=["other"]
    ) == ["files:read"]

  def test_falls_back_to_scopes_supported(self):
    md = pr_metadata(scopes_supported=["files:read", "files:write"])
    assert select_initial_scope(None, md) == "files:read files:write"

  def test_omits_scope_when_scopes_supported_absent(self):
    md = pr_metadata()  # no scopes_supported.
    assert select_initial_scope(None, md) is None
    # No challenge, no scopes_supported, no metadata → still omit.
    assert select_initial_scope(None, None) is None


class TestInsufficientScopeChallenge:
  """AC-37.25/26 (R-23.18-e..k): 403 Bearer challenge shape (restated from S35)."""

  def test_shape(self):
    challenge = InsufficientScopeChallenge(
      scope="files:write",
      resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
      error_description="File write permission required",
    )
    assert challenge.status == 403
    assert challenge.error == "insufficient_scope"  # REQUIRED (R-23.18-f)
    header = challenge.to_www_authenticate()
    assert header.startswith("Bearer ")
    assert 'error="insufficient_scope"' in header
    assert 'scope="files:write"' in header
    assert "resource_metadata=" in header
    assert "error_description=" in header

  def test_parse_requires_insufficient_scope_error(self):
    header = (
      'Bearer error="insufficient_scope", scope="files:write", '
      'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"'
    )
    challenge = parse_insufficient_scope_challenge(header)
    assert challenge.scopes == ["files:write"]
    # A non-insufficient-scope error is not a step-up trigger.
    with pytest.raises(ValueError):
      parse_insufficient_scope_challenge('Bearer error="invalid_token"')

  def test_single_challenge_with_all_scopes(self):
    # All required scopes appear in a single challenge (R-23.18-j).
    challenge = InsufficientScopeChallenge(scope="files:write files:delete")
    assert challenge.scopes == ["files:write", "files:delete"]

  def test_status_condition_mapping_referenced(self):
    assert AUTHORIZATION_CONDITION_BY_STATUS[401].startswith("authorization required")
    assert "scopes" in AUTHORIZATION_CONDITION_BY_STATUS[403]
    assert "malformed" in AUTHORIZATION_CONDITION_BY_STATUS[400]


class TestStepUpActor:
  """AC-37.27 (R-23.18-l,m,n / R-23.1-ae): user-acting SHOULD; client_credentials MAY."""

  def test_user_agent_should_step_up(self):
    assert should_attempt_step_up(StepUpActorKind.USER_AGENT) is True

  def test_client_credentials_may_step_up(self):
    # MAY attempt (or abort); attempting is permitted.
    assert should_attempt_step_up(StepUpActorKind.CLIENT_CREDENTIALS) is True

  def test_plan_unions_scopes(self):
    challenge = InsufficientScopeChallenge(scope="files:write")
    plan = plan_step_up_reauthorization(
      challenge,
      granted_scopes=["files:read"],
      resource=RESOURCE,
      recorded_issuer=ISSUER,
    )
    assert plan.scope == "files:read files:write"  # R-23.1-ae union
    assert plan.resource == RESOURCE
    assert plan.recorded_issuer == ISSUER


class TestScopeUnion:
  """AC-37.28 (R-23.18-o,p): union granted + challenged; never drop granted."""

  def test_union_preserves_granted(self):
    assert union_scopes(["files:read"], ["files:write"]) == [
      "files:read",
      "files:write",
    ]

  def test_does_not_drop_already_granted(self):
    # files:read MUST survive even when only files:write is challenged.
    result = union_scopes("files:read", "files:write")
    assert "files:read" in result

  def test_union_deduplicates_exact_repeats(self):
    assert union_scopes(["a", "b"], ["b", "c"]) == ["a", "b", "c"]

  def test_union_with_no_prior_scopes(self):
    assert union_scopes(None, ["files:write"]) == ["files:write"]


class TestStepUpRetry:
  """AC-37.29 (R-23.18-q,r / R-23.1-af,ag): bounded retries; permanent failure; tracking."""

  def test_default_retry_limit_is_small(self):
    assert DEFAULT_STEP_UP_RETRY_LIMIT <= 5

  def test_tracks_attempts_per_resource_and_operation(self):
    tracker = ScopeUpgradeTracker(retry_limit=2)
    assert tracker.attempts(RESOURCE, "tools/call") == 0
    tracker.record_attempt(RESOURCE, "tools/call")
    assert tracker.attempts(RESOURCE, "tools/call") == 1
    # A different operation is tracked separately.
    assert tracker.attempts(RESOURCE, "resources/read") == 0

  def test_permanent_failure_after_limit(self):
    tracker = ScopeUpgradeTracker(retry_limit=2)
    tracker.record_attempt(RESOURCE, "tools/call")
    tracker.record_attempt(RESOURCE, "tools/call")
    assert tracker.may_attempt(RESOURCE, "tools/call") is False
    with pytest.raises(PermanentAuthorizationFailureError):
      tracker.record_attempt(RESOURCE, "tools/call")


# ---------------------------------------------------------------------------
# §23.19 — Authorization security considerations
# ---------------------------------------------------------------------------


class TestResourceIndicator:
  """AC-37.30 (R-23.19-a): resource parameter on both legs, regardless of support."""

  def test_resource_parameter_for_both_legs(self):
    assert RESOURCE_INDICATOR_PARAMETER == "resource"
    params = resource_parameters_for_flow(RESOURCE)
    assert params == {"resource": RESOURCE}

  def test_empty_resource_rejected(self):
    with pytest.raises(ValueError):
      resource_parameters_for_flow("")


class TestAudienceBinding:
  """AC-37.31 (R-23.19-b,c,d): audience validation; client never sends wrong token."""

  def test_server_accepts_matching_audience(self):
    assert server_accepts_audience_bound_token(RESOURCE, RESOURCE) is True

  def test_server_rejects_wrong_audience(self):
    with pytest.raises(TokenAudienceError):
      server_accepts_audience_bound_token(RESOURCE, "https://other.example/mcp")

  def test_client_only_sends_to_matching_as(self):
    assert client_may_send_token_to_server(ISSUER, ISSUER) is True
    assert (
      client_may_send_token_to_server(ISSUER, "https://auth.other.example") is False
    )


class TestPerRequestRecord:
  """AC-37.32 (R-23.19-e,j): record validated issuer + verifier + state together."""

  def test_record_binds_issuer_verifier_state(self):
    record = record_per_request_authorization(
      validated_issuer=ISSUER, code_verifier="verifier-value", state="af0ifjsldkj"
    )
    assert isinstance(record, PerRequestAuthorizationRecord)
    assert record.recorded_issuer == ISSUER
    assert record.code_verifier == "verifier-value"
    assert record.state == "af0ifjsldkj"

  def test_requires_issuer_and_verifier(self):
    with pytest.raises(ValueError):
      record_per_request_authorization(validated_issuer="", code_verifier="v")
    with pytest.raises(ValueError):
      record_per_request_authorization(validated_issuer=ISSUER, code_verifier="")


class TestIssValidation:
  """AC-37.33 (R-23.19-f,g,h,i): iss exact match; absent-but-advertised reject; suppress."""

  def _record(self):
    return record_per_request_authorization(
      validated_issuer=ISSUER, code_verifier="v", state="s"
    )

  def test_exact_match_passes(self):
    assert (
      validate_response_iss(
        self._record(), returned_iss=ISSUER, iss_parameter_supported=True
      )
      is True
    )

  def test_absent_but_advertised_rejected(self):
    with pytest.raises(ResponseIssMismatchError):
      validate_response_iss(
        self._record(), returned_iss=None, iss_parameter_supported=True
      )

  def test_present_iss_compared_regardless_of_metadata(self):
    # iss present but does not match → rejected even when not advertised.
    with pytest.raises(ResponseIssMismatchError):
      validate_response_iss(
        self._record(),
        returned_iss="https://attacker.example",
        iss_parameter_supported=None,
      )

  def test_absent_and_not_advertised_proceeds(self):
    assert (
      validate_response_iss(
        self._record(), returned_iss=None, iss_parameter_supported=None
      )
      is True
    )

  def test_mismatch_suppresses_code_and_error_fields(self):
    # On mismatch the response is not actionable (code/error must be suppressed).
    assert (
      authorization_response_is_actionable(
        self._record(),
        returned_iss="https://attacker.example",
        iss_parameter_supported=True,
      )
      is False
    )
    assert (
      authorization_response_is_actionable(
        self._record(), returned_iss=ISSUER, iss_parameter_supported=True
      )
      is True
    )


class TestPkce:
  """AC-37.34 (R-23.19-k): PKCE with S256 is mandatory."""

  def test_pkce_required_with_s256(self):
    assert pkce_is_required() is True
    assert REQUIRED_PKCE_METHOD == "S256"


class TestState:
  """AC-37.35 (R-23.19-l): unpredictable state SHOULD be included and verified."""

  def test_state_recommended(self):
    assert state_is_recommended() is True


class TestTokenConfidentiality:
  """AC-37.36 (R-23.19-m,n,o,p): no logging/forwarding; bearer header only, not query."""

  def test_redacts_token_from_logs(self):
    token = "secret-access-token"
    line = f"sending request with token={token}"
    redacted = redact_token_for_logging(line, token)
    assert token not in redacted
    assert "[REDACTED]" in redacted

  def test_token_not_forwarded_to_third_party(self):
    assert_token_not_forwarded(destination_is_third_party=False)  # no raise.
    with pytest.raises(TokenConfidentialityError):
      assert_token_not_forwarded(destination_is_third_party=True)

  def test_access_token_only_in_bearer_header(self):
    header = build_bearer_authorization_header("secret-access-token")
    assert header == {BEARER_AUTHORIZATION_HEADER: "Bearer secret-access-token"}

  def test_token_rejected_in_query_string(self):
    token = "secret-access-token"
    assert_token_not_in_query_string("https://mcp.example.com/mcp", token)  # ok.
    with pytest.raises(TokenConfidentialityError):
      assert_token_not_in_query_string(
        f"https://mcp.example.com/mcp?access_token={token}", token
      )


class TestRefreshTokens:
  """AC-37.37 (R-23.19-q,r,s,t): confidential; grant_types; offline_access; no assume."""

  def test_keep_confidential(self):
    assert refresh_token_must_be_kept_confidential() is True

  def test_includes_refresh_token_grant_type(self):
    assert REFRESH_TOKEN_GRANT == "refresh_token"
    assert client_wants_refresh_grant_types(["authorization_code"]) == [
      "authorization_code",
      "refresh_token",
    ]
    # Idempotent if already present.
    assert client_wants_refresh_grant_types(["refresh_token"]) == ["refresh_token"]

  def test_offline_access_only_when_supported(self):
    md = as_metadata(scopes_supported=["files:read", "offline_access"])
    assert may_add_offline_access(md) is True
    assert add_offline_access_scope("files:read", md) == "files:read offline_access"
    # Not added when the AS does not list it.
    md2 = as_metadata(scopes_supported=["files:read"])
    assert may_add_offline_access(md2) is False
    assert add_offline_access_scope("files:read", md2) == "files:read"

  def test_offline_access_not_duplicated(self):
    md = as_metadata(scopes_supported=["offline_access"])
    assert add_offline_access_scope("offline_access", md) == "offline_access"

  def test_does_not_assume_refresh_token(self):
    assert refresh_token_is_guaranteed() is False


class TestResourceServerOfflineAccess:
  """AC-37.38 (R-23.19-u): a resource server excludes offline_access from its scopes."""

  def test_offline_access_excluded(self):
    assert OFFLINE_ACCESS_SCOPE_NAME == "offline_access"
    assert resource_server_should_exclude_offline_access(
      ["files:read", "offline_access", "files:write"]
    ) == ["files:read", "files:write"]

  def test_empty_scopes(self):
    assert resource_server_should_exclude_offline_access(None) == []


# ---------------------------------------------------------------------------
# Worked examples (§9 / §23.18)
# ---------------------------------------------------------------------------


class TestWorkedExamples:
  """The §9 / §23.18 worked HTTP examples, exercised end to end."""

  def test_cimd_metadata_document_example(self):
    # §9.2 example metadata document parses and self-validates.
    raw = {
      "client_id": "https://app.example.com/oauth/client-metadata.json",
      "client_name": "Example MCP Client",
      "client_uri": "https://app.example.com",
      "logo_uri": "https://app.example.com/logo.png",
      "redirect_uris": [
        "http://127.0.0.1:3000/callback",
        "http://localhost:3000/callback",
      ],
      "grant_types": ["authorization_code"],
      "response_types": ["code"],
      "token_endpoint_auth_method": "none",
    }
    doc = parse_cimd_document(raw)
    validate_cimd_document(doc, raw["client_id"])
    assert doc.grant_types == ["authorization_code"]

  def test_dcr_request_and_response_example(self):
    # §9.3 request body.
    req = build_client_registration_request(
      [
        "http://127.0.0.1:3000/callback",
        "http://localhost:3000/callback",
      ],
      is_native=True,
      client_name="Example MCP Client",
      grant_types=["authorization_code", "refresh_token"],
      response_types=["code"],
      token_endpoint_auth_method="none",
    )
    body = req.to_body()
    assert body["application_type"] == "native"
    assert body["grant_types"] == ["authorization_code", "refresh_token"]
    # §9.4 response body.
    resp = parse_client_registration_response(
      {
        "client_id": "s6BhdRkqt3",
        "client_id_issued_at": 1769555200,
        "application_type": "native",
        "redirect_uris": body["redirect_uris"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
      }
    )
    assert resp.client_id == "s6BhdRkqt3"
    assert resp.client_id_issued_at == 1769555200

  def test_step_up_example(self):
    # §9.5 / §23.18 example: held files:read, challenged files:write.
    header = (
      'Bearer error="insufficient_scope", scope="files:write", '
      'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", '
      'error_description="File write permission required for this operation"'
    )
    challenge = parse_insufficient_scope_challenge(header)
    plan = plan_step_up_reauthorization(
      challenge,
      granted_scopes="files:read",
      resource=RESOURCE,
      recorded_issuer=ISSUER,
    )
    # The union preserves files:read and adds files:write.
    assert plan.scope == "files:read files:write"
    assert plan.resource == RESOURCE
