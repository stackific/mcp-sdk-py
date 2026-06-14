"""Tests for S35 — Authorization I: Model, Applicability & Metadata Discovery.

Covers every normative atom of §23.1–§23.3 in scope for S35 and every numbered
acceptance criterion AC-35.1 .. AC-35.27.

AC → test coverage map:
  AC-35.1  (R-23.1-a)                     → TestApplicabilityOptional
  AC-35.2  (R-23.1-b)                     → TestStdioMustNotUseAuthorization
  AC-35.3  (R-23.1-c)                     → TestOtherTransportBestPractices
  AC-35.4  (R-23.1-d)                     → TestAuthorizationServerOAuth21
  AC-35.5  (R-23.1-e)                     → TestResourceServerTokenHandling
  AC-35.6  (R-23.1-f)                     → TestCustomStrategyOutOfScope
  AC-35.7  (R-23.1-g)                     → TestRolesBehaveAsSpecified
  AC-35.8  (R-23.1-h)                     → TestMultipleAuthorizationServers
  AC-35.9  (R-23.1-i/j/k/l)              → TestPerAuthorizationServerIsolation
  AC-35.10 (R-23.1-m/n/o)               → TestCanonicalResourceIdentifier
  AC-35.11 (R-23.1-p)                     → TestCanonicalCaseRobustness
  AC-35.12 (R-23.1-q/r/s)               → TestCanonicalSpecificityAndSlash
  AC-35.13 (R-23.1-t/u/v)               → TestUnauthorizedResponse
  AC-35.14 (R-23.1-w)                     → TestUnauthorizedScopeParameter
  AC-35.15 (R-23.1-x/y)                 → TestClientTreatsChallengedScopes
  AC-35.16 (R-23.1-z)                     → TestClientParsesWWWAuthenticate
  AC-35.17 (R-23.1-aa/ab/ac/ad)        → TestInsufficientScopeResponse
  AC-35.18 (R-23.2-a/b/c)               → TestProtectedResourceDiscoveryMechanisms
  AC-35.19 (R-23.2-d)                     → TestUsesHeaderResourceMetadata
  AC-35.20 (R-23.2-e/f)                 → TestWellKnownConstructionOrder
  AC-35.21 (R-23.2-g)                     → TestAbortOrFallback
  AC-35.22 (R-23.2-h/i/j)               → TestProtectedResourceMetadataShape
  AC-35.23 (R-23.3-a/b)                 → TestAuthorizationServerDiscoveryMechanisms
  AC-35.24 (R-23.3-c)                     → TestAuthorizationServerWellKnownOrder
  AC-35.25 (R-23.3-d/e)                 → TestIssuerMatchValidation
  AC-35.26 (R-23.3-f/g/h)               → TestAuthorizationServerMetadataRequired
  AC-35.27 (R-23.3-i/j)                 → TestResponseTypeAndCodeChallenge
"""

import pytest

from mcp_sdk_py.authorization import (
  AUTHORIZATION_OPTIONAL,
  AUTHORIZATION_STATUS_TABLE,
  BEARER_SCHEME,
  HTTP_BAD_REQUEST,
  HTTP_FORBIDDEN,
  HTTP_UNAUTHORIZED,
  INSUFFICIENT_SCOPE_ERROR,
  OAUTH_AS_METADATA_WELL_KNOWN_SUFFIX,
  OPENID_CONFIGURATION_WELL_KNOWN_SUFFIX,
  PROTECTED_RESOURCE_WELL_KNOWN_SUFFIX,
  WWW_AUTHENTICATE_HEADER,
  AuthorizationServerCredentials,
  AuthorizationServerMetadata,
  BearerChallenge,
  CanonicalResourceIdentifierError,
  IssuerMismatchError,
  OAuthRole,
  PerAuthorizationServerCredentialStore,
  ProtectedResourceDiscovery,
  ProtectedResourceDiscoveryError,
  ProtectedResourceMetadata,
  TransportClass,
  authorization_applies,
  build_authorization_server_well_known_urls,
  build_canonical_resource_identifier,
  build_insufficient_scope_response,
  build_protected_resource_well_known_urls,
  build_unauthorized_response,
  canonical_forms_equivalent,
  custom_strategy_is_out_of_scope,
  locate_protected_resource_metadata_uri,
  other_transport_security_is_out_of_scope,
  parse_authorization_server_metadata,
  parse_protected_resource_metadata,
  parse_www_authenticate,
  parse_www_authenticate_from_headers,
  protected_resource_discovery_plan,
  required_scopes_from_challenge,
  role_requirements,
  select_authorization_server,
  stdio_credentials_via_environment,
  validate_issuer_matches,
  validate_resource_matches,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_prm(**overrides) -> dict:
  doc = {
    "resource": "https://mcp.example.com/mcp",
    "authorization_servers": ["https://auth.example.com"],
    "scopes_supported": ["files:read", "files:write"],
    "bearer_methods_supported": ["header"],
  }
  doc.update(overrides)
  return doc


def _valid_asm(**overrides) -> dict:
  doc = {
    "issuer": "https://auth.example.com",
    "authorization_endpoint": "https://auth.example.com/authorize",
    "token_endpoint": "https://auth.example.com/token",
    "registration_endpoint": "https://auth.example.com/register",
    "scopes_supported": ["files:read", "files:write"],
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "code_challenge_methods_supported": ["S256"],
    "token_endpoint_auth_methods_supported": ["none"],
    "authorization_response_iss_parameter_supported": True,
    "client_id_metadata_document_supported": False,
  }
  doc.update(overrides)
  return doc


# ---------------------------------------------------------------------------
# AC-35.1 — authorization is OPTIONAL (R-23.1-a)
# ---------------------------------------------------------------------------

class TestApplicabilityOptional:
  def test_authorization_is_optional_flag(self):
    assert AUTHORIZATION_OPTIONAL is True

  def test_http_transport_is_governed_when_supported(self):
    # When an implementation supports it and operates over HTTP, §23 applies.
    assert authorization_applies(TransportClass.HTTP) is True

  def test_omitting_authorization_remains_conformant(self):
    # An implementation that does not support §23 (does not invoke the flow)
    # still applies it nowhere; the module imposes no obligation by import.
    # Non-HTTP transports are simply not governed.
    assert authorization_applies(TransportClass.OTHER) is False


# ---------------------------------------------------------------------------
# AC-35.2 — stdio MUST NOT use this flow; credentials via child env (R-23.1-b)
# ---------------------------------------------------------------------------

class TestStdioMustNotUseAuthorization:
  def test_stdio_does_not_apply(self):
    assert authorization_applies(TransportClass.STDIO) is False

  def test_credentials_conveyed_via_environment(self):
    env = {"API_TOKEN": "secret", "PATH": "/usr/bin"}
    conveyed = stdio_credentials_via_environment(env)
    assert conveyed == env
    # Returns a copy, not the same mutable mapping.
    conveyed["X"] = "1"
    assert "X" not in env

  def test_none_environment_yields_empty(self):
    assert stdio_credentials_via_environment(None) == {}


# ---------------------------------------------------------------------------
# AC-35.3 — non-HTTP/non-stdio transports use their own best practices (R-23.1-c)
# ---------------------------------------------------------------------------

class TestOtherTransportBestPractices:
  def test_other_transport_not_governed_by_section_23(self):
    assert authorization_applies(TransportClass.OTHER) is False
    assert other_transport_security_is_out_of_scope(TransportClass.OTHER) is True

  def test_http_transport_is_governed(self):
    assert other_transport_security_is_out_of_scope(TransportClass.HTTP) is False

  def test_stdio_is_also_outside_section_23_flow(self):
    assert other_transport_security_is_out_of_scope(TransportClass.STDIO) is True


# ---------------------------------------------------------------------------
# AC-35.4 — authorization server implements OAuth 2.1 (R-23.1-d)
# ---------------------------------------------------------------------------

class TestAuthorizationServerOAuth21:
  def test_authorization_server_requirement_mentions_oauth21_and_client_types(self):
    req = role_requirements(OAuthRole.AUTHORIZATION_SERVER)
    assert "OAuth 2.1" in req
    assert "confidential" in req and "public" in req
    assert "R-23.1-d" in req


# ---------------------------------------------------------------------------
# AC-35.5 — resource-server token handling conforms to OAuth 2.1 (R-23.1-e)
# ---------------------------------------------------------------------------

class TestResourceServerTokenHandling:
  def test_resource_server_requirement_cites_bearer_and_audience(self):
    req = role_requirements(OAuthRole.RESOURCE_SERVER)
    assert "§23.8" in req  # bearer-header
    assert "§23.6" in req  # audience-validation
    assert "R-23.1-e" in req


# ---------------------------------------------------------------------------
# AC-35.6 — custom strategy is out of scope yet still fully bound (R-23.1-f)
# ---------------------------------------------------------------------------

class TestCustomStrategyOutOfScope:
  def test_custom_strategy_permitted_and_still_bound(self):
    assert custom_strategy_is_out_of_scope() is True


# ---------------------------------------------------------------------------
# AC-35.7 — the three roles each behave as specified (R-23.1-g)
# ---------------------------------------------------------------------------

class TestRolesBehaveAsSpecified:
  def test_three_roles_defined(self):
    assert {r for r in OAuthRole} == {
      OAuthRole.RESOURCE_SERVER,
      OAuthRole.AUTHORIZATION_SERVER,
      OAuthRole.CLIENT,
    }

  def test_each_role_has_a_requirement_statement(self):
    for role in OAuthRole:
      assert role_requirements(role)

  def test_client_role_requirement(self):
    req = role_requirements(OAuthRole.CLIENT)
    assert "discovery" in req and "token" in req


# ---------------------------------------------------------------------------
# AC-35.8 — PRM may list one or more authorization servers (R-23.1-h)
# ---------------------------------------------------------------------------

class TestMultipleAuthorizationServers:
  def test_single_authorization_server_accepted(self):
    prm = parse_protected_resource_metadata(_valid_prm())
    assert prm.authorization_servers == ["https://auth.example.com"]

  def test_multiple_authorization_servers_accepted(self):
    doc = _valid_prm(
      authorization_servers=[
        "https://auth1.example.com",
        "https://auth2.example.com",
      ]
    )
    prm = parse_protected_resource_metadata(doc)
    assert len(prm.authorization_servers) == 2


# ---------------------------------------------------------------------------
# AC-35.9 — per-authorization-server credential isolation (R-23.1-i/j/k/l)
# ---------------------------------------------------------------------------

class TestPerAuthorizationServerIsolation:
  def test_separate_state_keyed_by_issuer(self):
    store = PerAuthorizationServerCredentialStore()
    store.store(AuthorizationServerCredentials("https://as1", client_id="c1"))
    store.store(AuthorizationServerCredentials("https://as2", client_id="c2"))
    assert store.get("https://as1").client_id == "c1"
    assert store.get("https://as2").client_id == "c2"
    assert store.known_issuers() == frozenset({"https://as1", "https://as2"})

  def test_does_not_assume_one_servers_credentials_work_at_another(self):
    # R-23.1-j: getting a different issuer never yields another's creds.
    store = PerAuthorizationServerCredentialStore()
    store.store(AuthorizationServerCredentials("https://as1", client_id="c1"))
    assert store.get("https://as2") is None
    assert store.has("https://as2") is False

  def test_no_reuse_when_indicated_server_changes(self):
    # R-23.1-k: indicated AS changed → no credentials for the new one.
    store = PerAuthorizationServerCredentialStore()
    store.store(AuthorizationServerCredentials("https://as1", client_id="c1"))
    # New indicated issuer as2: only as2's (absent) creds may be considered.
    assert store.credentials_for_indicated_server("https://as2") is None
    # The old creds are NOT returned for the new issuer.
    assert store.credentials_for_indicated_server("https://as1").client_id == "c1"

  def test_must_reregister_or_rediscover_against_new_server(self):
    # R-23.1-l: changed indicated AS with no stored state → must reauthorize.
    store = PerAuthorizationServerCredentialStore()
    store.store(AuthorizationServerCredentials("https://as1", client_id="c1"))
    assert store.must_reauthorize("https://as2") is True
    assert store.must_reauthorize("https://as1") is False


# ---------------------------------------------------------------------------
# AC-35.10 — canonical resource identifier: endpoint URL, absolute https/loopback
#            http, no fragment (R-23.1-m/n/o)
# ---------------------------------------------------------------------------

class TestCanonicalResourceIdentifier:
  def test_equals_endpoint_url(self):
    cri = build_canonical_resource_identifier("https://mcp.example.com/mcp")
    assert cri == "https://mcp.example.com/mcp"

  def test_https_with_port_preserved(self):
    cri = build_canonical_resource_identifier("https://mcp.example.com:8443")
    assert cri == "https://mcp.example.com:8443"

  def test_loopback_http_allowed(self):
    for host in ("localhost", "127.0.0.1"):
      cri = build_canonical_resource_identifier(f"http://{host}:3000/mcp")
      assert cri == f"http://{host}:3000/mcp"

  def test_non_loopback_http_rejected(self):
    with pytest.raises(CanonicalResourceIdentifierError):
      build_canonical_resource_identifier("http://mcp.example.com/mcp")

  def test_missing_scheme_rejected(self):
    with pytest.raises(CanonicalResourceIdentifierError):
      build_canonical_resource_identifier("mcp.example.com")

  def test_fragment_rejected(self):
    with pytest.raises(CanonicalResourceIdentifierError):
      build_canonical_resource_identifier("https://mcp.example.com#fragment")

  def test_unknown_scheme_rejected(self):
    with pytest.raises(CanonicalResourceIdentifierError):
      build_canonical_resource_identifier("ftp://mcp.example.com/mcp")


# ---------------------------------------------------------------------------
# AC-35.11 — receivers accept uppercase scheme/host (R-23.1-p)
# ---------------------------------------------------------------------------

class TestCanonicalCaseRobustness:
  def test_canonical_form_lowercases_scheme_and_host(self):
    cri = build_canonical_resource_identifier("HTTPS://MCP.EXAMPLE.COM/mcp")
    assert cri == "https://mcp.example.com/mcp"

  def test_path_case_is_preserved(self):
    # Only scheme/host are lowercased; the path remains case-sensitive.
    cri = build_canonical_resource_identifier("https://mcp.example.com/MyServer")
    assert cri == "https://mcp.example.com/MyServer"

  def test_receiver_accepts_uppercase_scheme_host(self):
    assert canonical_forms_equivalent(
      "HTTPS://MCP.EXAMPLE.COM/mcp",
      "https://mcp.example.com/mcp",
    )

  def test_different_path_not_equivalent(self):
    assert not canonical_forms_equivalent(
      "https://mcp.example.com/a",
      "https://mcp.example.com/b",
    )


# ---------------------------------------------------------------------------
# AC-35.12 — most-specific URI, path when needed, no trailing slash (R-23.1-q/r/s)
# ---------------------------------------------------------------------------

class TestCanonicalSpecificityAndSlash:
  def test_path_component_preserved_to_identify_server(self):
    # R-23.1-r: a path identifies an individual server at the host.
    cri = build_canonical_resource_identifier("https://host.example.com/server/mcp")
    assert cri == "https://host.example.com/server/mcp"

  def test_trailing_slash_omitted_by_default(self):
    # R-23.1-s: form WITHOUT a trailing slash by default.
    cri = build_canonical_resource_identifier("https://mcp.example.com/mcp/")
    assert cri == "https://mcp.example.com/mcp"

  def test_bare_host_trailing_slash_normalized(self):
    cri = build_canonical_resource_identifier("https://mcp.example.com/")
    assert cri == "https://mcp.example.com"

  def test_significant_trailing_slash_preserved_when_requested(self):
    cri = build_canonical_resource_identifier(
      "https://mcp.example.com/mcp/",
      keep_trailing_slash=True,
    )
    assert cri == "https://mcp.example.com/mcp/"


# ---------------------------------------------------------------------------
# AC-35.13 — 401 + Bearer WWW-Authenticate with resource_metadata (R-23.1-t/u/v)
# ---------------------------------------------------------------------------

class TestUnauthorizedResponse:
  def test_status_is_401(self):
    resp = build_unauthorized_response(
      "https://mcp.example.com/.well-known/oauth-protected-resource"
    )
    assert resp.status == HTTP_UNAUTHORIZED == 401

  def test_header_uses_bearer_and_carries_resource_metadata(self):
    metadata_uri = "https://mcp.example.com/.well-known/oauth-protected-resource"
    resp = build_unauthorized_response(metadata_uri)
    header = resp.headers[WWW_AUTHENTICATE_HEADER]
    assert header.startswith(BEARER_SCHEME + " ")
    assert f'resource_metadata="{metadata_uri}"' in header
    # The parsed structured challenge round-trips the absolute URI.
    assert resp.challenge.resource_metadata == metadata_uri

  def test_empty_resource_metadata_rejected(self):
    # R-23.1-v: resource_metadata is REQUIRED.
    with pytest.raises(ValueError):
      build_unauthorized_response("")


# ---------------------------------------------------------------------------
# AC-35.14 — 401 SHOULD include a scope parameter (R-23.1-w)
# ---------------------------------------------------------------------------

class TestUnauthorizedScopeParameter:
  def test_scope_included_when_known(self):
    resp = build_unauthorized_response(
      "https://mcp.example.com/.well-known/oauth-protected-resource",
      scope="files:read",
    )
    assert 'scope="files:read"' in resp.headers[WWW_AUTHENTICATE_HEADER]
    assert resp.challenge.scopes == ["files:read"]

  def test_scope_omitted_when_unknown(self):
    resp = build_unauthorized_response(
      "https://mcp.example.com/.well-known/oauth-protected-resource"
    )
    assert "scope=" not in resp.headers[WWW_AUTHENTICATE_HEADER]


# ---------------------------------------------------------------------------
# AC-35.15 — client treats challenged scopes as required; no subset/superset
#            relationship with scopes_supported (R-23.1-x/y)
# ---------------------------------------------------------------------------

class TestClientTreatsChallengedScopes:
  def test_challenged_scopes_are_authoritative(self):
    challenge = BearerChallenge(scope="files:write admin")
    assert required_scopes_from_challenge(challenge) == ["files:write", "admin"]

  def test_scopes_supported_does_not_influence_result(self):
    # R-23.1-y: no subset/superset assumption; scopes_supported is ignored.
    challenge = BearerChallenge(scope="files:write")
    result = required_scopes_from_challenge(
      challenge,
      scopes_supported=["files:read", "files:write", "admin"],
    )
    assert result == ["files:write"]

  def test_challenged_scope_not_in_scopes_supported_still_required(self):
    challenge = BearerChallenge(scope="unlisted:scope")
    result = required_scopes_from_challenge(
      challenge,
      scopes_supported=["files:read"],
    )
    assert result == ["unlisted:scope"]


# ---------------------------------------------------------------------------
# AC-35.16 — client parses WWW-Authenticate and reacts to 401 (R-23.1-z)
# ---------------------------------------------------------------------------

class TestClientParsesWWWAuthenticate:
  def test_parse_full_401_challenge(self):
    header = (
      'Bearer resource_metadata="https://mcp.example.com/.well-known/'
      'oauth-protected-resource", scope="files:read"'
    )
    challenge = parse_www_authenticate(header)
    assert challenge.resource_metadata == (
      "https://mcp.example.com/.well-known/oauth-protected-resource"
    )
    assert challenge.scope == "files:read"

  def test_round_trip_through_builder(self):
    metadata_uri = "https://mcp.example.com/.well-known/oauth-protected-resource"
    built = build_unauthorized_response(metadata_uri, scope="a b")
    parsed = parse_www_authenticate(built.headers[WWW_AUTHENTICATE_HEADER])
    assert parsed.resource_metadata == metadata_uri
    assert parsed.scopes == ["a", "b"]

  def test_parse_from_header_mapping_case_insensitive(self):
    headers = {
      "www-authenticate": (
        'Bearer resource_metadata="https://mcp.example.com/prm"'
      )
    }
    challenge = parse_www_authenticate_from_headers(headers)
    assert challenge.resource_metadata == "https://mcp.example.com/prm"

  def test_non_bearer_scheme_rejected(self):
    with pytest.raises(ValueError):
      parse_www_authenticate('Basic realm="x"')

  def test_absent_header_rejected(self):
    with pytest.raises(ValueError):
      parse_www_authenticate(None)


# ---------------------------------------------------------------------------
# AC-35.17 — 403 insufficient_scope response shape (R-23.1-aa/ab/ac/ad)
# ---------------------------------------------------------------------------

class TestInsufficientScopeResponse:
  def test_status_is_403(self):
    resp = build_insufficient_scope_response(
      "https://mcp.example.com/.well-known/oauth-protected-resource",
      "files:write",
    )
    assert resp.status == HTTP_FORBIDDEN == 403

  def test_header_carries_error_scope_and_resource_metadata(self):
    metadata_uri = "https://mcp.example.com/.well-known/oauth-protected-resource"
    resp = build_insufficient_scope_response(metadata_uri, "files:write")
    header = resp.headers[WWW_AUTHENTICATE_HEADER]
    assert header.startswith(BEARER_SCHEME + " ")
    assert f'error="{INSUFFICIENT_SCOPE_ERROR}"' in header
    assert 'scope="files:write"' in header
    assert f'resource_metadata="{metadata_uri}"' in header
    assert resp.challenge.error == "insufficient_scope"

  def test_all_required_scopes_in_a_single_challenge(self):
    # R-23.1-ac: a single challenge naming all required scopes, not incremental.
    resp = build_insufficient_scope_response(
      "https://mcp.example.com/prm",
      "files:write admin",
    )
    assert resp.challenge.scopes == ["files:write", "admin"]

  def test_optional_error_description_included(self):
    resp = build_insufficient_scope_response(
      "https://mcp.example.com/prm",
      "files:write",
      error_description="File write permission required for this operation",
    )
    header = resp.headers[WWW_AUTHENTICATE_HEADER]
    assert (
      'error_description="File write permission required for this operation"'
      in header
    )

  def test_error_description_optional_omitted(self):
    resp = build_insufficient_scope_response(
      "https://mcp.example.com/prm", "files:write"
    )
    assert "error_description" not in resp.headers[WWW_AUTHENTICATE_HEADER]

  def test_empty_scope_rejected(self):
    with pytest.raises(ValueError):
      build_insufficient_scope_response("https://mcp.example.com/prm", "")

  def test_parse_round_trip_403(self):
    resp = build_insufficient_scope_response(
      "https://mcp.example.com/prm",
      "files:write",
      error_description="needs write",
    )
    parsed = parse_www_authenticate(resp.headers[WWW_AUTHENTICATE_HEADER])
    assert parsed.error == "insufficient_scope"
    assert parsed.scope == "files:write"
    assert parsed.error_description == "needs write"
    assert parsed.resource_metadata == "https://mcp.example.com/prm"

  def test_status_table_covers_401_403_400(self):
    assert set(AUTHORIZATION_STATUS_TABLE) == {
      HTTP_UNAUTHORIZED,
      HTTP_FORBIDDEN,
      HTTP_BAD_REQUEST,
    }
    assert HTTP_BAD_REQUEST == 400


# ---------------------------------------------------------------------------
# AC-35.18 — PRM discovery via both header and well-known mechanisms
#            (R-23.2-a/b/c)
# ---------------------------------------------------------------------------

class TestProtectedResourceDiscoveryMechanisms:
  def test_well_known_suffix_value(self):
    assert PROTECTED_RESOURCE_WELL_KNOWN_SUFFIX == (
      "/.well-known/oauth-protected-resource"
    )

  def test_header_mechanism_supported(self):
    headers = {
      "WWW-Authenticate": 'Bearer resource_metadata="https://mcp.example.com/prm"'
    }
    plan = protected_resource_discovery_plan(
      "https://mcp.example.com/mcp", headers=headers
    )
    assert plan.header_uri == "https://mcp.example.com/prm"

  def test_well_known_mechanism_supported(self):
    plan = protected_resource_discovery_plan("https://mcp.example.com/mcp")
    assert plan.header_uri is None
    assert plan.well_known_urls  # well-known candidates available

  def test_client_uses_metadata_to_discover_authorization_servers(self):
    prm = parse_protected_resource_metadata(_valid_prm())
    assert prm.authorization_servers  # used for AS discovery


# ---------------------------------------------------------------------------
# AC-35.19 — when header carries resource_metadata, client uses that URI
#            (R-23.2-d)
# ---------------------------------------------------------------------------

class TestUsesHeaderResourceMetadata:
  def test_header_uri_used_directly(self):
    uri = locate_protected_resource_metadata_uri(
      www_authenticate='Bearer resource_metadata="https://mcp.example.com/prm"'
    )
    assert uri == "https://mcp.example.com/prm"

  def test_plan_prefers_header_uri_over_well_known(self):
    plan = protected_resource_discovery_plan(
      "https://mcp.example.com/mcp",
      www_authenticate='Bearer resource_metadata="https://mcp.example.com/custom-prm"',
    )
    # candidate order: the header URI is tried first and exclusively.
    assert plan.candidate_uris() == ["https://mcp.example.com/custom-prm"]

  def test_no_resource_metadata_param_returns_none(self):
    uri = locate_protected_resource_metadata_uri(
      www_authenticate='Bearer scope="files:read"'
    )
    assert uri is None


# ---------------------------------------------------------------------------
# AC-35.20 — well-known construction order: path-aware then root (R-23.2-e/f)
# ---------------------------------------------------------------------------

class TestWellKnownConstructionOrder:
  def test_path_aware_then_root(self):
    urls = build_protected_resource_well_known_urls(
      "https://example.com/public/mcp"
    )
    assert urls == [
      "https://example.com/.well-known/oauth-protected-resource/public/mcp",
      "https://example.com/.well-known/oauth-protected-resource",
    ]

  def test_no_path_yields_root_only(self):
    urls = build_protected_resource_well_known_urls("https://example.com")
    assert urls == ["https://example.com/.well-known/oauth-protected-resource"]

  def test_plan_candidate_order_uses_well_known_when_no_header(self):
    plan = protected_resource_discovery_plan("https://example.com/public/mcp")
    assert plan.candidate_uris() == [
      "https://example.com/.well-known/oauth-protected-resource/public/mcp",
      "https://example.com/.well-known/oauth-protected-resource",
    ]

  def test_first_valid_document_wins(self):
    plan = protected_resource_discovery_plan("https://example.com/public/mcp")
    # Simulate the root candidate being the first valid one.
    chosen = plan.resolve(
      valid_document_uri="https://example.com/.well-known/oauth-protected-resource"
    )
    assert chosen == (
      "https://example.com/.well-known/oauth-protected-resource"
    )


# ---------------------------------------------------------------------------
# AC-35.21 — neither well-known nor header → abort or fallback (R-23.2-g)
# ---------------------------------------------------------------------------

class TestAbortOrFallback:
  def test_abort_when_no_document_and_no_fallback(self):
    plan = protected_resource_discovery_plan("https://example.com/mcp")
    with pytest.raises(ProtectedResourceDiscoveryError):
      plan.resolve(valid_document_uri=None, fallback_available=False)

  def test_fallback_signalled_when_available(self):
    plan = protected_resource_discovery_plan("https://example.com/mcp")
    with pytest.raises(ProtectedResourceDiscoveryError):
      plan.resolve(valid_document_uri=None, fallback_available=True)

  def test_resolve_returns_uri_when_a_document_was_found(self):
    plan = ProtectedResourceDiscovery(header_uri=None, well_known_urls=["u"])
    assert plan.resolve(valid_document_uri="u") == "u"


# ---------------------------------------------------------------------------
# AC-35.22 — PRM shape: resource & authorization_servers; validate & select
#            (R-23.2-h/i/j)
# ---------------------------------------------------------------------------

class TestProtectedResourceMetadataShape:
  def test_valid_document_parses(self):
    prm = parse_protected_resource_metadata(_valid_prm())
    assert prm.resource == "https://mcp.example.com/mcp"
    assert prm.authorization_servers == ["https://auth.example.com"]
    assert prm.scopes_supported == ["files:read", "files:write"]
    assert prm.bearer_methods_supported == ["header"]

  def test_resource_required(self):
    doc = _valid_prm()
    del doc["resource"]
    with pytest.raises(ValueError):
      parse_protected_resource_metadata(doc)

  def test_authorization_servers_required(self):
    doc = _valid_prm()
    del doc["authorization_servers"]
    with pytest.raises(ValueError):
      parse_protected_resource_metadata(doc)

  def test_authorization_servers_must_have_at_least_one_entry(self):
    with pytest.raises(ValueError):
      parse_protected_resource_metadata(_valid_prm(authorization_servers=[]))

  def test_resource_must_equal_canonical_identifier(self):
    prm = parse_protected_resource_metadata(_valid_prm())
    # Matches (case-tolerant per R-23.1-p).
    validate_resource_matches(prm, "HTTPS://MCP.EXAMPLE.COM/mcp")
    # Mismatch raises.
    with pytest.raises(ValueError):
      validate_resource_matches(prm, "https://other.example.com/mcp")

  def test_client_selects_an_authorization_server(self):
    prm = parse_protected_resource_metadata(
      _valid_prm(authorization_servers=["https://as1", "https://as2"])
    )
    assert select_authorization_server(prm) == "https://as1"
    assert (
      select_authorization_server(prm, preferred_issuer="https://as2")
      == "https://as2"
    )

  def test_preferred_issuer_must_be_listed(self):
    prm = parse_protected_resource_metadata(_valid_prm())
    with pytest.raises(ValueError):
      select_authorization_server(prm, preferred_issuer="https://not-listed")

  def test_non_object_rejected(self):
    with pytest.raises(TypeError):
      parse_protected_resource_metadata(["not", "an", "object"])


# ---------------------------------------------------------------------------
# AC-35.23 — AS provides OAuth AS Metadata or OIDC Discovery; client supports
#            both (R-23.3-a/b)
# ---------------------------------------------------------------------------

class TestAuthorizationServerDiscoveryMechanisms:
  def test_both_well_known_suffixes_defined(self):
    assert OAUTH_AS_METADATA_WELL_KNOWN_SUFFIX == (
      "/.well-known/oauth-authorization-server"
    )
    assert OPENID_CONFIGURATION_WELL_KNOWN_SUFFIX == (
      "/.well-known/openid-configuration"
    )

  def test_no_path_issuer_attempts_both_mechanisms(self):
    urls = build_authorization_server_well_known_urls("https://auth.example.com")
    assert any(OAUTH_AS_METADATA_WELL_KNOWN_SUFFIX in u for u in urls)
    assert any(OPENID_CONFIGURATION_WELL_KNOWN_SUFFIX in u for u in urls)


# ---------------------------------------------------------------------------
# AC-35.24 — AS metadata well-known order for with-path and no-path (R-23.3-c)
# ---------------------------------------------------------------------------

class TestAuthorizationServerWellKnownOrder:
  def test_issuer_with_path_priority_order(self):
    urls = build_authorization_server_well_known_urls(
      "https://auth.example.com/tenant1"
    )
    assert urls == [
      "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
      "https://auth.example.com/.well-known/openid-configuration/tenant1",
      "https://auth.example.com/tenant1/.well-known/openid-configuration",
    ]

  def test_issuer_without_path_priority_order(self):
    urls = build_authorization_server_well_known_urls("https://auth.example.com")
    assert urls == [
      "https://auth.example.com/.well-known/oauth-authorization-server",
      "https://auth.example.com/.well-known/openid-configuration",
    ]

  def test_trailing_slash_issuer_treated_as_no_path(self):
    urls = build_authorization_server_well_known_urls("https://auth.example.com/")
    assert urls == [
      "https://auth.example.com/.well-known/oauth-authorization-server",
      "https://auth.example.com/.well-known/openid-configuration",
    ]


# ---------------------------------------------------------------------------
# AC-35.25 — issuer-match validation; reject mismatch (R-23.3-d/e)
# ---------------------------------------------------------------------------

class TestIssuerMatchValidation:
  def test_matching_issuer_accepted(self):
    asm = parse_authorization_server_metadata(_valid_asm())
    validate_issuer_matches(asm, "https://auth.example.com")

  def test_mismatched_issuer_rejected(self):
    # Document fetched using attacker issuer but claims honest issuer.
    asm = parse_authorization_server_metadata(
      _valid_asm(issuer="https://honest.example")
    )
    with pytest.raises(IssuerMismatchError):
      validate_issuer_matches(asm, "https://attacker.example")

  def test_issuer_match_is_exact(self):
    asm = parse_authorization_server_metadata(
      _valid_asm(issuer="https://auth.example.com")
    )
    # A trailing-slash difference is NOT identical → reject.
    with pytest.raises(IssuerMismatchError):
      validate_issuer_matches(asm, "https://auth.example.com/")

  def test_mismatch_error_carries_both_issuers(self):
    asm = parse_authorization_server_metadata(
      _valid_asm(issuer="https://honest.example")
    )
    with pytest.raises(IssuerMismatchError) as exc:
      validate_issuer_matches(asm, "https://attacker.example")
    assert exc.value.used_issuer == "https://attacker.example"
    assert exc.value.document_issuer == "https://honest.example"


# ---------------------------------------------------------------------------
# AC-35.26 — AS metadata required fields issuer/authorization/token endpoints
#            (R-23.3-f/g/h)
# ---------------------------------------------------------------------------

class TestAuthorizationServerMetadataRequired:
  def test_valid_document_parses_all_fields(self):
    asm = parse_authorization_server_metadata(_valid_asm())
    assert asm.issuer == "https://auth.example.com"
    assert asm.authorization_endpoint == "https://auth.example.com/authorize"
    assert asm.token_endpoint == "https://auth.example.com/token"
    assert asm.registration_endpoint == "https://auth.example.com/register"
    assert asm.authorization_response_iss_parameter_supported is True
    assert asm.client_id_metadata_document_supported is False

  def test_issuer_required(self):
    doc = _valid_asm()
    del doc["issuer"]
    with pytest.raises(ValueError):
      parse_authorization_server_metadata(doc)

  def test_authorization_endpoint_required(self):
    doc = _valid_asm()
    del doc["authorization_endpoint"]
    with pytest.raises(ValueError):
      parse_authorization_server_metadata(doc)

  def test_token_endpoint_required(self):
    doc = _valid_asm()
    del doc["token_endpoint"]
    with pytest.raises(ValueError):
      parse_authorization_server_metadata(doc)

  def test_registration_endpoint_optional(self):
    doc = _valid_asm()
    del doc["registration_endpoint"]
    asm = parse_authorization_server_metadata(doc)
    assert asm.registration_endpoint is None

  def test_non_object_rejected(self):
    with pytest.raises(TypeError):
      parse_authorization_server_metadata("not-an-object")


# ---------------------------------------------------------------------------
# AC-35.27 — response_types_supported includes "code"; code_challenge_methods
#            includes "S256" (R-23.3-i/j)
# ---------------------------------------------------------------------------

class TestResponseTypeAndCodeChallenge:
  def test_response_types_present_must_include_code(self):
    with pytest.raises(ValueError):
      parse_authorization_server_metadata(
        _valid_asm(response_types_supported=["token"])
      )

  def test_response_types_with_code_accepted(self):
    asm = parse_authorization_server_metadata(
      _valid_asm(response_types_supported=["code", "token"])
    )
    assert "code" in asm.response_types_supported

  def test_response_types_absent_is_allowed(self):
    doc = _valid_asm()
    del doc["response_types_supported"]
    asm = parse_authorization_server_metadata(doc)
    assert asm.response_types_supported is None

  def test_code_challenge_methods_present_must_include_s256(self):
    with pytest.raises(ValueError):
      parse_authorization_server_metadata(
        _valid_asm(code_challenge_methods_supported=["plain"])
      )

  def test_code_challenge_methods_with_s256_accepted(self):
    asm = parse_authorization_server_metadata(
      _valid_asm(code_challenge_methods_supported=["S256", "plain"])
    )
    assert "S256" in asm.code_challenge_methods_supported

  def test_code_challenge_methods_absent_is_allowed(self):
    doc = _valid_asm()
    del doc["code_challenge_methods_supported"]
    asm = parse_authorization_server_metadata(doc)
    assert asm.code_challenge_methods_supported is None
