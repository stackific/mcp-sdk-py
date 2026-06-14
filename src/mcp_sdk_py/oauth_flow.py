"""Authorization II: Auth-Code+PKCE Flow, Tokens & Worked Examples — S36.

The executable heart of MCP authorization. Given the discovery surface S35
established (protected-resource metadata, authorization-server metadata, the
canonical resource identifier, and the ``WWW-Authenticate`` challenge), this
module turns that metadata into an actual access token and uses it:

  - how a client obtains a ``client_id`` (pre-registration / Client ID Metadata
    Document / Dynamic Client Registration / user prompt) and the SHOULD priority
    order between them (§23.4);
  - the OAuth 2.0 authorization-code flow with PKCE (S256): generating the
    ``code_verifier``/``code_challenge`` pair, recording the selected
    authorization server's ``issuer`` in a per-request record, building the
    authorization-request query parameters, validating the redirect, and building
    the token-request body (§23.5);
  - Resource Indicators / audience binding: the ``resource`` parameter on both
    legs, server-side audience validation, and the client's "no other token" rule
    (§23.6);
  - issuer identification: the ``iss``-validation decision table, exact-string-
    match comparison (no normalization), and error-response suppression on
    mismatch (§23.7);
  - access-token usage: the bearer header on every request, no token in the query
    string, and the per-request 401/403 outcomes (§23.8);
  - refresh tokens: the refresh grant, ``offline_access`` handling, and the
    audience-bound refresh request (§23.9);
  - the §23.10 worked HTTP examples, exercised by the tests.

This module owns ONLY the flow, tokens, and the registration *mechanisms* that
§23.4 introduces. It does NOT re-implement metadata discovery, the canonical
resource identifier, or the challenge shape — those are S35
(:mod:`mcp_sdk_py.authorization`), reused here. The full elaboration of the
registration mechanisms (detailed DCR/CIMD semantics, scopes & step-up
authorization) is S37, and the consolidated security considerations are S44.

Public surface:

Client-id acquisition (§23.4):
  - ClientIdMechanism / CLIENT_ID_MECHANISM_PRIORITY / select_client_id_mechanism():
    the three mechanisms + the user-prompt fallback and the SHOULD priority order
    (R-23.4-a/b).
  - PreRegisteredCredentials / pre_registration_matches() /
    AuthorizationServerMismatchError: pre-registered credentials are AS-specific;
    a mismatch surfaces an error (R-23.4-c).
  - ClientIdMetadataDocument / parse_client_id_metadata_document() /
    validate_client_id_metadata_document() / CIMDValidationError: the CIMD shape,
    the ``client_id == URL`` identity rule, and the HTTPS/path constraints
    (R-23.4-d..g).
  - authorization_server_fetch_cimd() / authorization_server_validate_cimd() /
    CIMDCache: the authorization server's fetch / validate / cache duties
    (R-23.4-h..l).
  - ApplicationType / DynamicClientRegistrationRequest /
    DynamicClientRegistrationResponse / build_dcr_request() / parse_dcr_response()
    / application_type_for_client() / DCRRegistrationError /
    retry_dcr_with_adjustment() / DCRCredentialStore: the DCR summary, the
    ``application_type`` rule, failure handling, retry, and issuer-keyed
    persistence (R-23.4-m..t).

Authorization-code flow with PKCE (§23.5):
  - generate_code_verifier() / derive_code_challenge() / PKCE_CODE_CHALLENGE_METHOD
    / PKCEParameters / generate_pkce_parameters(): real S256 PKCE (R-23.5-a/b).
  - AuthorizationRecord / record_authorization_request(): the per-request record
    keyed to ``code_verifier``/``state`` carrying the recorded issuer (R-23.5-c).
  - AuthorizationRequest / build_authorization_request() /
    build_authorization_request_url() / select_request_scope(): the Step-2 query
    parameters and the scope-priority rule (R-23.5-d..j).
  - AuthorizationResponse / parse_authorization_response(): the redirect query
    parameters (R-23.5-k).
  - verify_state() / StateMismatchError / validate_redirect():
    state verification + ``iss`` validation before redeeming the code
    (R-23.5-h/l/m).
  - TokenRequest / build_token_request() / encode_token_request_body(): the
    Step-4 token-request body (R-23.5-n/o/p).
  - TokenResponse / parse_token_response(): the token-response shape.

Resource Indicators & audience binding (§23.6):
  - RESOURCE_PARAMETER / resource_indicator_for() / token_is_audience_bound() /
    server_accepts_token() / AudienceMismatchError / client_may_send_token():
    the ``resource`` parameter on both legs and the audience rules (R-23.6-a..i).

Issuer identification (§23.7):
  - IssValidationError / validate_iss() / iss_validation_action() /
    IssValidationAction: the four-row decision table and exact-match comparison
    (R-23.7-a..g).
  - error_response_is_actionable(): suppress an error response on ``iss`` mismatch
    (R-23.7-h).

Access-token usage (§23.8):
  - AUTHORIZATION_HEADER / build_authorization_header() / token_in_query_string()
    / TokenInQueryStringError: the bearer header rules (R-23.8-a/b/c).
  - validate_access_token() / TokenValidationOutcome / TokenValidationError /
    token_validation_status(): the per-request server-side validation and the
    401/403 outcomes (R-23.8-d/e/f).

Refresh tokens (§23.9):
  - OFFLINE_ACCESS_SCOPE / client_wants_refresh_grant_types() /
    may_request_offline_access() / build_refresh_token_request() /
    metadata_excludes_offline_access(): the refresh grant, ``offline_access``
    handling, and the audience-bound refresh request (R-23.9-a..g).

Spec: §23.4–§23.10 (lines 6445–6680)
Depends on: S35 (authorization model, metadata, canonical resource identifier,
  BearerChallenge), S34 (401/403 error model), S14 (Streamable HTTP transport).
"""

from __future__ import annotations

import base64
import enum
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from mcp_sdk_py.authorization import (
  HTTP_FORBIDDEN,
  HTTP_UNAUTHORIZED,
  INSUFFICIENT_SCOPE_ERROR,
  REQUIRED_CODE_CHALLENGE_METHOD,
  REQUIRED_RESPONSE_TYPE,
  AuthorizationServerMetadata,
  BearerChallenge,
  ProtectedResourceMetadata,
)

# ===========================================================================
# §23.4  Obtaining a client_id
# ===========================================================================


class ClientIdMechanism(enum.Enum):
  """A mechanism for obtaining a ``client_id`` before the flow (§23.4, R-23.4-a/b).

  Before initiating the authorization-code flow, the client MUST obtain a
  ``client_id`` through one of the three defined mechanisms, or fall back to
  prompting the user (R-23.4-a). The members are ordered by the SHOULD priority of
  R-23.4-b — see :data:`CLIENT_ID_MECHANISM_PRIORITY`.

  PRE_REGISTRATION:
    The client already holds a ``client_id`` (and possibly a secret) for that
    authorization server.
  CLIENT_ID_METADATA_DOCUMENT:
    The client is identified by an HTTPS-URL Client ID Metadata Document.
  DYNAMIC_CLIENT_REGISTRATION:
    The client registers programmatically at a ``registration_endpoint``
    (Deprecated).
  USER_PROMPT:
    The client prompts the user to enter client information (fallback).
  """

  PRE_REGISTRATION = "pre_registration"
  CLIENT_ID_METADATA_DOCUMENT = "client_id_metadata_document"
  DYNAMIC_CLIENT_REGISTRATION = "dynamic_client_registration"
  USER_PROMPT = "user_prompt"


#: The SHOULD priority order a client applies when it supports more than one
#: client-id mechanism: pre-registration → CIMD → DCR → user prompt (R-23.4-b).
CLIENT_ID_MECHANISM_PRIORITY: tuple[ClientIdMechanism, ...] = (
  ClientIdMechanism.PRE_REGISTRATION,
  ClientIdMechanism.CLIENT_ID_METADATA_DOCUMENT,
  ClientIdMechanism.DYNAMIC_CLIENT_REGISTRATION,
  ClientIdMechanism.USER_PROMPT,
)


def select_client_id_mechanism(
  available: object,
) -> ClientIdMechanism:
  """Select the client-id mechanism by the SHOULD priority order (R-23.4-a/b).

  A client that supports more than one mechanism SHOULD apply the priority order
  (1) pre-registration, (2) Client ID Metadata Documents, (3) Dynamic Client
  Registration, (4) prompt the user (R-23.4-b). The client MUST obtain a
  ``client_id`` through exactly one of these (R-23.4-a); the user-prompt fallback
  is always available, so a non-empty result is always returned.

  Args:
    available: the mechanisms the client supports (any iterable of
      :class:`ClientIdMechanism`); ``USER_PROMPT`` is always an implicit fallback.

  Returns:
    The single highest-priority supported mechanism (R-23.4-b).
  """
  supported = set(available)
  supported.add(ClientIdMechanism.USER_PROMPT)
  for mechanism in CLIENT_ID_MECHANISM_PRIORITY:
    if mechanism in supported:
      return mechanism
  # Unreachable: USER_PROMPT is always in CLIENT_ID_MECHANISM_PRIORITY and was
  # added to ``supported`` above.
  return ClientIdMechanism.USER_PROMPT


class AuthorizationServerMismatchError(ValueError):
  """Pre-registered credentials' AS differs from the indicated one (R-23.4-c).

  Raised by :func:`pre_registration_matches` when the authorization server a set
  of pre-registered credentials was registered with does not match the one
  indicated by the MCP server's protected-resource metadata. The client SHOULD
  surface this error rather than silently using mismatched credentials (R-23.4-c).

  Attributes:
    credential_issuer: the ``issuer`` the credentials were registered with.
    indicated_issuer: the ``issuer`` indicated by protected-resource metadata.
  """

  def __init__(self, credential_issuer: str, indicated_issuer: str) -> None:
    super().__init__(
      f"pre-registered credentials were registered with authorization server "
      f"{credential_issuer!r}, which does not match the authorization server "
      f"{indicated_issuer!r} indicated by protected-resource metadata; the "
      f"client surfaces an error rather than using mismatched credentials "
      f"(R-23.4-c)"
    )
    self.credential_issuer: str = credential_issuer
    self.indicated_issuer: str = indicated_issuer


@dataclass(frozen=True)
class PreRegisteredCredentials:
  """Pre-registered client credentials for one authorization server (R-23.4-c).

  Pre-registered credentials are specific to a particular authorization server;
  the client uses them only when the indicated authorization server matches the
  one they were registered with (R-23.4-c).

  Fields:
    issuer: the ``issuer`` of the authorization server these credentials are for.
    client_id: the pre-registered client identifier.
    client_secret: the pre-registered secret, for a confidential client (if any).
  """

  issuer: str
  client_id: str
  client_secret: str | None = None


def pre_registration_matches(
  credentials: PreRegisteredCredentials,
  indicated_issuer: str,
) -> bool:
  """Confirm pre-registered credentials match the indicated AS, else raise (R-23.4-c).

  When the authorization server indicated by protected-resource metadata does not
  match the one the pre-registered credentials were registered with, the client
  SHOULD surface an error rather than silently using mismatched credentials
  (R-23.4-c). The match is an exact ``issuer`` comparison (the issuer is an
  identity value).

  Args:
    credentials: the pre-registered credentials.
    indicated_issuer: the ``issuer`` indicated by protected-resource metadata.

  Returns:
    True when the credential issuer equals the indicated issuer.

  Raises:
    AuthorizationServerMismatchError: the issuers differ (R-23.4-c).
  """
  if credentials.issuer != indicated_issuer:
    raise AuthorizationServerMismatchError(credentials.issuer, indicated_issuer)
  return True


# ---------------------------------------------------------------------------
# §23.4  Client ID Metadata Documents (CIMD)
# ---------------------------------------------------------------------------

#: The CIMD ``client_id`` URL MUST use the ``https`` scheme (R-23.4-e).
CIMD_REQUIRED_SCHEME: str = "https"

#: The fields a CIMD document MUST include at least (R-23.4-f).
CIMD_REQUIRED_FIELDS: tuple[str, ...] = ("client_id", "client_name", "redirect_uris")


class CIMDValidationError(ValueError):
  """A Client ID Metadata Document violates the §23.4 CIMD constraints (R-23.4-e..k).

  Raised when a CIMD ``client_id`` URL is not an ``https`` URL with a path
  component (R-23.4-e), when the document is missing a required field (R-23.4-f/k),
  or when the document's ``client_id`` does not exactly equal the document URL
  (R-23.4-g/i).
  """


@dataclass(frozen=True)
class ClientIdMetadataDocument:
  """A Client ID Metadata Document (CIMD) — the JSON the ``client_id`` URL resolves to.

  An HTTPS URL used directly as the ``client_id``, resolving to this JSON document
  describing the client; portable across authorization servers (§23.4, R-23.4-d).

  Fields:
    client_id: the CIMD ``client_id``; MUST exactly equal the document's own URL,
      use the ``https`` scheme, and contain a path component (R-23.4-e/g).
    client_name: human-readable name of the client; REQUIRED (R-23.4-f).
    redirect_uris: allowed redirection URIs the authorization server validates
      against; REQUIRED (R-23.4-f/j).
    client_uri: OPTIONAL homepage of the client.
    logo_uri: OPTIONAL logo for consent screens.
    grant_types: OPTIONAL OAuth grant types the client uses.
    response_types: OPTIONAL OAuth response types.
    token_endpoint_auth_method: OPTIONAL token-endpoint auth method (e.g.
      ``"none"``).
  """

  client_id: str
  client_name: str
  redirect_uris: list[str]
  client_uri: str | None = None
  logo_uri: str | None = None
  grant_types: list[str] | None = None
  response_types: list[str] | None = None
  token_endpoint_auth_method: str | None = None


def is_url_formatted_client_id(client_id: str) -> bool:
  """Return True iff ``client_id`` is an HTTPS-URL (CIMD-formatted) identifier (R-23.4-e).

  A CIMD ``client_id`` is an HTTPS URL with a path component (R-23.4-e). On
  encountering a URL-formatted ``client_id`` the authorization server treats it as
  a CIMD (R-23.4-h). This recognises the ``https://…/path`` shape; it does not
  fetch or validate the document.
  """
  parts = urlsplit(client_id)
  return parts.scheme == CIMD_REQUIRED_SCHEME and bool(parts.netloc) and parts.path not in ("", "/")


def parse_client_id_metadata_document(raw: Any) -> ClientIdMetadataDocument:
  """Parse/validate a raw dict as a Client ID Metadata Document (R-23.4-f/k).

  The document MUST be valid JSON containing at least ``client_id``,
  ``client_name``, and ``redirect_uris`` (R-23.4-f/k). The ``client_id == URL``
  identity check (R-23.4-g) needs the document URL and is performed separately by
  :func:`validate_client_id_metadata_document`.

  Args:
    raw: the JSON-decoded document.

  Returns:
    A :class:`ClientIdMetadataDocument` with the validated required fields.

  Raises:
    CIMDValidationError: ``raw`` is not an object or a required field is missing.
    TypeError: a field has the wrong type.
  """
  if not isinstance(raw, dict):
    raise CIMDValidationError(
      f"a Client ID Metadata Document MUST be a JSON object; got "
      f"{type(raw).__name__} (R-23.4-k)"
    )
  for required in CIMD_REQUIRED_FIELDS:
    if required not in raw or raw[required] is None:
      raise CIMDValidationError(
        f"a Client ID Metadata Document MUST include at least {required!r}; it "
        f"is missing (R-23.4-f/k)"
      )

  client_id = raw["client_id"]
  client_name = raw["client_name"]
  redirect_uris = raw["redirect_uris"]
  if not isinstance(client_id, str):
    raise TypeError(f"CIMD client_id must be a string; got {type(client_id).__name__}")
  if not isinstance(client_name, str):
    raise TypeError(
      f"CIMD client_name must be a string; got {type(client_name).__name__}"
    )
  if not isinstance(redirect_uris, list) or not all(
    isinstance(u, str) for u in redirect_uris
  ):
    raise TypeError("CIMD redirect_uris must be an array of strings")

  grant_types = raw.get("grant_types")
  response_types = raw.get("response_types")
  if grant_types is not None and (
    not isinstance(grant_types, list) or not all(isinstance(g, str) for g in grant_types)
  ):
    raise TypeError("CIMD grant_types must be an array of strings")
  if response_types is not None and (
    not isinstance(response_types, list)
    or not all(isinstance(r, str) for r in response_types)
  ):
    raise TypeError("CIMD response_types must be an array of strings")

  return ClientIdMetadataDocument(
    client_id=client_id,
    client_name=client_name,
    redirect_uris=list(redirect_uris),
    client_uri=raw.get("client_uri"),
    logo_uri=raw.get("logo_uri"),
    grant_types=list(grant_types) if grant_types is not None else None,
    response_types=list(response_types) if response_types is not None else None,
    token_endpoint_auth_method=raw.get("token_endpoint_auth_method"),
  )


def validate_client_id_metadata_document(
  document: ClientIdMetadataDocument,
  document_url: str,
) -> None:
  """Validate a CIMD document against its hosting URL (R-23.4-e/g/i).

  The ``client_id`` URL MUST use the ``https`` scheme and MUST contain a path
  component (R-23.4-e), and the document's ``client_id`` value MUST exactly equal
  the document URL (R-23.4-g). The authorization server applies the same exact
  match when it fetches the document (R-23.4-i): see
  :func:`authorization_server_validate_cimd`.

  Args:
    document: the parsed CIMD document.
    document_url: the HTTPS URL the document was hosted/fetched at, i.e. the
      ``client_id`` value the client presents.

  Raises:
    CIMDValidationError: the URL is not ``https``-with-path, or the document's
      ``client_id`` does not exactly equal ``document_url`` (R-23.4-e/g).
  """
  if not is_url_formatted_client_id(document_url):
    raise CIMDValidationError(
      f"a CIMD client_id URL MUST use the 'https' scheme and contain a path "
      f"component; got {document_url!r} (R-23.4-e)"
    )
  if document.client_id != document_url:
    raise CIMDValidationError(
      f"a CIMD document's client_id {document.client_id!r} MUST exactly equal the "
      f"document URL {document_url!r} (R-23.4-g)"
    )


@dataclass
class _CachedCIMD:
  """One cached CIMD entry: the parsed document and its cache directives."""

  document: ClientIdMetadataDocument
  no_store: bool


class CIMDCache:
  """An authorization-server cache for CIMD documents, honoring HTTP headers (R-23.4-l).

  The authorization server SHOULD cache the CIMD document, respecting HTTP cache
  headers (R-23.4-l). A document served with ``Cache-Control: no-store`` is not
  cached; otherwise it is stored under its URL and returned on a repeated lookup,
  so the document is fetched once. This models the caching decision; it does not
  perform the HTTP fetch.
  """

  def __init__(self) -> None:
    self._by_url: dict[str, _CachedCIMD] = {}

  @staticmethod
  def _is_no_store(cache_headers: dict[str, str] | None) -> bool:
    """Return True iff cache headers forbid storing the response (R-23.4-l)."""
    if not cache_headers:
      return False
    for name, value in cache_headers.items():
      if name.lower() == "cache-control" and "no-store" in value.lower():
        return True
    return False

  def store(
    self,
    document_url: str,
    document: ClientIdMetadataDocument,
    *,
    cache_headers: dict[str, str] | None = None,
  ) -> None:
    """Cache ``document`` under its URL unless its headers forbid it (R-23.4-l).

    Respects ``Cache-Control: no-store`` by NOT caching such a response; any other
    (or absent) directive caches the document.
    """
    if self._is_no_store(cache_headers):
      self._by_url.pop(document_url, None)
      return
    self._by_url[document_url] = _CachedCIMD(document=document, no_store=False)

  def get(self, document_url: str) -> ClientIdMetadataDocument | None:
    """Return the cached CIMD document for ``document_url``, or None (R-23.4-l)."""
    entry = self._by_url.get(document_url)
    return entry.document if entry is not None else None


def authorization_server_fetch_cimd(
  client_id: str,
  resolver: object,
  *,
  cache: CIMDCache | None = None,
  cache_headers: dict[str, str] | None = None,
) -> ClientIdMetadataDocument:
  """Fetch (and optionally cache) a CIMD document for a URL ``client_id`` (R-23.4-h/l).

  On encountering a URL-formatted ``client_id`` the authorization server SHOULD
  fetch the document (R-23.4-h) and SHOULD cache it respecting HTTP cache headers
  (R-23.4-l). ``resolver`` is the caller's HTTP fetch: a callable
  ``client_id -> raw JSON dict``; this story owns the fetch/validate/cache
  *decision*, not the HTTP client itself. When a ``cache`` is supplied and holds
  the document, the cached copy is returned without re-fetching.

  Args:
    client_id: the URL-formatted ``client_id`` presented in the authorization
      request.
    resolver: a callable mapping the ``client_id`` URL to the raw JSON document.
    cache: an optional :class:`CIMDCache` to consult and populate (R-23.4-l).
    cache_headers: the HTTP cache headers from the fetch, used to decide caching.

  Returns:
    The parsed and (against the URL) validated :class:`ClientIdMetadataDocument`.

  Raises:
    CIMDValidationError: the fetched document is invalid (R-23.4-i/k).
  """
  if not is_url_formatted_client_id(client_id):
    raise CIMDValidationError(
      f"client_id {client_id!r} is not a URL-formatted (CIMD) identifier; only "
      f"URL-formatted client_ids are fetched (R-23.4-e/h)"
    )
  if cache is not None:
    cached = cache.get(client_id)
    if cached is not None:
      return cached
  raw = resolver(client_id)
  document = authorization_server_validate_cimd(client_id, raw)
  if cache is not None:
    cache.store(client_id, document, cache_headers=cache_headers)
  return document


def authorization_server_validate_cimd(
  client_id: str,
  raw: Any,
  *,
  presented_redirect_uri: str | None = None,
) -> ClientIdMetadataDocument:
  """Validate a fetched CIMD document on the authorization-server side (R-23.4-i/j/k).

  After fetching a URL-formatted ``client_id``'s document, the authorization
  server MUST validate that the document is valid JSON containing the required
  fields (R-23.4-k), MUST validate that the document's ``client_id`` matches the
  URL exactly (R-23.4-i), and MUST validate the redirect URI presented in the
  authorization request against ``redirect_uris`` in the document (R-23.4-j).

  Args:
    client_id: the URL the document was fetched from (the presented ``client_id``).
    raw: the raw JSON-decoded document body.
    presented_redirect_uri: the ``redirect_uri`` from the authorization request to
      validate against the document's ``redirect_uris`` (R-23.4-j); skipped when
      None.

  Returns:
    The validated :class:`ClientIdMetadataDocument`.

  Raises:
    CIMDValidationError: the body is not valid/complete JSON (R-23.4-k), the
      ``client_id`` does not match the URL (R-23.4-i), or the presented redirect
      URI is not in ``redirect_uris`` (R-23.4-j).
  """
  document = parse_client_id_metadata_document(raw)  # R-23.4-k
  validate_client_id_metadata_document(document, client_id)  # R-23.4-i
  if presented_redirect_uri is not None:
    if presented_redirect_uri not in document.redirect_uris:
      raise CIMDValidationError(
        f"the authorization request's redirect_uri {presented_redirect_uri!r} is "
        f"not listed in the CIMD document's redirect_uris "
        f"{document.redirect_uris!r}; the authorization server MUST validate it "
        f"(R-23.4-j)"
      )
  return document


# ---------------------------------------------------------------------------
# §23.4  Dynamic Client Registration (Deprecated)
# ---------------------------------------------------------------------------


class ApplicationType(enum.Enum):
  """The DCR ``application_type`` value required by MCP (R-23.4-m/n/o).

  When using DCR the client MUST specify an appropriate ``application_type``
  (R-23.4-m). Native applications (desktop, mobile, CLI, localhost-hosted) SHOULD
  use ``"native"`` (R-23.4-n); remote browser-based applications served from a
  non-local host SHOULD use ``"web"`` (R-23.4-o).
  """

  NATIVE = "native"
  WEB = "web"


def application_type_for_client(*, is_native: bool) -> ApplicationType:
  """Choose the DCR ``application_type`` for a client (R-23.4-n/o).

  Native applications — desktop, mobile, CLI tools, and locally-hosted apps
  accessed via ``localhost`` — SHOULD register ``application_type: "native"``
  (R-23.4-n); remote browser-based apps served from a non-local host SHOULD
  register ``application_type: "web"`` (R-23.4-o).

  Args:
    is_native: True for a native client (desktop/mobile/CLI/localhost).

  Returns:
    :data:`ApplicationType.NATIVE` for a native client, else
    :data:`ApplicationType.WEB`.
  """
  return ApplicationType.NATIVE if is_native else ApplicationType.WEB


@dataclass(frozen=True)
class DynamicClientRegistrationRequest:
  """A Dynamic Client Registration request body (Deprecated) (§23.4, R-23.4-m).

  The body POSTed to a ``registration_endpoint`` to obtain client credentials.
  MCP requires an ``application_type`` (R-23.4-m).

  Fields:
    redirect_uris: allowed redirection URIs; REQUIRED.
    application_type: ``native`` or ``web``; REQUIRED per MCP (R-23.4-m).
    client_name: OPTIONAL human-readable name.
    grant_types: OPTIONAL requested grant types.
    response_types: OPTIONAL requested response types.
    token_endpoint_auth_method: OPTIONAL token-endpoint auth method.
    scope: OPTIONAL space-delimited scopes.
  """

  redirect_uris: list[str]
  application_type: ApplicationType
  client_name: str | None = None
  grant_types: list[str] | None = None
  response_types: list[str] | None = None
  token_endpoint_auth_method: str | None = None
  scope: str | None = None

  def to_body(self) -> dict[str, Any]:
    """Render the registration request as a JSON-serialisable body (R-23.4-m).

    The ``application_type`` is always present (R-23.4-m); optional fields are
    included only when set.
    """
    body: dict[str, Any] = {
      "redirect_uris": list(self.redirect_uris),
      "application_type": self.application_type.value,
    }
    if self.client_name is not None:
      body["client_name"] = self.client_name
    if self.grant_types is not None:
      body["grant_types"] = list(self.grant_types)
    if self.response_types is not None:
      body["response_types"] = list(self.response_types)
    if self.token_endpoint_auth_method is not None:
      body["token_endpoint_auth_method"] = self.token_endpoint_auth_method
    if self.scope is not None:
      body["scope"] = self.scope
    return body


def build_dcr_request(
  redirect_uris: list[str],
  *,
  is_native: bool,
  client_name: str | None = None,
  grant_types: list[str] | None = None,
  response_types: list[str] | None = None,
  token_endpoint_auth_method: str | None = None,
  scope: str | None = None,
) -> DynamicClientRegistrationRequest:
  """Build a DCR registration request with an appropriate ``application_type`` (R-23.4-m/n/o).

  The client MUST specify an appropriate ``application_type`` during registration
  (R-23.4-m); it is derived from ``is_native`` per
  :func:`application_type_for_client` (R-23.4-n/o).

  Args:
    redirect_uris: the client's allowed redirection URIs.
    is_native: True for a native client (chooses ``"native"``).
    client_name: OPTIONAL human-readable name.
    grant_types: OPTIONAL requested grant types (e.g. include ``"refresh_token"``
      for refresh capability, R-23.9-a).
    response_types: OPTIONAL requested response types.
    token_endpoint_auth_method: OPTIONAL token-endpoint auth method.
    scope: OPTIONAL space-delimited scopes.

  Returns:
    The :class:`DynamicClientRegistrationRequest`.
  """
  return DynamicClientRegistrationRequest(
    redirect_uris=list(redirect_uris),
    application_type=application_type_for_client(is_native=is_native),
    client_name=client_name,
    grant_types=grant_types,
    response_types=response_types,
    token_endpoint_auth_method=token_endpoint_auth_method,
    scope=scope,
  )


@dataclass(frozen=True)
class DynamicClientRegistrationResponse:
  """A Dynamic Client Registration response (Deprecated) (§23.4).

  Fields:
    client_id: the issued client identifier; REQUIRED.
    client_secret: the issued secret, for a confidential client only; OPTIONAL.
  """

  client_id: str
  client_secret: str | None = None


class DCRRegistrationError(Exception):
  """A Dynamic Client Registration attempt failed (R-23.4-p/q).

  The client MUST be prepared to handle registration failures arising from
  redirect-URI constraints (R-23.4-p) and SHOULD surface a meaningful error on
  rejection (R-23.4-q). This carries the surfaced reason and whether the failure
  is recoverable by retrying with an adjusted ``application_type`` or conforming
  redirect URIs (R-23.4-r).

  Attributes:
    reason: a human-readable description of the rejection (R-23.4-q).
    recoverable: True when a retry with an adjusted request may succeed (R-23.4-r).
  """

  def __init__(self, reason: str, *, recoverable: bool = False) -> None:
    super().__init__(reason)
    self.reason: str = reason
    self.recoverable: bool = recoverable


def parse_dcr_response(raw: Any) -> DynamicClientRegistrationResponse:
  """Parse a DCR response, surfacing failures as errors (R-23.4-p/q).

  On success the body includes a ``client_id`` (and, for confidential clients, a
  ``client_secret``). The client MUST handle registration failures arising from
  redirect-URI constraints (R-23.4-p) and SHOULD surface a meaningful error on
  rejection (R-23.4-q): an ``error`` body is turned into a
  :class:`DCRRegistrationError` carrying the server's ``error_description``. An
  ``invalid_redirect_uri`` error is marked recoverable so the client MAY retry
  (R-23.4-r).

  Args:
    raw: the JSON-decoded registration response.

  Returns:
    The parsed :class:`DynamicClientRegistrationResponse` on success.

  Raises:
    DCRRegistrationError: the response is an error body, or lacks ``client_id``
      (R-23.4-p/q).
  """
  if not isinstance(raw, dict):
    raise DCRRegistrationError(
      f"DCR response must be a JSON object; got {type(raw).__name__}"
    )
  error = raw.get("error")
  if error is not None:
    description = raw.get("error_description") or str(error)
    recoverable = error == "invalid_redirect_uri"
    raise DCRRegistrationError(
      f"dynamic client registration was rejected: {description} "
      f"(error={error!r}) (R-23.4-q)",
      recoverable=recoverable,
    )
  client_id = raw.get("client_id")
  if not isinstance(client_id, str) or not client_id:
    raise DCRRegistrationError(
      "a successful DCR response MUST include a 'client_id'; it is missing "
      "(R-23.4-p/q)"
    )
  client_secret = raw.get("client_secret")
  if client_secret is not None and not isinstance(client_secret, str):
    raise DCRRegistrationError("DCR client_secret, when present, must be a string")
  return DynamicClientRegistrationResponse(
    client_id=client_id, client_secret=client_secret
  )


def retry_dcr_with_adjustment(
  request: DynamicClientRegistrationRequest,
  error: DCRRegistrationError,
  *,
  adjusted_application_type: ApplicationType | None = None,
  conforming_redirect_uris: list[str] | None = None,
) -> DynamicClientRegistrationRequest:
  """Build an adjusted DCR request after a recoverable rejection (R-23.4-r).

  On a recoverable rejection the client MAY retry registration with an adjusted
  ``application_type`` or conforming redirect URIs (R-23.4-r). This returns a new
  request with the supplied adjustments applied; at least one adjustment is
  required, and the original ``error`` must be recoverable.

  Args:
    request: the rejected request to base the retry on.
    error: the recoverable :class:`DCRRegistrationError` that prompted the retry.
    adjusted_application_type: a different ``application_type`` to try.
    conforming_redirect_uris: redirect URIs that conform to the server's
      constraints.

  Returns:
    A new :class:`DynamicClientRegistrationRequest` with the adjustments applied.

  Raises:
    DCRRegistrationError: the ``error`` is not recoverable (R-23.4-p/q).
    ValueError: no adjustment was supplied.
  """
  if not error.recoverable:
    raise DCRRegistrationError(
      f"the registration error is not recoverable; cannot retry: {error.reason} "
      f"(R-23.4-p)",
      recoverable=False,
    )
  if adjusted_application_type is None and conforming_redirect_uris is None:
    raise ValueError(
      "a DCR retry MUST adjust the application_type or use conforming redirect "
      "URIs (R-23.4-r)"
    )
  return DynamicClientRegistrationRequest(
    redirect_uris=(
      list(conforming_redirect_uris)
      if conforming_redirect_uris is not None
      else list(request.redirect_uris)
    ),
    application_type=adjusted_application_type or request.application_type,
    client_name=request.client_name,
    grant_types=request.grant_types,
    response_types=request.response_types,
    token_endpoint_auth_method=request.token_endpoint_auth_method,
    scope=request.scope,
  )


@dataclass
class _DCRRecord:
  """One persisted DCR credential keyed by its issuing AS ``issuer`` (R-23.4-s)."""

  issuer: str
  response: DynamicClientRegistrationResponse


class DCRCredentialStore:
  """Persisted DCR credentials, keyed by the issuing AS ``issuer`` (R-23.4-s/t).

  A client that persists credentials obtained via Dynamic Client Registration MUST
  associate them with the issuing authorization server, keyed by that
  authorization server's ``issuer`` (R-23.4-s), and MUST re-register when the
  authorization server changes (R-23.4-t). ``get`` returns credentials ONLY for
  the requested issuer, and :meth:`must_reregister` reports when no credentials
  exist for the indicated issuer.
  """

  def __init__(self) -> None:
    self._by_issuer: dict[str, _DCRRecord] = {}

  def store(self, issuer: str, response: DynamicClientRegistrationResponse) -> None:
    """Persist DCR credentials under their issuing AS ``issuer`` (R-23.4-s)."""
    self._by_issuer[issuer] = _DCRRecord(issuer=issuer, response=response)

  def get(self, issuer: str) -> DynamicClientRegistrationResponse | None:
    """Return the DCR credentials registered with ``issuer`` only (R-23.4-s)."""
    record = self._by_issuer.get(issuer)
    return record.response if record is not None else None

  def must_reregister(self, indicated_issuer: str) -> bool:
    """Return True iff the client MUST re-register for ``indicated_issuer`` (R-23.4-t).

    When the authorization server changes (no credentials are held for the
    indicated issuer), the client MUST re-register (R-23.4-t).
    """
    return indicated_issuer not in self._by_issuer


# ===========================================================================
# §23.5  The authorization-code flow with PKCE
# ===========================================================================

#: The PKCE code-challenge method REQUIRED for this flow (R-23.5-a/i). Aliases the
#: S35 constant so callers of this module need not import from two places.
PKCE_CODE_CHALLENGE_METHOD: str = REQUIRED_CODE_CHALLENGE_METHOD  # "S256"

#: The ``response_type`` value the authorization request MUST use (R-23.5-d).
RESPONSE_TYPE_CODE: str = REQUIRED_RESPONSE_TYPE  # "code"

#: The number of random bytes used for a ``code_verifier`` (32 bytes → 43
#: base64url characters, comfortably within RFC 7636's 43..128 range).
_CODE_VERIFIER_BYTES: int = 32
#: The number of random bytes used for a ``state`` value (high entropy, opaque).
_STATE_BYTES: int = 32


def _base64url_no_pad(data: bytes) -> str:
  """Return the base64url encoding of ``data`` with padding stripped (RFC 7636)."""
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_code_verifier() -> str:
  """Generate a high-entropy PKCE ``code_verifier`` (R-23.5-b).

  The client generates a high-entropy ``code_verifier`` (R-23.5-b). This draws 32
  cryptographically secure random bytes (via :mod:`secrets`) and base64url-encodes
  them without padding, yielding a 43-character verifier from the RFC 7636
  unreserved ``[A-Za-z0-9-._~]`` alphabet (here the ``-`` and ``_`` subset).

  Returns:
    A fresh, high-entropy ``code_verifier`` string.
  """
  return _base64url_no_pad(secrets.token_bytes(_CODE_VERIFIER_BYTES))


def derive_code_challenge(code_verifier: str) -> str:
  """Derive the S256 ``code_challenge`` from a ``code_verifier`` (R-23.5-a/b).

  PKCE is REQUIRED for this flow with the ``S256`` method (R-23.5-a); the challenge
  is ``code_challenge = BASE64URL(SHA-256(code_verifier))`` (R-23.5-b). The SHA-256
  digest is computed over the ASCII bytes of the verifier and base64url-encoded
  without padding.

  Args:
    code_verifier: the PKCE verifier to hash.

  Returns:
    The base64url-encoded, unpadded SHA-256 ``code_challenge``.
  """
  digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
  return _base64url_no_pad(digest)


@dataclass(frozen=True)
class PKCEParameters:
  """A PKCE ``code_verifier``/``code_challenge`` pair using S256 (R-23.5-a/b).

  Fields:
    code_verifier: the high-entropy verifier (kept secret until the token request).
    code_challenge: ``BASE64URL(SHA-256(code_verifier))``.
    code_challenge_method: always ``"S256"`` (R-23.5-a/i).
  """

  code_verifier: str
  code_challenge: str
  code_challenge_method: str = PKCE_CODE_CHALLENGE_METHOD


def generate_pkce_parameters() -> PKCEParameters:
  """Generate a fresh S256 PKCE parameter set for Step 1 (R-23.5-a/b).

  Generates a high-entropy ``code_verifier`` (R-23.5-b) and derives its S256
  ``code_challenge`` (R-23.5-a/b), with ``code_challenge_method`` fixed to
  ``"S256"`` (R-23.5-i).

  Returns:
    A :class:`PKCEParameters` carrying the verifier, challenge, and method.
  """
  verifier = generate_code_verifier()
  return PKCEParameters(
    code_verifier=verifier,
    code_challenge=derive_code_challenge(verifier),
    code_challenge_method=PKCE_CODE_CHALLENGE_METHOD,
  )


def generate_state() -> str:
  """Generate an opaque, unguessable ``state`` value (R-23.5-g).

  The client SHOULD include an opaque, unguessable ``state`` value binding the
  authorization request to the user-agent session (R-23.5-g). This draws 32
  cryptographically secure random bytes and base64url-encodes them.

  Returns:
    A fresh, high-entropy opaque ``state`` string.
  """
  return _base64url_no_pad(secrets.token_bytes(_STATE_BYTES))


# ---------------------------------------------------------------------------
# §23.5  Step 1 — record per-request state (recorded issuer)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationRecord:
  """A per-request authorization record created in Step 1 (R-23.5-c).

  Client-side bookkeeping the client MUST create before redirecting, associating
  the ``code_verifier`` (and the ``state`` value, if used) with the ``issuer`` from
  the selected authorization server's validated metadata — the *recorded issuer*
  used for the §23.7 ``iss`` comparison (R-23.5-c).

  Fields:
    code_verifier: the high-entropy PKCE verifier this record is keyed to.
    recorded_issuer: the ``issuer`` from the selected AS's validated metadata,
      stored for the later ``iss`` comparison (R-23.5-c, §23.7).
    state: the ``state`` value sent, if any.
  """

  code_verifier: str
  recorded_issuer: str
  state: str | None = None


def record_authorization_request(
  pkce: PKCEParameters,
  authorization_server_metadata: AuthorizationServerMetadata,
  *,
  state: str | None = None,
) -> AuthorizationRecord:
  """Record the per-request state before redirecting — Step 1 (R-23.5-c).

  Before redirecting the user agent, the client MUST record, in a per-request
  record associated with the ``code_verifier`` (and the ``state`` value, if used),
  the ``issuer`` value from the *selected authorization server's validated
  metadata* (R-23.5-c). The recorded issuer is taken from
  ``authorization_server_metadata.issuer`` — the value S35 already validated
  against the discovery construction value — so it is the trustworthy issuer for
  the §23.7 comparison.

  Args:
    pkce: the Step-1 PKCE parameters (supplies the ``code_verifier`` key).
    authorization_server_metadata: the selected AS's validated metadata; its
      ``issuer`` becomes the recorded issuer.
    state: the ``state`` value being sent, if used.

  Returns:
    The :class:`AuthorizationRecord` to retain until the redirect is validated.
  """
  return AuthorizationRecord(
    code_verifier=pkce.code_verifier,
    recorded_issuer=authorization_server_metadata.issuer,
    state=state,
  )


# ---------------------------------------------------------------------------
# §23.5  Step 2 — build the authorization request
# ---------------------------------------------------------------------------


def select_request_scope(
  challenge: BearerChallenge | None,
  protected_resource_metadata: ProtectedResourceMetadata | None,
) -> str | None:
  """Select the authorization-request ``scope`` by the priority rule (R-23.5-f).

  The client SHOULD apply this priority (R-23.5-f): (1) use the ``scope`` from the
  ``WWW-Authenticate`` challenge if present; (2) otherwise use all scopes in
  ``scopes_supported`` from protected-resource metadata; (3) omit ``scope`` when
  ``scopes_supported`` is absent.

  Args:
    challenge: the parsed ``WWW-Authenticate`` challenge, if one was received.
    protected_resource_metadata: the MCP server's protected-resource metadata.

  Returns:
    The space-delimited ``scope`` string to send, or None to omit ``scope``.
  """
  if challenge is not None and challenge.scope:
    return challenge.scope  # (1) challenge scope wins.
  if (
    protected_resource_metadata is not None
    and protected_resource_metadata.scopes_supported
  ):
    return " ".join(protected_resource_metadata.scopes_supported)  # (2)
  return None  # (3) scopes_supported absent → omit scope.


@dataclass(frozen=True)
class AuthorizationRequest:
  """The Step-2 authorization-request query parameters (§23.5, R-23.5-d..j).

  The query string directing the user agent to the AS's ``authorization_endpoint``.

  Fields:
    response_type: MUST be ``"code"`` (R-23.5-d).
    client_id: the client identifier obtained during registration.
    redirect_uri: MUST match one registered for the client (R-23.5-e).
    code_challenge: the PKCE challenge from Step 1 (R-23.5-b).
    code_challenge_method: MUST be ``"S256"`` (R-23.5-i).
    resource: the MCP server's canonical resource identifier; MUST be included
      (R-23.5-j, R-23.6-b).
    scope: the requested scopes per the scope-priority rule; omitted when no
      source is available (R-23.5-f).
    state: an opaque, unguessable session-binding value; SHOULD be present
      (R-23.5-g).
  """

  response_type: str
  client_id: str
  redirect_uri: str
  code_challenge: str
  code_challenge_method: str
  resource: str
  scope: str | None = None
  state: str | None = None

  def to_query_parameters(self) -> dict[str, str]:
    """Return the ordered authorization-request query parameters (R-23.5-d..j).

    Parameter order follows the §23.10 worked example: ``response_type``,
    ``client_id``, ``redirect_uri``, ``scope``, ``state``, ``code_challenge``,
    ``code_challenge_method``, ``resource``. Optional ``scope``/``state`` are
    emitted only when present.
    """
    params: dict[str, str] = {
      "response_type": self.response_type,
      "client_id": self.client_id,
      "redirect_uri": self.redirect_uri,
    }
    if self.scope is not None:
      params["scope"] = self.scope
    if self.state is not None:
      params["state"] = self.state
    params["code_challenge"] = self.code_challenge
    params["code_challenge_method"] = self.code_challenge_method
    params["resource"] = self.resource
    return params


def build_authorization_request(
  *,
  client_id: str,
  redirect_uri: str,
  resource: str,
  pkce: PKCEParameters,
  scope: str | None = None,
  state: str | None = None,
) -> AuthorizationRequest:
  """Build the Step-2 authorization request (§23.5, R-23.5-d/e/i/j).

  Sets ``response_type=code`` (R-23.5-d), carries the caller's ``redirect_uri``
  (which MUST match one registered for the client, R-23.5-e), uses the PKCE
  ``code_challenge`` with ``code_challenge_method=S256`` (R-23.5-b/i), and includes
  the ``resource`` parameter — the MCP server's canonical resource identifier —
  which MUST be present (R-23.5-j, R-23.6-b). ``scope`` is included only when
  supplied (use :func:`select_request_scope`), and an opaque ``state`` SHOULD be
  included (R-23.5-g).

  Args:
    client_id: the client identifier from registration.
    redirect_uri: the redirection URI; MUST be one registered for the client
      (R-23.5-e).
    resource: the MCP server's canonical resource identifier (R-23.5-j).
    pkce: the Step-1 PKCE parameters supplying ``code_challenge``/method.
    scope: the selected ``scope``, or None to omit it (R-23.5-f).
    state: the opaque ``state`` value, SHOULD be present (R-23.5-g).

  Returns:
    The :class:`AuthorizationRequest`.

  Raises:
    ValueError: ``resource`` is empty — it MUST be included (R-23.5-j/R-23.6-b).
  """
  if not resource:
    raise ValueError(
      "the authorization request MUST include a non-empty 'resource' parameter "
      "(the MCP server's canonical resource identifier) (R-23.5-j/R-23.6-b)"
    )
  return AuthorizationRequest(
    response_type=RESPONSE_TYPE_CODE,
    client_id=client_id,
    redirect_uri=redirect_uri,
    code_challenge=pkce.code_challenge,
    code_challenge_method=pkce.code_challenge_method,
    resource=resource,
    scope=scope,
    state=state,
  )


def build_authorization_request_url(
  authorization_endpoint: str,
  request: AuthorizationRequest,
) -> str:
  """Render the full authorization-request URL for the redirect (§23.5/§23.10).

  Appends the URL-encoded :meth:`AuthorizationRequest.to_query_parameters` to the
  authorization endpoint, producing the Step-2 redirect URL shown in §23.10. The
  query is percent-encoded with :func:`urllib.parse.urlencode`.

  Args:
    authorization_endpoint: the AS ``authorization_endpoint`` URL.
    request: the built :class:`AuthorizationRequest`.

  Returns:
    The full ``authorization_endpoint?<encoded query>`` URL.
  """
  query = urlencode(request.to_query_parameters())
  separator = "&" if "?" in authorization_endpoint else "?"
  return f"{authorization_endpoint}{separator}{query}"


# ---------------------------------------------------------------------------
# §23.5  Step 3 — redirect handling
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationResponse:
  """The Step-3 authorization-response (redirect) parameters (§23.5, R-23.5-k).

  The decoded query parameters the authorization server returns on the redirect.

  Fields:
    code: the authorization code to redeem; present on success.
    state: the echo of the request ``state``; the client verifies it (R-23.5-h/l).
    iss: the issuer identifier of the authorization server; SHOULD be present and
      is validated per §23.7 (R-23.5-k, §23.7).
    error: the error code on an error response.
    error_description: OPTIONAL human-readable error description.
    error_uri: OPTIONAL error URI.
  """

  code: str | None = None
  state: str | None = None
  iss: str | None = None
  error: str | None = None
  error_description: str | None = None
  error_uri: str | None = None

  @property
  def is_error(self) -> bool:
    """Return True iff this is an error authorization response."""
    return self.error is not None


def parse_authorization_response(
  redirect: str | dict[str, str],
) -> AuthorizationResponse:
  """Parse a Step-3 redirect into an :class:`AuthorizationResponse` (§23.5, R-23.7-g).

  Accepts either the raw redirect URL/query string or an already-decoded mapping.
  When a URL/query string is given, the ``application/x-www-form-urlencoded`` query
  is decoded WITHOUT applying any further normalization, so the ``iss`` value is
  preserved byte-for-byte for the exact-string comparison required by §23.7
  (R-23.7-g).

  Args:
    redirect: the redirect URL, its raw query string, or a decoded ``{key: value}``
      mapping.

  Returns:
    The parsed :class:`AuthorizationResponse`.
  """
  if isinstance(redirect, dict):
    fields = dict(redirect)
  else:
    query = redirect.split("?", 1)[1] if "?" in redirect else redirect
    # keep_blank_values so an explicitly empty parameter is preserved; no
    # additional decoding/normalization beyond the standard form-urlencoded
    # percent-decoding (R-23.7-g).
    fields = dict(parse_qsl(query, keep_blank_values=True))
  return AuthorizationResponse(
    code=fields.get("code"),
    state=fields.get("state"),
    iss=fields.get("iss"),
    error=fields.get("error"),
    error_description=fields.get("error_description"),
    error_uri=fields.get("error_uri"),
  )


class StateMismatchError(ValueError):
  """The redirect ``state`` does not match the value the client sent (R-23.5-h/l).

  Raised by :func:`verify_state` / :func:`validate_redirect` when the ``state``
  returned on the redirect is not identical to the ``state`` recorded in Step 1.
  The client MUST verify ``state`` and MUST confirm it matches before redeeming
  the code (R-23.5-h/l).
  """


def verify_state(record: AuthorizationRecord, response: AuthorizationResponse) -> None:
  """Verify the redirect ``state`` against the recorded value (R-23.5-h/l).

  When a ``state`` value was sent, the client MUST verify the returned ``state``
  (R-23.5-h) and MUST confirm it matches the value it sent before redeeming the
  code (R-23.5-l). The comparison is exact. When no ``state`` was sent, there is
  nothing to verify.

  Args:
    record: the per-request record carrying the sent ``state`` (if any).
    response: the parsed authorization response.

  Raises:
    StateMismatchError: a ``state`` was sent and the returned ``state`` differs or
      is absent (R-23.5-h/l).
  """
  if record.state is None:
    return
  if response.state != record.state:
    raise StateMismatchError(
      f"authorization-response state {response.state!r} does not match the state "
      f"{record.state!r} the client sent; the code MUST NOT be redeemed "
      f"(R-23.5-h/l)"
    )


# ===========================================================================
# §23.7  Issuer identification
# ===========================================================================


class IssValidationAction(enum.Enum):
  """The client action selected by the §23.7 ``iss``-validation table (R-23.7-d).

  COMPARE:
    Compare the present ``iss`` to the recorded issuer by exact string comparison.
  REJECT:
    Reject the response (``..._supported`` true but ``iss`` absent) (R-23.7-e).
  PROCEED:
    Proceed without an ``iss`` comparison (``..._supported`` false/absent and
    ``iss`` absent).
  """

  COMPARE = "compare"
  REJECT = "reject"
  PROCEED = "proceed"


class IssValidationError(ValueError):
  """``iss`` identification failed per §23.7 (R-23.7-a/d/e/g).

  Raised by :func:`validate_iss` when the authorization-response ``iss`` is absent
  although the AS advertises ``authorization_response_iss_parameter_supported:
  true`` (R-23.7-e), or when a present ``iss`` does not exactly match the recorded
  issuer (R-23.7-a/d/g). A mismatch means the authorization code MUST NOT be sent
  to any token endpoint, and an error response MUST NOT be acted on (R-23.7-a/h).
  """


def iss_validation_action(
  *,
  iss_parameter_supported: bool | None,
  iss_present: bool,
) -> IssValidationAction:
  """Select the client action from the four-row §23.7 table (R-23.7-d/e/f).

  Applies the decision table (R-23.7-d), using the recorded issuer for the
  comparison:

    - ``..._supported`` true  + ``iss`` present → COMPARE.
    - ``..._supported`` true  + ``iss`` absent  → REJECT (R-23.7-e).
    - ``..._supported`` false/absent + ``iss`` present → COMPARE (R-23.7-f).
    - ``..._supported`` false/absent + ``iss`` absent  → PROCEED.

  The third row is the local-policy provision: a client MUST compare a present
  ``iss`` regardless of whether the AS advertises support (R-23.7-f).

  Args:
    iss_parameter_supported: the AS's
      ``authorization_response_iss_parameter_supported`` (None when absent).
    iss_present: whether the authorization response carried an ``iss`` parameter.

  Returns:
    The :class:`IssValidationAction` to take.
  """
  supported = iss_parameter_supported is True
  if supported and iss_present:
    return IssValidationAction.COMPARE
  if supported and not iss_present:
    return IssValidationAction.REJECT  # R-23.7-e
  if not supported and iss_present:
    return IssValidationAction.COMPARE  # R-23.7-f local-policy provision
  return IssValidationAction.PROCEED


def validate_iss(
  record: AuthorizationRecord,
  response: AuthorizationResponse,
  *,
  iss_parameter_supported: bool | None,
) -> None:
  """Validate the authorization-response ``iss`` per §23.7 (R-23.7-a/d/e/f/g).

  To defend against authorization-server mix-up attacks, the client MUST validate
  the ``iss`` parameter against the recorded issuer BEFORE transmitting the
  authorization code to any token endpoint (R-23.7-a). The action is chosen by the
  §23.7 table (R-23.7-d): a missing ``iss`` when the AS advertises support is
  rejected (R-23.7-e); a present ``iss`` is always compared, advertised or not
  (R-23.7-f). The comparison is an EXACT string match — after form-urlencoded
  decoding the client MUST NOT apply scheme/host case folding, default-port
  elision, trailing-slash, or percent-encoding normalization (R-23.7-g).

  Args:
    record: the per-request record carrying the recorded issuer.
    response: the parsed authorization response (its ``iss`` is already decoded).
    iss_parameter_supported: the AS's
      ``authorization_response_iss_parameter_supported`` flag.

  Raises:
    IssValidationError: ``iss`` is absent when REQUIRED (R-23.7-e), or a present
      ``iss`` does not exactly equal the recorded issuer (R-23.7-a/d/g).
  """
  action = iss_validation_action(
    iss_parameter_supported=iss_parameter_supported,
    iss_present=response.iss is not None,
  )
  if action is IssValidationAction.PROCEED:
    return
  if action is IssValidationAction.REJECT:
    raise IssValidationError(
      "the authorization server advertises "
      "authorization_response_iss_parameter_supported=true but the authorization "
      "response carried no 'iss' parameter; the response MUST be rejected "
      "(R-23.7-e)"
    )
  # COMPARE: exact string match, NO normalization (R-23.7-g).
  if response.iss != record.recorded_issuer:
    raise IssValidationError(
      f"authorization-response iss {response.iss!r} does not exactly match the "
      f"recorded issuer {record.recorded_issuer!r} (exact string comparison, no "
      f"normalization); the code MUST NOT be sent to any token endpoint "
      f"(R-23.7-a/d/g)"
    )


def error_response_is_actionable(
  record: AuthorizationRecord,
  response: AuthorizationResponse,
  *,
  iss_parameter_supported: bool | None,
) -> bool:
  """Return True iff an error authorization response may be acted on (R-23.7-h).

  ``iss`` validation applies equally to error responses: on an ``iss`` mismatch
  the client MUST NOT act on or display ``error``, ``error_description``, or
  ``error_uri`` (R-23.7-h). This runs :func:`validate_iss`; if validation fails the
  error is NOT actionable (returns False), otherwise the error may be surfaced
  (returns True).

  Args:
    record: the per-request record carrying the recorded issuer.
    response: the (error) authorization response.
    iss_parameter_supported: the AS's
      ``authorization_response_iss_parameter_supported`` flag.

  Returns:
    True when ``iss`` validation passes and the error may be displayed; False when
    it fails and the error MUST be suppressed (R-23.7-h).
  """
  try:
    validate_iss(record, response, iss_parameter_supported=iss_parameter_supported)
  except IssValidationError:
    return False  # R-23.7-h: suppress error/error_description/error_uri.
  return True


def validate_redirect(
  record: AuthorizationRecord,
  response: AuthorizationResponse,
  *,
  iss_parameter_supported: bool | None,
) -> str:
  """Validate the Step-3 redirect and return the code to redeem (R-23.5-h/l/m).

  Before redeeming the code the client MUST verify that ``state`` matches the value
  it sent (R-23.5-h/l) and MUST validate ``iss`` per §23.7 (R-23.5-m). On a
  successful, non-error response both checks pass and the authorization ``code`` is
  returned for the Step-4 token request; only then may the code be transmitted to
  the token endpoint (R-23.7-a).

  Args:
    record: the per-request record from Step 1.
    response: the parsed authorization response.
    iss_parameter_supported: the selected AS's
      ``authorization_response_iss_parameter_supported`` flag.

  Returns:
    The authorization ``code`` to redeem.

  Raises:
    StateMismatchError: the ``state`` does not match (R-23.5-h/l).
    IssValidationError: ``iss`` validation fails (R-23.5-m, §23.7).
    ValueError: the response is an error response, or lacks a ``code``.
  """
  verify_state(record, response)  # R-23.5-h/l (before redeeming).
  validate_iss(  # R-23.5-m / §23.7 (before redeeming).
    record, response, iss_parameter_supported=iss_parameter_supported
  )
  if response.is_error:
    raise ValueError(
      f"authorization response is an error response (error={response.error!r}); "
      f"there is no code to redeem"
    )
  if not response.code:
    raise ValueError(
      "authorization response carries no 'code'; nothing to redeem (§23.5 Step 3)"
    )
  return response.code


# ===========================================================================
# §23.5/§23.6/§23.9  Token requests
# ===========================================================================

#: The Resource Indicators (RFC 8707) ``resource`` parameter name (R-23.6-a).
RESOURCE_PARAMETER: str = "resource"
#: The ``grant_type`` value for the initial authorization-code exchange (R-23.5-n).
GRANT_TYPE_AUTHORIZATION_CODE: str = "authorization_code"
#: The ``grant_type`` value for a refresh-token exchange (R-23.9-e).
GRANT_TYPE_REFRESH_TOKEN: str = "refresh_token"


@dataclass(frozen=True)
class TokenRequest:
  """A token-request body for either grant (§23.5 Step 4 / §23.9, R-23.5-n..p).

  The ``application/x-www-form-urlencoded`` body POSTed to ``token_endpoint``.

  Fields:
    grant_type: ``"authorization_code"`` (initial, R-23.5-n) or
      ``"refresh_token"`` (refresh, R-23.9-e).
    client_id: the client identifier; REQUIRED.
    resource: the MCP server's canonical resource identifier; REQUIRED and, for
      the auth-code grant, identical to the Step-2 value (R-23.5-p, R-23.6-b).
    code: the authorization code (auth-code grant); MUST be present then
      (R-23.5-n).
    redirect_uri: identical to the Step-2 ``redirect_uri`` (auth-code grant)
      (R-23.5-o).
    code_verifier: the PKCE verifier matching the Step-2 ``code_challenge``
      (auth-code grant).
    refresh_token: the refresh token being exchanged (refresh grant) (R-23.9-e).
    scope: OPTIONAL; present to narrow requested scopes on a refresh (R-23.9-f).
  """

  grant_type: str
  client_id: str
  resource: str
  code: str | None = None
  redirect_uri: str | None = None
  code_verifier: str | None = None
  refresh_token: str | None = None
  scope: str | None = None

  def to_form_fields(self) -> dict[str, str]:
    """Return the form fields for this token request (R-23.5-n..p / R-23.9-e/f).

    Only the fields relevant to the grant are emitted. ``resource`` is always
    present (R-23.6-b); for the auth-code grant ``code``, ``redirect_uri``, and
    ``code_verifier`` are present (R-23.5-n/o); for the refresh grant
    ``refresh_token`` is present (R-23.9-e) and ``scope`` MAY be present (R-23.9-f).
    """
    fields: dict[str, str] = {
      "grant_type": self.grant_type,
      "client_id": self.client_id,
    }
    if self.code is not None:
      fields["code"] = self.code
    if self.redirect_uri is not None:
      fields["redirect_uri"] = self.redirect_uri
    if self.code_verifier is not None:
      fields["code_verifier"] = self.code_verifier
    if self.refresh_token is not None:
      fields["refresh_token"] = self.refresh_token
    if self.scope is not None:
      fields["scope"] = self.scope
    fields[RESOURCE_PARAMETER] = self.resource
    return fields


def build_token_request(
  *,
  client_id: str,
  authorization_request: AuthorizationRequest,
  code: str,
  code_verifier: str,
) -> TokenRequest:
  """Build the Step-4 authorization-code token request (§23.5, R-23.5-n/o/p).

  Sets ``grant_type=authorization_code`` (R-23.5-n), carries the redeemed ``code``
  and the PKCE ``code_verifier``, sets ``redirect_uri`` identical to the value sent
  in Step 2 (R-23.5-o), and sets ``resource`` identical to the Step-2 value so the
  token stays audience-bound (R-23.5-p, R-23.6-b). Deriving ``redirect_uri`` and
  ``resource`` from the originating :class:`AuthorizationRequest` makes the
  "identical to Step 2" guarantee structural.

  Args:
    client_id: the client identifier.
    authorization_request: the Step-2 request, supplying the identical
      ``redirect_uri`` and ``resource`` (R-23.5-o/p).
    code: the authorization code from Step 3.
    code_verifier: the PKCE verifier from Step 1.

  Returns:
    The :class:`TokenRequest` for the token endpoint.
  """
  return TokenRequest(
    grant_type=GRANT_TYPE_AUTHORIZATION_CODE,
    client_id=client_id,
    resource=authorization_request.resource,  # identical to Step 2 (R-23.5-p)
    code=code,
    redirect_uri=authorization_request.redirect_uri,  # identical to Step 2 (R-23.5-o)
    code_verifier=code_verifier,
  )


def encode_token_request_body(request: TokenRequest) -> str:
  """Encode a token request as an ``application/x-www-form-urlencoded`` body (§23.10).

  Renders :meth:`TokenRequest.to_form_fields` with
  :func:`urllib.parse.urlencode`, producing the body shown in the §23.10 worked
  examples (with the URL-encoded ``resource``).

  Args:
    request: the token request to encode.

  Returns:
    The form-encoded request body string.
  """
  return urlencode(request.to_form_fields())


# ---------------------------------------------------------------------------
# §23.5  Token response
# ---------------------------------------------------------------------------

#: The ``token_type`` value the token response carries for a bearer token.
TOKEN_TYPE_BEARER: str = "Bearer"


@dataclass(frozen=True)
class TokenResponse:
  """A token-endpoint JSON response (§23.5, §23.10).

  Fields:
    access_token: the opaque bearer token; REQUIRED.
    token_type: the token type; ``"Bearer"`` (REQUIRED).
    expires_in: OPTIONAL lifetime in seconds.
    refresh_token: OPTIONAL refresh token, issued at the AS's discretion
      (R-23.9-d).
    scope: OPTIONAL granted scopes.
  """

  access_token: str
  token_type: str
  expires_in: int | None = None
  refresh_token: str | None = None
  scope: str | None = None

  @property
  def has_refresh_token(self) -> bool:
    """Return True iff a refresh token was issued (R-23.9-d).

    A client MUST NOT assume a refresh token will be issued (R-23.9-d); this lets
    a caller check rather than assume.
    """
    return self.refresh_token is not None


def parse_token_response(raw: Any) -> TokenResponse:
  """Parse/validate a token-endpoint JSON response (§23.5, R-23.9-d).

  ``access_token`` and ``token_type`` are REQUIRED. ``refresh_token`` is OPTIONAL —
  the client MUST NOT assume one is issued (R-23.9-d) — and is simply absent when
  the AS does not return one.

  Args:
    raw: the JSON-decoded token response.

  Returns:
    The validated :class:`TokenResponse`.

  Raises:
    TypeError: ``raw`` or a field has the wrong type.
    ValueError: a REQUIRED field is missing.
  """
  if not isinstance(raw, dict):
    raise TypeError(f"token response must be a JSON object; got {type(raw).__name__}")
  access_token = raw.get("access_token")
  if access_token is None:
    raise ValueError("token response is missing the REQUIRED 'access_token' field")
  if not isinstance(access_token, str):
    raise TypeError(
      f"token response access_token must be a string; got "
      f"{type(access_token).__name__}"
    )
  token_type = raw.get("token_type")
  if token_type is None:
    raise ValueError("token response is missing the REQUIRED 'token_type' field")
  if not isinstance(token_type, str):
    raise TypeError(
      f"token response token_type must be a string; got {type(token_type).__name__}"
    )
  expires_in = raw.get("expires_in")
  if expires_in is not None and (
    not isinstance(expires_in, int) or isinstance(expires_in, bool)
  ):
    raise TypeError(
      f"token response expires_in must be an integer; got "
      f"{type(expires_in).__name__}"
    )
  refresh_token = raw.get("refresh_token")
  if refresh_token is not None and not isinstance(refresh_token, str):
    raise TypeError("token response refresh_token, when present, must be a string")
  scope = raw.get("scope")
  if scope is not None and not isinstance(scope, str):
    raise TypeError("token response scope, when present, must be a string")
  return TokenResponse(
    access_token=access_token,
    token_type=token_type,
    expires_in=expires_in,
    refresh_token=refresh_token,
    scope=scope,
  )


# ===========================================================================
# §23.6  Resource Indicators & audience binding
# ===========================================================================


def resource_indicator_for(canonical_resource_identifier: str) -> str:
  """Return the ``resource`` Resource Indicator for an MCP server (R-23.6-c/d).

  The ``resource`` parameter MUST identify the MCP server the client intends to use
  the token with (R-23.6-c) and MUST be that server's canonical resource
  identifier (R-23.6-d). The client passes the canonical resource identifier built
  in S35; this function makes that the explicit Resource Indicator value and
  rejects an empty value (the client MUST send ``resource``, R-23.6-b/e).

  Args:
    canonical_resource_identifier: the MCP server's canonical resource identifier.

  Returns:
    The ``resource`` parameter value.

  Raises:
    ValueError: the canonical resource identifier is empty (R-23.6-b/d).
  """
  if not canonical_resource_identifier:
    raise ValueError(
      "the 'resource' parameter MUST be the MCP server's non-empty canonical "
      "resource identifier (R-23.6-c/d)"
    )
  return canonical_resource_identifier


def authorization_and_token_resource_match(
  authorization_request: AuthorizationRequest,
  token_request: TokenRequest,
) -> bool:
  """Confirm both legs carry the same ``resource`` (R-23.6-b, R-23.5-p).

  The ``resource`` parameter MUST be included in BOTH the authorization request and
  the token request (R-23.6-b) and the token-request value MUST be identical to the
  Step-2 value (R-23.5-p). Returns True only when both carry a non-empty,
  byte-identical ``resource``.

  Args:
    authorization_request: the Step-2 authorization request.
    token_request: the Step-4 token request.

  Returns:
    True iff both carry the same non-empty ``resource`` value.
  """
  return bool(
    authorization_request.resource
    and authorization_request.resource == token_request.resource
  )


class AudienceMismatchError(ValueError):
  """A presented token's audience is not this MCP server (R-23.6-f/g).

  Raised by :func:`server_accepts_token` when a token's audience does not include
  the server's own canonical resource identifier. The MCP server MUST validate
  that a presented token was issued for it (R-23.6-f) and MUST reject tokens not
  intended for it (R-23.6-g).
  """


def token_is_audience_bound(token_audience: object, resource: str) -> bool:
  """Return True iff a token's audience includes ``resource`` (R-23.6-f).

  Audience binding: the token is issued for one specific MCP server, identified by
  its canonical resource identifier in the token's audience (R-23.6-f). The
  audience may be a single value or a collection; this returns True only when
  ``resource`` is among the token's audiences.

  Args:
    token_audience: the token's audience claim — a string or an iterable of
      strings.
    resource: the server's own canonical resource identifier.

  Returns:
    True iff ``resource`` is present in the token's audience.
  """
  if isinstance(token_audience, str):
    return token_audience == resource
  try:
    return resource in set(token_audience)
  except TypeError:
    return False


def server_accepts_token(token_audience: object, own_resource: str) -> bool:
  """Validate a presented token's audience on the MCP server (R-23.6-f/g/h).

  On every request the MCP server MUST validate that the token was issued
  specifically for it as the intended audience (R-23.6-f), MUST reject tokens not
  intended for it (R-23.6-g), and MUST only accept tokens valid for its own
  resources, never accepting or forwarding any other token (R-23.6-h). This
  returns True only when the token is audience-bound to ``own_resource``; it raises
  on a mismatch so a caller cannot silently forward a foreign token.

  Args:
    token_audience: the presented token's audience claim.
    own_resource: the server's own canonical resource identifier.

  Returns:
    True when the token is bound to this server's audience.

  Raises:
    AudienceMismatchError: the token is not bound to ``own_resource`` (R-23.6-g/h).
  """
  if not token_is_audience_bound(token_audience, own_resource):
    raise AudienceMismatchError(
      f"the presented token's audience {token_audience!r} does not include this "
      f"MCP server's canonical resource identifier {own_resource!r}; the server "
      f"MUST reject tokens not intended for it and MUST NOT accept or forward any "
      f"other token (R-23.6-g/h)"
    )
  return True


def client_may_send_token(token_audience: object, target_resource: str) -> bool:
  """Return True iff the client MAY send this token to ``target_resource`` (R-23.6-i).

  The client MUST NOT send the MCP server any token other than one issued by that
  server's authorization server for that server (R-23.6-i). A token may be sent
  only when its audience binds it to ``target_resource``.

  Args:
    token_audience: the token's audience claim.
    target_resource: the canonical resource identifier of the server being called.

  Returns:
    True iff the token is audience-bound to ``target_resource`` and so may be sent.
  """
  return token_is_audience_bound(token_audience, target_resource)


# ===========================================================================
# §23.8  Access-token usage
# ===========================================================================

#: The HTTP request header carrying the bearer access token (R-23.8-b).
AUTHORIZATION_HEADER: str = "Authorization"
#: The bearer scheme prefix used in the ``Authorization`` header (R-23.8-b).
AUTHORIZATION_BEARER_PREFIX: str = "Bearer"


class TokenInQueryStringError(ValueError):
  """An access token was placed in the URI query string (R-23.8-c).

  Raised by :func:`token_in_query_string` when a request URL carries an
  ``access_token`` query parameter; the access token MUST NOT be placed in the URI
  query string (R-23.8-c).
  """


def build_authorization_header(access_token: str) -> dict[str, str]:
  """Build the ``Authorization: Bearer <token>`` request header (R-23.8-a/b).

  Authorization MUST be included on every HTTP request from client to server
  (R-23.8-a). The client MUST use the HTTP ``Authorization`` request header with
  the ``Bearer`` scheme: ``Authorization: Bearer <access-token>`` (R-23.8-b). This
  returns that single-entry header mapping.

  Args:
    access_token: the bearer access token.

  Returns:
    ``{"Authorization": "Bearer <access_token>"}``.

  Raises:
    ValueError: ``access_token`` is empty.
  """
  if not access_token:
    raise ValueError(
      "the Authorization header MUST carry a non-empty bearer access token "
      "(R-23.8-b)"
    )
  return {AUTHORIZATION_HEADER: f"{AUTHORIZATION_BEARER_PREFIX} {access_token}"}


def token_in_query_string(request_url: str) -> bool:
  """Reject an access token in the URI query string (R-23.8-c).

  The access token MUST NOT be placed in the URI query string (R-23.8-c). This
  inspects the URL's query for an ``access_token`` parameter and raises if one is
  present; it returns False when the URL is clean.

  Args:
    request_url: the request URL to inspect.

  Returns:
    False when no ``access_token`` query parameter is present.

  Raises:
    TokenInQueryStringError: the URL carries an ``access_token`` query parameter
      (R-23.8-c).
  """
  query = urlsplit(request_url).query
  for key, _ in parse_qsl(query, keep_blank_values=True):
    if key == "access_token":
      raise TokenInQueryStringError(
        "the access token MUST NOT be placed in the URI query string; found an "
        "'access_token' query parameter (R-23.8-c)"
      )
  return False


class TokenValidationOutcome(enum.Enum):
  """The result of per-request server-side token validation (R-23.8-d/e/f).

  VALID:
    The token's signature/introspection, expiry, audience, and scope all satisfy
    the operation (R-23.8-d).
  UNAUTHORIZED:
    The token is missing, invalid, or expired → ``401 Unauthorized`` (R-23.8-e).
  INSUFFICIENT_SCOPE:
    The token is valid but lacks the required scope → ``403 Forbidden`` with an
    ``insufficient_scope`` challenge (R-23.8-f).
  """

  VALID = "valid"
  UNAUTHORIZED = "unauthorized"
  INSUFFICIENT_SCOPE = "insufficient_scope"


#: The HTTP status each :class:`TokenValidationOutcome` maps to (R-23.8-e/f).
TOKEN_VALIDATION_STATUS: dict[TokenValidationOutcome, int | None] = {
  TokenValidationOutcome.VALID: None,
  TokenValidationOutcome.UNAUTHORIZED: HTTP_UNAUTHORIZED,
  TokenValidationOutcome.INSUFFICIENT_SCOPE: HTTP_FORBIDDEN,
}


class TokenValidationError(Exception):
  """Per-request token validation failed (R-23.8-e/f).

  Raised by :func:`validate_access_token` when validation does not yield
  :data:`TokenValidationOutcome.VALID`. It carries the :class:`TokenValidationOutcome`
  and the HTTP status the server returns (``401`` for missing/invalid/expired,
  ``403`` for insufficient scope).

  Attributes:
    outcome: the failing :class:`TokenValidationOutcome`.
    status: the HTTP status code to return (R-23.8-e/f).
  """

  def __init__(self, outcome: TokenValidationOutcome) -> None:
    status = TOKEN_VALIDATION_STATUS[outcome]
    super().__init__(
      f"access-token validation failed with outcome {outcome.value!r}; the MCP "
      f"server responds with HTTP {status} (R-23.8-e/f)"
    )
    self.outcome: TokenValidationOutcome = outcome
    self.status: int | None = status


def token_validation_status(outcome: TokenValidationOutcome) -> int | None:
  """Return the HTTP status for a token-validation ``outcome`` (R-23.8-e/f).

  A missing/invalid/expired token yields ``401`` (R-23.8-e); a valid token lacking
  the required scope yields ``403`` (R-23.8-f); a valid token yields None (the
  request proceeds).
  """
  return TOKEN_VALIDATION_STATUS[outcome]


def validate_access_token(
  *,
  token_present: bool,
  signature_valid: bool,
  not_expired: bool,
  audience_matches: bool,
  granted_scopes: object,
  required_scopes: object,
) -> TokenValidationOutcome:
  """Validate an access token on the MCP server per request (R-23.8-d/e/f).

  On every request the MCP server MUST validate the token's signature or
  introspection result, its expiry, its audience (that it was issued for this
  server, §23.6), and its scope against what the operation requires (R-23.8-d). A
  missing, invalid, or expired token (or a wrong audience) yields
  :data:`TokenValidationOutcome.UNAUTHORIZED` → ``401`` (R-23.8-e); a token that is
  otherwise valid but lacks a required scope yields
  :data:`TokenValidationOutcome.INSUFFICIENT_SCOPE` → ``403`` (R-23.8-f);
  everything satisfied yields :data:`TokenValidationOutcome.VALID`.

  Args:
    token_present: whether an ``Authorization: Bearer`` token was presented.
    signature_valid: whether signature/introspection validation passed.
    not_expired: whether the token is unexpired.
    audience_matches: whether the audience includes this server (§23.6).
    granted_scopes: the scopes the token carries (iterable of strings).
    required_scopes: the scopes the operation requires (iterable of strings).

  Returns:
    The :class:`TokenValidationOutcome`.
  """
  if not token_present or not signature_valid or not not_expired or not audience_matches:
    return TokenValidationOutcome.UNAUTHORIZED  # R-23.8-e (and §23.6 audience)
  granted = set(granted_scopes)
  required = set(required_scopes)
  if not required.issubset(granted):
    return TokenValidationOutcome.INSUFFICIENT_SCOPE  # R-23.8-f
  return TokenValidationOutcome.VALID


# ===========================================================================
# §23.9  Refresh tokens
# ===========================================================================

#: The OAuth ``offline_access`` scope a client MAY request for refresh (R-23.9-b).
OFFLINE_ACCESS_SCOPE: str = "offline_access"
#: The grant type a refresh-capable client SHOULD list in its metadata (R-23.9-a).
REFRESH_TOKEN_GRANT_TYPE: str = "refresh_token"


def client_wants_refresh_grant_types(
  base_grant_types: list[str] | None = None,
) -> list[str]:
  """Return ``grant_types`` including ``refresh_token`` for refresh capability (R-23.9-a).

  A client that desires refresh capability SHOULD include ``refresh_token`` in its
  ``grant_types`` client metadata (R-23.9-a). This appends ``"refresh_token"`` to
  the supplied grant types (defaulting to ``["authorization_code"]``) without
  duplicating it.

  Args:
    base_grant_types: the client's existing grant types; defaults to
      ``["authorization_code"]``.

  Returns:
    The grant-types list including ``"refresh_token"``.
  """
  grant_types = list(base_grant_types) if base_grant_types else [GRANT_TYPE_AUTHORIZATION_CODE]
  if REFRESH_TOKEN_GRANT_TYPE not in grant_types:
    grant_types.append(REFRESH_TOKEN_GRANT_TYPE)
  return grant_types


def may_request_offline_access(
  authorization_server_metadata: AuthorizationServerMetadata,
) -> bool:
  """Return True iff the client MAY request ``offline_access`` (R-23.9-b).

  The client MAY add ``offline_access`` to the ``scope`` parameter of the
  authorization and token requests WHEN the authorization-server metadata lists
  ``offline_access`` in ``scopes_supported`` (R-23.9-b). Returns True only in that
  case.

  Args:
    authorization_server_metadata: the selected AS's metadata.

  Returns:
    True iff ``scopes_supported`` lists ``offline_access``.
  """
  supported = authorization_server_metadata.scopes_supported
  return bool(supported) and OFFLINE_ACCESS_SCOPE in supported


def add_offline_access_scope(
  scope: str | None,
  authorization_server_metadata: AuthorizationServerMetadata,
) -> str | None:
  """Add ``offline_access`` to a ``scope`` string when permitted (R-23.9-b).

  The client MAY add ``offline_access`` to the ``scope`` parameter only when the
  authorization-server metadata lists it in ``scopes_supported`` (R-23.9-b). When
  permitted and not already present it is appended; otherwise the ``scope`` is
  returned unchanged.

  Args:
    scope: the current space-delimited scope string, or None.
    authorization_server_metadata: the selected AS's metadata gating the addition.

  Returns:
    The (possibly augmented) scope string, or None if it was None and not added.
  """
  if not may_request_offline_access(authorization_server_metadata):
    return scope
  existing = scope.split() if scope else []
  if OFFLINE_ACCESS_SCOPE not in existing:
    existing.append(OFFLINE_ACCESS_SCOPE)
  return " ".join(existing)


def build_refresh_token_request(
  *,
  client_id: str,
  refresh_token: str,
  resource: str,
  scope: str | None = None,
) -> TokenRequest:
  """Build a refresh-token request, keeping the token audience-bound (R-23.9-e/f).

  To obtain a new access token the client makes a token request with
  ``grant_type=refresh_token``, the ``refresh_token`` value, and the SAME
  ``resource`` parameter (the MCP server's canonical resource identifier) so the
  refreshed token remains audience-bound (R-23.9-e). The client MAY include a
  ``scope`` parameter to narrow the requested scopes (R-23.9-f).

  Args:
    client_id: the client identifier.
    refresh_token: the refresh token being exchanged (kept confidential, R-23.9-c).
    resource: the MCP server's canonical resource identifier — identical to the
      original token request so the new token stays audience-bound (R-23.9-e).
    scope: an OPTIONAL narrower scope to request (R-23.9-f).

  Returns:
    The refresh :class:`TokenRequest`.

  Raises:
    ValueError: ``refresh_token`` or ``resource`` is empty (R-23.9-e).
  """
  if not refresh_token:
    raise ValueError("a refresh request MUST carry a non-empty refresh_token (R-23.9-e)")
  if not resource:
    raise ValueError(
      "a refresh request MUST carry the same non-empty 'resource' parameter to "
      "keep the token audience-bound (R-23.9-e)"
    )
  return TokenRequest(
    grant_type=GRANT_TYPE_REFRESH_TOKEN,
    client_id=client_id,
    resource=resource,
    refresh_token=refresh_token,
    scope=scope,
  )


def metadata_excludes_offline_access(
  *,
  www_authenticate_scope: str | None = None,
  protected_resource_metadata: ProtectedResourceMetadata | None = None,
) -> bool:
  """Return True iff the MCP server omits ``offline_access`` as a resource scope (R-23.9-g).

  The MCP server, as a protected resource, SHOULD NOT include ``offline_access`` in
  its ``WWW-Authenticate`` ``scope`` parameter or in protected-resource metadata
  ``scopes_supported``, because refresh tokens are not a resource requirement
  (R-23.9-g). Returns True only when ``offline_access`` appears in NEITHER source.

  Args:
    www_authenticate_scope: the ``scope`` from a server ``WWW-Authenticate``
      challenge, if any.
    protected_resource_metadata: the server's protected-resource metadata, if any.

  Returns:
    True iff ``offline_access`` is absent from both the challenge ``scope`` and
    ``scopes_supported`` (R-23.9-g).
  """
  if www_authenticate_scope and OFFLINE_ACCESS_SCOPE in www_authenticate_scope.split():
    return False
  if (
    protected_resource_metadata is not None
    and protected_resource_metadata.scopes_supported
    and OFFLINE_ACCESS_SCOPE in protected_resource_metadata.scopes_supported
  ):
    return False
  return True
