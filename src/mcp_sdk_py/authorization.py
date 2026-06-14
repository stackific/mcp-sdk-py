"""Authorization I: Model, Applicability & Metadata Discovery — S35.

The foundation of MCP authorization: the OAuth 2.0/2.1 security model for the
HTTP-based (Streamable HTTP) transport, the role contract, how an MCP server
names itself as a token audience (its *canonical resource identifier*), how an
unauthorized or under-scoped request is signalled at the HTTP layer
(``401``/``403`` with a ``WWW-Authenticate`` ``Bearer`` challenge), and the
two-stage ``.well-known`` metadata-discovery chain a client walks — first the
server's protected-resource metadata, then the selected authorization server's
metadata.

This module owns ONLY discovery and the challenge surface (§23.1–§23.3); it does
not run the authorization-code+PKCE flow, token requests, or registration (those
are S36/S37). It deliberately does NOT implement the client-side *step-up* flow
that reacts to a ``403`` (scope union, bounded retry, attempt tracking) — that is
owned by S37 (§23.18); this module only produces/parses the static ``403`` shape.

Public surface:

Applicability & roles (§23.1):
  - AUTHORIZATION_OPTIONAL: authorization is OPTIONAL (R-23.1-a).
  - TransportClass / authorization_applies(): §23 governs HTTP-based transports
    only; stdio MUST NOT use it; other transports follow their own best
    practices (R-23.1-a/b/c).
  - stdio_credentials_via_environment(): for stdio, credentials are conveyed out
    of band through the child process environment (R-23.1-b).
  - OAuthRole / role_requirements(): the three OAuth 2.1 roles each MUST behave
    per their role (R-23.1-d/e/g).
  - custom_strategy_is_out_of_scope(): a custom auth strategy is outside §23 yet
    bound by every other requirement (R-23.1-f).
  - PerAuthorizationServerCredentialStore: per-AS registration state keyed by
    ``issuer`` (R-23.1-h/i/j/k/l).

Canonical resource identifier (§23.1):
  - CanonicalResourceIdentifierError / build_canonical_resource_identifier():
    construct/validate the server's canonical resource id (R-23.1-m..s).
  - canonical_forms_equivalent(): scheme/host-case-insensitive comparison
    (R-23.1-p).

Unauthorized / insufficient-scope challenges (§23.1):
  - BearerChallenge / build_unauthorized_response() / build_insufficient_scope_response():
    the ``401``/``403`` + ``WWW-Authenticate: Bearer`` challenge shapes
    (R-23.1-t..ad).
  - parse_www_authenticate(): parse a ``WWW-Authenticate`` ``Bearer`` header
    (R-23.1-z).
  - required_scopes_from_challenge(): a client treats the challenged scope set as
    authoritative (R-23.1-x/y).
  - AUTHORIZATION_STATUS_TABLE: the 401/403/400 status-code table.

Protected-resource metadata discovery (§23.2):
  - ProtectedResourceMetadata / parse_protected_resource_metadata() (R-23.2-h/i).
  - PROTECTED_RESOURCE_WELL_KNOWN_SUFFIX / build_protected_resource_well_known_urls()
    (R-23.2-f).
  - locate_protected_resource_metadata_uri() / ProtectedResourceDiscovery
    (R-23.2-c/d/e/g).
  - select_authorization_server() / validate_resource_matches() (R-23.2-j).

Authorization-server metadata discovery (§23.3):
  - AuthorizationServerMetadata / parse_authorization_server_metadata() (R-23.3-f..j).
  - build_authorization_server_well_known_urls() (R-23.3-c).
  - IssuerMismatchError / validate_issuer_matches() (R-23.3-d/e).

Spec: §23.1–§23.3 (lines 6228–6444)
Depends on: S14 (Streamable HTTP transport: get_header), S08 (discovery shape).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from mcp_sdk_py.streamable_http import get_header


# ---------------------------------------------------------------------------
# §23.1  Applicability
# ---------------------------------------------------------------------------

#: Authorization is OPTIONAL for an MCP implementation; when an implementation
#: supports it, the rules of §23 apply (R-23.1-a). An implementation that omits
#: §23 behavior remains conformant.
AUTHORIZATION_OPTIONAL: bool = True


class TransportClass(enum.Enum):
  """Transport families for the §23 applicability rule (R-23.1-a/b/c).

  HTTP:
    The Streamable HTTP transport of §9 — the ONLY transport §23 authorization
    governs (R-23.1-a).
  STDIO:
    The stdio transport of §8 — MUST NOT use this authorization flow; required
    credentials are conveyed out of band through the child process environment
    (R-23.1-b).
  OTHER:
    Any other transport — MUST follow that transport's established security best
    practices; such transports are outside the scope of §23 (R-23.1-c).
  """

  HTTP = "http"
  STDIO = "stdio"
  OTHER = "other"


def authorization_applies(transport: TransportClass) -> bool:
  """Return True iff §23 authorization governs ``transport`` (R-23.1-a/b/c).

  Authorization as defined in §23 applies ONLY to the HTTP-based transport
  (R-23.1-a). The stdio transport MUST NOT use this flow (R-23.1-b), and any
  other transport is outside §23 and MUST instead follow its own established
  security best practices (R-23.1-c).

  Args:
    transport: the transport family carrying the MCP traffic.

  Returns:
    True only for :data:`TransportClass.HTTP`; False for STDIO and OTHER.
  """
  return transport is TransportClass.HTTP


def stdio_credentials_via_environment(
  environment: dict[str, str] | None,
) -> dict[str, str]:
  """Return the out-of-band credentials for a stdio-launched server (R-23.1-b).

  The stdio transport MUST NOT use the §23 authorization flow; instead a client
  launching a server over stdio conveys any required credentials out of band
  through the child process environment (R-23.1-b). This helper records that an
  attempt to authorize a stdio server goes through the process environment, not
  through bearer tokens / discovery.

  Args:
    environment: the child process environment mapping, or None for an empty one.

  Returns:
    A copy of the environment mapping the credentials are conveyed through.
  """
  return dict(environment or {})


def other_transport_security_is_out_of_scope(transport: TransportClass) -> bool:
  """Return True iff ``transport`` is governed by its own best practices, not §23.

  An implementation using any transport other than the HTTP-based one MUST follow
  established security best practices for that transport; such transports are
  outside the scope of §23 (R-23.1-c). Returns True for any non-HTTP transport.
  """
  return transport is not TransportClass.HTTP


# ---------------------------------------------------------------------------
# §23.1  Roles
# ---------------------------------------------------------------------------

class OAuthRole(enum.Enum):
  """The three OAuth 2.1 roles that participate in §23 (R-23.1-d/e/g).

  RESOURCE_SERVER:
    The MCP server. It accepts bearer-token-bearing requests, validates them,
    and serves or rejects; it publishes protected-resource metadata naming the
    authorization servers it trusts.
  AUTHORIZATION_SERVER:
    A (co-hosted or separate) OAuth 2.1 authorization server that authenticates
    the user and issues access tokens for the MCP server. There may be more than
    one; each is independent and keyed by its ``issuer`` (R-23.1-h).
  CLIENT:
    The MCP client acting on behalf of the resource owner: it performs
    discovery, obtains a token, and presents it on each request.
  """

  RESOURCE_SERVER = "resource_server"
  AUTHORIZATION_SERVER = "authorization_server"
  CLIENT = "client"


def role_requirements(role: OAuthRole) -> str:
  """Return the normative role obligation summary for ``role`` (R-23.1-d/e/g).

  Each participating role MUST behave as specified for its role (R-23.1-g). An
  authorization server MUST implement OAuth 2.1 with appropriate security
  measures for both confidential and public clients (R-23.1-d). Access-token
  handling on requests to the MCP server MUST conform to OAuth 2.1
  resource-request requirements, including the bearer-header rules of §23.8 and
  the audience-validation rules of §23.6 (R-23.1-e).

  Args:
    role: the OAuth 2.1 role.

  Returns:
    A short human-readable statement of the role's normative obligation.
  """
  if role is OAuthRole.AUTHORIZATION_SERVER:
    return (
      "MUST implement OAuth 2.1 with appropriate security measures for both "
      "confidential and public clients (R-23.1-d)"
    )
  if role is OAuthRole.RESOURCE_SERVER:
    return (
      "MUST validate access tokens per OAuth 2.1 resource-request requirements, "
      "including bearer-header (§23.8) and audience-validation (§23.6) rules "
      "(R-23.1-e)"
    )
  return (
    "MUST perform discovery, obtain a token, and present it on each request "
    "as an OAuth 2.1 client (R-23.1-g)"
  )


def custom_strategy_is_out_of_scope() -> bool:
  """Return True: a custom auth strategy is outside §23 yet still fully bound (R-23.1-f).

  A client and a server MAY negotiate their own custom authentication and
  authorization strategy. Such a strategy is outside the scope of §23, but an
  implementation that uses one is still bound by every other applicable
  requirement of this specification (R-23.1-f).
  """
  return True


# ---------------------------------------------------------------------------
# §23.1  Per-authorization-server credential isolation
# ---------------------------------------------------------------------------

@dataclass
class AuthorizationServerCredentials:
  """Registration state held for one authorization server (R-23.1-i).

  A client MUST maintain separate registration state — client credentials and
  tokens — per authorization server, keyed by that server's ``issuer`` (R-23.1-i).

  Fields:
    issuer: the authorization server's ``issuer`` identifier; the isolation key.
    client_id: the registered/assigned client identifier at this server, if any.
    client_secret: the client secret at this server, if any (confidential client).
    tokens: opaque token state for this server (access/refresh tokens, etc.).
  """

  issuer: str
  client_id: str | None = None
  client_secret: str | None = None
  tokens: dict[str, Any] = field(default_factory=dict)


class PerAuthorizationServerCredentialStore:
  """Per-authorization-server credential isolation keyed by ``issuer`` (R-23.1-i..l).

  A client MUST maintain separate registration state (client credentials,
  tokens) per authorization server, keyed by that authorization server's
  ``issuer`` identifier (R-23.1-i), and MUST NOT assume credentials valid for one
  authorization server are accepted by another (R-23.1-j). When the authorization
  server indicated by the MCP server's protected-resource metadata changes, the
  client MUST NOT reuse credentials registered with a different authorization
  server (R-23.1-k) and MUST re-register or re-discover against the new one
  (R-23.1-l).

  ``get`` returns the credentials for an issuer ONLY (never another issuer's),
  enforcing R-23.1-j. ``credentials_for_indicated_server`` and ``must_reauthorize``
  implement the AS-change rules (R-23.1-k/l).
  """

  def __init__(self) -> None:
    self._by_issuer: dict[str, AuthorizationServerCredentials] = {}

  def store(self, credentials: AuthorizationServerCredentials) -> None:
    """Persist registration state under its ``issuer`` key (R-23.1-i)."""
    self._by_issuer[credentials.issuer] = credentials

  def get(self, issuer: str) -> AuthorizationServerCredentials | None:
    """Return the credentials registered for ``issuer`` only, or None (R-23.1-i/j).

    Never returns another authorization server's credentials: a client MUST NOT
    assume credentials valid for one authorization server are accepted by another
    (R-23.1-j).
    """
    return self._by_issuer.get(issuer)

  def has(self, issuer: str) -> bool:
    """Return True iff registration state exists for ``issuer`` (R-23.1-i)."""
    return issuer in self._by_issuer

  def credentials_for_indicated_server(
    self,
    indicated_issuer: str,
  ) -> AuthorizationServerCredentials | None:
    """Return reusable credentials for the indicated authorization server (R-23.1-k).

    When the authorization server indicated by the MCP server's
    protected-resource metadata changes, the client MUST NOT reuse credentials
    registered with a different authorization server (R-23.1-k). This returns the
    credentials ONLY when they were registered against ``indicated_issuer``; it
    never returns a different server's credentials.
    """
    return self._by_issuer.get(indicated_issuer)

  def must_reauthorize(self, indicated_issuer: str) -> bool:
    """Return True iff the client MUST re-register/re-discover for ``indicated_issuer`` (R-23.1-l).

    When the indicated authorization server changes (there is no stored
    registration state for it), the client MUST re-register or re-discover
    against the new one (R-23.1-l). Returns True when no credentials exist for
    the indicated issuer.
    """
    return indicated_issuer not in self._by_issuer

  def known_issuers(self) -> frozenset[str]:
    """Return the set of issuers for which registration state is held."""
    return frozenset(self._by_issuer)


# ---------------------------------------------------------------------------
# §23.1  Canonical resource identifier of an MCP server
# ---------------------------------------------------------------------------

#: The ``https`` scheme: the only scheme allowed for a canonical resource id
#: except for loopback/local development (R-23.1-n).
HTTPS_SCHEME: str = "https"
#: The ``http`` scheme: allowed for a canonical resource id ONLY for
#: loopback/local development (R-23.1-n).
HTTP_SCHEME: str = "http"

#: Host names that count as loopback/local development, for which the ``http``
#: scheme is permitted in a canonical resource identifier (R-23.1-n).
LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


class CanonicalResourceIdentifierError(ValueError):
  """A URL violates the canonical-resource-identifier constraints (R-23.1-m..s).

  Raised by :func:`build_canonical_resource_identifier` when the supplied
  endpoint URL is not an absolute ``https`` (or loopback ``http``) URI or
  contains a fragment component (R-23.1-n/o).
  """


def is_loopback_host(host: str) -> bool:
  """Return True iff ``host`` is a loopback/local-development host (R-23.1-n).

  The ``http`` scheme is permitted for a canonical resource identifier only for
  loopback/local development; this recognises ``localhost`` and the IPv4/IPv6
  loopback literals (matched case-insensitively for the hostname).
  """
  return host.lower() in LOOPBACK_HOSTS


def build_canonical_resource_identifier(
  endpoint_url: str,
  *,
  keep_trailing_slash: bool = False,
) -> str:
  """Construct an MCP server's canonical resource identifier (R-23.1-m..s).

  The canonical resource identifier MUST be the MCP server's endpoint URL
  (R-23.1-m). It MUST be an absolute URI with the ``https`` scheme — or ``http``
  only for loopback/local development (R-23.1-n) — and MUST NOT contain a fragment
  component (R-23.1-o). The canonical form uses a lowercase scheme and host
  (R-23.1-p). A path component is preserved when present (R-23.1-r: a path MUST be
  included when needed to identify an individual server at the host; the caller
  supplies the most-specific URL it can, R-23.1-q). The returned form omits a
  trailing slash unless ``keep_trailing_slash`` marks it semantically significant
  (R-23.1-s).

  Args:
    endpoint_url: the MCP server's endpoint URL.
    keep_trailing_slash: True iff a trailing path slash is semantically
      significant for this resource and must be preserved (R-23.1-s).

  Returns:
    The canonical resource identifier: lowercase scheme/host, no fragment, and
    no trailing slash unless ``keep_trailing_slash`` is set.

  Raises:
    CanonicalResourceIdentifierError: the URL is relative, lacks a host, uses a
      disallowed scheme, or contains a fragment (R-23.1-n/o).
  """
  parts = urlsplit(endpoint_url)

  scheme = parts.scheme.lower()
  host = (parts.hostname or "").lower()

  if not scheme or not host:
    raise CanonicalResourceIdentifierError(
      f"canonical resource identifier {endpoint_url!r} MUST be an absolute URI "
      f"with a scheme and host (R-23.1-n)"
    )
  if parts.fragment:
    raise CanonicalResourceIdentifierError(
      f"canonical resource identifier {endpoint_url!r} MUST NOT contain a "
      f"fragment component (R-23.1-o)"
    )
  if scheme == HTTPS_SCHEME:
    pass
  elif scheme == HTTP_SCHEME:
    if not is_loopback_host(host):
      raise CanonicalResourceIdentifierError(
        f"canonical resource identifier {endpoint_url!r} may use the 'http' "
        f"scheme only for loopback/local development; host {host!r} is not "
        f"loopback (R-23.1-n)"
      )
  else:
    raise CanonicalResourceIdentifierError(
      f"canonical resource identifier {endpoint_url!r} MUST use the 'https' "
      f"scheme (or 'http' only for loopback); got scheme {scheme!r} (R-23.1-n)"
    )

  # Rebuild the authority with a lowercase host while preserving any port and
  # userinfo (R-23.1-p: canonical form has lowercase scheme and host).
  netloc = host
  if parts.port is not None:
    netloc = f"{host}:{parts.port}"
  if parts.username is not None:
    userinfo = parts.username
    if parts.password is not None:
      userinfo = f"{userinfo}:{parts.password}"
    netloc = f"{userinfo}@{netloc}"

  path = parts.path
  if not keep_trailing_slash and path.endswith("/") and path != "/":
    path = path.rstrip("/")  # R-23.1-s: omit a non-significant trailing slash.
  elif path == "/" and not keep_trailing_slash:
    path = ""  # bare-host endpoint: canonicalize "https://h/" → "https://h".

  # query is retained verbatim; fragment is already rejected above.
  return urlunsplit((scheme, netloc, path, parts.query, ""))


def canonical_forms_equivalent(a: str, b: str) -> bool:
  """Compare two resource identifiers, tolerating scheme/host case (R-23.1-p).

  The canonical form uses a lowercase scheme and host, but receivers SHOULD
  accept uppercase scheme and host components for robustness (R-23.1-p). This
  lowercases ONLY the scheme and host of each side, leaving the (case-sensitive)
  path/query untouched, before comparing.

  Returns:
    True iff ``a`` and ``b`` denote the same resource once scheme/host case is
    normalized.
  """
  def _norm(value: str) -> tuple[str, str, str, str]:
    p = urlsplit(value)
    host = (p.hostname or "").lower()
    netloc = host
    if p.port is not None:
      netloc = f"{host}:{p.port}"
    return (p.scheme.lower(), netloc, p.path, p.query)

  return _norm(a) == _norm(b)


# ---------------------------------------------------------------------------
# §23.1  HTTP status-code table for authorization errors
# ---------------------------------------------------------------------------

#: HTTP 401: authorization required, or token missing/invalid/expired (§23.1).
HTTP_UNAUTHORIZED: int = 401
#: HTTP 403: invalid scope or insufficient permissions (§23.1).
HTTP_FORBIDDEN: int = 403
#: HTTP 400: malformed authorization request (§23.1).
HTTP_BAD_REQUEST: int = 400

#: The §23.1 authorization-error status-code table: status → meaning/usage.
AUTHORIZATION_STATUS_TABLE: dict[int, str] = {
  HTTP_UNAUTHORIZED: "Authorization required, or token missing/invalid/expired",
  HTTP_FORBIDDEN: "Invalid scope or insufficient permissions",
  HTTP_BAD_REQUEST: "Malformed authorization request",
}


# ---------------------------------------------------------------------------
# §23.1  WWW-Authenticate Bearer challenge
# ---------------------------------------------------------------------------

#: The HTTP response header carrying the ``Bearer`` challenge (R-23.1-u).
WWW_AUTHENTICATE_HEADER: str = "WWW-Authenticate"
#: The HTTP scheme used by every §23 challenge (R-23.1-u).
BEARER_SCHEME: str = "Bearer"
#: The ``error`` value for the insufficient-scope case (R-23.1-ab).
INSUFFICIENT_SCOPE_ERROR: str = "insufficient_scope"


@dataclass(frozen=True)
class BearerChallenge:
  """A parsed/constructed ``WWW-Authenticate: Bearer`` challenge (R-23.1-t..ad).

  Models the parameter set carried in a ``WWW-Authenticate`` response header for
  the ``401`` (R-23.1-t/u/v/w) and ``403`` (R-23.1-aa/ab/ad) cases. It is not a
  JSON object; :meth:`to_header_value` renders the HTTP header value and
  :func:`parse_www_authenticate` produces one from a received header.

  Fields:
    resource_metadata: absolute URI of the MCP server's protected-resource
      metadata document. REQUIRED on a ``401`` (R-23.1-v); recommended on a
      ``403`` (R-23.1-ab).
    scope: space-delimited scopes required for the operation; SHOULD be present
      (R-23.1-w/ab). The challenged scope set is authoritative (R-23.1-x).
    error: ``"insufficient_scope"`` on the ``403`` scope-shortfall case
      (R-23.1-ab); None on a plain ``401``.
    error_description: OPTIONAL human-readable description of the failure
      (R-23.1-ad).
  """

  resource_metadata: str | None = None
  scope: str | None = None
  error: str | None = None
  error_description: str | None = None

  @property
  def scopes(self) -> list[str]:
    """Return the challenged scopes as a list (space-delimited ``scope``).

    A client MUST treat the challenged scope set as the scopes required to
    satisfy the request (R-23.1-x). Returns an empty list when no ``scope`` was
    present.
    """
    if not self.scope:
      return []
    return self.scope.split()

  def to_header_value(self) -> str:
    """Render the ``WWW-Authenticate`` header value for this challenge (R-23.1-u..ad).

    Produces ``Bearer`` followed by the quoted ``error``, ``scope``,
    ``resource_metadata``, and ``error_description`` parameters that are present,
    comma-separated. Parameter ordering follows the §23.1 wire examples (``error``
    first on a ``403``, then ``scope``, then ``resource_metadata``).
    """
    params: list[str] = []
    if self.error is not None:
      params.append(f'error="{self.error}"')
    if self.scope is not None:
      params.append(f'scope="{self.scope}"')
    if self.resource_metadata is not None:
      params.append(f'resource_metadata="{self.resource_metadata}"')
    if self.error_description is not None:
      params.append(f'error_description="{self.error_description}"')
    if not params:
      return BEARER_SCHEME
    return f"{BEARER_SCHEME} " + ", ".join(params)


@dataclass(frozen=True)
class ChallengeResponse:
  """An HTTP authorization-challenge response: status + ``WWW-Authenticate`` (R-23.1-t/u).

  Fields:
    status: the HTTP status code (401 or 403).
    headers: the response headers — always includes ``WWW-Authenticate``.
    challenge: the structured :class:`BearerChallenge` rendered into the header.
  """

  status: int
  headers: dict[str, str]
  challenge: BearerChallenge


def build_unauthorized_response(
  resource_metadata: str,
  *,
  scope: str | None = None,
) -> ChallengeResponse:
  """Build the ``401 Unauthorized`` challenge (R-23.1-t/u/v/w).

  When a request to the MCP server lacks valid authorization, the server MUST
  respond with HTTP ``401`` (R-23.1-t) and MUST include a ``WWW-Authenticate``
  header that uses the ``Bearer`` scheme and directs the client to the
  protected-resource metadata (R-23.1-u). That header MUST include the
  ``resource_metadata`` parameter whose value is the absolute URI of the
  protected-resource metadata document (R-23.1-v), and SHOULD include a ``scope``
  parameter listing the scopes required to access the resource (R-23.1-w).

  This ``401`` is an HTTP-layer response of the §9 transport and is distinct from
  the JSON-RPC error codes of §22; it carries no JSON-RPC error body requirement.

  Args:
    resource_metadata: absolute URI of the protected-resource metadata document
      (REQUIRED, R-23.1-v).
    scope: space-delimited scopes required for the operation (SHOULD, R-23.1-w).

  Returns:
    A :class:`ChallengeResponse` with status 401 and a ``Bearer`` challenge.

  Raises:
    ValueError: ``resource_metadata`` is empty (it is REQUIRED, R-23.1-v).
  """
  if not resource_metadata:
    raise ValueError(
      "the 401 WWW-Authenticate header MUST include a non-empty "
      "resource_metadata parameter (R-23.1-v)"
    )
  challenge = BearerChallenge(resource_metadata=resource_metadata, scope=scope)
  return ChallengeResponse(
    status=HTTP_UNAUTHORIZED,
    headers={WWW_AUTHENTICATE_HEADER: challenge.to_header_value()},
    challenge=challenge,
  )


def build_insufficient_scope_response(
  resource_metadata: str,
  scope: str,
  *,
  error_description: str | None = None,
) -> ChallengeResponse:
  """Build the ``403 Forbidden`` insufficient-scope challenge (R-23.1-aa..ad).

  When a request carries a valid token that lacks the scope required for the
  operation, the MCP server SHOULD respond with HTTP ``403`` and a
  ``WWW-Authenticate`` ``Bearer`` header (R-23.1-aa) containing
  ``error="insufficient_scope"``, a ``scope`` parameter, and a
  ``resource_metadata`` parameter (R-23.1-ab). The server SHOULD include ALL
  scopes required for the current operation in a single challenge rather than
  challenging incrementally (R-23.1-ac) — so ``scope`` is supplied complete here.
  The challenge MAY include an OPTIONAL human-readable ``error_description``
  (R-23.1-ad).

  The client-side reaction to this challenge (scope union, bounded retry, attempt
  tracking) is the step-up flow owned by S37 and is intentionally not defined
  here.

  Args:
    resource_metadata: absolute URI of the protected-resource metadata document
      (R-23.1-ab).
    scope: the complete, space-delimited set of scopes required for the operation
      in a single challenge (R-23.1-ab/ac).
    error_description: OPTIONAL human-readable description (R-23.1-ad).

  Returns:
    A :class:`ChallengeResponse` with status 403 and an insufficient-scope
    ``Bearer`` challenge.

  Raises:
    ValueError: ``scope`` or ``resource_metadata`` is empty (R-23.1-ab).
  """
  if not scope:
    raise ValueError(
      "the 403 insufficient_scope challenge SHOULD carry a non-empty 'scope' "
      "parameter naming all required scopes in a single challenge "
      "(R-23.1-ab/ac)"
    )
  if not resource_metadata:
    raise ValueError(
      "the 403 insufficient_scope challenge SHOULD carry a 'resource_metadata' "
      "parameter (R-23.1-ab)"
    )
  challenge = BearerChallenge(
    resource_metadata=resource_metadata,
    scope=scope,
    error=INSUFFICIENT_SCOPE_ERROR,
    error_description=error_description,
  )
  return ChallengeResponse(
    status=HTTP_FORBIDDEN,
    headers={WWW_AUTHENTICATE_HEADER: challenge.to_header_value()},
    challenge=challenge,
  )


def _parse_bearer_params(params_blob: str) -> dict[str, str]:
  """Parse the ``key=value`` parameter list of a Bearer challenge (R-23.1-z).

  Handles quoted ("..."), comma-separated parameters with surrounding
  whitespace, per RFC 7235 auth-param syntax sufficient for the §23 challenge
  parameters.
  """
  result: dict[str, str] = {}
  i = 0
  n = len(params_blob)
  while i < n:
    # Skip leading separators/whitespace.
    while i < n and params_blob[i] in ", \t\r\n":
      i += 1
    if i >= n:
      break
    # Read the parameter name up to '='.
    eq = params_blob.find("=", i)
    if eq == -1:
      break
    name = params_blob[i:eq].strip()
    i = eq + 1
    while i < n and params_blob[i] in " \t":
      i += 1
    if i < n and params_blob[i] == '"':
      # Quoted value: read until the closing unescaped quote.
      i += 1
      chars: list[str] = []
      while i < n:
        ch = params_blob[i]
        if ch == "\\" and i + 1 < n:
          chars.append(params_blob[i + 1])
          i += 2
          continue
        if ch == '"':
          i += 1
          break
        chars.append(ch)
        i += 1
      value = "".join(chars)
    else:
      # Token value: read until the next comma.
      comma = params_blob.find(",", i)
      end = n if comma == -1 else comma
      value = params_blob[i:end].strip()
      i = end
    if name:
      result[name] = value
  return result


def parse_www_authenticate(header_value: str | None) -> BearerChallenge:
  """Parse a ``WWW-Authenticate`` ``Bearer`` header into a challenge (R-23.1-z).

  A client MUST be able to parse ``WWW-Authenticate`` headers and react to
  ``401 Unauthorized`` responses from the MCP server (R-23.1-z). This extracts the
  ``Bearer`` scheme's ``resource_metadata``, ``scope``, ``error``, and
  ``error_description`` parameters into a :class:`BearerChallenge`.

  Args:
    header_value: the raw ``WWW-Authenticate`` header value (or None).

  Returns:
    The parsed :class:`BearerChallenge`.

  Raises:
    ValueError: the header is absent/empty or does not use the ``Bearer`` scheme.
  """
  if not header_value or not header_value.strip():
    raise ValueError(
      "WWW-Authenticate header is absent or empty; cannot parse a Bearer "
      "challenge (R-23.1-z)"
    )
  stripped = header_value.strip()
  scheme, _, rest = stripped.partition(" ")
  if scheme.lower() != BEARER_SCHEME.lower():
    raise ValueError(
      f"WWW-Authenticate scheme {scheme!r} is not 'Bearer'; only the Bearer "
      f"scheme is used by §23 (R-23.1-u/z)"
    )
  params = _parse_bearer_params(rest)
  return BearerChallenge(
    resource_metadata=params.get("resource_metadata"),
    scope=params.get("scope"),
    error=params.get("error"),
    error_description=params.get("error_description"),
  )


def parse_www_authenticate_from_headers(headers: dict[str, Any]) -> BearerChallenge:
  """Parse the ``WWW-Authenticate`` header out of a header mapping (R-23.1-z).

  Looks the header up case-insensitively (reusing the §9 transport's
  :func:`get_header`) and parses it as a ``Bearer`` challenge.

  Raises:
    ValueError: no ``WWW-Authenticate`` header is present, or it is not a Bearer
      challenge.
  """
  return parse_www_authenticate(get_header(headers, WWW_AUTHENTICATE_HEADER))


def required_scopes_from_challenge(
  challenge: BearerChallenge,
  scopes_supported: list[str] | None = None,
) -> list[str]:
  """Return the scopes a client MUST request for the challenged operation (R-23.1-x/y).

  A client MUST treat the challenged scope set as the scopes required to satisfy
  the request (R-23.1-x) and MUST NOT assume any subset/superset relationship
  between the challenged scopes and the ``scopes_supported`` value from
  protected-resource metadata (R-23.1-y). Accordingly this returns the challenged
  scopes verbatim and IGNORES ``scopes_supported`` entirely (it is accepted only
  to make the independence explicit at the call site).

  Args:
    challenge: the parsed challenge carrying the authoritative ``scope`` set.
    scopes_supported: the resource's ``scopes_supported``; deliberately unused —
      no subset/superset relationship may be assumed (R-23.1-y).

  Returns:
    The challenged scopes (possibly empty), unchanged.
  """
  # R-23.1-y: scopes_supported has no subset/superset relationship with the
  # challenged set, so it never influences the result.
  return challenge.scopes


# ---------------------------------------------------------------------------
# §23.2  Protected-resource metadata
# ---------------------------------------------------------------------------

#: The ``.well-known`` path suffix for protected-resource metadata (R-23.2-f).
PROTECTED_RESOURCE_WELL_KNOWN_SUFFIX: str = "/.well-known/oauth-protected-resource"


@dataclass(frozen=True)
class ProtectedResourceMetadata:
  """An OAuth 2.0 Protected Resource Metadata document (§23.2, R-23.2-h/i).

  Published by the MCP server; names its canonical resource identifier and the
  authorization servers it trusts. The client uses it to select an authorization
  server.

  Fields:
    resource: the protected resource's canonical resource identifier; REQUIRED
      and MUST equal the MCP server's canonical resource identifier (R-23.2-h).
    authorization_servers: one or more authorization server ``issuer`` URLs;
      REQUIRED for MCP, MUST be present and contain at least one entry
      (R-23.2-i). Each is an independent authorization server.
    scopes_supported: OPTIONAL scopes the resource recognizes; used for scope
      selection when no scope is given in the challenge.
    bearer_methods_supported: OPTIONAL supported methods of presenting the access
      token; for MCP this is the bearer header method.
  """

  resource: str
  authorization_servers: list[str]
  scopes_supported: list[str] | None = None
  bearer_methods_supported: list[str] | None = None


def parse_protected_resource_metadata(raw: Any) -> ProtectedResourceMetadata:
  """Parse/validate a raw dict as a ProtectedResourceMetadata document (R-23.2-h/i).

  ``resource`` is REQUIRED (R-23.2-h) and ``authorization_servers`` is REQUIRED
  for MCP, MUST be present, and MUST contain at least one entry (R-23.2-i). The
  cross-check that ``resource`` equals the MCP server's canonical resource id is
  performed separately by :func:`validate_resource_matches` (R-23.2-h/j), because
  it needs the server identity the client is contacting.

  Args:
    raw: the JSON-decoded metadata document.

  Returns:
    A validated :class:`ProtectedResourceMetadata`.

  Raises:
    TypeError: ``raw`` (or a field) has the wrong type.
    ValueError: a REQUIRED field is missing, or ``authorization_servers`` is
      empty (R-23.2-h/i).
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"ProtectedResourceMetadata must be a JSON object; got {type(raw).__name__}"
    )

  resource = raw.get("resource")
  if resource is None:
    raise ValueError(
      "ProtectedResourceMetadata is missing the REQUIRED 'resource' field "
      "(R-23.2-h)"
    )
  if not isinstance(resource, str):
    raise TypeError(
      f"ProtectedResourceMetadata.resource must be a string; got "
      f"{type(resource).__name__}"
    )

  authorization_servers = raw.get("authorization_servers")
  if authorization_servers is None:
    raise ValueError(
      "ProtectedResourceMetadata is missing the REQUIRED 'authorization_servers' "
      "field (R-23.2-i)"
    )
  if not isinstance(authorization_servers, list):
    raise TypeError(
      f"ProtectedResourceMetadata.authorization_servers must be an array; got "
      f"{type(authorization_servers).__name__}"
    )
  if len(authorization_servers) == 0:
    raise ValueError(
      "ProtectedResourceMetadata.authorization_servers MUST contain at least one "
      "entry (R-23.2-i)"
    )
  for i, issuer in enumerate(authorization_servers):
    if not isinstance(issuer, str):
      raise TypeError(
        f"ProtectedResourceMetadata.authorization_servers[{i}] must be a string; "
        f"got {type(issuer).__name__}"
      )

  scopes_supported = _optional_string_list(raw, "scopes_supported")
  bearer_methods_supported = _optional_string_list(raw, "bearer_methods_supported")

  return ProtectedResourceMetadata(
    resource=resource,
    authorization_servers=list(authorization_servers),
    scopes_supported=scopes_supported,
    bearer_methods_supported=bearer_methods_supported,
  )


def _optional_string_list(raw: dict[str, Any], key: str) -> list[str] | None:
  """Return ``raw[key]`` as a validated list[str], or None when absent."""
  value = raw.get(key)
  if value is None:
    return None
  if not isinstance(value, list):
    raise TypeError(f"{key} must be an array of strings; got {type(value).__name__}")
  for i, item in enumerate(value):
    if not isinstance(item, str):
      raise TypeError(f"{key}[{i}] must be a string; got {type(item).__name__}")
  return list(value)


def validate_resource_matches(
  metadata: ProtectedResourceMetadata,
  canonical_resource_identifier: str,
) -> None:
  """Validate ``metadata.resource`` against the server being contacted (R-23.2-h/j).

  ``ProtectedResourceMetadata.resource`` MUST equal the MCP server's canonical
  resource identifier (R-23.2-h); the client validates ``resource`` against the
  MCP server it is contacting (R-23.2-j). Comparison tolerates scheme/host case
  per R-23.1-p (:func:`canonical_forms_equivalent`).

  Raises:
    ValueError: ``metadata.resource`` does not equal the canonical resource
      identifier (R-23.2-h/j).
  """
  if not canonical_forms_equivalent(metadata.resource, canonical_resource_identifier):
    raise ValueError(
      f"ProtectedResourceMetadata.resource {metadata.resource!r} MUST equal the "
      f"MCP server's canonical resource identifier "
      f"{canonical_resource_identifier!r} (R-23.2-h/j)"
    )


def select_authorization_server(
  metadata: ProtectedResourceMetadata,
  *,
  preferred_issuer: str | None = None,
) -> str:
  """Select one authorization server ``issuer`` from the metadata (R-23.2-j).

  The client selects an authorization server from ``authorization_servers``
  (R-23.2-j); each listed server is independent and selecting which to use is the
  client's responsibility. When ``preferred_issuer`` is given and present in the
  list it is chosen; otherwise the first listed issuer is selected.

  Args:
    metadata: the validated protected-resource metadata.
    preferred_issuer: an issuer to prefer if it is listed.

  Returns:
    The selected authorization server issuer URL.

  Raises:
    ValueError: ``authorization_servers`` is empty (should not occur after
      parsing), or ``preferred_issuer`` is given but not listed.
  """
  servers = metadata.authorization_servers
  if not servers:
    raise ValueError(
      "no authorization server to select; authorization_servers is empty "
      "(R-23.2-i)"
    )
  if preferred_issuer is not None:
    if preferred_issuer not in servers:
      raise ValueError(
        f"preferred issuer {preferred_issuer!r} is not listed in "
        f"authorization_servers {servers!r} (R-23.2-j)"
      )
    return preferred_issuer
  return servers[0]


# ---------------------------------------------------------------------------
# §23.2  Protected-resource metadata discovery (well-known construction)
# ---------------------------------------------------------------------------

def build_protected_resource_well_known_urls(endpoint_url: str) -> list[str]:
  """Build the protected-resource ``.well-known`` URLs in priority order (R-23.2-f).

  Given an MCP server endpoint such as ``https://example.com/public/mcp``, the
  client MUST attempt, in this order (R-23.2-f):

    1. Path-aware: insert the path component after the well-known suffix —
       ``https://example.com/.well-known/oauth-protected-resource/public/mcp``
    2. Root: ``https://example.com/.well-known/oauth-protected-resource``

  When the endpoint has no path component the two candidates coincide and a
  single root URL is returned.

  Args:
    endpoint_url: the MCP server endpoint URL.

  Returns:
    The ordered list of candidate metadata URLs to try.
  """
  parts = urlsplit(endpoint_url)
  origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
  root = origin + PROTECTED_RESOURCE_WELL_KNOWN_SUFFIX

  path = parts.path.strip("/")
  if not path:
    return [root]
  path_aware = f"{origin}{PROTECTED_RESOURCE_WELL_KNOWN_SUFFIX}/{path}"
  return [path_aware, root]


def locate_protected_resource_metadata_uri(
  *,
  www_authenticate: str | None = None,
  headers: dict[str, Any] | None = None,
) -> str | None:
  """Return the metadata URI from a ``WWW-Authenticate`` header, if any (R-23.2-d).

  The client MUST support both discovery mechanisms (R-23.2-c). When the
  ``resource_metadata`` parameter is present in the ``WWW-Authenticate`` header on
  a ``401``, the client MUST use this URI (R-23.2-d). Returns that URI, or None
  when no header / no ``resource_metadata`` is available — in which case the
  caller falls back to well-known construction (R-23.2-e).

  Args:
    www_authenticate: the raw ``WWW-Authenticate`` header value, if known.
    headers: a header mapping to look the header up in (case-insensitively),
      used when ``www_authenticate`` is not given directly.

  Returns:
    The ``resource_metadata`` URI from the header, or None when unavailable.
  """
  value = www_authenticate
  if value is None and headers is not None:
    value = get_header(headers, WWW_AUTHENTICATE_HEADER)
  if value is None or not value.strip():
    return None
  try:
    challenge = parse_www_authenticate(value)
  except ValueError:
    return None
  return challenge.resource_metadata


class ProtectedResourceDiscoveryError(Exception):
  """No protected-resource metadata could be located (R-23.2-g).

  Raised by :func:`protected_resource_discovery_plan` (via ``decide_outcome``)
  when neither a header URI nor any well-known location yields a valid document
  and no fallback is configured: the client MUST then abort the authorization
  attempt or fall back to pre-configured values (R-23.2-g).
  """


@dataclass(frozen=True)
class ProtectedResourceDiscovery:
  """The ordered protected-resource discovery plan for one endpoint (R-23.2-c/d/e/f/g).

  Captures the §23.2 "discover then act" order so a caller can execute the
  fetches itself (this story owns the order and validation, not the HTTP client).

  Fields:
    header_uri: the ``resource_metadata`` URI from a ``WWW-Authenticate`` header,
      used first when present (R-23.2-d).
    well_known_urls: the ordered well-known candidates to try when no header URI
      is available — path-aware first, then root (R-23.2-e/f).
  """

  header_uri: str | None
  well_known_urls: list[str]

  def candidate_uris(self) -> list[str]:
    """Return all candidate metadata URIs in attempt order (R-23.2-d/e/f).

    The header URI (when present) is tried first (R-23.2-d); otherwise the
    well-known URLs are tried in order and the first valid document wins
    (R-23.2-e/f).
    """
    if self.header_uri is not None:
      return [self.header_uri]
    return list(self.well_known_urls)

  def resolve(
    self,
    *,
    valid_document_uri: str | None,
    fallback_available: bool = False,
  ) -> str:
    """Resolve discovery to the chosen metadata URI, or abort (R-23.2-e/g).

    ``valid_document_uri`` is the first candidate (in :meth:`candidate_uris`
    order) that returned a valid document, or None when none did. When none did
    and no header URI was provided, the client MUST abort the authorization
    attempt or fall back to pre-configured values (R-23.2-g): if
    ``fallback_available`` is False this raises, signalling "abort".

    Returns:
      The URI of the valid metadata document.

    Raises:
      ProtectedResourceDiscoveryError: no valid document and no fallback
        (R-23.2-g).
    """
    if valid_document_uri is not None:
      return valid_document_uri
    if fallback_available:
      raise ProtectedResourceDiscoveryError(
        "no well-known protected-resource metadata document was found; falling "
        "back to pre-configured values (R-23.2-g)"
      )
    raise ProtectedResourceDiscoveryError(
      "neither the WWW-Authenticate header nor any well-known location yielded a "
      "valid protected-resource metadata document and no fallback is configured; "
      "abort the authorization attempt (R-23.2-g)"
    )


def protected_resource_discovery_plan(
  endpoint_url: str,
  *,
  www_authenticate: str | None = None,
  headers: dict[str, Any] | None = None,
) -> ProtectedResourceDiscovery:
  """Build the protected-resource discovery plan for an endpoint (R-23.2-c/d/e/f).

  Supports both discovery mechanisms (R-23.2-c): it records the header
  ``resource_metadata`` URI when present (used first, R-23.2-d) and otherwise
  the ordered well-known candidates (R-23.2-e/f).

  Args:
    endpoint_url: the MCP server endpoint URL the client is contacting.
    www_authenticate: the raw ``WWW-Authenticate`` header value, if known.
    headers: a header mapping to look the header up in, if ``www_authenticate``
      is not given.

  Returns:
    The :class:`ProtectedResourceDiscovery` plan.
  """
  header_uri = locate_protected_resource_metadata_uri(
    www_authenticate=www_authenticate,
    headers=headers,
  )
  well_known = build_protected_resource_well_known_urls(endpoint_url)
  return ProtectedResourceDiscovery(header_uri=header_uri, well_known_urls=well_known)


# ---------------------------------------------------------------------------
# §23.3  Authorization-server metadata
# ---------------------------------------------------------------------------

#: The OAuth 2.0 Authorization Server Metadata well-known suffix (R-23.3-c).
OAUTH_AS_METADATA_WELL_KNOWN_SUFFIX: str = "/.well-known/oauth-authorization-server"
#: The OpenID Connect Discovery well-known suffix (R-23.3-c).
OPENID_CONFIGURATION_WELL_KNOWN_SUFFIX: str = "/.well-known/openid-configuration"

#: The ``response_type`` value that ``response_types_supported`` MUST include for
#: the authorization-code flow when that field is present (R-23.3-i).
REQUIRED_RESPONSE_TYPE: str = "code"
#: The PKCE code-challenge method ``code_challenge_methods_supported`` MUST
#: include to interoperate with this flow when that field is present (R-23.3-j).
REQUIRED_CODE_CHALLENGE_METHOD: str = "S256"


@dataclass(frozen=True)
class AuthorizationServerMetadata:
  """An OAuth 2.0 / OpenID Connect Authorization Server Metadata document (§23.3).

  Describes the authorization server's issuer identity and the endpoints the
  client uses to run the flow.

  Fields:
    issuer: the authorization server's issuer identifier URL; REQUIRED and MUST
      be identical to the value used to construct the discovery URL (R-23.3-f).
    authorization_endpoint: URL of the authorization endpoint; REQUIRED
      (R-23.3-g).
    token_endpoint: URL of the token endpoint; REQUIRED (R-23.3-h).
    registration_endpoint: OPTIONAL Dynamic Client Registration endpoint URL.
    scopes_supported: OPTIONAL scopes the authorization server recognizes.
    response_types_supported: OPTIONAL; if present MUST include ``"code"``
      (R-23.3-i).
    grant_types_supported: OPTIONAL grant types; for this flow includes
      ``"authorization_code"`` and, for refresh, ``"refresh_token"``.
    code_challenge_methods_supported: OPTIONAL but RECOMMENDED; if present MUST
      include ``"S256"`` (R-23.3-j).
    token_endpoint_auth_methods_supported: OPTIONAL token-endpoint client-auth
      methods (e.g. ``"none"``, ``"private_key_jwt"``).
    authorization_response_iss_parameter_supported: OPTIONAL; ``true`` when the
      AS includes the ``iss`` parameter in authorization responses.
    client_id_metadata_document_supported: OPTIONAL; ``true`` when the AS accepts
      HTTPS-URL client identifiers via Client ID Metadata Documents.
  """

  issuer: str
  authorization_endpoint: str
  token_endpoint: str
  registration_endpoint: str | None = None
  scopes_supported: list[str] | None = None
  response_types_supported: list[str] | None = None
  grant_types_supported: list[str] | None = None
  code_challenge_methods_supported: list[str] | None = None
  token_endpoint_auth_methods_supported: list[str] | None = None
  authorization_response_iss_parameter_supported: bool | None = None
  client_id_metadata_document_supported: bool | None = None


def parse_authorization_server_metadata(raw: Any) -> AuthorizationServerMetadata:
  """Parse/validate a raw dict as an AuthorizationServerMetadata document (R-23.3-f..j).

  ``issuer``, ``authorization_endpoint``, and ``token_endpoint`` are REQUIRED
  (R-23.3-f/g/h). If ``response_types_supported`` is present it MUST include
  ``"code"`` (R-23.3-i). If ``code_challenge_methods_supported`` is present
  (OPTIONAL but RECOMMENDED) it MUST include ``"S256"`` (R-23.3-j). The
  issuer-match cross-check against the construction value is performed separately
  by :func:`validate_issuer_matches` (R-23.3-d/e/f).

  Args:
    raw: the JSON-decoded metadata document.

  Returns:
    A validated :class:`AuthorizationServerMetadata`.

  Raises:
    TypeError: ``raw`` (or a field) has the wrong type.
    ValueError: a REQUIRED field is missing, ``response_types_supported`` omits
      ``"code"`` (R-23.3-i), or ``code_challenge_methods_supported`` omits
      ``"S256"`` (R-23.3-j).
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"AuthorizationServerMetadata must be a JSON object; got "
      f"{type(raw).__name__}"
    )

  issuer = _required_string(raw, "issuer", "R-23.3-f")
  authorization_endpoint = _required_string(
    raw, "authorization_endpoint", "R-23.3-g"
  )
  token_endpoint = _required_string(raw, "token_endpoint", "R-23.3-h")

  registration_endpoint = _optional_string(raw, "registration_endpoint")
  scopes_supported = _optional_string_list(raw, "scopes_supported")
  response_types_supported = _optional_string_list(raw, "response_types_supported")
  grant_types_supported = _optional_string_list(raw, "grant_types_supported")
  code_challenge_methods_supported = _optional_string_list(
    raw, "code_challenge_methods_supported"
  )
  token_endpoint_auth_methods_supported = _optional_string_list(
    raw, "token_endpoint_auth_methods_supported"
  )
  iss_param = _optional_bool(raw, "authorization_response_iss_parameter_supported")
  cid_md = _optional_bool(raw, "client_id_metadata_document_supported")

  # R-23.3-i: if response_types_supported is present it MUST include "code".
  if (
    response_types_supported is not None
    and REQUIRED_RESPONSE_TYPE not in response_types_supported
  ):
    raise ValueError(
      f"AuthorizationServerMetadata.response_types_supported, when present, MUST "
      f"include {REQUIRED_RESPONSE_TYPE!r} for the authorization-code flow "
      f"(R-23.3-i); got {response_types_supported!r}"
    )

  # R-23.3-j: if code_challenge_methods_supported is present it MUST include "S256".
  if (
    code_challenge_methods_supported is not None
    and REQUIRED_CODE_CHALLENGE_METHOD not in code_challenge_methods_supported
  ):
    raise ValueError(
      f"AuthorizationServerMetadata.code_challenge_methods_supported, when "
      f"present, MUST include {REQUIRED_CODE_CHALLENGE_METHOD!r} to interoperate "
      f"with this flow (R-23.3-j); got {code_challenge_methods_supported!r}"
    )

  return AuthorizationServerMetadata(
    issuer=issuer,
    authorization_endpoint=authorization_endpoint,
    token_endpoint=token_endpoint,
    registration_endpoint=registration_endpoint,
    scopes_supported=scopes_supported,
    response_types_supported=response_types_supported,
    grant_types_supported=grant_types_supported,
    code_challenge_methods_supported=code_challenge_methods_supported,
    token_endpoint_auth_methods_supported=token_endpoint_auth_methods_supported,
    authorization_response_iss_parameter_supported=iss_param,
    client_id_metadata_document_supported=cid_md,
  )


def _required_string(raw: dict[str, Any], key: str, atom: str) -> str:
  """Return ``raw[key]`` as a non-empty string, else raise (REQUIRED field)."""
  value = raw.get(key)
  if value is None:
    raise ValueError(
      f"AuthorizationServerMetadata is missing the REQUIRED {key!r} field ({atom})"
    )
  if not isinstance(value, str):
    raise TypeError(
      f"AuthorizationServerMetadata.{key} must be a string; got "
      f"{type(value).__name__}"
    )
  return value


def _optional_string(raw: dict[str, Any], key: str) -> str | None:
  """Return ``raw[key]`` as a string, or None when absent."""
  value = raw.get(key)
  if value is None:
    return None
  if not isinstance(value, str):
    raise TypeError(f"{key} must be a string; got {type(value).__name__}")
  return value


def _optional_bool(raw: dict[str, Any], key: str) -> bool | None:
  """Return ``raw[key]`` as a bool, or None when absent."""
  value = raw.get(key)
  if value is None:
    return None
  if not isinstance(value, bool):
    raise TypeError(f"{key} must be a boolean; got {type(value).__name__}")
  return value


def build_authorization_server_well_known_urls(issuer: str) -> list[str]:
  """Build the AS-metadata ``.well-known`` URLs in priority order (R-23.3-c).

  The client MUST attempt multiple endpoints to handle issuer URLs with and
  without path components, in this exact priority order (R-23.3-c):

  For an issuer **with a path** (e.g. ``https://auth.example.com/tenant1``):
    1. OAuth AS Metadata with path insertion:
       ``https://auth.example.com/.well-known/oauth-authorization-server/tenant1``
    2. OIDC Discovery with path insertion:
       ``https://auth.example.com/.well-known/openid-configuration/tenant1``
    3. OIDC Discovery with path appending:
       ``https://auth.example.com/tenant1/.well-known/openid-configuration``

  For an issuer **without a path** (e.g. ``https://auth.example.com``):
    1. ``https://auth.example.com/.well-known/oauth-authorization-server``
    2. ``https://auth.example.com/.well-known/openid-configuration``

  Args:
    issuer: the authorization server issuer URL selected from
      ``authorization_servers``.

  Returns:
    The ordered list of candidate AS-metadata URLs to try.
  """
  parts = urlsplit(issuer)
  origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
  path = parts.path.strip("/")

  if not path:
    return [
      origin + OAUTH_AS_METADATA_WELL_KNOWN_SUFFIX,
      origin + OPENID_CONFIGURATION_WELL_KNOWN_SUFFIX,
    ]
  return [
    f"{origin}{OAUTH_AS_METADATA_WELL_KNOWN_SUFFIX}/{path}",
    f"{origin}{OPENID_CONFIGURATION_WELL_KNOWN_SUFFIX}/{path}",
    f"{origin}/{path}{OPENID_CONFIGURATION_WELL_KNOWN_SUFFIX}",
  ]


class IssuerMismatchError(ValueError):
  """An AS-metadata document's ``issuer`` differs from the construction value (R-23.3-e).

  Raised by :func:`validate_issuer_matches` when the ``issuer`` value in a fetched
  document is not identical to the issuer identifier used to construct the
  well-known URL; the client MUST NOT use such a document (R-23.3-e).

  Attributes:
    used_issuer: the issuer identifier used to build the discovery URL.
    document_issuer: the (mismatching) ``issuer`` in the fetched document.
  """

  def __init__(self, used_issuer: str, document_issuer: str) -> None:
    super().__init__(
      f"authorization-server metadata fetched using issuer {used_issuer!r} "
      f"contains issuer {document_issuer!r}; the document's issuer MUST be "
      f"identical to the construction value, so the document MUST NOT be used "
      f"(R-23.3-d/e)"
    )
    self.used_issuer: str = used_issuer
    self.document_issuer: str = document_issuer


def validate_issuer_matches(
  metadata: AuthorizationServerMetadata,
  used_issuer: str,
) -> None:
  """Validate the document ``issuer`` against the construction value (R-23.3-d/e/f).

  After retrieving an AS-metadata document, the client MUST validate that the
  ``issuer`` value in the document is identical to the issuer identifier used to
  construct the well-known URL (R-23.3-d). If they differ, the client MUST NOT use
  the document (R-23.3-e). The comparison is exact (identical), as the issuer is
  an identity value.

  Args:
    metadata: the parsed AS-metadata document.
    used_issuer: the issuer identifier used to build the discovery URL.

  Raises:
    IssuerMismatchError: the document's ``issuer`` is not identical to
      ``used_issuer`` (R-23.3-e).
  """
  if metadata.issuer != used_issuer:
    raise IssuerMismatchError(used_issuer, metadata.issuer)
