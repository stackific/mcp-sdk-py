"""Authorization III: Registration Mechanisms, Scopes & Security — S37.

This module completes the MCP authorization surface. S35
(:mod:`mcp_sdk_py.authorization`) established the authorization model and the
metadata-discovery primitives; S36 (:mod:`mcp_sdk_py.oauth_flow`) built the
authorization-code flow with PKCE, resource indicators, issuer identification,
and token usage. S37 turns those into a complete, deployable
registration-and-security profile, owning the normative atoms of §23.11–§23.19:

  - §23.11 — obtaining a ``client_id`` and the mechanism-selection priority,
    gated by the AS metadata pre-checks (R-23.11-a..e);
  - §23.12 — Client ID Metadata Documents (CIMD): the client-side hosting/format
    requirements and the AS-side fetch/validate/cache rules (R-23.12-a..l);
  - §23.13 — pre-registration support (R-23.13-a);
  - §23.14/§23.15 — the deprecated Dynamic Client Registration (DCR):
    ``ClientRegistrationRequest``/``ClientRegistrationResponse`` and the
    ``application_type`` selection, failure-handling, and retry rules
    (R-23.14-a..e, R-23.15-a..f);
  - §23.16 — credential binding to the issuer: issuer-keyed storage, no cross-AS
    reuse, re-registration on mismatch, exact-string comparison, and the CIMD
    exemption (R-23.16-a..g);
  - §23.17 — discovery robustness: protected-resource well-known fallback and the
    ``authorization_servers`` requirement, plus the AS-metadata well-known
    ordering for path and non-path issuers and issuer self-consistency
    (R-23.17-a..i);
  - §23.18 — scope selection and the step-up authorization flow: scope priority,
    the ``insufficient_scope`` challenge shape (response-shape grade owned by
    S35), scope union, bounded retry, and attempt tracking (R-23.18-a..r,
    R-23.1-ae/af/ag);
  - §23.19 — the security considerations: audience-bound tokens / Resource
    Indicators, exact issuer validation, PKCE, ``state``, token confidentiality,
    and refresh-token handling (R-23.19-a..u).

To stay free of duplicate public names this module deliberately uses S37-specific
identifiers (e.g. :class:`CimdDocument`, :class:`RegistrationApplicationType`,
:class:`RegistrationMechanism`) and the story's own DCR type names
(:class:`ClientRegistrationRequest`/:class:`ClientRegistrationResponse`), and it
reuses the S35 data types (:class:`AuthorizationServerMetadata`,
:class:`ProtectedResourceMetadata`, :class:`BearerChallenge`) and the S36
PKCE/issuer primitives rather than redefining them.

Spec: §23.11–§23.19 (lines 6681–6998).
Depends on: S35 (authorization model, metadata, canonical resource identifier,
  ``BearerChallenge``, well-known URL builders, issuer-match validation), S36
  (PKCE parameters, the authorization record, ``iss`` validation), S34 (the
  401/403 error model), S14/S15 (the Streamable HTTP transport).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from mcp_sdk_py.authorization import (
  BEARER_SCHEME,
  HTTP_BAD_REQUEST,
  HTTP_FORBIDDEN,
  HTTP_UNAUTHORIZED,
  INSUFFICIENT_SCOPE_ERROR,
  AuthorizationServerMetadata,
  BearerChallenge,
  ProtectedResourceMetadata,
  build_authorization_server_well_known_urls,
  build_protected_resource_well_known_urls,
  locate_protected_resource_metadata_uri,
  validate_issuer_matches,
)

# ===========================================================================
# §23.11  Client registration mechanisms — obtaining a client_id
# ===========================================================================


class RegistrationMechanism(enum.Enum):
  """A mechanism for obtaining a ``client_id`` for the discovered AS (§23.11).

  Before initiating an authorization flow a client MUST obtain a ``client_id``
  for use with the discovered authorization server (R-23.11-a). Three mechanisms
  are defined, plus a user-prompt fallback; the members are ordered by the SHOULD
  selection priority of R-23.11-b — see :data:`REGISTRATION_MECHANISM_PRIORITY`.

  PRE_REGISTRATION:
    The client already holds pre-registered client information for the target AS
    (§23.13).
  CLIENT_ID_METADATA_DOCUMENT:
    The client is identified by an HTTPS-URL Client ID Metadata Document, used
    only when the AS sets ``client_id_metadata_document_supported: true``
    (§23.12, R-23.11-d).
  DYNAMIC_CLIENT_REGISTRATION:
    The client registers programmatically at the AS ``registration_endpoint``,
    used only when that endpoint is present (§23.14, Deprecated, R-23.11-e).
  USER_PROMPT:
    The client prompts the user to supply the client information (fallback).
  """

  PRE_REGISTRATION = "pre_registration"
  CLIENT_ID_METADATA_DOCUMENT = "client_id_metadata_document"
  DYNAMIC_CLIENT_REGISTRATION = "dynamic_client_registration"
  USER_PROMPT = "user_prompt"


#: The SHOULD priority order a multi-mechanism client follows: pre-registration →
#: CIMD → DCR → user prompt (R-23.11-b).
REGISTRATION_MECHANISM_PRIORITY: tuple[RegistrationMechanism, ...] = (
  RegistrationMechanism.PRE_REGISTRATION,
  RegistrationMechanism.CLIENT_ID_METADATA_DOCUMENT,
  RegistrationMechanism.DYNAMIC_CLIENT_REGISTRATION,
  RegistrationMechanism.USER_PROMPT,
)


class RegistrationMechanismUnavailableError(ValueError):
  """A registration mechanism was attempted that the AS metadata does not gate (R-23.11-d/e).

  Raised by :func:`select_registration_mechanism` when the caller forces a
  mechanism the metadata does not support: CIMD is attempted while
  ``client_id_metadata_document_supported`` is not ``true`` (R-23.11-d), or DCR is
  attempted while ``registration_endpoint`` is absent (R-23.11-e).
  """


def authorization_server_supports_cimd(
  metadata: AuthorizationServerMetadata,
) -> bool:
  """Return True iff the AS metadata advertises CIMD support (R-23.11-d).

  A client MUST NOT attempt Client ID Metadata Documents unless the AS metadata
  sets ``client_id_metadata_document_supported`` to ``true`` (R-23.11-d). This is
  the metadata pre-check that gates the CIMD mechanism.

  Args:
    metadata: the validated authorization-server metadata.

  Returns:
    True only when ``client_id_metadata_document_supported`` is exactly ``True``.
  """
  return metadata.client_id_metadata_document_supported is True


def authorization_server_supports_dcr(
  metadata: AuthorizationServerMetadata,
) -> bool:
  """Return True iff the AS metadata advertises a ``registration_endpoint`` (R-23.11-e).

  A client MUST NOT attempt Dynamic Client Registration unless the AS metadata
  advertises a ``registration_endpoint`` (R-23.11-e). This is the metadata
  pre-check that gates the (deprecated) DCR mechanism.

  Args:
    metadata: the validated authorization-server metadata.

  Returns:
    True only when ``registration_endpoint`` is present and non-empty.
  """
  return bool(metadata.registration_endpoint)


def select_registration_mechanism(
  metadata: AuthorizationServerMetadata,
  *,
  has_pre_registered_credentials: bool = False,
  supports_cimd: bool = True,
  supports_dcr: bool = True,
  forced: RegistrationMechanism | None = None,
) -> RegistrationMechanism:
  """Select the registration mechanism by the §23.11 priority, gated by metadata.

  A client MUST check the AS metadata before choosing a mechanism (R-23.11-c) and
  SHOULD attempt the mechanisms in priority order, using the first that applies
  (R-23.11-b): (1) pre-registered credentials if held; (2) CIMD if the AS sets
  ``client_id_metadata_document_supported: true`` (R-23.11-d); (3) DCR if the AS
  advertises a ``registration_endpoint`` (R-23.11-e); (4) otherwise prompt the
  user. The CIMD/DCR steps are skipped unless their metadata gate is satisfied, so
  the function can never return a mechanism the metadata forbids. Because the
  user-prompt fallback always applies, a mechanism is always returned (R-23.11-a).

  Args:
    metadata: the validated AS metadata, inspected before the choice (R-23.11-c).
    has_pre_registered_credentials: whether the client already holds pre-registered
      client information for this AS (priority 1).
    supports_cimd: whether the client itself implements CIMD (priority 2). The AS
      gate (R-23.11-d) is enforced regardless.
    supports_dcr: whether the client itself implements DCR (priority 3). The AS
      gate (R-23.11-e) is enforced regardless.
    forced: force a specific mechanism (used to validate a caller's choice against
      the metadata gates); CIMD/DCR are validated against R-23.11-d/e.

  Returns:
    The selected :class:`RegistrationMechanism`.

  Raises:
    RegistrationMechanismUnavailableError: ``forced`` names CIMD without the AS
      gate (R-23.11-d) or DCR without the AS gate (R-23.11-e).
  """
  cimd_gated = authorization_server_supports_cimd(metadata)
  dcr_gated = authorization_server_supports_dcr(metadata)

  if forced is not None:
    if forced is RegistrationMechanism.CLIENT_ID_METADATA_DOCUMENT and not cimd_gated:
      raise RegistrationMechanismUnavailableError(
        "a client MUST NOT attempt Client ID Metadata Documents unless the AS "
        "metadata sets client_id_metadata_document_supported: true (R-23.11-d)"
      )
    if forced is RegistrationMechanism.DYNAMIC_CLIENT_REGISTRATION and not dcr_gated:
      raise RegistrationMechanismUnavailableError(
        "a client MUST NOT attempt Dynamic Client Registration unless the AS "
        "metadata advertises a registration_endpoint (R-23.11-e)"
      )
    return forced

  if has_pre_registered_credentials:
    return RegistrationMechanism.PRE_REGISTRATION  # (1)
  if supports_cimd and cimd_gated:
    return RegistrationMechanism.CLIENT_ID_METADATA_DOCUMENT  # (2) R-23.11-d
  if supports_dcr and dcr_gated:
    return RegistrationMechanism.DYNAMIC_CLIENT_REGISTRATION  # (3) R-23.11-e
  return RegistrationMechanism.USER_PROMPT  # (4)


def client_id_obtained(client_id: str | None) -> bool:
  """Return True iff the client holds a ``client_id`` to start the flow (R-23.11-a).

  Before initiating an authorization flow against the discovered AS, a client MUST
  have already obtained a ``client_id`` for that AS (R-23.11-a). This is the
  precondition guard the flow checks: a non-empty ``client_id`` must be present.

  Args:
    client_id: the ``client_id`` the client currently holds (or None).

  Returns:
    True when a non-empty ``client_id`` has been obtained.
  """
  return bool(client_id)


# ===========================================================================
# §23.12  Client ID Metadata Documents (CIMD)
# ===========================================================================

#: The scheme a CIMD ``client_id`` URL MUST use (R-23.12-b/c).
CIMD_HTTPS_SCHEME: str = "https"

#: The fields a CIMD document MUST contain at least (R-23.12-d/i).
CIMD_REQUIRED_DOCUMENT_FIELDS: tuple[str, ...] = (
  "client_id",
  "client_name",
  "redirect_uris",
)

#: The OAuth ``error`` codes an AS returns on a CIMD/DCR validation failure
#: (inherited from RFC 6749; referenced, not owned by this story).
CIMD_VALIDATION_FAILURE_ERRORS: tuple[str, ...] = ("invalid_client", "invalid_request")

#: The token-endpoint auth method a CIMD client MAY use with a JWKS configuration
#: (R-23.12-f).
PRIVATE_KEY_JWT_AUTH_METHOD: str = "private_key_jwt"


class CimdDocumentError(ValueError):
  """A Client ID Metadata Document violates a §23.12 constraint (R-23.12-c..j).

  Raised when a CIMD ``client_id`` URL is not an ``https`` URL with a path
  component (R-23.12-b/c), when the document is not a valid JSON object with the
  required fields (R-23.12-d/i), when the document's ``client_id`` does not equal
  its URL byte-for-byte (R-23.12-e/h), or, on the AS side, when the presented
  ``redirect_uri`` is not listed (R-23.12-j).
  """


def is_cimd_client_id(client_id: str) -> bool:
  """Return True iff ``client_id`` is an HTTPS-URL CIMD identifier (R-23.12-b/c).

  A CIMD ``client_id`` MUST be hosted at an HTTPS URL (R-23.12-b) whose URL uses
  the ``https`` scheme and contains a path component (R-23.12-c), e.g.
  ``https://app.example.com/oauth/client-metadata.json``. This recognises that
  shape (host present, ``https`` scheme, non-empty path other than ``/``); it does
  not fetch or validate the document body.

  Args:
    client_id: the candidate ``client_id`` value.

  Returns:
    True when ``client_id`` is an ``https://host/path`` URL.
  """
  parts = urlsplit(client_id)
  return (
    parts.scheme == CIMD_HTTPS_SCHEME
    and bool(parts.netloc)
    and parts.path not in ("", "/")
  )


@dataclass(frozen=True)
class CimdDocument:
  """A Client ID Metadata Document (§23.12, §6.1).

  The self-hosted JSON document a CIMD client serves at its ``client_id`` URL;
  the AS fetches it on demand to learn about the client. Portable across
  authorization servers, so no per-issuer registration state exists (§23.16
  exemption).

  Fields:
    client_id: the HTTPS URL of this document; MUST equal the URL it is served
      from, byte-for-byte (R-23.12-c/e).
    client_name: human-readable client name shown on the consent page; REQUIRED
      (R-23.12-d).
    redirect_uris: allowed redirect URIs for the authorization-code flow; REQUIRED
      (R-23.12-d), validated by the AS (R-23.12-j).
    client_uri: OPTIONAL home page of the client.
    logo_uri: OPTIONAL URL of the client's logo.
    grant_types: OPTIONAL OAuth grant types the client uses.
    response_types: OPTIONAL OAuth response types the client uses.
    token_endpoint_auth_method: OPTIONAL token-endpoint auth method (e.g.
      ``"none"`` or ``"private_key_jwt"``, R-23.12-f).
    additional: any further OAuth client metadata fields that appeared (§6.1
      ``[key: string]: unknown``), preserved verbatim.
  """

  client_id: str
  client_name: str
  redirect_uris: list[str]
  client_uri: str | None = None
  logo_uri: str | None = None
  grant_types: list[str] | None = None
  response_types: list[str] | None = None
  token_endpoint_auth_method: str | None = None
  additional: dict[str, Any] = field(default_factory=dict)

  def uses_private_key_jwt(self) -> bool:
    """Return True iff the document declares ``private_key_jwt`` token auth (R-23.12-f).

    A CIMD client MAY authenticate to the token endpoint with ``private_key_jwt``
    and an appropriate JWKS configuration, in which case the document conveys the
    key material (R-23.12-f).
    """
    return self.token_endpoint_auth_method == PRIVATE_KEY_JWT_AUTH_METHOD


def parse_cimd_document(raw: Any) -> CimdDocument:
  """Parse and validate a raw object as a Client ID Metadata Document (R-23.12-d/i).

  The document MUST be a valid JSON object containing at least ``client_id``,
  ``client_name``, and ``redirect_uris`` (R-23.12-d/i). The
  ``client_id == URL`` identity check (R-23.12-e/h) requires the hosting URL and is
  performed by :func:`validate_cimd_document` /
  :func:`authorization_server_validate_cimd_document`. Unknown fields are preserved
  in :attr:`CimdDocument.additional` (§6.1 ``[key: string]: unknown``).

  Args:
    raw: the JSON-decoded document body.

  Returns:
    A :class:`CimdDocument` with the validated required fields.

  Raises:
    CimdDocumentError: ``raw`` is not an object or a required field is missing.
    TypeError: a field has the wrong JSON type.
  """
  if not isinstance(raw, dict):
    raise CimdDocumentError(
      f"a Client ID Metadata Document MUST be a valid JSON object; got "
      f"{type(raw).__name__} (R-23.12-d/i)"
    )
  for required in CIMD_REQUIRED_DOCUMENT_FIELDS:
    if raw.get(required) is None:
      raise CimdDocumentError(
        f"a Client ID Metadata Document MUST contain at least {required!r}; it is "
        f"missing (R-23.12-d/i)"
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

  known = {
    "client_id",
    "client_name",
    "redirect_uris",
    "client_uri",
    "logo_uri",
    "grant_types",
    "response_types",
    "token_endpoint_auth_method",
  }
  grant_types = _optional_str_list(raw, "grant_types")
  response_types = _optional_str_list(raw, "response_types")
  return CimdDocument(
    client_id=client_id,
    client_name=client_name,
    redirect_uris=list(redirect_uris),
    client_uri=_optional_str(raw, "client_uri"),
    logo_uri=_optional_str(raw, "logo_uri"),
    grant_types=grant_types,
    response_types=response_types,
    token_endpoint_auth_method=_optional_str(raw, "token_endpoint_auth_method"),
    additional={k: v for k, v in raw.items() if k not in known},
  )


def validate_cimd_document(document: CimdDocument, document_url: str) -> None:
  """Validate a CIMD document against the URL it is hosted at (R-23.12-c/e).

  The ``client_id`` URL MUST use the ``https`` scheme and contain a path component
  (R-23.12-c), and the document's ``client_id`` value MUST equal the document's
  own URL exactly, byte-for-byte, with no normalization (R-23.12-e). This is the
  client-side self-check; the AS applies the same exact match on fetch (R-23.12-h),
  see :func:`authorization_server_validate_cimd_document`.

  Args:
    document: the parsed CIMD document.
    document_url: the HTTPS URL the document is served at (the presented
      ``client_id``).

  Raises:
    CimdDocumentError: the URL is not ``https``-with-path (R-23.12-c) or the
      document's ``client_id`` does not equal the URL byte-for-byte (R-23.12-e).
  """
  if not is_cimd_client_id(document_url):
    raise CimdDocumentError(
      f"a CIMD client_id URL MUST use the 'https' scheme and contain a path "
      f"component; got {document_url!r} (R-23.12-b/c)"
    )
  if document.client_id != document_url:
    raise CimdDocumentError(
      f"a CIMD document's client_id {document.client_id!r} MUST equal the "
      f"document's own URL {document_url!r} exactly, byte-for-byte, with no "
      f"normalization (R-23.12-e)"
    )


@dataclass
class _CachedCimd:
  """One cached CIMD entry: the parsed document, kept under its URL (R-23.12-k)."""

  document: CimdDocument


class CimdDocumentCache:
  """An AS-side cache for CIMD documents, honoring HTTP cache headers (R-23.12-k).

  The authorization server SHOULD cache the metadata document, respecting HTTP
  cache headers (R-23.12-k). A response served with ``Cache-Control: no-store`` is
  not cached; otherwise the document is stored under its URL and returned on a
  repeated lookup, so the AS fetches it once. This models the caching decision; it
  does not perform the HTTP fetch.
  """

  def __init__(self) -> None:
    self._by_url: dict[str, _CachedCimd] = {}

  @staticmethod
  def _forbids_storage(cache_headers: dict[str, str] | None) -> bool:
    """Return True iff cache headers forbid storing the response (R-23.12-k)."""
    if not cache_headers:
      return False
    for name, value in cache_headers.items():
      if name.lower() == "cache-control" and "no-store" in value.lower():
        return True
    return False

  def store(
    self,
    document_url: str,
    document: CimdDocument,
    *,
    cache_headers: dict[str, str] | None = None,
  ) -> None:
    """Cache ``document`` under its URL unless its headers forbid it (R-23.12-k).

    Respects ``Cache-Control: no-store`` by NOT caching such a response; any other
    (or absent) directive caches the document.
    """
    if self._forbids_storage(cache_headers):
      self._by_url.pop(document_url, None)
      return
    self._by_url[document_url] = _CachedCimd(document=document)

  def get(self, document_url: str) -> CimdDocument | None:
    """Return the cached CIMD document for ``document_url``, or None (R-23.12-k)."""
    entry = self._by_url.get(document_url)
    return entry.document if entry is not None else None


def default_cimd_domain_trust_policy(
  document_url: str,
  allowed_domains: frozenset[str] | set[str] | None,
) -> bool:
  """Apply a host-domain trust policy over a CIMD client_id URL (R-23.12-l).

  The AS SHOULD apply the security considerations of CIMD — for example, a trust
  policy over the allowed client-hosting domains (R-23.12-l). When
  ``allowed_domains`` is given, the document URL's host MUST be one of them;
  ``None`` means no restriction (every host is allowed). This is a sample policy
  illustrating R-23.12-l; deployments may substitute a stricter one.

  Args:
    document_url: the CIMD ``client_id`` URL the AS fetched.
    allowed_domains: the set of hostnames permitted to host CIMD documents, or
      None to allow any.

  Returns:
    True when the document URL's host is permitted by the policy.
  """
  if allowed_domains is None:
    return True
  host = urlsplit(document_url).hostname
  return host is not None and host in allowed_domains


def authorization_server_fetch_cimd_document(
  client_id: str,
  resolver: Any,
  *,
  cache: CimdDocumentCache | None = None,
  cache_headers: dict[str, str] | None = None,
  allowed_domains: frozenset[str] | set[str] | None = None,
) -> CimdDocument:
  """Fetch (and cache) a CIMD document for a URL ``client_id`` on the AS side (R-23.12-g/k/l).

  When the ``client_id`` is a URL, the AS SHOULD fetch the metadata document by
  performing an HTTP GET on the ``client_id`` URL (R-23.12-g) and SHOULD cache it,
  respecting HTTP cache headers (R-23.12-k). ``resolver`` is the caller's HTTP
  fetch — a callable ``client_id -> raw JSON object`` — because this story owns the
  fetch/validate/cache *decision*, not the HTTP client. A host-domain trust policy
  is applied first (R-23.12-l). When a ``cache`` already holds the document the
  cached copy is returned without re-fetching.

  Args:
    client_id: the URL-formatted ``client_id`` from the authorization request.
    resolver: a callable mapping the ``client_id`` URL to the raw JSON document.
    cache: an optional :class:`CimdDocumentCache` to consult and populate
      (R-23.12-k).
    cache_headers: the HTTP cache headers from the fetch, used to decide caching.
    allowed_domains: an optional host-domain allowlist for the trust policy
      (R-23.12-l).

  Returns:
    The parsed and URL-validated :class:`CimdDocument`.

  Raises:
    CimdDocumentError: ``client_id`` is not a CIMD URL, the host is not permitted
      by the trust policy (R-23.12-l), or the fetched document is invalid
      (R-23.12-h/i).
  """
  if not is_cimd_client_id(client_id):
    raise CimdDocumentError(
      f"client_id {client_id!r} is not a URL-formatted (CIMD) identifier; only "
      f"URL-formatted client_ids are fetched (R-23.12-c/g)"
    )
  if not default_cimd_domain_trust_policy(client_id, allowed_domains):
    raise CimdDocumentError(
      f"the CIMD client_id host for {client_id!r} is not permitted by the "
      f"client-hosting domain trust policy (R-23.12-l)"
    )
  if cache is not None:
    cached = cache.get(client_id)
    if cached is not None:
      return cached
  raw = resolver(client_id)
  document = authorization_server_validate_cimd_document(client_id, raw)
  if cache is not None:
    cache.store(client_id, document, cache_headers=cache_headers)
  return document


def authorization_server_validate_cimd_document(
  client_id: str,
  raw: Any,
  *,
  presented_redirect_uri: str | None = None,
) -> CimdDocument:
  """Validate a fetched CIMD document on the AS side (R-23.12-h/i/j).

  After fetching a URL-formatted ``client_id``'s document the AS MUST validate that
  the document is valid JSON with the required fields (R-23.12-i), MUST validate
  that the fetched document's ``client_id`` matches the URL it was fetched from,
  exactly (R-23.12-h), and MUST validate the ``redirect_uri`` presented in the
  authorization request against ``redirect_uris`` in the document, rejecting
  requests whose redirect URI is not listed (R-23.12-j).

  Args:
    client_id: the URL the document was fetched from (the presented ``client_id``).
    raw: the raw JSON-decoded document body.
    presented_redirect_uri: the ``redirect_uri`` from the authorization request to
      validate against the document's ``redirect_uris`` (R-23.12-j); skipped when
      None.

  Returns:
    The validated :class:`CimdDocument`.

  Raises:
    CimdDocumentError: the body is not a valid/complete document (R-23.12-i), the
      ``client_id`` does not match the URL (R-23.12-h), or the presented redirect
      URI is not listed (R-23.12-j). On such a failure the AS returns an OAuth
      ``error`` such as ``invalid_client`` / ``invalid_request``
      (:data:`CIMD_VALIDATION_FAILURE_ERRORS`).
  """
  document = parse_cimd_document(raw)  # R-23.12-i
  validate_cimd_document(document, client_id)  # R-23.12-h
  if presented_redirect_uri is not None and (
    presented_redirect_uri not in document.redirect_uris
  ):
    raise CimdDocumentError(
      f"the authorization request's redirect_uri {presented_redirect_uri!r} is "
      f"not listed in the CIMD document's redirect_uris "
      f"{document.redirect_uris!r}; the AS MUST reject the request (R-23.12-j)"
    )
  return document


def cimd_client_id_is_portable() -> bool:
  """Return True: a CIMD ``client_id`` is portable across authorization servers (§23.12).

  A ``client_id`` based on a Client ID Metadata Document is a self-hosted HTTPS URL
  resolved on demand, so it is portable across authorization servers and no
  re-registration is required when the target AS changes (informative consequence
  of the §23.12 rules; the §23.16 exemption rests on this).
  """
  return True


# ===========================================================================
# §23.13  Pre-registration
# ===========================================================================

#: The two non-CIMD/non-DCR sources of static client credentials a client SHOULD
#: support out of band (R-23.13-a).
PRE_REGISTRATION_CREDENTIAL_SOURCES: tuple[str, ...] = (
  "hardcoded_for_authorization_server",
  "entered_via_configuration_interface",
)


@dataclass(frozen=True)
class PreRegisteredClientInformation:
  """Static, out-of-band client credentials for one authorization server (§23.13).

  A client SHOULD support static client credentials supplied out of band, either
  hardcoded for a specific AS or entered by the user through a configuration
  interface (R-23.13-a). Pre-registered credentials are specific to the AS that
  issued them and are bound to that AS's ``issuer`` (§23.16, R-23.16-a).

  Fields:
    issuer: the ``issuer`` of the AS these credentials were registered with; the
      §23.16 storage key (R-23.16-a/b).
    client_id: the pre-registered client identifier.
    client_secret: the pre-registered secret, for a confidential client (if any).
  """

  issuer: str
  client_id: str
  client_secret: str | None = None


def client_supports_pre_registration(credential_source: str) -> bool:
  """Return True iff ``credential_source`` is a supported pre-registration source (R-23.13-a).

  A client SHOULD support static client credentials supplied out of band —
  hardcoded for a specific AS, or entered by the user via a configuration
  interface (R-23.13-a). Both sources in
  :data:`PRE_REGISTRATION_CREDENTIAL_SOURCES` are supported.

  Args:
    credential_source: the source identifier to check.

  Returns:
    True when the source is one this client supports.
  """
  return credential_source in PRE_REGISTRATION_CREDENTIAL_SOURCES


# ===========================================================================
# §23.14 / §23.15  Dynamic Client Registration (Deprecated)
# ===========================================================================

#: DCR is Deprecated; new implementations SHOULD use CIMD instead (R-23.14-a).
DCR_DEPRECATED: bool = True


class RegistrationApplicationType(enum.Enum):
  """The DCR ``application_type`` value, ``"native"`` or ``"web"`` (§23.15).

  When performing DCR a client MUST specify an ``application_type`` consistent with
  its redirect URIs, because OIDC servers enforce redirect-URI constraints based on
  it (R-23.15-a). Native applications (desktop, mobile, CLI, or locally hosted apps
  reached via ``localhost``/loopback) SHOULD use ``"native"`` (R-23.15-b); remote
  browser-based applications served from a non-local host SHOULD use ``"web"``
  (R-23.15-c).
  """

  NATIVE = "native"
  WEB = "web"


#: The ``application_type`` an OIDC server defaults to when the field is omitted
#: (R-23.15-a); conflicts with native-style (loopback) redirect URIs.
OIDC_DEFAULT_APPLICATION_TYPE: RegistrationApplicationType = (
  RegistrationApplicationType.WEB
)


def registration_application_type_for(*, is_native: bool) -> RegistrationApplicationType:
  """Choose the DCR ``application_type`` consistent with the client (R-23.15-a/b/c).

  A native application — desktop, mobile, CLI, or a locally hosted app reached via
  ``localhost``/loopback — SHOULD register ``"native"`` (R-23.15-b); a remote
  browser-based app served from a non-local host SHOULD register ``"web"``
  (R-23.15-c). The chosen value MUST be consistent with the redirect URIs
  (R-23.15-a).

  Args:
    is_native: True for a native client (desktop/mobile/CLI/loopback).

  Returns:
    :data:`RegistrationApplicationType.NATIVE` for a native client, else
    :data:`RegistrationApplicationType.WEB`.
  """
  return (
    RegistrationApplicationType.NATIVE
    if is_native
    else RegistrationApplicationType.WEB
  )


@dataclass(frozen=True)
class ClientRegistrationRequest:
  """A Dynamic Client Registration request body (Deprecated) (§23.14, §6.2).

  The JSON client-metadata object a client POSTs to the AS ``registration_endpoint``
  (R-23.14-b). ``redirect_uris`` is REQUIRED (R-23.14-c) and ``application_type`` is
  REQUIRED for MCP clients (R-23.14-d).

  Fields:
    redirect_uris: redirect URIs for the authorization-code flow; REQUIRED
      (R-23.14-c).
    application_type: ``"native"`` or ``"web"``; REQUIRED for MCP clients
      (R-23.14-d), consistent with the redirect URIs (R-23.15-a).
    client_name: OPTIONAL human-readable client name.
    grant_types: OPTIONAL grant types the client will use (e.g.
      ``["authorization_code", "refresh_token"]``).
    response_types: OPTIONAL response types the client will use (e.g. ``["code"]``).
    token_endpoint_auth_method: OPTIONAL token-endpoint auth method (e.g.
      ``"none"``).
    scope: OPTIONAL space-delimited scopes the client may request.
    additional: any further OAuth client metadata fields (§6.2
      ``[key: string]: unknown``).
  """

  redirect_uris: list[str]
  application_type: RegistrationApplicationType
  client_name: str | None = None
  grant_types: list[str] | None = None
  response_types: list[str] | None = None
  token_endpoint_auth_method: str | None = None
  scope: str | None = None
  additional: dict[str, Any] = field(default_factory=dict)

  def to_body(self) -> dict[str, Any]:
    """Render the registration request as a JSON-serialisable body (R-23.14-c/d).

    ``redirect_uris`` and ``application_type`` are always present (R-23.14-c/d);
    optional fields and any ``additional`` metadata are included only when set.
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
    for key, value in self.additional.items():
      body.setdefault(key, value)
    return body


def build_client_registration_request(
  redirect_uris: list[str],
  *,
  is_native: bool,
  client_name: str | None = None,
  grant_types: list[str] | None = None,
  response_types: list[str] | None = None,
  token_endpoint_auth_method: str | None = None,
  scope: str | None = None,
  additional: dict[str, Any] | None = None,
) -> ClientRegistrationRequest:
  """Build a DCR request with the required fields and a consistent type (R-23.14-c/d, R-23.15-a).

  ``redirect_uris`` is REQUIRED (R-23.14-c) and a consistent ``application_type``
  is REQUIRED for MCP clients (R-23.14-d, R-23.15-a); the latter is derived from
  ``is_native`` via :func:`registration_application_type_for` (R-23.15-b/c).

  Args:
    redirect_uris: the client's redirect URIs; MUST be non-empty (R-23.14-c).
    is_native: True for a native client (chooses ``"native"``).
    client_name: OPTIONAL human-readable name.
    grant_types: OPTIONAL grant types (e.g. include ``"refresh_token"`` for refresh
      capability, R-23.19-r).
    response_types: OPTIONAL response types.
    token_endpoint_auth_method: OPTIONAL token-endpoint auth method.
    scope: OPTIONAL space-delimited scopes.
    additional: OPTIONAL further client-metadata fields.

  Returns:
    The :class:`ClientRegistrationRequest`.

  Raises:
    ValueError: ``redirect_uris`` is empty — it is REQUIRED (R-23.14-c).
  """
  if not redirect_uris:
    raise ValueError(
      "a ClientRegistrationRequest MUST include a non-empty 'redirect_uris' "
      "(R-23.14-c)"
    )
  return ClientRegistrationRequest(
    redirect_uris=list(redirect_uris),
    application_type=registration_application_type_for(is_native=is_native),
    client_name=client_name,
    grant_types=grant_types,
    response_types=response_types,
    token_endpoint_auth_method=token_endpoint_auth_method,
    scope=scope,
    additional=dict(additional) if additional is not None else {},
  )


@dataclass(frozen=True)
class ClientRegistrationResponse:
  """A Dynamic Client Registration response (Deprecated) (§23.14, §6.3).

  The AS response returning the issued ``client_id`` (REQUIRED, R-23.14-e) plus any
  registered metadata (echoed back).

  Fields:
    client_id: the issued client identifier; REQUIRED (R-23.14-e).
    client_secret: the issued secret, for confidential clients only; OPTIONAL.
    client_id_issued_at: time the ``client_id`` was issued (Unix seconds);
      OPTIONAL.
    client_secret_expires_at: expiry of ``client_secret`` (Unix seconds); ``0``
      means no expiry; OPTIONAL.
    echoed_metadata: the registered metadata echoed back (e.g. ``redirect_uris``,
      ``application_type``), preserved verbatim (§6.3 ``[key: string]: unknown``).
  """

  client_id: str
  client_secret: str | None = None
  client_id_issued_at: int | None = None
  client_secret_expires_at: int | None = None
  echoed_metadata: dict[str, Any] = field(default_factory=dict)


class ClientRegistrationError(Exception):
  """A Dynamic Client Registration attempt failed (R-23.15-d/e/f).

  A client MUST be prepared for registration to fail because of redirect-URI
  constraints when the AS implements OIDC (R-23.15-d), and SHOULD surface a
  meaningful error to the user or developer (R-23.15-e). This carries the surfaced
  reason and whether the failure can be retried with an adjusted ``application_type``
  or conforming redirect URIs (R-23.15-f).

  Attributes:
    reason: a human-readable description of the rejection (R-23.15-e).
    error: the OAuth ``error`` code from the AS, if any.
    recoverable: True when a retry with an adjusted request may succeed
      (R-23.15-f).
  """

  def __init__(
    self,
    reason: str,
    *,
    error: str | None = None,
    recoverable: bool = False,
  ) -> None:
    super().__init__(reason)
    self.reason: str = reason
    self.error: str | None = error
    self.recoverable: bool = recoverable


def parse_client_registration_response(raw: Any) -> ClientRegistrationResponse:
  """Parse a DCR response, surfacing failures as errors (R-23.14-e, R-23.15-d/e/f).

  On success the body includes the issued ``client_id`` (REQUIRED, R-23.14-e) and
  echoes back the registered metadata. The client MUST be prepared for the AS to
  reject the request because of redirect-URI constraints (R-23.15-d) and SHOULD
  surface a meaningful error on rejection (R-23.15-e): an ``error`` body becomes a
  :class:`ClientRegistrationError` carrying the AS's ``error_description``. An
  ``invalid_redirect_uri`` rejection is marked recoverable so the client MAY retry
  (R-23.15-f).

  Args:
    raw: the JSON-decoded registration response.

  Returns:
    The parsed :class:`ClientRegistrationResponse` on success.

  Raises:
    ClientRegistrationError: the response is an error body or lacks ``client_id``
      (R-23.14-e, R-23.15-d/e).
  """
  if not isinstance(raw, dict):
    raise ClientRegistrationError(
      f"a DCR response must be a JSON object; got {type(raw).__name__}"
    )
  error = raw.get("error")
  if error is not None:
    description = raw.get("error_description") or str(error)
    raise ClientRegistrationError(
      f"dynamic client registration was rejected: {description} (error={error!r}) "
      f"(R-23.15-d/e)",
      error=str(error),
      recoverable=error == "invalid_redirect_uri",
    )
  client_id = raw.get("client_id")
  if not isinstance(client_id, str) or not client_id:
    raise ClientRegistrationError(
      "a successful ClientRegistrationResponse MUST include a 'client_id'; it is "
      "missing (R-23.14-e)"
    )
  client_secret = raw.get("client_secret")
  if client_secret is not None and not isinstance(client_secret, str):
    raise ClientRegistrationError("DCR client_secret, when present, must be a string")
  echoed_keys = {
    "client_id",
    "client_secret",
    "client_id_issued_at",
    "client_secret_expires_at",
  }
  return ClientRegistrationResponse(
    client_id=client_id,
    client_secret=client_secret,
    client_id_issued_at=_optional_int(raw, "client_id_issued_at"),
    client_secret_expires_at=_optional_int(raw, "client_secret_expires_at"),
    echoed_metadata={k: v for k, v in raw.items() if k not in echoed_keys},
  )


def surface_registration_error(error: ClientRegistrationError) -> str:
  """Return a meaningful, user/developer-facing message for a DCR rejection (R-23.15-e).

  On rejection (e.g. an OIDC redirect-URI constraint, R-23.15-d) the client SHOULD
  surface a meaningful error to the user or developer (R-23.15-e). This renders
  the rejection reason (and OAuth ``error`` code when present) into a single
  message a caller can display or log.

  Args:
    error: the :class:`ClientRegistrationError` raised by the parse/registration.

  Returns:
    A human-readable description of the failure (R-23.15-e).
  """
  if error.error:
    return f"client registration failed ({error.error}): {error.reason}"
  return f"client registration failed: {error.reason}"


def retry_client_registration(
  request: ClientRegistrationRequest,
  error: ClientRegistrationError,
  *,
  adjusted_application_type: RegistrationApplicationType | None = None,
  conforming_redirect_uris: list[str] | None = None,
) -> ClientRegistrationRequest:
  """Build an adjusted DCR request after a recoverable rejection (R-23.15-f).

  On a recoverable rejection the client MAY retry registration with an adjusted
  ``application_type`` or with redirect URIs that conform to the AS's requirements
  (R-23.15-f). This returns a new request with the supplied adjustments applied; at
  least one adjustment is required, and the original ``error`` must be recoverable.

  Args:
    request: the rejected request to base the retry on.
    error: the recoverable :class:`ClientRegistrationError` that prompted the retry.
    adjusted_application_type: a different ``application_type`` to try.
    conforming_redirect_uris: redirect URIs that conform to the AS's constraints.

  Returns:
    A new :class:`ClientRegistrationRequest` with the adjustments applied.

  Raises:
    ClientRegistrationError: ``error`` is not recoverable (R-23.15-d).
    ValueError: no adjustment was supplied.
  """
  if not error.recoverable:
    raise ClientRegistrationError(
      f"the registration error is not recoverable; cannot retry: {error.reason} "
      f"(R-23.15-d)",
      error=error.error,
      recoverable=False,
    )
  if adjusted_application_type is None and conforming_redirect_uris is None:
    raise ValueError(
      "a DCR retry MUST adjust the application_type or use conforming redirect "
      "URIs (R-23.15-f)"
    )
  return ClientRegistrationRequest(
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
    additional=dict(request.additional),
  )


# ===========================================================================
# §23.16  Credential binding to the issuer
# ===========================================================================


def issuers_match(stored_issuer: str, discovered_issuer: str) -> bool:
  """Compare two issuer identifiers by EXACT string match (R-23.16-f).

  The comparison between a stored issuer and a discovered issuer MUST be an exact
  string match (R-23.16-f): no scheme/host case folding, default-port elision,
  trailing-slash, or percent-encoding normalization is applied. Two issuers that
  differ only by such normalization are treated as DIFFERENT.

  Args:
    stored_issuer: the ``issuer`` the credentials were registered with.
    discovered_issuer: the ``issuer`` discovered for the target MCP server.

  Returns:
    True only when the two strings are byte-for-byte identical.
  """
  return stored_issuer == discovered_issuer


class IssuerCredentialMismatchError(ValueError):
  """Stored credentials' AS does not match the discovered AS (R-23.16-d/g).

  Raised by :func:`bind_credentials_to_issuer` / :meth:`IssuerBoundCredentialStore`
  when the AS indicated by protected-resource metadata does not match the one a set
  of credentials was registered with (exact ``issuer`` comparison, R-23.16-d). For
  pre-registered credentials the client SHOULD surface this error rather than
  silently using mismatched credentials (R-23.16-g).

  Attributes:
    credential_issuer: the ``issuer`` the credentials were registered with.
    discovered_issuer: the ``issuer`` discovered for the target MCP server.
  """

  def __init__(self, credential_issuer: str, discovered_issuer: str) -> None:
    super().__init__(
      f"credentials registered with authorization server {credential_issuer!r} "
      f"MUST NOT be reused with authorization server {discovered_issuer!r} "
      f"indicated by protected-resource metadata; the client surfaces an error "
      f"rather than using mismatched credentials (R-23.16-d/g)"
    )
    self.credential_issuer: str = credential_issuer
    self.discovered_issuer: str = discovered_issuer


def bind_credentials_to_issuer(
  credential_issuer: str,
  discovered_issuer: str,
) -> None:
  """Confirm credentials may be reused with the discovered AS, else raise (R-23.16-c/d/g).

  A client MUST NOT reuse credentials issued by one AS with a different AS
  (R-23.16-c); when the target MCP server's protected-resource metadata indicates a
  different AS (detected by comparing the ``issuer`` exactly), the client MUST NOT
  reuse the existing credentials (R-23.16-d) and SHOULD surface an error rather
  than silently using mismatched credentials (R-23.16-g).

  Args:
    credential_issuer: the ``issuer`` the credentials were registered with.
    discovered_issuer: the ``issuer`` discovered for the target MCP server.

  Raises:
    IssuerCredentialMismatchError: the issuers differ by exact comparison
      (R-23.16-d/g).
  """
  if not issuers_match(credential_issuer, discovered_issuer):
    raise IssuerCredentialMismatchError(credential_issuer, discovered_issuer)


@dataclass
class _IssuerBoundRecord:
  """One credential set keyed by its issuing AS ``issuer`` (R-23.16-a/b)."""

  issuer: str
  credentials: Any


class IssuerBoundCredentialStore:
  """Persisted client credentials keyed by the issuing AS ``issuer`` (R-23.16-a..e).

  A client that uses pre-registered credentials, or persists DCR-obtained
  credentials, MUST associate them with the specific AS that issued them, keyed by
  that AS's ``issuer`` from the validated AS metadata (R-23.16-a); the storage key
  MUST be the ``issuer`` (R-23.16-b). Credentials are returned ONLY for an exact
  ``issuer`` match (R-23.16-c/f), so a different target AS never sees them; when no
  credentials exist for the discovered issuer the client MUST re-register
  (R-23.16-e). CIMD ``client_id`` URLs are exempt — they carry no per-issuer state —
  and need not be stored here (§23.16 exemption).
  """

  def __init__(self) -> None:
    self._by_issuer: dict[str, _IssuerBoundRecord] = {}

  def store(self, issuer: str, credentials: Any) -> None:
    """Persist ``credentials`` under their issuing AS ``issuer`` (R-23.16-a/b)."""
    if not issuer:
      raise ValueError(
        "the storage key for persisted client credentials MUST be the AS's "
        "non-empty 'issuer' identifier (R-23.16-b)"
      )
    self._by_issuer[issuer] = _IssuerBoundRecord(issuer=issuer, credentials=credentials)

  def get(self, issuer: str) -> Any | None:
    """Return the credentials registered with ``issuer`` only, by exact match (R-23.16-c/f).

    Returns None for any other issuer, so credentials issued by one AS are never
    reused with a different AS (R-23.16-c) — the lookup is an exact string match
    (R-23.16-f).
    """
    record = self._by_issuer.get(issuer)
    return record.credentials if record is not None else None

  def must_reregister(self, discovered_issuer: str) -> bool:
    """Return True iff the client MUST re-register for ``discovered_issuer`` (R-23.16-e).

    When the target MCP server's protected-resource metadata indicates a different
    AS than any held credentials were registered with (no exact-match credentials
    are stored), the client MUST re-register with the new AS (R-23.16-e).
    """
    return discovered_issuer not in self._by_issuer


def cimd_credentials_exempt_from_reregistration() -> bool:
  """Return True: CIMD credentials are exempt from re-registration (§23.16 exemption).

  Credentials based on a Client ID Metadata Document are exempt from
  re-registration, because the ``client_id`` is a portable self-hosted HTTPS URL
  the AS resolves on demand; there is no per-issuer registration state to bind
  (informative §23.16 exemption).
  """
  return True


# ===========================================================================
# §23.17  Discovery robustness
# ===========================================================================


def locate_protected_resource_metadata_urls(
  endpoint_url: str,
  *,
  www_authenticate: str | None = None,
  headers: dict[str, Any] | None = None,
) -> list[str]:
  """Locate the protected-resource metadata URL(s) in priority order (R-23.17-a/b).

  If the MCP server returned a ``WWW-Authenticate`` header with a
  ``resource_metadata`` parameter on a ``401`` response, the client MUST use that
  URL (R-23.17-a) — so a single-element list with that URL is returned. Otherwise
  the client MUST fall back to constructing the well-known URIs in order
  (R-23.17-b): (1) the suffix prefixed to the MCP endpoint's path component, then
  (2) the suffix at the host root. The well-known construction reuses the S35
  builder.

  Args:
    endpoint_url: the MCP server endpoint URL (used for the well-known fallback).
    www_authenticate: the raw ``WWW-Authenticate`` header value, if known.
    headers: a header mapping to look the header up in, when not given directly.

  Returns:
    The ordered list of candidate metadata URLs (one when taken from the header).
  """
  from_header = locate_protected_resource_metadata_uri(
    www_authenticate=www_authenticate, headers=headers
  )
  if from_header is not None:
    return [from_header]  # R-23.17-a: MUST use the header-supplied URL.
  return build_protected_resource_well_known_urls(endpoint_url)  # R-23.17-b


def protected_resource_authorization_servers(
  metadata: ProtectedResourceMetadata,
) -> list[str]:
  """Return the ``authorization_servers`` from protected-resource metadata (R-23.17-c/d).

  The protected-resource metadata document MUST contain ``authorization_servers``,
  an array of one or more AS issuer identifiers (R-23.17-c). When more than one is
  listed, each is independent and the client selects which to use, maintaining
  separate registration state per AS (R-23.17-d) — see
  :class:`IssuerBoundCredentialStore`.

  Args:
    metadata: the validated protected-resource metadata.

  Returns:
    The non-empty list of AS issuer identifiers (R-23.17-c).

  Raises:
    ValueError: ``authorization_servers`` is empty (it MUST list at least one,
      R-23.17-c).
  """
  servers = metadata.authorization_servers
  if not servers:
    raise ValueError(
      "protected-resource metadata MUST contain a non-empty 'authorization_servers' "
      "array of one or more AS issuer identifiers (R-23.17-c)"
    )
  return list(servers)


def build_authorization_server_metadata_urls(issuer: str) -> list[str]:
  """Build the AS-metadata well-known URLs in §23.17 priority order (R-23.17-e/f/g).

  A client MUST attempt multiple well-known endpoints derived from the AS's
  ``issuer`` to interoperate with both OAuth 2.0 Authorization Server Metadata and
  OpenID Connect Discovery 1.0 (R-23.17-e). For an issuer URL **with** a path
  component the order is OAuth path insertion, OIDC path insertion, OIDC path
  appending (R-23.17-f); for an issuer **without** a path component the order is
  OAuth then OIDC (R-23.17-g). This reuses the S35 builder, which encodes exactly
  this ordering.

  Args:
    issuer: the AS ``issuer`` identifier selected from ``authorization_servers``.

  Returns:
    The ordered list of candidate AS-metadata URLs to try (R-23.17-f/g).
  """
  return build_authorization_server_well_known_urls(issuer)


def validate_authorization_server_metadata_issuer(
  metadata: AuthorizationServerMetadata,
  expected_issuer: str,
) -> None:
  """Validate a fetched AS-metadata document's ``issuer`` self-consistency (R-23.17-h/i).

  After retrieving an AS-metadata document the client MUST validate that the
  ``issuer`` value in the document is identical to the issuer identifier used to
  construct the well-known URL (R-23.17-h); if they differ the client MUST NOT use
  the metadata (R-23.17-i) — e.g. expecting ``https://honest.example`` but
  receiving ``"issuer": "https://attacker.example"`` is rejected. This delegates to
  the S35 exact-match check.

  Args:
    metadata: the parsed AS-metadata document.
    expected_issuer: the issuer identifier used to build the well-known URL.

  Raises:
    IssuerMismatchError: the document's ``issuer`` is not identical to
      ``expected_issuer`` (R-23.17-i). Re-exported from S35.
  """
  validate_issuer_matches(metadata, expected_issuer)


# ===========================================================================
# §23.18  Scope selection
# ===========================================================================


def select_initial_scope(
  challenge: BearerChallenge | None,
  protected_resource_metadata: ProtectedResourceMetadata | None,
) -> str | None:
  """Select the initial-handshake ``scope`` by least-privilege priority (R-23.18-a..d).

  During the initial authorization handshake the client SHOULD follow least
  privilege and select scopes in this order (R-23.18-a): (1) the ``scope`` from the
  initial ``WWW-Authenticate`` challenge if present — treated as AUTHORITATIVE for
  the current operation (R-23.18-b) with NO assumed set relationship to
  ``scopes_supported`` (R-23.18-c); (2) otherwise all scopes from
  ``scopes_supported``; (3) when ``scopes_supported`` is absent, omit ``scope``
  entirely (R-23.18-d).

  Args:
    challenge: the parsed ``WWW-Authenticate`` challenge, if one was received.
    protected_resource_metadata: the MCP server's protected-resource metadata.

  Returns:
    The space-delimited ``scope`` string to send, or None to omit ``scope``.
  """
  if challenge is not None and challenge.scope:
    return challenge.scope  # (1) challenged scope is authoritative (R-23.18-b/c).
  if (
    protected_resource_metadata is not None
    and protected_resource_metadata.scopes_supported
  ):
    return " ".join(protected_resource_metadata.scopes_supported)  # (2)
  return None  # (3) scopes_supported absent → omit scope (R-23.18-d).


def challenged_scopes_are_authoritative(
  challenge: BearerChallenge,
  scopes_supported: list[str] | None = None,
) -> list[str]:
  """Return the challenged scopes verbatim as authoritative (R-23.18-b/c).

  A client MUST treat the challenged scopes as authoritative for the current
  operation (R-23.18-b) and MUST NOT assume any set relationship between them and
  ``scopes_supported`` (R-23.18-c). Accordingly this returns the challenged scopes
  unchanged and ignores ``scopes_supported`` entirely (it is accepted only to make
  the independence explicit at the call site).

  Args:
    challenge: the parsed challenge carrying the authoritative ``scope`` set.
    scopes_supported: deliberately unused — no set relationship may be assumed
      (R-23.18-c).

  Returns:
    The challenged scopes (possibly empty), unchanged.
  """
  return challenge.scopes


# ===========================================================================
# §23.18  Insufficient-scope challenge (response shape owned by S35; restated)
# ===========================================================================

#: The ``error`` value REQUIRED on the insufficient-scope challenge (R-23.18-f).
INSUFFICIENT_SCOPE_ERROR_CODE: str = INSUFFICIENT_SCOPE_ERROR

#: The §23.18 / §23.1 authorization status-condition mapping (reference only;
#: owned by S35). 401 = authorization required / token absent/invalid; 403 =
#: invalid scopes / insufficient permissions; 400 = malformed authorization
#: request.
AUTHORIZATION_CONDITION_BY_STATUS: dict[int, str] = {
  HTTP_UNAUTHORIZED: "authorization required, or token absent/invalid",
  HTTP_FORBIDDEN: "invalid scopes or insufficient permissions",
  HTTP_BAD_REQUEST: "malformed authorization request",
}


@dataclass(frozen=True)
class InsufficientScopeChallenge:
  """The runtime trigger view of a ``403`` insufficient-scope challenge (§23.18).

  The authoritative ``403`` response shape is owned by S35; this restates the
  challenge as the runtime trigger for the step-up flow (§7.10/§7.11). The server
  SHOULD respond ``403 Forbidden`` with a ``Bearer`` challenge (R-23.18-e) carrying
  ``error="insufficient_scope"`` (REQUIRED, R-23.18-f), a ``scope`` (RECOMMENDED,
  R-23.18-g) and ``resource_metadata`` (RECOMMENDED, R-23.18-h), and OPTIONALLY an
  ``error_description`` (R-23.18-i). The server SHOULD include ALL scopes required
  for the operation in a single challenge (R-23.18-j) and be consistent in its
  scope-inclusion strategy (R-23.18-k).

  Fields:
    scope: the space-delimited scopes required to satisfy the current operation.
    resource_metadata: the protected-resource metadata document URL.
    error_description: an OPTIONAL human-readable description.
    status: the HTTP status — always ``403`` (R-23.18-e).
    error: the ``error`` code — always ``"insufficient_scope"`` (R-23.18-f).
  """

  scope: str | None = None
  resource_metadata: str | None = None
  error_description: str | None = None
  status: int = HTTP_FORBIDDEN
  error: str = INSUFFICIENT_SCOPE_ERROR_CODE

  @property
  def scopes(self) -> list[str]:
    """Return the challenged scopes as a list (space-delimited ``scope``)."""
    return self.scope.split() if self.scope else []

  def to_www_authenticate(self) -> str:
    """Render the ``WWW-Authenticate`` value for this challenge (R-23.18-e..i).

    Defers to the S35 :class:`BearerChallenge` renderer so the wire shape matches
    the response-shape grade owned by S35.
    """
    return BearerChallenge(
      resource_metadata=self.resource_metadata,
      scope=self.scope,
      error=self.error,
      error_description=self.error_description,
    ).to_header_value()


def parse_insufficient_scope_challenge(
  header_value: str,
) -> InsufficientScopeChallenge:
  """Parse a ``403`` ``WWW-Authenticate`` value into a step-up trigger (R-23.18-e/l).

  Parses the ``Bearer`` challenge (reusing the S35 parser) into the runtime
  trigger for the step-up flow (R-23.18-l). The challenge MUST carry
  ``error="insufficient_scope"`` (R-23.18-f); any other ``error`` is not a
  scope-shortfall trigger and is rejected.

  Args:
    header_value: the raw ``WWW-Authenticate`` header value from the ``403``.

  Returns:
    The parsed :class:`InsufficientScopeChallenge`.

  Raises:
    ValueError: the header is not a Bearer challenge or its ``error`` is not
      ``"insufficient_scope"`` (R-23.18-f).
  """
  # Parse using the S35 challenge parser to keep the wire shape under S35's grade.
  from mcp_sdk_py.authorization import parse_www_authenticate

  challenge = parse_www_authenticate(header_value)
  if challenge.error != INSUFFICIENT_SCOPE_ERROR_CODE:
    raise ValueError(
      f"the challenge error {challenge.error!r} is not "
      f"{INSUFFICIENT_SCOPE_ERROR_CODE!r}; it is not an insufficient-scope "
      f"trigger for the step-up flow (R-23.18-f)"
    )
  return InsufficientScopeChallenge(
    scope=challenge.scope,
    resource_metadata=challenge.resource_metadata,
    error_description=challenge.error_description,
  )


# ===========================================================================
# §23.18  Step-up authorization flow
# ===========================================================================

#: The default bound on step-up retries: "no more than a few" (R-23.18-q/r).
DEFAULT_STEP_UP_RETRY_LIMIT: int = 3


class StepUpActorKind(enum.Enum):
  """Which kind of client is performing the step-up flow (R-23.18-m/n).

  USER_AGENT:
    A client acting on behalf of a user; it SHOULD attempt the step-up flow
    (R-23.18-m).
  CLIENT_CREDENTIALS:
    A client acting on its own behalf (a ``client_credentials`` client); it MAY
    attempt the step-up flow or abort the request (R-23.18-n).
  """

  USER_AGENT = "user_agent"
  CLIENT_CREDENTIALS = "client_credentials"


class PermanentAuthorizationFailureError(Exception):
  """Step-up retries were exhausted without success (R-23.18-q, R-23.1-af).

  The client retries the original request after re-authorizing no more than a few
  times; persistent failure MUST be treated as a permanent authorization failure
  (R-23.18-q). Raised when the retry limit is reached.

  Attributes:
    resource: the MCP server resource the operation targeted.
    operation: the operation being retried.
    attempts: how many step-up attempts were made before giving up.
  """

  def __init__(self, resource: str, operation: str, attempts: int) -> None:
    super().__init__(
      f"step-up authorization for operation {operation!r} on resource "
      f"{resource!r} failed permanently after {attempts} attempt(s); persistent "
      f"failure is a permanent authorization failure (R-23.18-q)"
    )
    self.resource: str = resource
    self.operation: str = operation
    self.attempts: int = attempts


def union_scopes(granted: list[str] | str | None, challenged: list[str] | str) -> list[str]:
  """Compute the UNION of already-granted and newly-challenged scopes (R-23.18-o/p).

  When determining the required scopes for re-authorization the client MUST
  accumulate (union) the already-granted/already-requested scopes with the newly
  challenged scopes (R-23.18-o) and MUST NOT drop the already-granted scopes, or it
  would lose permissions needed for other operations (R-23.18-p). For example a
  client holding ``files:read`` challenged for ``files:write`` re-authorizes with
  ``["files:read", "files:write"]`` and does NOT drop ``files:read``. Order is
  stable: granted scopes first (in their given order), then any newly challenged
  scopes not already present. Hierarchically redundant scopes need not be
  deduplicated — the AS normalizes redundancy during token issuance (R-23.18-r).

  Args:
    granted: the already-granted/already-requested scopes (list, space-delimited
      string, or None).
    challenged: the scopes from the current challenge (list or space-delimited
      string).

  Returns:
    The union as an order-stable list, granted scopes preserved (R-23.18-o/p).
  """
  granted_list = _as_scope_list(granted)
  challenged_list = _as_scope_list(challenged)
  result = list(granted_list)  # R-23.18-p: never drop already-granted scopes.
  for scope in challenged_list:
    if scope not in result:
      result.append(scope)
  return result


@dataclass
class ScopeUpgradeTracker:
  """Tracks step-up attempts per resource-and-operation, enforcing a limit (R-23.18-q/r).

  A client SHOULD implement retry limits and SHOULD track scope-upgrade attempts to
  avoid repeated failures for the same resource-and-operation combination
  (R-23.18-r); persistent failure MUST be treated as a permanent authorization
  failure (R-23.18-q). This counts attempts keyed by ``(resource, operation)`` and
  refuses further attempts once the limit is reached.

  Fields:
    retry_limit: the maximum number of step-up attempts per resource-and-operation
      (a small bound, R-23.18-q/r).
  """

  retry_limit: int = DEFAULT_STEP_UP_RETRY_LIMIT
  _attempts: dict[tuple[str, str], int] = field(default_factory=dict)

  def attempts(self, resource: str, operation: str) -> int:
    """Return how many step-up attempts were recorded for this combination (R-23.18-r)."""
    return self._attempts.get((resource, operation), 0)

  def may_attempt(self, resource: str, operation: str) -> bool:
    """Return True iff a further step-up attempt is within the limit (R-23.18-q/r)."""
    return self.attempts(resource, operation) < self.retry_limit

  def record_attempt(self, resource: str, operation: str) -> int:
    """Record one step-up attempt for the combination, enforcing the limit (R-23.18-q).

    Raises:
      PermanentAuthorizationFailureError: the retry limit is already reached;
        persistent failure is a permanent authorization failure (R-23.18-q).
    """
    if not self.may_attempt(resource, operation):
      raise PermanentAuthorizationFailureError(
        resource, operation, self.attempts(resource, operation)
      )
    key = (resource, operation)
    self._attempts[key] = self._attempts.get(key, 0) + 1
    return self._attempts[key]


def should_attempt_step_up(actor: StepUpActorKind) -> bool:
  """Decide whether to attempt the step-up flow for an actor kind (R-23.18-l/m/n).

  On a scope-related error a client SHOULD obtain a new access token with an
  increased scope set via the step-up flow (R-23.18-l). A client acting on behalf
  of a user SHOULD attempt it (R-23.18-m); a ``client_credentials`` client MAY
  attempt it or abort (R-23.18-n). This returns the SHOULD recommendation: True for
  a user-agent client, and (by default) True for a client_credentials client, which
  remains free to abort instead.

  Args:
    actor: the kind of client performing the operation.

  Returns:
    True when the step-up flow is recommended/permitted for the actor.
  """
  if actor is StepUpActorKind.USER_AGENT:
    return True  # R-23.18-m: SHOULD attempt.
  return True  # R-23.18-n: MAY attempt (or abort); attempting is permitted.


@dataclass(frozen=True)
class StepUpReauthorizationPlan:
  """The plan for a step-up re-authorization request (R-23.18-q, R-23.19-a/e/k).

  Describes the fresh authorization-code + PKCE flow the client initiates with the
  unioned scope set: the ``resource`` parameter identifying the MCP server
  (R-23.19-a) and the recorded expected ``issuer`` (R-23.19-e), with PKCE and
  ``state`` carried by the S36 flow. The mechanics live in S36; this captures the
  S37-owned decision (union scopes + bounded retry).

  Fields:
    scope: the space-delimited union scope set to request (R-23.18-o/p).
    resource: the MCP server's canonical resource identifier (R-23.19-a).
    recorded_issuer: the validated ``issuer`` recorded before redirect (R-23.19-e).
  """

  scope: str
  resource: str
  recorded_issuer: str


def plan_step_up_reauthorization(
  challenge: InsufficientScopeChallenge,
  *,
  granted_scopes: list[str] | str | None,
  resource: str,
  recorded_issuer: str,
) -> StepUpReauthorizationPlan:
  """Plan a step-up re-authorization from an insufficient-scope challenge (R-23.18-l..q).

  Builds the re-authorization plan: parse the challenge (R-23.18-l), union the
  already-granted scopes with the challenged scopes WITHOUT dropping the granted
  ones (R-23.18-o/p), and carry the ``resource`` (R-23.19-a) and recorded
  ``issuer`` (R-23.19-e) the fresh S36 auth-code+PKCE flow needs (R-23.18-q). The
  caller drives the bounded retry via a :class:`ScopeUpgradeTracker`.

  Args:
    challenge: the parsed insufficient-scope challenge (R-23.18-l).
    granted_scopes: the scopes the client already holds/requested (R-23.18-o).
    resource: the MCP server's canonical resource identifier (R-23.19-a).
    recorded_issuer: the validated AS ``issuer`` recorded before redirect
      (R-23.19-e).

  Returns:
    A :class:`StepUpReauthorizationPlan` carrying the union scope and binding
    parameters.
  """
  union = union_scopes(granted_scopes, challenge.scopes)
  return StepUpReauthorizationPlan(
    scope=" ".join(union),
    resource=resource,
    recorded_issuer=recorded_issuer,
  )


# ===========================================================================
# §23.19  Authorization security considerations
# ===========================================================================

#: The Resource Indicators (RFC 8707) parameter name sent on both the
#: authorization request and the token request (R-23.19-a).
RESOURCE_INDICATOR_PARAMETER: str = "resource"

#: The PKCE code-challenge method REQUIRED by §23.19 (R-23.19-k).
REQUIRED_PKCE_METHOD: str = "S256"

#: The request header an access token MUST be sent in, and only there (R-23.19-p).
BEARER_AUTHORIZATION_HEADER: str = "Authorization"
#: The ``Authorization`` header value prefix for a bearer token (R-23.19-p).
BEARER_TOKEN_PREFIX: str = f"{BEARER_SCHEME} "


def resource_parameters_for_flow(canonical_resource: str) -> dict[str, str]:
  """Return the ``resource`` parameter for BOTH flow legs (R-23.19-a).

  A client MUST implement Resource Indicators by sending a ``resource`` parameter,
  identifying the MCP server by its canonical URI, in BOTH the authorization
  request and the token request, regardless of whether the AS is known to support
  it (R-23.19-a). This returns the ``{resource: <canonical>}`` parameter the client
  adds to each leg.

  Args:
    canonical_resource: the MCP server's canonical resource identifier.

  Returns:
    The single-entry ``resource`` parameter mapping (R-23.19-a).

  Raises:
    ValueError: ``canonical_resource`` is empty — it MUST be sent (R-23.19-a).
  """
  if not canonical_resource:
    raise ValueError(
      "a client MUST send a non-empty 'resource' parameter identifying the MCP "
      "server's canonical URI on both the authorization and token requests "
      "(R-23.19-a)"
    )
  return {RESOURCE_INDICATOR_PARAMETER: canonical_resource}


class TokenAudienceError(ValueError):
  """A token's audience does not match the server it is presented to (R-23.19-b/d).

  Raised by :func:`server_accepts_audience_bound_token` when a server is presented
  a token whose audience is not itself: a server MUST validate that an access token
  was issued specifically for it as the intended audience and MUST reject tokens
  whose audience does not match (R-23.19-b), and MUST NOT accept or transit any
  token other than one issued for it (R-23.19-d).
  """


def server_accepts_audience_bound_token(
  token_audience: str,
  server_resource: str,
) -> bool:
  """Validate that a token's audience matches the server, else raise (R-23.19-b/d).

  A server MUST validate that an access token was issued specifically for it as the
  intended audience and MUST reject tokens whose audience does not match
  (R-23.19-b); it MUST NOT accept or transit any token other than one issued for it
  (R-23.19-d). The audience is compared exactly to the server's canonical resource
  identifier.

  Args:
    token_audience: the audience the token was issued for.
    server_resource: the server's own canonical resource identifier.

  Returns:
    True when the audiences match exactly.

  Raises:
    TokenAudienceError: the token's audience does not match the server (R-23.19-b/d).
  """
  if token_audience != server_resource:
    raise TokenAudienceError(
      f"a token issued for audience {token_audience!r} MUST NOT be accepted by the "
      f"server {server_resource!r}; the server rejects tokens whose audience does "
      f"not match (R-23.19-b/d)"
    )
  return True


def client_may_send_token_to_server(
  token_issuing_authorization_server: str,
  server_authorization_server: str,
) -> bool:
  """Decide whether a client may send a token to a given MCP server (R-23.19-c).

  A client MUST NOT send a token to an MCP server other than one issued by that MCP
  server's authorization server (R-23.19-c). The token may be sent only when the
  AS that issued it is the AS the target server relies on (exact ``issuer``
  comparison).

  Args:
    token_issuing_authorization_server: the ``issuer`` of the AS that issued the
      token.
    server_authorization_server: the ``issuer`` of the AS the target MCP server
      relies on.

  Returns:
    True only when the two issuers match exactly (R-23.19-c).
  """
  return issuers_match(
    token_issuing_authorization_server, server_authorization_server
  )


@dataclass(frozen=True)
class PerRequestAuthorizationRecord:
  """The per-request record holding the recorded issuer, verifier, and state (R-23.19-e/j).

  A client MUST record the validated ``issuer`` of the selected AS before
  redirecting the user-agent (R-23.19-e); the recorded issuer, PKCE
  ``code_verifier``, and ``state`` MUST be stored in the SAME per-request record
  (R-23.19-j). This is the §23.19 view of that record; the S36 flow consumes it for
  the ``iss``/``state`` validation.

  Fields:
    recorded_issuer: the validated AS ``issuer`` recorded before redirect
      (R-23.19-e).
    code_verifier: the PKCE ``code_verifier`` (kept secret until the token
      request, R-23.19-k).
    state: the unpredictable ``state`` value (R-23.19-l).
  """

  recorded_issuer: str
  code_verifier: str
  state: str | None = None


def record_per_request_authorization(
  *,
  validated_issuer: str,
  code_verifier: str,
  state: str | None = None,
) -> PerRequestAuthorizationRecord:
  """Create the single per-request record before redirecting (R-23.19-e/j).

  A client MUST record the validated ``issuer`` of the selected AS before
  redirecting the user-agent (R-23.19-e), and the recorded issuer, PKCE
  ``code_verifier``, and ``state`` MUST live in the SAME per-request record
  (R-23.19-j). This binds all three together.

  Args:
    validated_issuer: the validated AS ``issuer`` to record (R-23.19-e).
    code_verifier: the PKCE ``code_verifier`` (R-23.19-k).
    state: the unpredictable ``state`` value, if used (R-23.19-l).

  Returns:
    The :class:`PerRequestAuthorizationRecord`.

  Raises:
    ValueError: ``validated_issuer`` or ``code_verifier`` is empty (both are
      required parts of the record, R-23.19-e/j/k).
  """
  if not validated_issuer:
    raise ValueError(
      "the validated AS 'issuer' MUST be recorded before redirecting (R-23.19-e)"
    )
  if not code_verifier:
    raise ValueError(
      "the PKCE 'code_verifier' MUST be stored in the per-request record "
      "(R-23.19-j/k)"
    )
  return PerRequestAuthorizationRecord(
    recorded_issuer=validated_issuer,
    code_verifier=code_verifier,
    state=state,
  )


def validate_response_iss(
  record: PerRequestAuthorizationRecord,
  *,
  returned_iss: str | None,
  iss_parameter_supported: bool | None,
) -> bool:
  """Validate the authorization-response ``iss`` against the recorded issuer (R-23.19-f/g/h).

  Before transmitting the authorization code to any token endpoint the client MUST
  validate the ``iss`` returned in the authorization response against the recorded
  issuer using EXACT string comparison (R-23.19-f). If the AS metadata sets
  ``authorization_response_iss_parameter_supported`` to ``true`` and ``iss`` is
  absent, the client MUST reject the response (R-23.19-g). If ``iss`` is present the
  client MUST compare it exactly regardless of metadata (R-23.19-h).

  Args:
    record: the per-request record carrying the recorded issuer (R-23.19-e).
    returned_iss: the ``iss`` value in the authorization response (or None).
    iss_parameter_supported: the AS's
      ``authorization_response_iss_parameter_supported`` (None when absent).

  Returns:
    True when validation passes (either an exact ``iss`` match, or no ``iss`` while
    the AS does not advertise support).

  Raises:
    ResponseIssMismatchError: ``iss`` is absent while the AS advertises support
      (R-23.19-g), or a present ``iss`` does not match the recorded issuer exactly
      (R-23.19-f/h).
  """
  supported = iss_parameter_supported is True
  if returned_iss is None:
    if supported:
      raise ResponseIssMismatchError(
        record.recorded_issuer,
        None,
        "the AS advertises authorization_response_iss_parameter_supported: true "
        "but no 'iss' was returned; the response MUST be rejected (R-23.19-g)",
      )
    return True  # No iss, not advertised → nothing to compare.
  # R-23.19-h: a present iss MUST be compared exactly, regardless of metadata.
  if not issuers_match(returned_iss, record.recorded_issuer):
    raise ResponseIssMismatchError(
      record.recorded_issuer,
      returned_iss,
      "the returned 'iss' does not match the recorded issuer by exact string "
      "comparison; the code MUST NOT be transmitted (R-23.19-f/h)",
    )
  return True


class ResponseIssMismatchError(ValueError):
  """The authorization response's ``iss`` failed validation (R-23.19-f/g/h/i).

  Raised by :func:`validate_response_iss` when ``iss`` is absent though advertised
  (R-23.19-g) or a present ``iss`` does not exactly match the recorded issuer
  (R-23.19-f/h). On such a mismatch the client MUST NOT act on or display the
  authorization code or any ``error``, ``error_description``, or ``error_uri``
  (R-23.19-i) — see :func:`authorization_response_is_actionable`.

  Attributes:
    recorded_issuer: the issuer recorded before the redirect.
    returned_iss: the ``iss`` returned (or None when absent).
  """

  def __init__(
    self, recorded_issuer: str, returned_iss: str | None, detail: str
  ) -> None:
    super().__init__(
      f"iss validation failed (recorded={recorded_issuer!r}, "
      f"returned={returned_iss!r}): {detail}"
    )
    self.recorded_issuer: str = recorded_issuer
    self.returned_iss: str | None = returned_iss


def authorization_response_is_actionable(
  record: PerRequestAuthorizationRecord,
  *,
  returned_iss: str | None,
  iss_parameter_supported: bool | None,
) -> bool:
  """Return whether the authorization response may be acted on/displayed (R-23.19-i).

  On an ``iss`` mismatch the client MUST NOT act on or display the authorization
  code or any ``error``, ``error_description``, or ``error_uri`` (R-23.19-i). This
  reports actionability without raising: False when :func:`validate_response_iss`
  would reject (so the caller suppresses the code AND any error fields), True
  otherwise.

  Args:
    record: the per-request record carrying the recorded issuer.
    returned_iss: the ``iss`` returned in the response (or None).
    iss_parameter_supported: the AS's
      ``authorization_response_iss_parameter_supported``.

  Returns:
    True when the response is actionable, False when it MUST be suppressed
    (R-23.19-i).
  """
  try:
    return validate_response_iss(
      record,
      returned_iss=returned_iss,
      iss_parameter_supported=iss_parameter_supported,
    )
  except ResponseIssMismatchError:
    return False


def pkce_is_required() -> bool:
  """Return True: a client MUST use PKCE with ``S256`` (R-23.19-k).

  A client MUST use Proof Key for Code Exchange: generate a ``code_verifier``, send
  the derived ``code_challenge`` with ``code_challenge_method=S256`` in the
  authorization request, and send the ``code_verifier`` in the token request
  (R-23.19-k). The PKCE mechanics live in S36; this records that PKCE is mandatory
  here.
  """
  return True


def state_is_recommended() -> bool:
  """Return True: a client SHOULD include and verify an unpredictable ``state`` (R-23.19-l).

  A client SHOULD include an unpredictable ``state`` value in the authorization
  request and verify it on the callback, binding the response to the request as a
  CSRF defense (R-23.19-l). The ``state`` lives in the per-request record
  (:class:`PerRequestAuthorizationRecord`, R-23.19-j).
  """
  return True


class TokenConfidentialityError(ValueError):
  """A token-confidentiality rule was violated (R-23.19-m/n/o/p).

  Raised when an access or refresh token would be logged or forwarded to a third
  party (R-23.19-m/n), or when an access token would be placed in the URI query
  string instead of the ``Authorization: Bearer`` header (R-23.19-p).
  """


def redact_token_for_logging(value: str, token: str) -> str:
  """Redact a token from a string before it is logged (R-23.19-m).

  Access tokens and refresh tokens MUST NOT be logged (R-23.19-m). This replaces
  any occurrence of ``token`` in ``value`` with a fixed redaction marker so a
  caller can log surrounding context without leaking the token.

  Args:
    value: the string about to be logged.
    token: the access or refresh token that MUST NOT appear in logs.

  Returns:
    ``value`` with every occurrence of ``token`` replaced by ``"[REDACTED]"``.
  """
  if not token:
    return value
  return value.replace(token, "[REDACTED]")


def assert_token_not_forwarded(destination_is_third_party: bool) -> None:
  """Assert a token is not being forwarded to a third party (R-23.19-n).

  Access tokens and refresh tokens MUST NOT be forwarded to third parties
  (R-23.19-n). This guards a forwarding decision.

  Args:
    destination_is_third_party: True when the destination is a third party.

  Raises:
    TokenConfidentialityError: the destination is a third party (R-23.19-n).
  """
  if destination_is_third_party:
    raise TokenConfidentialityError(
      "access and refresh tokens MUST NOT be forwarded to third parties "
      "(R-23.19-n)"
    )


def build_bearer_authorization_header(access_token: str) -> dict[str, str]:
  """Build the ``Authorization: Bearer`` header carrying the access token (R-23.19-p).

  A client MUST send the access token ONLY in the
  ``Authorization: Bearer <access-token>`` request header on every request to the
  MCP server (R-23.19-p). This returns that single header; the token MUST NOT be
  placed in the URI query string (see :func:`assert_token_not_in_query_string`).

  Args:
    access_token: the access token to send.

  Returns:
    The ``{"Authorization": "Bearer <token>"}`` header mapping (R-23.19-p).

  Raises:
    ValueError: ``access_token`` is empty.
  """
  if not access_token:
    raise ValueError("the access token to send MUST be non-empty (R-23.19-p)")
  return {BEARER_AUTHORIZATION_HEADER: f"{BEARER_TOKEN_PREFIX}{access_token}"}


def assert_token_not_in_query_string(url: str, access_token: str) -> None:
  """Assert the access token is not present in a request URI query string (R-23.19-p).

  A client MUST NOT place the access token in the URI query string (R-23.19-p); it
  belongs only in the ``Authorization: Bearer`` header. This guards a request URL.

  Args:
    url: the request URL about to be sent.
    access_token: the access token that MUST NOT appear in the query string.

  Raises:
    TokenConfidentialityError: the token appears in the URL's query component
      (R-23.19-p).
  """
  query = urlsplit(url).query
  if access_token and access_token in query:
    raise TokenConfidentialityError(
      "a client MUST NOT place the access token in the URI query string; it goes "
      "only in the Authorization: Bearer header (R-23.19-p)"
    )


# ===========================================================================
# §23.19  Refresh tokens
# ===========================================================================

#: The grant type a client wanting refresh tokens SHOULD include in its client
#: metadata ``grant_types`` (R-23.19-r).
REFRESH_TOKEN_GRANT: str = "refresh_token"

#: The scope a client MAY add to obtain refresh tokens, when the AS lists it in
#: ``scopes_supported`` (R-23.19-s).
OFFLINE_ACCESS_SCOPE_NAME: str = "offline_access"


def client_wants_refresh_grant_types(
  grant_types: list[str] | None,
) -> list[str]:
  """Ensure ``refresh_token`` is present in a client's ``grant_types`` (R-23.19-r).

  A client that wants refresh tokens SHOULD include ``refresh_token`` in its
  ``grant_types`` client metadata (R-23.19-r). This returns the grant-types list
  with ``refresh_token`` added if it was absent (preserving order and any existing
  entries).

  Args:
    grant_types: the client's current ``grant_types`` (or None).

  Returns:
    A grant-types list that includes ``refresh_token`` (R-23.19-r).
  """
  result = list(grant_types) if grant_types is not None else []
  if REFRESH_TOKEN_GRANT not in result:
    result.append(REFRESH_TOKEN_GRANT)
  return result


def may_add_offline_access(
  metadata: AuthorizationServerMetadata,
) -> bool:
  """Return whether a client MAY add ``offline_access`` to its scopes (R-23.19-s).

  A client MAY add ``offline_access`` to the ``scope`` parameter of the
  authorization and token requests when the AS metadata lists ``offline_access`` in
  ``scopes_supported`` (R-23.19-s). Returns True only when the AS advertises it.

  Args:
    metadata: the validated AS metadata.

  Returns:
    True when ``offline_access`` is listed in ``scopes_supported`` (R-23.19-s).
  """
  return (
    metadata.scopes_supported is not None
    and OFFLINE_ACCESS_SCOPE_NAME in metadata.scopes_supported
  )


def add_offline_access_scope(
  scope: str | None,
  metadata: AuthorizationServerMetadata,
) -> str | None:
  """Add ``offline_access`` to a scope string when the AS lists it (R-23.19-s).

  A client MAY add ``offline_access`` to its requested scopes when the AS metadata
  lists it in ``scopes_supported`` (R-23.19-s). This appends ``offline_access`` to
  ``scope`` only when :func:`may_add_offline_access` holds and it is not already
  present; otherwise ``scope`` is returned unchanged.

  Args:
    scope: the current space-delimited scope string (or None).
    metadata: the validated AS metadata.

  Returns:
    The scope string with ``offline_access`` appended when permitted, else the
    original ``scope`` (R-23.19-s).
  """
  if not may_add_offline_access(metadata):
    return scope
  existing = scope.split() if scope else []
  if OFFLINE_ACCESS_SCOPE_NAME in existing:
    return scope
  existing.append(OFFLINE_ACCESS_SCOPE_NAME)
  return " ".join(existing)


def refresh_token_must_be_kept_confidential() -> bool:
  """Return True: a client wanting refresh tokens MUST keep them confidential (R-23.19-q).

  A client that wants refresh tokens MUST keep them confidential in transit and
  storage (R-23.19-q) — the same confidentiality the §23.19 token rules require for
  access and refresh tokens (R-23.19-m/n/o). This records that obligation.
  """
  return True


def refresh_token_is_guaranteed() -> bool:
  """Return False: a client MUST NOT assume a refresh token will be issued (R-23.19-t).

  A client MUST NOT assume a refresh token will be issued; the AS retains
  discretion (R-23.19-t). This always returns False so callers do not depend on a
  refresh token being present.
  """
  return False


def resource_server_should_exclude_offline_access(
  scopes: list[str] | None,
) -> list[str]:
  """Strip ``offline_access`` from a resource server's advertised scopes (R-23.19-u).

  A server (protected resource) SHOULD NOT include ``offline_access`` in its
  ``WWW-Authenticate`` scope or in ``scopes_supported``, because refresh tokens are
  not a resource requirement (R-23.19-u). This returns the scopes with
  ``offline_access`` removed.

  Args:
    scopes: the scope list a resource server would advertise (or None).

  Returns:
    The scopes with ``offline_access`` excluded (R-23.19-u).
  """
  if not scopes:
    return []
  return [s for s in scopes if s != OFFLINE_ACCESS_SCOPE_NAME]


# ===========================================================================
# Internal parsing helpers
# ===========================================================================


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
  """Return ``raw[key]`` as a string, or None when absent."""
  value = raw.get(key)
  if value is None:
    return None
  if not isinstance(value, str):
    raise TypeError(f"{key} must be a string; got {type(value).__name__}")
  return value


def _optional_int(raw: dict[str, Any], key: str) -> int | None:
  """Return ``raw[key]`` as an int, or None when absent (bools are rejected)."""
  value = raw.get(key)
  if value is None:
    return None
  if isinstance(value, bool) or not isinstance(value, int):
    raise TypeError(f"{key} must be an integer; got {type(value).__name__}")
  return value


def _optional_str_list(raw: dict[str, Any], key: str) -> list[str] | None:
  """Return ``raw[key]`` as a list[str], or None when absent."""
  value = raw.get(key)
  if value is None:
    return None
  if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
    raise TypeError(f"{key} must be an array of strings")
  return list(value)


def _as_scope_list(scopes: list[str] | str | None) -> list[str]:
  """Normalize scopes given as a list, space-delimited string, or None to a list."""
  if scopes is None:
    return []
  if isinstance(scopes, str):
    return scopes.split()
  return list(scopes)
