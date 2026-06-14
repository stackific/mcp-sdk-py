"""Security Considerations — the consolidated security baseline — S44.

This module is the authoritative, cross-cutting **security-requirements catalog**
for the MCP Python SDK. §28 of the specification is a consolidating,
principles-and-rules section: it defines **no new wire types**; instead it
restates and binds together the most consequential consent, isolation,
validation, confidentiality, and sandboxing obligations introduced piecemeal
alongside individual features (tools, elicitation, sampling, authorization, UI),
turning them into a single enforceable security baseline (§28). The protocol
cannot enforce most of these obligations at the wire level; conformance depends
on implementations honoring them (R-28-a).

This module therefore does two things, mirroring the cross-cutting governance
pattern of S45 (:mod:`mcp_sdk_py.conformance`):

1. It assembles the authoritative **catalog** of every §28 normative atom — the
   ``SecurityRequirement`` table keyed by atom id, each carrying its RFC-2119
   level, the §28 subsection that owns it, the role(s) it binds, and a one-line
   restatement. This is the single checklist S45 (Conformance) reconciles
   against. The catalog *references* — it never redefines — the behaviours other
   modules implement.

2. Where a §28 rule is a **checkable predicate** that no sibling module already
   owns, it implements the real guard here (the constitution forbids
   isinstance-only "validation" that dodges a rule): the host consent +
   human-in-the-loop gate (§28.2/§28.3), no-silent-escalation / fresh-consent on
   material change (§28.2), the spoof-resistant consent surface and identity
   disclosure (§28.2/§28.7/§28.8), server isolation / no cross-server relay
   (§28.4), continuation-token integrity & replay defense (§28.6), the UI
   sandbox/CSP least-privilege policy (§28.8), the metadata-carries-no-authority
   rule and log redaction (§28.9), bounded-depth/size validation, SSRF guarding,
   no-external-schema-dereference, cursor opacity, and ``file://`` path
   sanitization with authorized-root enforcement (§28.10).

Where a sibling already owns the real check, this module **references** it so the
behaviour lives in exactly one place:

  - Audience binding / token rejection / no-passthrough / per-AS issuer keying —
    S37 (:mod:`mcp_sdk_py.oauth_registration`:
    ``server_accepts_audience_bound_token``, ``client_may_send_token_to_server``,
    ``TokenAudienceError``, ``issuers_match``).
  - Exact issuer comparison (mix-up defense), PKCE ``S256``, ``state`` CSRF —
    S36 (:mod:`mcp_sdk_py.oauth_flow`: ``validate_iss``, ``verify_state``,
    ``PKCE_CODE_CHALLENGE_METHOD``, ``generate_pkce_parameters``,
    ``generate_state``) and S35 (:mod:`mcp_sdk_py.authorization`:
    ``validate_issuer_matches``, ``REQUIRED_CODE_CHALLENGE_METHOD``).
  - ``requestState`` integrity primitives — S17
    (:mod:`mcp_sdk_py.multi_round_trip`: ``make_hmac_request_state``,
    ``verify_hmac_request_state``, ``InvalidRequestStateError``).
  - ``Origin`` validation / DNS-rebinding defense — S15
    (:mod:`mcp_sdk_py.http_responses`: ``OriginValidator``).
  - Tool-annotation untrust and argument schema validation — S24/S25
    (:mod:`mcp_sdk_py.tools_call`: ``client_may_use_annotations``,
    ``validate_arguments_against_input_schema``).
  - Pagination ``Cursor`` opacity — S04/S18
    (:mod:`mcp_sdk_py.result_error`: ``validate_cursor``;
    :mod:`mcp_sdk_py.pagination`: ``InvalidCursorError``).
  - The standard JSON-RPC error codes used to report validation failures — S04/S34
    (:mod:`mcp_sdk_py.errors`).

Out of scope (owned elsewhere, not redefined here): the ``tools/call`` wire
shapes (S25), the Tool / ``inputSchema`` JSON-Schema rules (S24), the elicitation
form schema (S30/S31), the sampling mechanics (S33), the full authorization flow
(S35–S37; §23 prevails), the ``requestState`` exchange algorithm (S17),
pagination format (S18), resource reading and URI schemes (S26/S27), the full
``Origin`` rules (S15/§9.11), trace context and ``_meta`` structure (S05/S23),
and the error-code registry shape (S34).

Spec: §28 Security Considerations (lines 8337–8425)
Depends on: S25 (tools/call), S31 (elicitation consent), S33 (sampling),
  S37 (authorization), S42 (UI host); references S04/S15/S17/S34/S35/S36.
"""

from __future__ import annotations

import enum
import posixpath
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from mcp_sdk_py.errors import INVALID_PARAMS_CODE, INVALID_REQUEST_CODE
from mcp_sdk_py.foundations import RequirementLevel, Role
from mcp_sdk_py.result_error import ErrorObject

# Sibling primitives referenced (never redefined) so each real check lives once.
from mcp_sdk_py.http_responses import OriginValidator  # noqa: F401  (re-exported)
from mcp_sdk_py.multi_round_trip import (
  InvalidRequestStateError,
  make_hmac_request_state,
  verify_hmac_request_state,
)
from mcp_sdk_py.oauth_flow import (
  PKCE_CODE_CHALLENGE_METHOD,
  generate_pkce_parameters,
  generate_state,
)
from mcp_sdk_py.oauth_registration import (
  TokenAudienceError,
  client_may_send_token_to_server,
  issuers_match,
  server_accepts_audience_bound_token,
)
from mcp_sdk_py.result_error import validate_cursor
from mcp_sdk_py.tools_call import (
  client_may_use_annotations,
  validate_arguments_against_input_schema,
)


# ===========================================================================
# §28  The security-requirements catalog (atom table)
# ===========================================================================


class SecurityPrinciple(enum.Enum):
  """The four core security principles every implementation is built on (§28.1).

  Every conforming implementation MUST be designed around these four principles;
  they are the foundation from which the more specific §28 requirements derive
  (R-28.1-a, AC-44.1). They are not wire values — they are the design axes a
  conformance review checks an implementation against.

  USER_CONSENT_AND_CONTROL:
    Users MUST explicitly consent to, and understand, all data access and
    operations, and retain control over what is shared and done (§28.1 item 1).
  DATA_PRIVACY:
    A server receives only host-elected context; no exposure/transmission
    without consent; data protected by access controls (§28.1 item 2).
  TOOL_SAFETY:
    Tools are arbitrary code execution treated with caution; definitions and
    annotations are untrusted; consent precedes any invocation (§28.1 item 3).
  HOST_MEDIATED_TRUST:
    The host is the single trust boundary; trust decisions are made and enforced
    at the host, never delegated to a server (§28.1 item 4).
  """

  USER_CONSENT_AND_CONTROL = "user_consent_and_control"
  DATA_PRIVACY = "data_privacy"
  TOOL_SAFETY = "tool_safety"
  HOST_MEDIATED_TRUST = "host_mediated_trust"


#: The four core principles, in §28.1 order. An implementation MUST be designed
#: around all four (R-28.1-a, AC-44.1); a design missing any one is not built on
#: the required foundation.
CORE_SECURITY_PRINCIPLES: tuple[SecurityPrinciple, ...] = (
  SecurityPrinciple.USER_CONSENT_AND_CONTROL,
  SecurityPrinciple.DATA_PRIVACY,
  SecurityPrinciple.TOOL_SAFETY,
  SecurityPrinciple.HOST_MEDIATED_TRUST,
)


def design_is_built_on_core_principles(addressed: Iterable[SecurityPrinciple]) -> bool:
  """True iff a design addresses all four core principles (R-28-a, R-28.1-a, AC-44.1).

  A conformance assessment reviews a design and asks whether it demonstrably
  addresses the security/trust obligations of arbitrary data access and code
  execution and is built around the four core principles (AC-44.1). This returns
  ``True`` only when every member of :data:`CORE_SECURITY_PRINCIPLES` is present
  in ``addressed``; a design that omits any principle is not conformant
  (R-28.1-a).

  Args:
    addressed: the principles the reviewed design demonstrably addresses.

  Returns:
    True iff all four core principles are addressed.
  """
  return set(CORE_SECURITY_PRINCIPLES) <= set(addressed)


@dataclass(frozen=True)
class SecurityRequirement:
  """One normative atom of the §28 security baseline (the catalog entry).

  This is the *catalog* entry, not the behaviour: the behaviour itself is owned
  by the §28 subsection named in :attr:`section` and (where code exists) by the
  sibling module that implements it. S44 references those requirements to build
  the authoritative checklist S45 reconciles against (R-28-a … R-28.10-p).

  Fields:
    atom: the requirement id exactly as written in the story (e.g. "R-28.5-b").
    level: the RFC-2119 keyword (S01 :class:`RequirementLevel`) the atom carries.
    section: the §28 subsection that normatively owns the obligation.
    roles: the roles the atom binds; an empty set binds every party.
    summary: a one-line restatement of the obligation (informational).
    ac: the acceptance criterion that covers the atom (e.g. "AC-44.12").
  """

  atom: str
  level: RequirementLevel
  section: str
  roles: frozenset[Role]
  summary: str
  ac: str

  @property
  def is_mandatory(self) -> bool:
    """True for absolute obligations/prohibitions (MUST / MUST NOT / SHALL etc.).

    A mandatory atom must be satisfied with no exceptions; a SHOULD/RECOMMENDED
    atom is judged only as its keyword allows (R-28-a, §2.1).
    """
    return (
      self.level.is_absolute_requirement or self.level.is_absolute_prohibition
    )

  def binds_role(self, role: Role) -> bool:
    """True iff this atom binds ``role`` (an empty :attr:`roles` binds all)."""
    return not self.roles or role in self.roles


def _sr(
  atom: str,
  level: RequirementLevel,
  section: str,
  roles: frozenset[Role],
  summary: str,
  ac: str,
) -> SecurityRequirement:
  """Construct a catalog entry (terse builder for the table below)."""
  return SecurityRequirement(atom, level, section, roles, summary, ac)


_HOST = frozenset({Role.HOST})
_CLIENT = frozenset({Role.CLIENT})
_SERVER = frozenset({Role.SERVER})
_ANY: frozenset[Role] = frozenset()

_L = RequirementLevel


#: The authoritative §28 security-requirement catalog, keyed by atom id. Each
#: entry records the RFC-2119 level, the §28 subsection that owns the behaviour,
#: the role(s) it binds, a one-line restatement, and the covering acceptance
#: criterion. This is the single security checklist S45 reconciles against; it
#: references — never redefines — the behaviours other modules implement.
SECURITY_REQUIREMENTS: dict[str, SecurityRequirement] = {
  r.atom: r
  for r in (
    # §28 Overarching obligation
    _sr("R-28-a", _L.MUST, "§28", _ANY,
        "address the security/trust obligations of data access & code execution",
        "AC-44.1"),
    # §28.1 Core security principles
    _sr("R-28.1-a", _L.MUST, "§28.1", _ANY,
        "be designed around the four core security principles", "AC-44.1"),
    _sr("R-28.1-b", _L.MUST, "§28.1", _ANY,
        "users explicitly consent to and understand all access & operations",
        "AC-44.2"),
    _sr("R-28.1-c", _L.MUST, "§28.1", _ANY,
        "users retain control over what is shared and what actions are taken",
        "AC-44.2"),
    _sr("R-28.1-d", _L.SHOULD, "§28.1", _ANY,
        "provide clear interfaces for reviewing & authorizing activities",
        "AC-44.2"),
    _sr("R-28.1-e", _L.MUST, "§28.1", _HOST,
        "obtain explicit user consent before exposing user data to a server",
        "AC-44.3"),
    _sr("R-28.1-f", _L.MUST_NOT, "§28.1", _HOST,
        "do not transmit resource data elsewhere without user consent",
        "AC-44.3"),
    _sr("R-28.1-g", _L.SHOULD, "§28.1", _ANY,
        "protect user data with appropriate access controls", "AC-44.4"),
    _sr("R-28.1-h", _L.MUST, "§28.1", _ANY,
        "treat tools as arbitrary code execution requiring caution", "AC-44.5"),
    _sr("R-28.1-i", _L.MUST, "§28.1", _ANY,
        "treat tool descriptions/annotations as untrusted unless from a trusted server",
        "AC-44.6"),
    _sr("R-28.1-j", _L.MUST, "§28.1", _HOST,
        "obtain explicit user consent before invoking any tool", "AC-44.5"),
    _sr("R-28.1-k", _L.SHOULD, "§28.1", _ANY,
        "build consent/authorization flows, access controls, privacy considerations",
        "AC-44.5"),
    # §28.2 User consent and control
    _sr("R-28.2-a", _L.MUST, "§28.2", _HOST,
        "obtain explicit consent before exposing data or invoking any operation",
        "AC-44.2"),
    _sr("R-28.2-b", _L.MUST, "§28.2", _HOST,
        "consent is informed: user understands data/action before authorizing",
        "AC-44.2"),
    _sr("R-28.2-c", _L.MUST, "§28.2", _HOST,
        "users can review, authorize, and decline activities", "AC-44.7"),
    _sr("R-28.2-d", _L.MUST_NOT, "§28.2", _HOST,
        "do not treat the absence of an explicit refusal as consent", "AC-44.7"),
    _sr("R-28.2-e", _L.MUST_NOT, "§28.2", _HOST,
        "do not silently escalate consent to broader scope or a different operation",
        "AC-44.7"),
    _sr("R-28.2-f", _L.MUST, "§28.2", _HOST,
        "seek fresh consent where an operation differs materially", "AC-44.7"),
    _sr("R-28.2-g", _L.SHOULD, "§28.2", _HOST,
        "present consent prompts in a spoof-resistant form", "AC-44.7"),
    # §28.3 Tool safety
    _sr("R-28.3-a", _L.MUST, "§28.3", _ANY,
        "treat a tool invocation as a request to execute arbitrary code",
        "AC-44.5"),
    _sr("R-28.3-b", _L.MUST, "§28.3", _ANY,
        "treat tool definitions as untrusted unless from a trusted server",
        "AC-44.6"),
    _sr("R-28.3-c", _L.MUST_NOT, "§28.3", _ANY,
        "do not rely on a tool annotation as a security guarantee", "AC-44.6"),
    _sr("R-28.3-d", _L.MUST, "§28.3", _HOST,
        "keep a human in the loop: user can review/understand/deny before it runs",
        "AC-44.8"),
    _sr("R-28.3-e", _L.MUST_NOT, "§28.3", _HOST,
        "the decision to invoke a tool does not rest solely with the model",
        "AC-44.8"),
    _sr("R-28.3-f", _L.SHOULD, "§28.3", _HOST,
        "guard against prompt-injection via descriptions/results/resource contents",
        "AC-44.8"),
    _sr("R-28.3-g", _L.MUST, "§28.3", _SERVER,
        "rate-limit tools/call so a client cannot drive unbounded execution",
        "AC-44.9"),
    _sr("R-28.3-h", _L.MUST, "§28.3", _SERVER,
        "reject a request exceeding the tools/call rate limit rather than execute",
        "AC-44.9"),
    _sr("R-28.3-i", _L.MUST, "§28.3", _SERVER,
        "sanitize tool outputs before returning them", "AC-44.9"),
    _sr("R-28.3-j", _L.SHOULD, "§28.3", _CLIENT,
        "show tool arguments to the user before issuing tools/call", "AC-44.10"),
    _sr("R-28.3-k", _L.SHOULD, "§28.3", _CLIENT,
        "apply a per-call timeout and surface a failure on elapse", "AC-44.10"),
    _sr("R-28.3-l", _L.SHOULD, "§28.3", _CLIENT,
        "log tool usage for audit without recording credentials/tokens",
        "AC-44.10"),
    # §28.4 Data privacy and isolation
    _sr("R-28.4-a", _L.MUST, "§28.4", _SERVER,
        "a server receives only the context the host elects to share", "AC-44.11"),
    _sr("R-28.4-b", _L.MUST_NOT, "§28.4", _HOST,
        "do not transmit resource/user data to a server or third party w/o consent",
        "AC-44.11"),
    _sr("R-28.4-c", _L.SHOULD, "§28.4", _ANY,
        "protect user data with access controls commensurate with sensitivity",
        "AC-44.4"),
    _sr("R-28.4-d", _L.MUST, "§28.4", _HOST,
        "servers are isolated from one another", "AC-44.11"),
    _sr("R-28.4-e", _L.MUST_NOT, "§28.4", _HOST,
        "one server cannot observe another's existence/data/activity", "AC-44.11"),
    _sr("R-28.4-f", _L.MUST_NOT, "§28.4", _HOST,
        "do not relay one server's requests/results/context/credentials to another",
        "AC-44.11"),
    # §28.5 Authorization security (§23 authoritative)
    _sr("R-28.5-a", _L.MUST, "§28.5", _ANY,
        "when authorization is used, satisfy §23 Authorization", "AC-44.12"),
    _sr("R-28.5-b", _L.MUST, "§28.5", _SERVER,
        "validate every token was issued for this server as the audience",
        "AC-44.12"),
    _sr("R-28.5-c", _L.MUST, "§28.5", _SERVER,
        "reject any token not bound to this server or otherwise unverifiable",
        "AC-44.12"),
    _sr("R-28.5-d", _L.MUST, "§28.5", _SERVER,
        "validate a token before processing the request it accompanies", "AC-44.12"),
    _sr("R-28.5-e", _L.MUST_NOT, "§28.5", _SERVER,
        "do not return data to an unauthorized party", "AC-44.12"),
    _sr("R-28.5-f", _L.MUST_NOT, "§28.5", _SERVER,
        "do not accept a token for another resource or forward a client token onward",
        "AC-44.13"),
    _sr("R-28.5-g", _L.MUST, "§28.5", _SERVER,
        "use a separate upstream-issued token when calling an upstream API",
        "AC-44.13"),
    _sr("R-28.5-h", _L.MUST, "§28.5", _CLIENT,
        "record the expected issuer before redirecting the user agent", "AC-44.14"),
    _sr("R-28.5-i", _L.MUST, "§28.5", _CLIENT,
        "compare returned issuer by exact string comparison; reject mismatches",
        "AC-44.14"),
    _sr("R-28.5-j", _L.MUST, "§28.5", _CLIENT,
        "use PKCE with the S256 challenge method where technically capable",
        "AC-44.15"),
    _sr("R-28.5-k", _L.MUST, "§28.5", _CLIENT,
        "verify PKCE support via metadata; refuse to proceed if unconfirmed",
        "AC-44.15"),
    _sr("R-28.5-l", _L.SHOULD, "§28.5", _CLIENT,
        "generate and verify a state value in the authorization code flow",
        "AC-44.16"),
    _sr("R-28.5-m", _L.MUST, "§28.5", _CLIENT,
        "discard any result whose state is absent or does not match the original",
        "AC-44.16"),
    _sr("R-28.5-n", _L.MUST, "§28.5", _ANY,
        "store tokens securely; keep refresh tokens confidential in transit & rest",
        "AC-44.17"),
    _sr("R-28.5-o", _L.MUST_NOT, "§28.5", _ANY,
        "tokens are never logged", "AC-44.17"),
    _sr("R-28.5-p", _L.MUST_NOT, "§28.5", _ANY,
        "tokens are never forwarded to any party other than the issued one",
        "AC-44.17"),
    _sr("R-28.5-q", _L.MUST, "§28.5", _ANY,
        "AS endpoints and redirect URIs use HTTPS (localhost redirect permitted)",
        "AC-44.17"),
    # §28.6 Multi-round-trip and continuation safety
    _sr("R-28.6-a", _L.MUST, "§28.6", _SERVER,
        "protect requestState integrity & confidentiality (sign/encrypt/opaque handle)",
        "AC-44.18"),
    _sr("R-28.6-b", _L.MUST, "§28.6", _SERVER,
        "reject a continuation token that fails integrity validation", "AC-44.18"),
    _sr("R-28.6-c", _L.SHOULD, "§28.6", _SERVER,
        "guard against replay (single-use/session/operation binding, time-bounded)",
        "AC-44.18"),
    # §28.7 Elicitation and sampling consent
    _sr("R-28.7-a", _L.MUST, "§28.7", _CLIENT,
        "server-initiated elicitation/sampling remains under user control",
        "AC-44.19"),
    _sr("R-28.7-b", _L.MUST, "§28.7", _CLIENT,
        "user can review and approve/edit/decline/cancel before anything returns",
        "AC-44.19"),
    _sr("R-28.7-c", _L.MUST, "§28.7", _CLIENT,
        "user can decline or cancel an elicitation at any point", "AC-44.19"),
    _sr("R-28.7-d", _L.MUST_NOT, "§28.7", _SERVER,
        "do not use elicitation to phish for credentials or other secrets",
        "AC-44.19"),
    _sr("R-28.7-e", _L.SHOULD, "§28.7", _CLIENT,
        "show requesting server identity; treat secret requests as suspect",
        "AC-44.19"),
    _sr("R-28.7-f", _L.MUST, "§28.7", _HOST,
        "sampling prompts & completions are subject to human review & approval",
        "AC-44.20"),
    _sr("R-28.7-g", _L.MUST_NOT, "§28.7", _HOST,
        "do not disclose more conversation context than the user authorized",
        "AC-44.20"),
    # §28.8 User-interface sandboxing
    _sr("R-28.8-a", _L.MUST, "§28.8", _HOST,
        "render server UI in an isolated sandbox under a restrictive CSP", "AC-44.21"),
    _sr("R-28.8-b", _L.MUST, "§28.8", _HOST,
        "mediate every privileged action the UI requests", "AC-44.21"),
    _sr("R-28.8-c", _L.MUST, "§28.8", _HOST,
        "route a UI-requested tool invocation through the normal consent path",
        "AC-44.21"),
    _sr("R-28.8-d", _L.MUST_NOT, "§28.8", _HOST,
        "the UI cannot cause a tool to run without host mediation and user consent",
        "AC-44.21"),
    _sr("R-28.8-e", _L.MUST_NOT, "§28.8", _HOST,
        "do not expose credentials/tokens/unrelated context to the sandbox",
        "AC-44.22"),
    _sr("R-28.8-f", _L.MUST_NOT, "§28.8", _HOST,
        "prevent exfiltration via navigation/network/inter-frame beyond policy",
        "AC-44.22"),
    _sr("R-28.8-g", _L.SHOULD, "§28.8", _HOST,
        "constrain sandbox network/storage/scripting to the minimum required",
        "AC-44.22"),
    _sr("R-28.8-h", _L.SHOULD, "§28.8", _HOST,
        "host-rendered consent/identity indicators cannot be spoofed/obscured",
        "AC-44.22"),
    # §28.9 Metadata and observability
    _sr("R-28.9-a", _L.MUST_NOT, "§28.9", _ANY,
        "metadata carries no authority; never use for authn/authz/access control",
        "AC-44.23"),
    _sr("R-28.9-b", _L.SHOULD, "§28.9", _ANY,
        "validate metadata structure and ignore values not understood", "AC-44.23"),
    _sr("R-28.9-c", _L.SHOULD, "§28.9", _ANY,
        "avoid logging sensitive metadata/request/result content", "AC-44.23"),
    _sr("R-28.9-d", _L.MUST_NOT, "§28.9", _ANY,
        "credentials and tokens are never logged", "AC-44.17"),
    _sr("R-28.9-e", _L.SHOULD, "§28.9", _ANY,
        "minimize and redact observability data crossing the trust boundary",
        "AC-44.23"),
    # §28.10 Input validation and resource bounds
    _sr("R-28.10-a", _L.MUST, "§28.10", _ANY,
        "validate all inputs accepted from a peer before acting on them",
        "AC-44.24"),
    _sr("R-28.10-b", _L.MUST_NOT, "§28.10", _ANY,
        "do not assume a peer is well-behaved", "AC-44.24"),
    _sr("R-28.10-c", _L.MUST, "§28.10", _SERVER,
        "validate tool-call arguments against the declared input schema",
        "AC-44.24"),
    _sr("R-28.10-d", _L.SHOULD, "§28.10", _CLIENT,
        "validate structured results against a declared output schema", "AC-44.24"),
    _sr("R-28.10-e", _L.MUST, "§28.10", _ANY,
        "report validation failures as errors (§22) rather than acting on them",
        "AC-44.24"),
    _sr("R-28.10-f", _L.MUST, "§28.10", _ANY,
        "validate resource URIs/templates before dereferencing or matching",
        "AC-44.25"),
    _sr("R-28.10-g", _L.MUST_NOT, "§28.10", _ANY,
        "do not follow a URI to a location the user has not authorized", "AC-44.25"),
    _sr("R-28.10-h", _L.SHOULD, "§28.10", _ANY,
        "guard against SSRF where a URI could trigger a network request",
        "AC-44.25"),
    _sr("R-28.10-i", _L.MUST, "§28.10", _SERVER,
        "validate the Origin header on every connection; reject untrusted (§9.11)",
        "AC-44.26"),
    _sr("R-28.10-j", _L.MUST, "§28.10", _SERVER,
        "treat a pagination cursor as opaque/untrusted; reject malformed/expired",
        "AC-44.27"),
    _sr("R-28.10-k", _L.MUST, "§28.10", _ANY,
        "bound schema nesting depth and validation time", "AC-44.28"),
    _sr("R-28.10-l", _L.SHOULD, "§28.10", _ANY,
        "impose message/payload size limits and reject oversized inputs",
        "AC-44.28"),
    _sr("R-28.10-m", _L.MUST_NOT, "§28.10", _SERVER,
        "do not automatically dereference external schema references", "AC-44.29"),
    _sr("R-28.10-n", _L.MUST, "§28.10", _ANY,
        "schemas are self-contained or resolved only against trusted sources",
        "AC-44.29"),
    _sr("R-28.10-o", _L.MUST, "§28.10", _SERVER,
        "sanitize file:// paths to prevent directory traversal", "AC-44.30"),
    _sr("R-28.10-p", _L.MUST_NOT, "§28.10", _SERVER,
        "do not serve a file outside user-authorized directories", "AC-44.30"),
  )
}


def security_requirement(atom: str) -> SecurityRequirement:
  """Return the catalog entry for ``atom`` (e.g. ``"R-28.5-b"``) (§28).

  Raises:
    KeyError: ``atom`` is not a §28 catalog atom.
  """
  return SECURITY_REQUIREMENTS[atom]


def security_requirements_for_role(role: Role) -> tuple[SecurityRequirement, ...]:
  """Every §28 atom that binds ``role`` (an empty roles set binds all parties)."""
  return tuple(
    r for r in SECURITY_REQUIREMENTS.values() if r.binds_role(role)
  )


def mandatory_security_requirements() -> tuple[SecurityRequirement, ...]:
  """Every absolute (MUST / MUST NOT / SHALL / SHALL NOT) §28 atom (R-28-a)."""
  return tuple(r for r in SECURITY_REQUIREMENTS.values() if r.is_mandatory)


# ===========================================================================
# §28.2 / §28.3  Host consent + human-in-the-loop gate
# ===========================================================================


class ConsentRequiredError(Exception):
  """A host-mediated operation was attempted without satisfying the consent gate.

  Raised when an operation that acts on the user's behalf — exposing data,
  invoking a tool, running an elicitation/sampling flow — is driven without the
  explicit, informed user consent §28.2 requires, or when consent is escalated
  silently. Silence is never consent (R-28.2-d); the model or server-provided UI
  alone can never drive the operation past this gate (R-28.3-e, R-28.8-d).
  """


class ConsentOutcome(enum.Enum):
  """The user's explicit decision at the host consent gate (§28.2).

  Consent MUST be an explicit, affirmative act: the absence of a refusal is not
  consent (R-28.2-d), and the user MUST always be able to decline (R-28.2-c).

  APPROVE:
    The user reviewed the operation and explicitly authorized it (R-28.2-c).
  DECLINE:
    The user explicitly refused (R-28.2-c).
  CANCEL:
    The user cancelled an in-progress operation; treated as a refusal so nothing
    is returned to the server (R-28.7-c).
  PENDING:
    No explicit decision yet. This is NOT consent (R-28.2-d): the gate treats it
    exactly as a non-approval.
  """

  APPROVE = "approve"
  DECLINE = "decline"
  CANCEL = "cancel"
  PENDING = "pending"

  @property
  def is_explicit_approval(self) -> bool:
    """True only for APPROVE; every other outcome (incl. PENDING) is non-consent."""
    return self is ConsentOutcome.APPROVE


@dataclass(frozen=True)
class ConsentRecord:
  """A record of a consent the user has granted, against which escalation is judged.

  The host keeps these so it can detect when a later operation is *materially
  different* from one already authorized and so seek fresh consent rather than
  silently escalating (R-28.2-e/f). The ``scope`` set captures the data/action
  scope the user understood and approved (R-28.2-b).

  Fields:
    operation: the operation identifier the user authorized (e.g. a tool name).
    server_identity: the identity of the server the consent is bound to; consent
      for one server never carries to another (§28.4 isolation).
    scope: the set of data/action scope tokens the user approved.
    outcome: the explicit decision; only APPROVE grants consent (R-28.2-c/d).
  """

  operation: str
  server_identity: str
  scope: frozenset[str] = frozenset()
  outcome: ConsentOutcome = ConsentOutcome.APPROVE

  def covers(self, operation: str, server_identity: str, scope: Iterable[str]) -> bool:
    """True iff this granted consent already covers the proposed operation/scope.

    Coverage requires an explicit prior approval (R-28.2-c/d) for the *same*
    operation on the *same* server, whose approved :attr:`scope` is a superset of
    the proposed scope. Anything broader, a different operation, or a different
    server is a *material change* requiring fresh consent (R-28.2-e/f).
    """
    if not self.outcome.is_explicit_approval:
      return False
    if self.operation != operation or self.server_identity != server_identity:
      return False
    return set(scope) <= self.scope


def is_material_change(
  prior: ConsentRecord | None,
  *,
  operation: str,
  server_identity: str,
  scope: Iterable[str],
) -> bool:
  """True iff the proposed operation differs materially from a prior consent (R-28.2-e/f).

  A material change is a new operation, a different server, or a broader scope of
  data/action than the user already authorized; the host MUST NOT silently
  escalate (R-28.2-e) and MUST seek fresh consent in that case (R-28.2-f). With no
  prior consent, every operation is a material change.

  Args:
    prior: the matching prior consent record, or None when none exists.
    operation: the proposed operation identifier.
    server_identity: the server the operation targets.
    scope: the data/action scope the proposed operation needs.

  Returns:
    True iff fresh consent must be sought (R-28.2-f).
  """
  if prior is None:
    return True
  return not prior.covers(operation, server_identity, list(scope))


@dataclass(frozen=True)
class ConsentPrompt:
  """A spoof-resistant consent prompt the host renders to the user (§28.2/§28.7/§28.8).

  Consent MUST be *informed* — the prompt MUST carry enough information for the
  user to understand what data will be shared or what action will be taken before
  authorizing it (R-28.2-b) — and SHOULD be presented in a form that cannot be
  spoofed by server-provided content (R-28.2-g, R-28.8-h). The requesting server's
  identity MUST be disclosed so the user knows who is asking (R-28.7-e).

  Fields:
    operation: the operation being authorized (e.g. a tool name).
    server_identity: the requesting server's identity, always disclosed.
    description: a human-readable explanation of the data/action involved.
    arguments: the arguments to be shown so exfiltration through parameters can
      be detected (R-28.3-j). Empty when there are none.
    host_rendered: True when the prompt is drawn by the trusted host chrome, not
      by server-provided/sandboxed content — the spoof-resistance property
      (R-28.2-g, R-28.8-h).
  """

  operation: str
  server_identity: str
  description: str
  arguments: Mapping[str, Any] = field(default_factory=dict)
  host_rendered: bool = True

  @property
  def is_informed(self) -> bool:
    """True iff the prompt discloses server identity and a non-empty description.

    A prompt with no description or no disclosed server identity is not
    *informed* and cannot satisfy R-28.2-b / R-28.7-e.
    """
    return bool(self.server_identity) and bool(self.description.strip())

  @property
  def is_spoof_resistant(self) -> bool:
    """True iff the prompt is host-rendered (not drawable by server content).

    A host-rendered prompt cannot be spoofed by server-provided or sandboxed
    content (R-28.2-g, R-28.8-h).
    """
    return self.host_rendered


@dataclass(frozen=True)
class ConsentGate:
  """The single host gate every user-acting operation passes before a server.

  This is the enforcement point of §28.2/§28.3/§28.8: an operation acting on the
  user's behalf (exposing data, invoking a tool, an elicitation/sampling flow, a
  UI-requested action) reaches a server only after the user has explicitly,
  informedly consented at the host (R-28.2-a/b/c). No path lets the model alone,
  or server-provided UI, drive the operation past the gate (R-28.3-e, R-28.8-c/d).
  Silence is never consent (R-28.2-d), and a material change requires fresh
  consent (R-28.2-e/f).

  Construct with the prior consent records the host holds (keyed nowhere — this is
  a pure decision object); call :meth:`evaluate` to obtain the decision and
  :meth:`authorize` to enforce it (raising on any non-approval).
  """

  prior_consents: tuple[ConsentRecord, ...] = ()

  def _matching_prior(
    self, operation: str, server_identity: str
  ) -> ConsentRecord | None:
    """Return the most-recent matching prior approval for operation+server."""
    for record in reversed(self.prior_consents):
      if (
        record.operation == operation
        and record.server_identity == server_identity
        and record.outcome.is_explicit_approval
      ):
        return record
    return None

  def evaluate(
    self,
    prompt: ConsentPrompt,
    *,
    scope: Iterable[str] = (),
    decision: ConsentOutcome = ConsentOutcome.PENDING,
    initiated_by_model_only: bool = False,
    requested_by_sandboxed_ui: bool = False,
  ) -> bool:
    """Decide whether the operation may proceed to the server (§28.2/§28.3/§28.8).

    The gate grants passage only when ALL of the following hold:

    * the prompt is *informed* (server identity + description) and
      *spoof-resistant* (host-rendered) (R-28.2-b/g, R-28.7-e, R-28.8-h);
    * the operation was not driven by the model alone (R-28.3-e) nor caused to
      run by sandboxed UI without host mediation (R-28.8-c/d);
    * either the user explicitly approved this exact operation/scope now, or a
      prior approval already covers it AND the new request is not a material
      change (R-28.2-c/d/e/f).

    A ``decision`` of PENDING (the default) is never treated as consent
    (R-28.2-d).

    Args:
      prompt: the host-rendered consent prompt shown to the user.
      scope: the data/action scope the operation needs.
      decision: the user's explicit decision now (PENDING when not yet given).
      initiated_by_model_only: True when the model alone proposed the action with
        no human able to deny it — never permitted to pass (R-28.3-e).
      requested_by_sandboxed_ui: True when sandboxed UI requested the action; it
        MUST still pass the normal consent/human-in-the-loop path (R-28.8-c/d).

    Returns:
      True iff the operation may proceed to the server.
    """
    if not prompt.is_informed or not prompt.is_spoof_resistant:
      return False
    # The model alone, or sandboxed UI, can never bypass human consent.
    if initiated_by_model_only:
      return False
    scope_list = list(scope)
    prior = self._matching_prior(prompt.operation, prompt.server_identity)
    materially_new = is_material_change(
      prior,
      operation=prompt.operation,
      server_identity=prompt.server_identity,
      scope=scope_list,
    )
    if not materially_new:
      # An existing, non-escalating approval already covers this operation; a
      # UI-requested action still rode through this same host gate (R-28.8-c).
      return True
    # A new or materially-different operation demands a fresh explicit approval
    # (R-28.2-f). Silence/decline/cancel never suffice (R-28.2-c/d, R-28.7-c).
    return decision.is_explicit_approval

  def authorize(
    self,
    prompt: ConsentPrompt,
    *,
    scope: Iterable[str] = (),
    decision: ConsentOutcome = ConsentOutcome.PENDING,
    initiated_by_model_only: bool = False,
    requested_by_sandboxed_ui: bool = False,
  ) -> ConsentRecord:
    """Enforce the gate, returning a fresh ConsentRecord or raising (§28.2/§28.3).

    Raises:
      ConsentRequiredError: the operation does not satisfy the consent gate
        (silence, decline/cancel, model-only initiation, an un-mediated UI
        request, a spoofable/uninformed prompt, or silent escalation).
    """
    if not self.evaluate(
      prompt,
      scope=scope,
      decision=decision,
      initiated_by_model_only=initiated_by_model_only,
      requested_by_sandboxed_ui=requested_by_sandboxed_ui,
    ):
      raise ConsentRequiredError(
        f"operation {prompt.operation!r} on server "
        f"{prompt.server_identity!r} did not satisfy the host consent gate; "
        f"explicit, informed, host-rendered consent is required and silence is "
        f"never consent (R-28.2-a/b/c/d/e/f, R-28.3-e, R-28.8-c/d)"
      )
    return ConsentRecord(
      operation=prompt.operation,
      server_identity=prompt.server_identity,
      scope=frozenset(scope),
      outcome=ConsentOutcome.APPROVE,
    )


def decision_rests_solely_with_model(*, human_can_deny: bool) -> bool:
  """True iff a tool decision would rest solely with the model (R-28.3-e).

  The decision to invoke a tool MUST NOT rest solely with the model (R-28.3-e);
  a human MUST be able to deny it before it runs (R-28.3-d). This returns
  ``True`` — the prohibited condition — only when no human can deny.
  """
  return not human_can_deny


# ===========================================================================
# §28.4  Data privacy and server isolation
# ===========================================================================


class ServerIsolationError(Exception):
  """An operation would breach the §28.4 mutual server-isolation boundary.

  Raised when the host would relay one server's requests, results, context, or
  credentials to another server, or otherwise let one server observe another
  (R-28.4-e/f). Servers MUST be isolated from one another (R-28.4-d).
  """


@dataclass(frozen=True)
class ServerIsolationBoundary:
  """Enforces mutual server isolation and host-elected context (§28.4).

  A server receives only the context the host elects to share with it (R-28.4-a);
  servers MUST be isolated (R-28.4-d) so one cannot observe another (R-28.4-e);
  and the host MUST NOT relay one server's requests/results/context/credentials
  to another (R-28.4-f). This boundary checks a proposed data flow against the
  origin/target server identities and the user's consent.

  Fields:
    consented_targets: a mapping from a data item key to the set of server
      identities the user consented to expose that item to (R-28.4-b).
  """

  consented_targets: Mapping[str, frozenset[str]] = field(default_factory=dict)

  def may_expose(self, item_key: str, target_server: str) -> bool:
    """True iff the user consented to exposing ``item_key`` to ``target_server``.

    Data is exposed to a server only with the user's consent (R-28.4-b); the host
    elects which context each server sees (R-28.4-a).
    """
    return target_server in self.consented_targets.get(item_key, frozenset())

  def assert_no_cross_server_relay(
    self, origin_server: str, target_server: str
  ) -> None:
    """Raise unless origin == target: a server's data never crosses to another.

    The host MUST NOT relay one server's requests, results, context, or
    credentials to another server (R-28.4-f), and one server MUST NOT observe
    another (R-28.4-e).

    Raises:
      ServerIsolationError: ``origin_server`` differs from ``target_server``.
    """
    if origin_server != target_server:
      raise ServerIsolationError(
        f"refusing to relay data from server {origin_server!r} to a different "
        f"server {target_server!r}; servers are isolated and the host MUST NOT "
        f"relay one server's requests/results/context/credentials to another "
        f"(R-28.4-d/e/f)"
      )

  def assert_exposure_consented(self, item_key: str, target_server: str) -> None:
    """Raise unless the user consented to exposing ``item_key`` to the server.

    Raises:
      ConsentRequiredError: no consent exists for this exposure (R-28.4-b).
    """
    if not self.may_expose(item_key, target_server):
      raise ConsentRequiredError(
        f"exposing {item_key!r} to server {target_server!r} requires the user's "
        f"consent (R-28.1-e, R-28.4-b)"
      )


def access_control_is_sufficient(
  data_sensitivity: int, applied_control_strength: int
) -> bool:
  """True iff applied access-control strength matches data sensitivity (R-28.1-g/R-28.4-c).

  User data SHOULD be protected with access controls commensurate with its
  sensitivity (R-28.1-g, R-28.4-c). Both arguments are ordinal levels (higher =
  more sensitive / stronger control); the control is sufficient only when it is
  at least as strong as the data is sensitive.
  """
  return applied_control_strength >= data_sensitivity


# ===========================================================================
# §28.5  Authorization security (real checks owned by S35–S37; referenced here)
# ===========================================================================


def server_must_reject_token(token_audience: str, server_resource: str) -> bool:
  """True iff a server MUST reject a presented token on audience grounds (R-28.5-b/c/d/e).

  A server MUST validate that every access token was issued for it as the intended
  audience (R-28.5-b) and MUST reject any token not bound to it (R-28.5-c), before
  processing the request (R-28.5-d); it returns no data to an unauthorized party
  (R-28.5-e). The real audience comparison is owned by S37
  (:func:`server_accepts_audience_bound_token`); this wraps it into the §28.5
  reject/accept predicate without redefining the comparison.

  Args:
    token_audience: the audience the presented token was issued for.
    server_resource: the server's own canonical resource identifier.

  Returns:
    True when the token MUST be rejected (audience mismatch), False when accepted.
  """
  try:
    server_accepts_audience_bound_token(token_audience, server_resource)
  except TokenAudienceError:
    return True
  return False


def server_may_forward_client_token() -> bool:
  """Always False: a server MUST NOT forward a client token to an upstream API (R-28.5-f/g).

  A server MUST NOT accept a token issued for another resource and MUST NOT forward
  a token received from a client onward to an upstream API (R-28.5-f). When it calls
  an upstream API it acts as a client and MUST use a *separate* token issued by the
  upstream authorization server (R-28.5-g). The passthrough is categorically
  forbidden, so this is always ``False``.
  """
  return False


def exact_issuer_matches(returned_issuer: str | None, recorded_issuer: str) -> bool:
  """True iff a returned issuer exactly matches the recorded one (R-28.5-h/i).

  Before redirecting, the client records the expected issuer (R-28.5-h); on the
  response it MUST compare any returned issuer by *exact string comparison* — no
  scheme/host case folding, default-port elision, trailing-slash, or
  percent-encoding normalization — and MUST reject mismatches (R-28.5-i). The
  exact comparison is owned by S37 (:func:`issuers_match`); an absent returned
  issuer never matches.
  """
  if returned_issuer is None:
    return False
  return issuers_match(recorded_issuer, returned_issuer)


def authorization_endpoint_uri_is_secure(uri: str) -> bool:
  """True iff an AS endpoint / redirect URI satisfies the HTTPS rule (R-28.5-q).

  Authorization-server endpoints and redirect URIs MUST use HTTPS, with a
  ``localhost`` (loopback) redirect URI permitted as the only exception
  (R-28.5-q). The loopback exception covers ``localhost``, ``127.0.0.0/8``, and
  the IPv6 loopback ``::1``.

  Args:
    uri: the endpoint or redirect URI to check.

  Returns:
    True iff the URI uses ``https`` (any host) or ``http`` with a loopback host.
  """
  parts = urlsplit(uri)
  scheme = parts.scheme.lower()
  if scheme == "https":
    return True
  if scheme == "http":
    host = (parts.hostname or "").lower()
    if host == "localhost" or host == "::1":
      return True
    if host.startswith("127."):
      return True
  return False


# ===========================================================================
# §28.6  Continuation-token integrity & replay defense
# ===========================================================================


class ContinuationTokenError(Exception):
  """A requestState continuation token failed integrity validation (R-28.6-b).

  Raised when a receiver is handed a continuation token that does not verify —
  the receiver MUST reject it rather than act on its contents (R-28.6-b) — or a
  replay is detected (R-28.6-c). The cryptographic integrity primitive itself is
  owned by S17 (:func:`verify_hmac_request_state`).
  """


@dataclass
class ContinuationTokenGuard:
  """Protects requestState integrity & confidentiality and guards replay (§28.6).

  A server MUST protect both the integrity and confidentiality of the
  ``requestState`` continuation token so a client cannot read, forge, or tamper
  with the continuation state it represents (R-28.6-a). A receiver MUST reject a
  token that fails integrity validation rather than acting on its contents
  (R-28.6-b). Servers SHOULD guard against replay, e.g. by binding a token to a
  single use and bounding its validity in time (R-28.6-c).

  Integrity is delegated to S17's HMAC primitive (the token's payload is opaque
  server-held state, so confidentiality is preserved by signing an unguessable
  handle, not by embedding secrets). Single-use replay defense is enforced here
  by tracking already-consumed tokens.

  Fields:
    secret_key: the server secret used to sign/verify (kept confidential).
    single_use: when True, a verified token may be consumed only once (R-28.6-c).
  """

  secret_key: bytes
  single_use: bool = True
  _consumed: set[str] = field(default_factory=set)

  def issue(self, payload: str) -> str:
    """Mint an integrity-protected continuation token for ``payload`` (R-28.6-a).

    The returned token is an unguessable, HMAC-signed handle; the payload is the
    server's own continuation state, never client-readable secrets (R-28.6-a).
    """
    return make_hmac_request_state(payload, self.secret_key)

  def accept(self, token: str) -> str:
    """Verify and consume a continuation token, returning its payload (R-28.6-b/c).

    Verifies integrity via S17's HMAC primitive (R-28.6-b); under
    :attr:`single_use`, rejects a token already consumed to defeat replay
    (R-28.6-c).

    Raises:
      ContinuationTokenError: the token fails integrity validation (R-28.6-b) or
        is a replay of an already-consumed token (R-28.6-c).
    """
    try:
      payload = verify_hmac_request_state(token, self.secret_key)
    except InvalidRequestStateError as exc:
      raise ContinuationTokenError(
        f"continuation token failed integrity validation and MUST be rejected "
        f"rather than acted upon (R-28.6-b): {exc}"
      ) from exc
    if self.single_use:
      if token in self._consumed:
        raise ContinuationTokenError(
          "continuation token has already been used; replay is rejected "
          "(R-28.6-c)"
        )
      self._consumed.add(token)
    return payload


# ===========================================================================
# §28.7  Elicitation and sampling consent
# ===========================================================================


#: Substrings whose presence in an elicitation field name/prompt marks it as a
#: likely request for a secret, which clients SHOULD treat as suspect (R-28.7-e)
#: and which a server MUST NOT use elicitation to phish for (R-28.7-d).
_SECRET_REQUEST_MARKERS: frozenset[str] = frozenset({
  "password", "passwd", "secret", "token", "credential", "api key", "apikey",
  "private key", "passphrase", "pin", "ssn", "social security", "cvv",
  "card number", "security code", "otp", "one-time", "mnemonic", "seed phrase",
})


def elicitation_requests_secret(text: str) -> bool:
  """True iff an elicitation field/prompt appears to request a secret (R-28.7-d/e).

  A server MUST NOT use elicitation to phish for credentials or other secrets
  (R-28.7-d); clients SHOULD treat requests for passwords, tokens, or similar
  secrets as suspect (R-28.7-e). This is a heuristic over the field name / prompt
  text: it matches case-insensitively against :data:`_SECRET_REQUEST_MARKERS`.
  A client SHOULD surface a matching request as suspect.

  Args:
    text: the elicitation field name, label, or prompt to inspect.

  Returns:
    True iff the text appears to request a credential/secret.
  """
  lowered = text.lower()
  return any(marker in lowered for marker in _SECRET_REQUEST_MARKERS)


def elicitation_response_may_be_returned(decision: ConsentOutcome) -> bool:
  """True iff an elicitation response may be returned to the server (R-28.7-a/b/c).

  For elicitation, the client MUST give the user the ability to approve, edit,
  decline, or cancel before *anything* is returned to the server (R-28.7-b), and
  the user MUST be able to decline or cancel at any point (R-28.7-c). A response
  is returned only on an explicit approval; a decline, cancel, or pending state
  returns nothing.
  """
  return decision.is_explicit_approval


def sampling_may_proceed(
  *,
  prompt_reviewed_and_approved: bool,
  completion_reviewed_and_approved: bool,
  context_within_authorized: bool,
) -> bool:
  """True iff a server-driven sampling flow may proceed (R-28.7-f/g).

  Where a server can drive model sampling, both the prompts sent and the
  completions produced MUST be subject to human review and approval before they
  are acted upon or transmitted (R-28.7-f), and the host MUST NOT disclose more
  conversation context than the user authorized (R-28.7-g). All three conditions
  must hold.

  Args:
    prompt_reviewed_and_approved: the user saw and approved what is sent.
    completion_reviewed_and_approved: the user saw and approved what came back.
    context_within_authorized: the disclosed context does not exceed what was
      authorized (R-28.7-g).
  """
  return (
    prompt_reviewed_and_approved
    and completion_reviewed_and_approved
    and context_within_authorized
  )


# ===========================================================================
# §28.8  User-interface sandboxing
# ===========================================================================


@dataclass(frozen=True)
class SandboxPolicy:
  """A least-privilege sandbox + CSP policy for server-provided UI (§28.8).

  Where a server provides interactive UI, the host MUST render it in an isolated,
  sandboxed execution context governed by a *restrictive* content-security policy
  (R-28.8-a). The host MUST NOT expose credentials/tokens/unrelated context to the
  sandbox (R-28.8-e) and MUST NOT let it exfiltrate state via navigation, network,
  or inter-frame channels beyond what the policy permits (R-28.8-f); it SHOULD
  constrain network/storage/scripting to the minimum the feature requires
  (R-28.8-g) and ensure host-rendered consent/identity indicators cannot be
  spoofed/obscured (R-28.8-h).

  All fields default to the most restrictive setting; a caller relaxes only what
  a feature truly needs (least privilege, R-28.8-g).

  Fields:
    isolated: the content runs in an isolated execution context (R-28.8-a).
    allow_network: the sandbox may make network requests (default deny, R-28.8-f/g).
    allow_storage: the sandbox may use persistent storage (default deny, R-28.8-g).
    allow_scripting: the sandbox may run scripts (default deny, R-28.8-g).
    allow_top_navigation: the sandbox may navigate the top frame (default deny —
      an exfiltration channel, R-28.8-f).
    allow_inter_frame: the sandbox may message other frames (default deny —
      an exfiltration channel, R-28.8-f).
    exposes_credentials: the host exposes credentials/tokens to the content —
      MUST be False (R-28.8-e).
    host_chrome_protected: host-rendered consent/identity indicators cannot be
      spoofed or obscured by the content (R-28.8-h).
  """

  isolated: bool = True
  allow_network: bool = False
  allow_storage: bool = False
  allow_scripting: bool = False
  allow_top_navigation: bool = False
  allow_inter_frame: bool = False
  exposes_credentials: bool = False
  host_chrome_protected: bool = True

  @property
  def is_restrictive(self) -> bool:
    """True iff the policy meets the §28.8 minimum-restrictiveness bar.

    The content MUST be isolated (R-28.8-a), the host MUST NOT expose credentials
    (R-28.8-e), the two exfiltration channels (top-frame navigation, inter-frame
    messaging) MUST be denied unless explicitly opened by policy (R-28.8-f), and
    host chrome MUST remain spoof-resistant (R-28.8-h).
    """
    return (
      self.isolated
      and not self.exposes_credentials
      and not self.allow_top_navigation
      and not self.allow_inter_frame
      and self.host_chrome_protected
    )

  def content_security_policy(self) -> str:
    """Render the effective CSP header value for the sandbox (R-28.8-a/f/g).

    Produces a restrictive Content-Security-Policy: ``default-src 'none'`` denies
    everything by default; ``script-src`` and ``connect-src`` are opened only when
    the policy explicitly permits scripting/network (least privilege, R-28.8-g);
    ``frame-ancestors 'self'`` and ``form-action 'none'`` close inter-frame and
    form-based exfiltration channels (R-28.8-f).
    """
    script_src = "'self'" if self.allow_scripting else "'none'"
    connect_src = "'self'" if self.allow_network else "'none'"
    directives = [
      "default-src 'none'",
      f"script-src {script_src}",
      f"connect-src {connect_src}",
      "frame-ancestors 'self'",
      "form-action 'none'",
      "base-uri 'none'",
    ]
    return "; ".join(directives)


class UnmediatedToolInvocationError(Exception):
  """Sandboxed UI attempted to run a tool without host mediation/consent (R-28.8-d).

  Raised when server-provided UI tries to cause a ``tools/call`` to execute
  without routing through the host's normal consent and human-in-the-loop path
  (R-28.8-c); the UI MUST NOT be able to cause a tool to run without the host's
  mediation and the user's consent (R-28.8-d).
  """


def route_ui_tool_invocation(
  gate: ConsentGate,
  prompt: ConsentPrompt,
  *,
  scope: Iterable[str] = (),
  decision: ConsentOutcome = ConsentOutcome.PENDING,
) -> ConsentRecord:
  """Route a UI-requested tool invocation through the host consent path (R-28.8-b/c/d).

  The host MUST mediate every privileged action the UI requests (R-28.8-b); a tool
  invocation requested by server-provided UI MUST be routed through the host's
  *normal* consent and human-in-the-loop path (R-28.8-c), and the UI MUST NOT be
  able to cause a tool to run without that mediation and the user's consent
  (R-28.8-d). This forces the request through :meth:`ConsentGate.authorize` with
  the sandbox-origin flag set so the same gate decides it.

  Raises:
    UnmediatedToolInvocationError: the consent gate did not authorize the action
      (so the UI cannot run the tool without mediation/consent) (R-28.8-d).
  """
  try:
    return gate.authorize(
      prompt,
      scope=scope,
      decision=decision,
      requested_by_sandboxed_ui=True,
    )
  except ConsentRequiredError as exc:
    raise UnmediatedToolInvocationError(
      f"server-provided UI cannot cause tool {prompt.operation!r} to run "
      f"without host mediation and the user's consent (R-28.8-c/d): {exc}"
    ) from exc


# ===========================================================================
# §28.9  Metadata and observability
# ===========================================================================


def metadata_value_carries_authority() -> bool:
  """Always False: metadata is never a source of authority (R-28.9-a).

  A receiver MUST NOT treat any metadata value as a source of authority: trace
  identifiers, progress tokens, and similar fields MUST NOT be used for
  authentication, authorization, or any access-control decision, since a peer can
  set them to arbitrary values (R-28.9-a). The answer is categorically ``False``.
  """
  return False


def use_metadata_for_access_control(_metadata: Mapping[str, Any]) -> bool:
  """Never authorize from metadata: always returns False (R-28.9-a).

  This is the enforcement form of :func:`metadata_value_carries_authority`: no
  metadata value (trace id, progress token, …) may ever drive an access-control
  decision (R-28.9-a). It ignores its argument and always denies.
  """
  return False


def filter_known_metadata(
  metadata: Mapping[str, Any], known_keys: Iterable[str]
) -> dict[str, Any]:
  """Keep only metadata keys the receiver understands, ignoring the rest (R-28.9-b).

  Receivers SHOULD validate the structure of metadata they consume and ignore
  values they do not understand (R-28.9-b). This returns a new dict containing
  only the entries whose key is in ``known_keys``; unknown keys are dropped, never
  acted upon.
  """
  known = set(known_keys)
  return {k: v for k, v in metadata.items() if k in known}


#: Substrings of a key name that mark its value as sensitive — credentials,
#: tokens, and similar secrets that MUST NOT be logged (R-28.5-o, R-28.9-c/d).
_SENSITIVE_KEY_MARKERS: frozenset[str] = frozenset({
  "token", "secret", "password", "passwd", "credential", "authorization",
  "api key", "apikey", "api_key", "private key", "private_key", "access_token",
  "refresh_token", "client_secret", "passphrase", "bearer", "cookie", "session",
  "code_verifier",
})

#: The placeholder substituted for a redacted value crossing the trust boundary.
REDACTION_PLACEHOLDER: str = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
  """True iff a key name marks a value that MUST NOT be logged (R-28.5-o, R-28.9-d).

  Credentials and tokens MUST NOT be logged (R-28.5-o, R-28.9-d); sensitive
  metadata/content SHOULD be avoided in logs (R-28.9-c). This matches a key name
  case-insensitively against :data:`_SENSITIVE_KEY_MARKERS`.
  """
  lowered = key.lower()
  return any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS)


def redact_for_log(value: Any, *, _depth: int = 0) -> Any:
  """Redact credentials/tokens/sensitive fields before logging (R-28.5-o, R-28.9-c/d/e).

  Tokens and credentials MUST NOT be logged (R-28.5-o, R-28.9-d); sensitive
  metadata/content SHOULD be avoided (R-28.9-c); and data crossing the trust
  boundary SHOULD be minimized and redacted (R-28.9-e). This walks a value and
  replaces any mapping value whose key :func:`is_sensitive_key` with
  :data:`REDACTION_PLACEHOLDER`, recursing into nested mappings and sequences.
  Recursion is bounded by :data:`MAX_VALIDATION_DEPTH` so a hostile structure
  cannot exhaust the stack (R-28.10-k).

  Args:
    value: the structure to redact (any JSON-like value).

  Returns:
    A redacted copy safe to log; the input is not mutated.
  """
  if _depth > MAX_VALIDATION_DEPTH:
    return REDACTION_PLACEHOLDER
  if isinstance(value, Mapping):
    out: dict[str, Any] = {}
    for k, v in value.items():
      if isinstance(k, str) and is_sensitive_key(k):
        out[k] = REDACTION_PLACEHOLDER
      else:
        out[k] = redact_for_log(v, _depth=_depth + 1)
    return out
  if isinstance(value, (list, tuple)):
    return [redact_for_log(v, _depth=_depth + 1) for v in value]
  return value


# ===========================================================================
# §28.10  Input validation and resource bounds
# ===========================================================================


class ValidationError(Exception):
  """A peer-supplied input failed validation and MUST be reported as an error.

  Per R-28.10-a/b/e a receiver MUST validate all peer inputs, MUST NOT assume the
  peer is well-behaved, and MUST report validation failures as errors (§22)
  rather than acting on them. Carries the JSON-RPC error code to surface.

  Attributes:
    error_code: the JSON-RPC error code (defaults to -32602 Invalid params).
    reason: a machine-readable reason placed in the error ``data``.
  """

  def __init__(
    self,
    message: str,
    *,
    error_code: int = INVALID_PARAMS_CODE,
    reason: str | None = None,
  ) -> None:
    super().__init__(message)
    self.error_code: int = error_code
    self.reason: str | None = reason

  def to_error_object(self) -> ErrorObject:
    """Render this failure as the §22 error object to return (R-28.10-e)."""
    data = {"reason": self.reason} if self.reason is not None else None
    if data is None:
      return ErrorObject(code=self.error_code, message=str(self))
    return ErrorObject(code=self.error_code, message=str(self), data=data)


#: The maximum schema/payload nesting depth a receiver will descend while
#: validating, so a pathological structure cannot cause unbounded recursion
#: (R-28.10-k). A receiver MUST bound nesting depth.
MAX_VALIDATION_DEPTH: int = 64

#: The default maximum message/payload byte size a receiver accepts; larger
#: inputs SHOULD be rejected (R-28.10-l). 4 MiB is a conservative default.
MAX_MESSAGE_BYTES: int = 4 * 1024 * 1024


def validate_tool_arguments(tool: Any, arguments: Mapping[str, Any] | None) -> None:
  """Validate tool-call arguments against the tool's input schema (R-28.10-c/e).

  A server MUST validate tool-call arguments against the tool's declared input
  schema before relying on them (R-28.10-c); a validation failure MUST be reported
  as an error rather than acted upon (R-28.10-e). The real JSON-Schema check is
  owned by S24 (:func:`validate_arguments_against_input_schema`); this wraps it so
  a failure raises a :class:`ValidationError` carrying the -32602 code.

  Raises:
    ValidationError: the arguments do not satisfy the input schema (R-28.10-e).
  """
  if not validate_arguments_against_input_schema(tool, arguments):
    raise ValidationError(
      "Tool arguments failed input-schema validation",
      error_code=INVALID_PARAMS_CODE,
      reason="input-schema-validation-failed",
    )


def validate_pagination_cursor(
  value: Any, recognized: Iterable[str] | None = None
) -> str:
  """Validate an opaque pagination cursor; reject malformed/unknown/expired (R-28.10-j).

  A server MUST treat a pagination cursor as opaque and untrusted input, MUST
  validate it, and MUST reject a malformed, unknown, or expired cursor with an
  error rather than interpreting attacker-controlled contents (R-28.10-j). The
  opaque-string type check is owned by S04 (:func:`validate_cursor`); when
  ``recognized`` is supplied, the cursor must be one the server actually minted.

  Args:
    value: the cursor presented by the peer (untrusted).
    recognized: the set of cursors the server recognizes, or None to skip the
      membership check (the type/opacity check still applies).

  Returns:
    The validated cursor string.

  Raises:
    ValidationError: the cursor is not a string, or (when ``recognized`` is given)
      is not a recognized cursor — reported as -32602 (R-28.10-j).
  """
  try:
    cursor = validate_cursor(value)
  except TypeError as exc:
    raise ValidationError(
      "Invalid cursor",
      error_code=INVALID_PARAMS_CODE,
      reason="malformed-or-expired",
    ) from exc
  if recognized is not None and cursor not in set(recognized):
    raise ValidationError(
      "Invalid cursor",
      error_code=INVALID_PARAMS_CODE,
      reason="malformed-or-expired",
    )
  return cursor


def assert_message_within_size(size_bytes: int, *, limit: int = MAX_MESSAGE_BYTES) -> None:
  """Reject a message/payload exceeding the size limit (R-28.10-l).

  Receivers SHOULD impose limits on message and payload size and reject inputs
  that exceed them (R-28.10-l).

  Raises:
    ValidationError: ``size_bytes`` exceeds ``limit`` (reported as -32600).
  """
  if size_bytes > limit:
    raise ValidationError(
      f"message of {size_bytes} bytes exceeds the {limit}-byte limit",
      error_code=INVALID_REQUEST_CODE,
      reason="payload-too-large",
    )


def bounded_depth(value: Any, *, max_depth: int = MAX_VALIDATION_DEPTH) -> int:
  """Return the structure's nesting depth, raising if it exceeds the bound (R-28.10-k).

  A receiver MUST bound the resources consumed while validating, including bounding
  schema nesting depth, so a hostile or pathological schema cannot cause unbounded
  computation or memory use (R-28.10-k). This measures depth and aborts as soon as
  ``max_depth`` is exceeded — it never descends past the bound, so a deeply nested
  hostile payload costs only O(max_depth) stack.

  Args:
    value: the structure (schema or payload) to measure.
    max_depth: the maximum permitted nesting depth.

  Returns:
    The measured nesting depth (1 for a scalar / empty container).

  Raises:
    ValidationError: nesting exceeds ``max_depth`` (reported as -32602).
  """

  def _depth(node: Any, level: int) -> int:
    if level > max_depth:
      raise ValidationError(
        f"input nesting exceeds the maximum depth of {max_depth} (R-28.10-k)",
        error_code=INVALID_PARAMS_CODE,
        reason="max-depth-exceeded",
      )
    if isinstance(node, Mapping):
      if not node:
        return level
      return max(_depth(v, level + 1) for v in node.values())
    if isinstance(node, (list, tuple)):
      if not node:
        return level
      return max(_depth(v, level + 1) for v in node)
    return level

  return _depth(value, 1)


#: JSON-Schema keywords whose value is an external reference. A server MUST NOT
#: automatically dereference these (R-28.10-m); a ``$ref`` that points outside the
#: document is an external reference.
_REF_KEYWORDS: frozenset[str] = frozenset({"$ref", "$dynamicRef", "$recursiveRef"})


def _ref_is_external(ref: str) -> bool:
  """True iff a JSON-Schema ``$ref`` points outside the current document.

  An internal reference is empty or a same-document JSON Pointer (``#`` /
  ``#/...``). Anything with a scheme, a network/path location, or a non-empty part
  before the ``#`` fragment is external and MUST NOT be auto-dereferenced
  (R-28.10-m).
  """
  if ref.startswith("#"):
    return False
  parts = urlsplit(ref)
  # A bare fragment ("#/...") has no scheme/netloc/path; anything else is external.
  return bool(parts.scheme or parts.netloc or parts.path)


def schema_has_external_references(
  schema: Any, *, max_depth: int = MAX_VALIDATION_DEPTH
) -> bool:
  """True iff a tool schema contains an external ``$ref`` (R-28.10-m/n).

  A server MUST NOT automatically dereference external schema references in a tool
  schema (R-28.10-m); schemas MUST be self-contained or resolved only against
  explicitly trusted sources (R-28.10-n). This *detects* external references so a
  caller can refuse to auto-dereference them; it never fetches anything. Traversal
  is depth-bounded so a hostile schema cannot exhaust resources (R-28.10-k).

  Returns:
    True iff any ``$ref``/``$dynamicRef``/``$recursiveRef`` points outside the
    document.
  """

  def _walk(node: Any, level: int) -> bool:
    if level > max_depth:
      return False
    if isinstance(node, Mapping):
      for key, val in node.items():
        if key in _REF_KEYWORDS and isinstance(val, str) and _ref_is_external(val):
          return True
        if _walk(val, level + 1):
          return True
      return False
    if isinstance(node, (list, tuple)):
      return any(_walk(v, level + 1) for v in node)
    return False

  return _walk(schema, 1)


def assert_no_external_schema_references(schema: Any) -> None:
  """Reject a tool schema carrying external references (R-28.10-m/n).

  A server MUST NOT automatically dereference external schema references
  (R-28.10-m); schemas MUST be self-contained or resolved only against trusted
  sources (R-28.10-n). This raises if any external reference is present, so the
  server never auto-dereferences one.

  Raises:
    ValidationError: the schema contains an external ``$ref`` (R-28.10-m/n).
  """
  if schema_has_external_references(schema):
    raise ValidationError(
      "tool schema contains an external reference; external references MUST NOT "
      "be automatically dereferenced and schemas MUST be self-contained "
      "(R-28.10-m, R-28.10-n)",
      error_code=INVALID_PARAMS_CODE,
      reason="external-schema-reference",
    )


# ---------------------------------------------------------------------------
# §28.10  URI validation, SSRF, and file:// path sanitization
# ---------------------------------------------------------------------------


#: URI schemes that can cause a receiver to issue an outbound network request,
#: so a URI bearing one needs SSRF scrutiny before being followed (R-28.10-h).
_NETWORK_SCHEMES: frozenset[str] = frozenset({"http", "https", "ftp", "ftps", "ws", "wss"})


class UriValidationError(Exception):
  """A resource URI failed validation or pointed to an unauthorized location.

  Raised when a URI is malformed (R-28.10-f), would be followed to a location the
  user has not authorized (R-28.10-g), or would trigger an SSRF-prone network
  request to a disallowed host (R-28.10-h).
  """


def validate_resource_uri(
  uri: str, *, allowed_schemes: Iterable[str] | None = None
) -> str:
  """Validate a resource URI before dereferencing or matching it (R-28.10-f).

  A receiver MUST validate resource URIs and URI templates before dereferencing or
  matching them (R-28.10-f). This checks the URI parses and (when
  ``allowed_schemes`` is given) bears an allowed scheme. It does NOT fetch
  anything.

  Args:
    uri: the resource URI to validate.
    allowed_schemes: the schemes the receiver permits, or None to allow any
      well-formed scheme.

  Returns:
    The validated URI string.

  Raises:
    UriValidationError: the URI is malformed or bears a disallowed scheme.
  """
  if not isinstance(uri, str) or not uri:
    raise UriValidationError("resource URI must be a non-empty string (R-28.10-f)")
  parts = urlsplit(uri)
  if not parts.scheme:
    raise UriValidationError(f"resource URI {uri!r} has no scheme (R-28.10-f)")
  if allowed_schemes is not None:
    allowed = {s.lower() for s in allowed_schemes}
    if parts.scheme.lower() not in allowed:
      raise UriValidationError(
        f"resource URI scheme {parts.scheme!r} is not in the authorized set "
        f"{sorted(allowed)!r} (R-28.10-f/g)"
      )
  return uri


def is_ssrf_safe_host(host: str, *, allowed_hosts: Iterable[str]) -> bool:
  """True iff a host is on the SSRF allowlist (R-28.10-h).

  Implementations SHOULD guard against server-side request forgery when a URI
  could cause the receiver to issue a network request (R-28.10-h). This is the
  allowlist predicate: a host is safe to fetch only when it is explicitly
  permitted; everything else (including loopback/internal hosts not on the list)
  is refused.
  """
  return host.lower() in {h.lower() for h in allowed_hosts}


def assert_uri_followable(
  uri: str,
  *,
  allowed_schemes: Iterable[str] | None = None,
  allowed_hosts: Iterable[str] | None = None,
) -> str:
  """Validate a URI and assert it may be followed (R-28.10-f/g/h).

  Validates the URI (R-28.10-f), and — for a network-capable scheme — refuses to
  follow it to any host not on ``allowed_hosts`` (the user-authorized location
  rule R-28.10-g and the SSRF guard R-28.10-h). A non-network scheme (e.g.
  ``file``) is not subject to the host allowlist here; ``file://`` path safety is
  enforced by :func:`sanitize_file_path`.

  Raises:
    UriValidationError: validation fails, or a network URI targets a host the user
      has not authorized (R-28.10-g/h).
  """
  validate_resource_uri(uri, allowed_schemes=allowed_schemes)
  parts = urlsplit(uri)
  if parts.scheme.lower() in _NETWORK_SCHEMES:
    host = parts.hostname or ""
    if allowed_hosts is None or not is_ssrf_safe_host(host, allowed_hosts=allowed_hosts):
      raise UriValidationError(
        f"refusing to follow URI {uri!r} to host {host!r}: the host is not "
        f"user-authorized and following it risks SSRF (R-28.10-g/h)"
      )
  return uri


class FilePathTraversalError(Exception):
  """A file:// path escaped its authorized root via traversal or an absolute path.

  Raised by :func:`sanitize_file_path` when a requested path resolves outside the
  authorized root — e.g. it contains ``..`` segments that climb above the root, or
  it is an absolute path escaping it. When serving ``file://`` resources a server
  MUST sanitize file paths to prevent directory traversal (R-28.10-o) and MUST NOT
  serve a file outside the user-authorized directories (R-28.10-p).
  """


def sanitize_file_path(authorized_root: str, requested_path: str) -> str:
  """Sanitize a file:// path against directory traversal and root escape (R-28.10-o/p).

  When serving ``file://`` resources, a server MUST sanitize file paths to prevent
  directory-traversal attacks — for example paths containing ``..`` segments or
  absolute paths escaping the authorized root (R-28.10-o) — and MUST NOT serve a
  file outside the directories the user has authorized (R-28.10-p).

  The check is performed on the *normalized* path so that ``..`` segments,
  redundant separators, and a leading ``/`` cannot climb above (or escape) the
  authorized root. The returned path is the safe, normalized absolute path within
  the root; a request that would escape the root raises rather than returning a
  partially-sanitized value (which would defeat the purpose).

  Args:
    authorized_root: the directory the user authorized (the confinement root).
    requested_path: the peer-supplied path (or ``file://`` URI path), untrusted.

  Returns:
    The normalized absolute path, guaranteed to lie within ``authorized_root``.

  Raises:
    FilePathTraversalError: the requested path escapes the authorized root
      (R-28.10-o/p).
  """
  # Use POSIX semantics on the URI path component (file:// paths are POSIX-shaped).
  root = PurePosixPath(posixpath.normpath("/" + authorized_root.strip("/")))
  # A leading slash on the request is stripped so it is treated as relative to the
  # root; ``..`` segments are then normalized and cannot climb above "/".
  decoded = unquote(requested_path)
  joined = posixpath.normpath(posixpath.join(str(root), decoded.lstrip("/")))
  resolved = PurePosixPath(joined)
  # Confinement check: the resolved path MUST be the root itself or below it.
  if resolved != root and root not in resolved.parents:
    raise FilePathTraversalError(
      f"requested path {requested_path!r} escapes the authorized root "
      f"{authorized_root!r}; a server MUST NOT serve a file outside the "
      f"user-authorized directories (R-28.10-o, R-28.10-p)"
    )
  return str(resolved)


def path_is_within_authorized_root(authorized_root: str, requested_path: str) -> bool:
  """True iff a requested file:// path stays within the authorized root (R-28.10-o/p).

  The non-raising companion to :func:`sanitize_file_path`: returns ``False`` for a
  path that would escape the authorized root rather than raising.
  """
  try:
    sanitize_file_path(authorized_root, requested_path)
  except FilePathTraversalError:
    return False
  return True


__all__ = [
  # §28.1 core principles
  "SecurityPrinciple",
  "CORE_SECURITY_PRINCIPLES",
  "design_is_built_on_core_principles",
  # §28 catalog
  "SecurityRequirement",
  "SECURITY_REQUIREMENTS",
  "security_requirement",
  "security_requirements_for_role",
  "mandatory_security_requirements",
  # §28.2 / §28.3 consent gate
  "ConsentRequiredError",
  "ConsentOutcome",
  "ConsentRecord",
  "ConsentPrompt",
  "ConsentGate",
  "is_material_change",
  "decision_rests_solely_with_model",
  # §28.4 isolation
  "ServerIsolationError",
  "ServerIsolationBoundary",
  "access_control_is_sufficient",
  # §28.5 authorization security
  "server_must_reject_token",
  "server_may_forward_client_token",
  "exact_issuer_matches",
  "authorization_endpoint_uri_is_secure",
  # §28.6 continuation safety
  "ContinuationTokenError",
  "ContinuationTokenGuard",
  # §28.7 elicitation / sampling consent
  "elicitation_requests_secret",
  "elicitation_response_may_be_returned",
  "sampling_may_proceed",
  # §28.8 UI sandboxing
  "SandboxPolicy",
  "UnmediatedToolInvocationError",
  "route_ui_tool_invocation",
  # §28.9 metadata & observability
  "metadata_value_carries_authority",
  "use_metadata_for_access_control",
  "filter_known_metadata",
  "is_sensitive_key",
  "redact_for_log",
  "REDACTION_PLACEHOLDER",
  # §28.10 input validation & bounds
  "ValidationError",
  "MAX_VALIDATION_DEPTH",
  "MAX_MESSAGE_BYTES",
  "validate_tool_arguments",
  "validate_pagination_cursor",
  "assert_message_within_size",
  "bounded_depth",
  "schema_has_external_references",
  "assert_no_external_schema_references",
  "UriValidationError",
  "validate_resource_uri",
  "is_ssrf_safe_host",
  "assert_uri_followable",
  "FilePathTraversalError",
  "sanitize_file_path",
  "path_is_within_authorized_root",
  # Referenced sibling primitives re-exported for the security surface
  "OriginValidator",
  "TokenAudienceError",
  "server_accepts_audience_bound_token",
  "client_may_send_token_to_server",
  "issuers_match",
  "client_may_use_annotations",
  "PKCE_CODE_CHALLENGE_METHOD",
  "generate_pkce_parameters",
  "generate_state",
]
