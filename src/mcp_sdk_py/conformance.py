"""Conformance Requirements & References — S45.

This module is the authoritative **conformance catalog** for the MCP Python
SDK. It restates, as a single coherent rulebook, what it means for an
implementation to be a conformant MCP party along the three independent axes of
§29.1:

  - **role** (client, server, or both — §29.1, §29.2, §29.3);
  - **feature surface** (the baseline plus whatever capabilities and extensions
    are advertised — §29.4, §29.5);
  - **transport** (each transport implemented, independently — §29.8).

A party is conformant *if and only if* every applicable normative requirement on
its chosen roles, advertised features, and implemented transports is satisfied,
judged on observable wire behaviour alone (§29.1, §29.9).

This is a cross-cutting, governance story. It owns **no new wire types**: its
only structured artifact is the :class:`ConformanceProfile`, an abstract
descriptor used to reason about and report conformance. Everything else here is
the consolidated **requirement catalog** (the ``R-29.*`` and ``R-30-a`` atoms,
each carrying its RFC-2119 level, axis, and the section that normatively defines
the behaviour) plus the decision procedures that adjudicate it: the §29.2
baseline-server request disposition, the §29.3 baseline-client envelope and
retry discipline, the §29.4 capability-conditioned obligation map, the §29.5
optionality of extensions and deprecated features, the §29.6 robustness rules,
the §29.7 stateless invariants, the §29.8 transport conformance points, and the
§29.9 determination procedure.

Per the constitution and §30, the §30 reference markers are **provenance-only**;
they are never load-bearing, and this module's behaviour never depends on the
content of any cited work (R-30-a).

Code ownership (referenced, never redefined):
  - The error codes ``-32004`` / ``-32003`` / ``-32602`` and their normative
    ``data`` shapes — S34 (:mod:`mcp_sdk_py.errors`) and S09
    (:mod:`mcp_sdk_py.negotiation`). This story only mandates *when* they are
    emitted; it reuses S09's builders for the §29.2 rejections.
  - The wire protocol-revision value and per-request envelope keys — S05/S06/S07
    (:mod:`mcp_sdk_py.meta_object`, :mod:`mcp_sdk_py.revision`).
  - The transport names and the "at least one transport" model — S12
    (:mod:`mcp_sdk_py.transport`).
  - The ``resultType`` discriminator vocabulary — S04
    (:mod:`mcp_sdk_py.result_error`) and S38
    (:mod:`mcp_sdk_py.extension_mechanism`, ``CORE_RESULT_TYPES``).
  - The per-capability ``input_required`` machinery and ``requestState``
    integrity primitives — S17 (:mod:`mcp_sdk_py.multi_round_trip`).
  - The HTTP-vs-stdio authorization applicability — S35
    (:mod:`mcp_sdk_py.authorization`).

Spec: §29–§30 (lines 8426–8585)
Depends on: S34 (error registry), S09 (negotiation builders), S04/S38
  (result types), S17 (multi-round-trip), S12 (transports), S35 (authorization).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.authorization import TransportClass, authorization_applies
from mcp_sdk_py.extension_mechanism import CORE_RESULT_TYPES
from mcp_sdk_py.foundations import RequirementLevel
from mcp_sdk_py.meta_object import (
  CURRENT_PROTOCOL_VERSION,
  KEY_CLIENT_CAPABILITIES,
  KEY_CLIENT_INFO,
  KEY_PROTOCOL_VERSION,
)
from mcp_sdk_py.multi_round_trip import (
  INPUT_REQUEST_ELICITATION,
  make_hmac_request_state,
  verify_hmac_request_state,
)
from mcp_sdk_py.negotiation import (
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
  UNSUPPORTED_PROTOCOL_VERSION_CODE,
  build_missing_required_client_capability_error,
  build_unsupported_protocol_version_error,
)
from mcp_sdk_py.result_error import ErrorObject
from mcp_sdk_py.transport import (
  DEFINED_TRANSPORTS,
  TRANSPORT_STDIO,
  TRANSPORT_STREAMABLE_HTTP,
)


# ---------------------------------------------------------------------------
# Cross-module constants reused verbatim (referenced, not redefined)
# ---------------------------------------------------------------------------

#: -32602 Invalid params (S04/S34). A malformed §4 envelope — a missing required
#: field — is rejected with this code (R-29.2-j, §29.2 item 6).
INVALID_PARAMS_CODE: int = -32602

#: The wire protocol revision every conformance profile always advertises
#: (R-29.2-h note, R-29.9-c, §29.9 item 3). Reused from S05 so the value lives in
#: exactly one place (``2026-07-28``).
WIRE_PROTOCOL_REVISION: str = CURRENT_PROTOCOL_VERSION


# ---------------------------------------------------------------------------
# §29.1  The three conformance axes
# ---------------------------------------------------------------------------

class ConformanceRole(enum.Enum):
  """A role a conformant implementation may play (§29.1 axis 1).

  A requirement that names a role binds an implementation only when it plays
  that role; an implementation that plays BOTH MUST satisfy each role's
  requirements (R-29.1-a, R-29.1-b). ``host`` is the trust boundary of §1.1 and
  is not itself a wire role, so the conformance axis is client/server only.
  """

  CLIENT = "client"
  SERVER = "server"


class ConformanceAxis(enum.Enum):
  """The three independent axes conformance is scoped along (§29.1).

  ROLE:
    What a party *is* — client, server, or both (§29.1 axis 1, §29.2/§29.3).
  FEATURE_SURFACE:
    What a party *advertises* — the baseline plus advertised capabilities and
    extensions (§29.1 axis 2, §29.4, §29.5).
  TRANSPORT:
    What a party *speaks* — each transport it implements, independently (§29.1
    axis 3, §29.8).
  """

  ROLE = "role"
  FEATURE_SURFACE = "feature_surface"
  TRANSPORT = "transport"


#: The transports a conformance profile may name; reused from S12's transport
#: model (R-29.8-a). At least one MUST be implemented (R-29.8-a).
CONFORMANCE_TRANSPORTS: frozenset[str] = DEFINED_TRANSPORTS


# ---------------------------------------------------------------------------
# §29 catalog: the requirement atom and its level / axis / section
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConformanceRequirement:
  """One normative atom of the §29/§30 conformance contract.

  This is the catalog entry, not the behaviour: the behaviour itself is owned by
  the section named in :attr:`section` and (where code exists) by the sibling
  module that implements it. This story *references* those requirements to build
  the authoritative checklist (R-29.1-a … R-30-a).

  Fields:
    atom: the requirement id exactly as written in the story (e.g. "R-29.2-h").
    level: the RFC-2119 keyword (S01 :class:`RequirementLevel`) the atom carries.
    axis: which conformance axis (§29.1) the atom belongs to.
    roles: the roles the atom binds; empty means it binds every party regardless
      of role (e.g. the robustness rules of §29.6).
    section: the spec section that normatively defines the behaviour.
    summary: a one-line restatement of the obligation (informational).
  """

  atom: str
  level: RequirementLevel
  axis: ConformanceAxis
  roles: frozenset[ConformanceRole]
  section: str
  summary: str

  @property
  def is_mandatory(self) -> bool:
    """True for absolute obligations/prohibitions (MUST / MUST NOT / SHALL etc.).

    A mandatory atom must be satisfied for conformance with no exceptions
    (R-29.1-a); a discretionary (MAY/OPTIONAL) or conditional (SHOULD) atom is
    judged only as its keyword allows.
    """
    return (
      self.level.is_absolute_requirement or self.level.is_absolute_prohibition
    )

  def binds_role(self, role: ConformanceRole) -> bool:
    """True iff this atom binds ``role`` (an empty :attr:`roles` binds all)."""
    return not self.roles or role in self.roles


def _req(
  atom: str,
  level: RequirementLevel,
  axis: ConformanceAxis,
  roles: frozenset[ConformanceRole],
  section: str,
  summary: str,
) -> ConformanceRequirement:
  """Construct a catalog entry (terse builder for the table below)."""
  return ConformanceRequirement(atom, level, axis, roles, section, summary)


_CLIENT = frozenset({ConformanceRole.CLIENT})
_SERVER = frozenset({ConformanceRole.SERVER})
_BOTH = frozenset({ConformanceRole.CLIENT, ConformanceRole.SERVER})
_ANY: frozenset[ConformanceRole] = frozenset()

_L = RequirementLevel
_AX_ROLE = ConformanceAxis.ROLE
_AX_FEAT = ConformanceAxis.FEATURE_SURFACE
_AX_TRANS = ConformanceAxis.TRANSPORT


#: The authoritative §29/§30 requirement catalog, keyed by atom id. Each entry
#: records the RFC-2119 level, the conformance axis, the roles it binds, the
#: section that owns the behaviour, and a one-line restatement. This is the
#: single checklist S46 reconciles against; it references — never redefines — the
#: behaviours other modules implement.
CONFORMANCE_REQUIREMENTS: dict[str, ConformanceRequirement] = {
  r.atom: r
  for r in (
    # §29.1 Meaning of conformance
    _req("R-29.1-a", _L.MUST, _AX_ROLE, _ANY, "§29.1",
         "satisfy every applicable normative requirement for roles & features"),
    _req("R-29.1-b", _L.MUST, _AX_ROLE, _BOTH, "§29.1",
         "a both-roles party satisfies each role's requirements"),
    _req("R-29.1-c", _L.MUST, _AX_ROLE, _ANY, "§3",
         "use the §3 base message format for all protocol traffic"),
    _req("R-29.1-d", _L.MUST, _AX_ROLE, _ANY, "§4",
         "operate under the §4 stateless, per-request model"),
    _req("R-29.1-e", _L.MUST_NOT, _AX_ROLE, _ANY, "§4",
         "do not derive protocol state from connection/process/stream identity"),
    _req("R-29.1-f", _L.MAY, _AX_ROLE, _ANY, "§29.9",
         "any internal architecture/language is permitted; only the wire binds"),
    # §29.2 Baseline server conformance
    _req("R-29.2-a", _L.MUST, _AX_ROLE, _SERVER, "§5",
         "implement server/discover; the obligation to answer is unconditional"),
    _req("R-29.2-b", _L.MAY, _AX_ROLE, _CLIENT, "§5",
         "a client MAY call server/discover first, but is not obligated to"),
    _req("R-29.2-c", _L.MUST, _AX_ROLE, _SERVER, "§5/§6",
         "advertise supported revisions & capabilities consistently with §6"),
    _req("R-29.2-d", _L.MUST_NOT, _AX_ROLE, _SERVER, "§29.4",
         "do not advertise a revision/capability not implemented"),
    _req("R-29.2-e", _L.MUST, _AX_ROLE, _SERVER, "§4",
         "honor the §4 per-request metadata envelope on every request"),
    _req("R-29.2-f", _L.MUST_NOT, _AX_ROLE, _SERVER, "§4",
         "infer no protocol state across requests, even on one connection"),
    _req("R-29.2-g", _L.MUST_NOT, _AX_ROLE, _SERVER, "§4",
         "do not require connection/process reuse for related operations"),
    _req("R-29.2-h", _L.MUST, _AX_ROLE, _SERVER, "§22.3.2",
         "reject an unsupported revision with -32004 {supported, requested}"),
    _req("R-29.2-i", _L.MUST, _AX_ROLE, _SERVER, "§22.3.1",
         "reject a missing required capability with -32003 requiredCapabilities"),
    _req("R-29.2-j", _L.MUST, _AX_ROLE, _SERVER, "§22.4",
         "reject a malformed §4 envelope (missing required field) with -32602"),
    _req("R-29.2-k", _L.MUST, _AX_ROLE, _SERVER, "§3",
         "set the resultType discriminator on every successful result"),
    _req("R-29.2-l", _L.MUST, _AX_ROLE, _SERVER, "§3/§6",
         "resultType is drawn from core + advertised-extension values only"),
    _req("R-29.2-m", _L.MUST, _AX_FEAT, _SERVER, "§6",
         "gate every feature behind its advertised capability"),
    _req("R-29.2-n", _L.MUST_NOT, _AX_FEAT, _SERVER, "§29.4",
         "expose/exercise nothing unadvertised; solicit no undeclared behavior"),
    # §29.3 Baseline client conformance
    _req("R-29.3-a", _L.MUST, _AX_ROLE, _CLIENT, "§4",
         "include revision, identity, relevant capabilities on every request"),
    _req("R-29.3-b", _L.MUST, _AX_ROLE, _CLIENT, "§5",
         "send a supported revision and select a mutually supported one"),
    _req("R-29.3-c", _L.SHOULD, _AX_ROLE, _CLIENT, "§5/§22",
         "on -32004, retry from server's supported list or surface an error"),
    _req("R-29.3-d", _L.MUST, _AX_ROLE, _CLIENT, "§4",
         "treat designated-opaque values (cursor, requestState, sub id) opaquely"),
    _req("R-29.3-e", _L.MUST_NOT, _AX_ROLE, _CLIENT, "§4",
         "do not inspect/parse/modify/assume opaque-value contents"),
    _req("R-29.3-f", _L.MUST, _AX_ROLE, _CLIENT, "§4",
         "echo a required opaque value back byte-for-byte unchanged"),
    _req("R-29.3-g", _L.MUST, _AX_ROLE, _CLIENT, "§11",
         "be able to fulfill an input_required result for declared capabilities"),
    _req("R-29.3-h", _L.MUST, _AX_ROLE, _CLIENT, "§11",
         "construct requested inputs before retrying the original request"),
    _req("R-29.3-i", _L.MAY, _AX_ROLE, _CLIENT, "§11",
         "MAY retry immediately when no input requests are present"),
    _req("R-29.3-j", _L.MUST, _AX_ROLE, _CLIENT, "§11/§3",
         "retry with a fresh id; echo requestState exactly or omit when none"),
    _req("R-29.3-k", _L.MUST, _AX_ROLE, _CLIENT, "§3/§29.6",
         "interpret results by resultType and apply §29.6 robustness"),
    # §29.4 Capability-conditioned conformance
    _req("R-29.4-a", _L.MUST, _AX_FEAT, _ANY, "§6",
         "advertising a capability binds you to its MUST-level behaviors"),
    _req("R-29.4-b", _L.MUST, _AX_FEAT, _SERVER, "§16",
         "a server advertising tools satisfies §16"),
    _req("R-29.4-c", _L.MUST, _AX_FEAT, _SERVER, "§17/§10",
         "a server advertising resources satisfies §17 (subscriptions §10)"),
    _req("R-29.4-d", _L.MUST, _AX_FEAT, _SERVER, "§18",
         "a server advertising prompts satisfies §18"),
    _req("R-29.4-e", _L.MUST, _AX_FEAT, _SERVER, "§19",
         "a server advertising completion satisfies §19"),
    _req("R-29.4-f", _L.MUST, _AX_FEAT, _CLIENT, "§20",
         "a client advertising elicitation satisfies §20"),
    _req("R-29.4-g", _L.MUST, _AX_FEAT, _ANY, "§10",
         "any party advertising streaming/subscription satisfies §10"),
    _req("R-29.4-h", _L.MUST_NOT, _AX_FEAT, _ANY, "§29.4",
         "do not exercise/expose/depend on a feature not advertised"),
    _req("R-29.4-i", _L.MUST_NOT, _AX_FEAT, _SERVER, "§29.2",
         "do not return a result type / solicit / invoke outside advertised"),
    _req("R-29.4-j", _L.MUST_NOT, _AX_FEAT, _ANY, "§29.4",
         "do not advertise a capability whose behavior is not implemented"),
    _req("R-29.4-k", _L.MUST_NOT, _AX_FEAT, _SERVER, "§22.3.1",
         "do not rely on an undeclared client capability; else -32003"),
    _req("R-29.4-l", _L.MUST_NOT, _AX_FEAT, _SERVER, "§11/§20",
         "no input request of a kind the client has not declared"),
    _req("R-29.4-m", _L.MUST, _AX_FEAT, _ANY, "§21",
         "advertising a deprecated client-provided capability binds its behavior"),
    _req("R-29.4-n", _L.MUST_NOT, _AX_FEAT, _ANY, "§21",
         "do not rely on a deprecated client-provided capability you did not advertise"),
    # §29.5 Optionality of extensions and deprecated features
    _req("R-29.5-a", _L.OPTIONAL, _AX_FEAT, _ANY, "§24/§25/§26",
         "extensions are OPTIONAL; zero advertised extensions is conformant"),
    _req("R-29.5-b", _L.MUST, _AX_FEAT, _ANY, "§24/§22",
         "advertising an extension binds its MUST-level behaviors & fallback"),
    _req("R-29.5-c", _L.MUST, _AX_FEAT, _ANY, "§6",
         "extension identifiers follow §6 naming rules"),
    _req("R-29.5-d", _L.MUST, _AX_FEAT, _ANY, "§24/§22",
         "one-sided extension: revert to core or reject with an error"),
    _req("R-29.5-e", _L.OPTIONAL, _AX_FEAT, _ANY, "§27",
         "Deprecated features are OPTIONAL to implement"),
    _req("R-29.5-f", _L.MUST, _AX_FEAT, _ANY, "§27",
         "an implemented Deprecated feature is followed in full; no partial"),
    # §29.6 Robustness and forward compatibility
    _req("R-29.6-a", _L.MUST, _AX_FEAT, _ANY, "§2",
         "be tolerant of inputs richer than understood"),
    _req("R-29.6-b", _L.MUST, _AX_FEAT, _ANY, "§2",
         "ignore unrecognized object fields rather than rejecting"),
    _req("R-29.6-c", _L.MUST, _AX_FEAT, _ANY, "§2/§6",
         "ignore unrecognized advertised capabilities; not an error"),
    _req("R-29.6-d", _L.MUST, _AX_FEAT, _ANY, "§6/§24",
         "ignore unrecognized extension identifiers (triggers §29.5 fallback)"),
    _req("R-29.6-e", _L.MUST, _AX_ROLE, _CLIENT, "§22",
         "accept unrecognized error codes as failures without crashing"),
    _req("R-29.6-f", _L.MUST, _AX_FEAT, _ANY, "§3",
         "an unrecognized resultType MUST be treated as an error"),
    _req("R-29.6-g", _L.MUST_NOT, _AX_ROLE, _CLIENT, "§3",
         "do not act on a result whose discriminator cannot be interpreted"),
    _req("R-29.6-h", _L.MUST, _AX_FEAT, _ANY, "§3",
         "apply the §3 absence rule when resultType is absent"),
    _req("R-29.6-i", _L.MUST_NOT, _AX_FEAT, _ANY, "§29.6",
         "ignoring the unknown MUST NOT discard understood required content"),
    # §29.7 Conformance and the stateless model
    _req("R-29.7-a", _L.MUST, _AX_ROLE, _SERVER, "§4",
         "process each request independently; infer no context from earlier ones"),
    _req("R-29.7-b", _L.MUST, _AX_ROLE, _ANY, "§4/§11",
         "spanning state rides an explicit client-supplied identifier/opaque value"),
    _req("R-29.7-c", _L.MUST_NOT, _AX_ROLE, _ANY, "§4",
         "do not treat connection/process as the lifetime boundary"),
    _req("R-29.7-d", _L.MUST, _AX_ROLE, _SERVER, "§11/§28",
         "treat a passed-through requestState as attacker-controlled input"),
    _req("R-29.7-e", _L.MUST, _AX_ROLE, _SERVER, "§11/§28",
         "protect requestState integrity; reject state that fails verification"),
    # §29.8 Transport conformance
    _req("R-29.8-a", _L.MUST, _AX_TRANS, _ANY, "§7",
         "implement at least one §7 transport"),
    _req("R-29.8-b", _L.MUST, _AX_TRANS, _ANY, "§8/§9",
         "uphold each transport's framing/routing/error-mapping"),
    _req("R-29.8-c", _L.MUST, _AX_TRANS, _ANY, "§9",
         "map -32602 / -32003 to the prescribed Streamable HTTP statuses"),
    _req("R-29.8-d", _L.SHOULD, _AX_TRANS, _ANY, "§23",
         "an HTTP-based transport SHOULD conform to §23 authorization"),
    _req("R-29.8-e", _L.SHOULD_NOT, _AX_TRANS, _ANY, "§8/§23",
         "stdio SHOULD NOT apply §23; obtain credentials from the environment"),
    _req("R-29.8-f", _L.MUST_NOT, _AX_TRANS, _ANY, "§7",
         "no transport's conformance is contingent on another"),
    _req("R-29.8-g", _L.MAY, _AX_TRANS, _ANY, "§7",
         "multiple transports MAY be offered concurrently"),
    # §29.9 Determining conformance
    _req("R-29.9-a", _L.MAY, _AX_ROLE, _ANY, "§29.9",
         "satisfying every applicable requirement is sufficient for interop"),
    _req("R-29.9-b", _L.MUST, _AX_FEAT, _ANY, "§29.4",
         "fully implement an advertised feature or do not advertise it"),
    _req("R-29.9-c", _L.MUST, _AX_FEAT, _ANY, "§Appendix B/C/D",
         "use the exact Appendix B/C/D codes, _meta keys, capability identifiers"),
    # §30 References
    _req("R-30-a", _L.MAY, _AX_ROLE, _ANY, "§30",
         "citation markers are provenance-only and never load-bearing"),
  )
}


def requirement(atom: str) -> ConformanceRequirement:
  """Return the catalog entry for ``atom`` (e.g. ``"R-29.2-h"``) (§29/§30).

  Raises:
    KeyError: ``atom`` is not a catalog atom.
  """
  return CONFORMANCE_REQUIREMENTS[atom]


def requirements_for_role(role: ConformanceRole) -> tuple[ConformanceRequirement, ...]:
  """Every catalog atom that binds ``role`` (R-29.1-a/b).

  An atom with an empty :attr:`ConformanceRequirement.roles` binds every party
  and is therefore included for either role.
  """
  return tuple(
    r for r in CONFORMANCE_REQUIREMENTS.values() if r.binds_role(role)
  )


def requirements_for_axis(axis: ConformanceAxis) -> tuple[ConformanceRequirement, ...]:
  """Every catalog atom belonging to ``axis`` (§29.1)."""
  return tuple(r for r in CONFORMANCE_REQUIREMENTS.values() if r.axis is axis)


def mandatory_requirements() -> tuple[ConformanceRequirement, ...]:
  """Every absolute (MUST / MUST NOT / SHALL / SHALL NOT) catalog atom (R-29.1-a)."""
  return tuple(r for r in CONFORMANCE_REQUIREMENTS.values() if r.is_mandatory)


# ---------------------------------------------------------------------------
# §29.4  Capability-conditioned obligation map
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CapabilityObligation:
  """One row of the §29.4 capability → obligation map.

  Advertising the capability is a binding assertion of full MUST-level
  conformance for the section(s) named here (R-29.4-a … R-29.4-g, R-29.4-j).

  Fields:
    capability: the advertised capability identifier (Appendix D wire key).
    role: the role that may advertise the capability (client or server).
    sections: the spec section(s) whose MUST-level behavior the capability binds.
    atom: the §29.4 atom that imposes the obligation.
  """

  capability: str
  role: ConformanceRole
  sections: tuple[str, ...]
  atom: str


#: The §29.4 item-1 obligation map: each advertised capability binds the
#: MUST-level behavior of the named section(s) (R-29.4-b … R-29.4-g). Keys are
#: the Appendix D capability identifiers (referenced, owned by the feature
#: stories / S46). ``resourceSubscriptions`` additionally pulls in §10, and any
#: streaming/subscription capability pulls in §10 (R-29.4-c, R-29.4-g).
CAPABILITY_OBLIGATIONS: dict[str, CapabilityObligation] = {
  "tools": CapabilityObligation("tools", ConformanceRole.SERVER, ("§16",), "R-29.4-b"),
  "resources": CapabilityObligation(
    "resources", ConformanceRole.SERVER, ("§17",), "R-29.4-c"),
  "resourceSubscriptions": CapabilityObligation(
    "resourceSubscriptions", ConformanceRole.SERVER, ("§17", "§10"), "R-29.4-c"),
  "prompts": CapabilityObligation(
    "prompts", ConformanceRole.SERVER, ("§18",), "R-29.4-d"),
  "completions": CapabilityObligation(
    "completions", ConformanceRole.SERVER, ("§19",), "R-29.4-e"),
  "elicitation": CapabilityObligation(
    "elicitation", ConformanceRole.CLIENT, ("§20",), "R-29.4-f"),
  "subscriptions": CapabilityObligation(
    "subscriptions", ConformanceRole.SERVER, ("§10",), "R-29.4-g"),
}


def obligations_for_capabilities(
  capabilities: list[str] | frozenset[str] | tuple[str, ...],
) -> tuple[CapabilityObligation, ...]:
  """Return the §29.4 obligations incurred by advertising ``capabilities``.

  Only *recognized* capabilities incur an obligation; an unrecognized capability
  is ignored here (it is simply unsupported, R-29.6-c) and never an error.
  Advertising any capability in the map is a binding assertion of full MUST-level
  conformance for its section(s) (R-29.4-a, R-29.4-j).

  Args:
    capabilities: the advertised capability identifiers.

  Returns:
    The matching obligations, in the iteration order of ``capabilities``.
  """
  seen: set[str] = set()
  out: list[CapabilityObligation] = []
  for cap in capabilities:
    if cap in CAPABILITY_OBLIGATIONS and cap not in seen:
      seen.add(cap)
      out.append(CAPABILITY_OBLIGATIONS[cap])
  return tuple(out)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConformanceViolation(Exception):
  """An observable wire behaviour violates a §29 normative requirement.

  Carries the offending :attr:`atom` so a caller can map the violation back to
  the catalog. Raised by the §29.2/§29.3/§29.4/§29.7 decision procedures below
  when an implementation steps outside its conformance contract.
  """

  def __init__(self, atom: str, message: str) -> None:
    super().__init__(f"{message} ({atom})")
    self.atom: str = atom


# ---------------------------------------------------------------------------
# §29.2  Baseline server request disposition
# ---------------------------------------------------------------------------

class ServerDisposition(enum.Enum):
  """The outcome of the §29.2 baseline-server request-disposition checks.

  Each rejecting member names the registry-exact code the server MUST return;
  SUCCESS means the request passed every baseline check and the server returns a
  resultType-tagged success (§29.2 items 4–8).

  REJECT_UNSUPPORTED_REVISION:
    The declared revision is not implemented ⇒ -32004 (R-29.2-h).
  REJECT_MALFORMED_ENVELOPE:
    A §4-required field is missing ⇒ -32602 (R-29.2-j).
  REJECT_MISSING_CAPABILITY:
    A required client capability is undeclared ⇒ -32003 (R-29.2-i, R-29.4-k).
  REFUSE_UNADVERTISED_FEATURE:
    The feature is not gated behind an advertised capability ⇒ refuse, never
    expose or solicit (R-29.2-m, R-29.2-n).
  SUCCESS:
    All checks pass; return a resultType-tagged result (R-29.2-k).
  """

  REJECT_UNSUPPORTED_REVISION = "reject_unsupported_revision"
  REJECT_MALFORMED_ENVELOPE = "reject_malformed_envelope"
  REJECT_MISSING_CAPABILITY = "reject_missing_capability"
  REFUSE_UNADVERTISED_FEATURE = "refuse_unadvertised_feature"
  SUCCESS = "success"


#: The §4-required per-request envelope fields a conformant request carries on
#: every request: the protocol revision, the client identity, and the client
#: capabilities (R-29.3-a, §29.2 item 6). Reused from S05's meta-object keys so
#: the wire spellings live in one place.
REQUIRED_ENVELOPE_FIELDS: tuple[str, ...] = (
  KEY_PROTOCOL_VERSION,
  KEY_CLIENT_INFO,
  KEY_CLIENT_CAPABILITIES,
)

#: The mapping from a rejecting :class:`ServerDisposition` to its registry-exact
#: JSON-RPC error code (R-29.2-h/i/j). SUCCESS and REFUSE have no error code.
DISPOSITION_ERROR_CODE: dict[ServerDisposition, int] = {
  ServerDisposition.REJECT_UNSUPPORTED_REVISION: UNSUPPORTED_PROTOCOL_VERSION_CODE,
  ServerDisposition.REJECT_MALFORMED_ENVELOPE: INVALID_PARAMS_CODE,
  ServerDisposition.REJECT_MISSING_CAPABILITY: MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
}


@dataclass(frozen=True)
class DispositionResult:
  """The resolved §29.2 disposition of one request plus its rejection error.

  Fields:
    disposition: the :class:`ServerDisposition` reached by the checks.
    error: the registry-exact :class:`ErrorObject` to return when the
      disposition rejects (None for SUCCESS / REFUSE_UNADVERTISED_FEATURE).
    atom: the §29.2 atom that determined the disposition.
  """

  disposition: ServerDisposition
  error: ErrorObject | None
  atom: str

  @property
  def is_success(self) -> bool:
    """True iff the request passed every baseline check (R-29.2-k)."""
    return self.disposition is ServerDisposition.SUCCESS


def dispose_server_request(
  *,
  request_revision: str,
  supported_revisions: list[str],
  envelope_fields: dict[str, Any],
  required_capabilities: list[str] | None = None,
  declared_client_capabilities: dict[str, Any] | None = None,
  feature_advertised: bool = True,
) -> DispositionResult:
  """Apply the §29.2 baseline-server request disposition to one request.

  Implements, **strictly on the request's own §4 envelope** (no connection or
  stream state, R-29.1-e / R-29.2-f), the ordered checks of the §29.2 decision
  graph:

    1. Revision supported? If the declared revision is not in
       ``supported_revisions``, reject with -32004 whose ``data`` lists the
       supported revisions and the requested one (R-29.2-h, AC-45.8).
    2. All §4-required envelope fields present? If any of
       :data:`REQUIRED_ENVELOPE_FIELDS` is absent, the envelope is malformed and
       is rejected with -32602 (R-29.2-j, AC-45.10).
    3. Required client capability declared? If a required capability is not in
       ``declared_client_capabilities``, reject with -32003 whose
       ``data.requiredCapabilities`` carries the ``ClientCapabilities`` object
       (R-29.2-i, R-29.4-k, AC-45.9).
    4. Feature gated by an advertised capability? If not, refuse — never expose
       or solicit unadvertised behavior (R-29.2-m, R-29.2-n, AC-45.12).

  On success the server returns a resultType-tagged result (R-29.2-k); building
  that result is the feature story's job, not this disposition's.

  Args:
    request_revision: the protocol revision the request declares.
    supported_revisions: the revisions this server implements (always includes
      :data:`WIRE_PROTOCOL_REVISION`).
    envelope_fields: the per-request ``_meta`` envelope of the request.
    required_capabilities: client capabilities this request needs declared.
    declared_client_capabilities: the capabilities the request's metadata
      declares (a ClientCapabilities object / dict).
    feature_advertised: True iff the requested feature is gated behind a
      capability this server advertised.

  Returns:
    A :class:`DispositionResult` carrying the disposition, the registry-exact
    error (when rejecting), and the governing §29.2 atom.
  """
  # (1) revision supported? — judged on the envelope alone (R-29.2-h).
  if request_revision not in supported_revisions:
    error = build_unsupported_protocol_version_error(
      supported_revisions, request_revision
    )
    return DispositionResult(
      ServerDisposition.REJECT_UNSUPPORTED_REVISION, error, "R-29.2-h"
    )
  # (2) all §4-required envelope fields present? (R-29.2-j).
  missing_field = next(
    (f for f in REQUIRED_ENVELOPE_FIELDS if f not in envelope_fields), None
  )
  if missing_field is not None:
    error = ErrorObject(
      code=INVALID_PARAMS_CODE,
      message=(
        f"Invalid params: the §4-required envelope field {missing_field!r} is "
        "absent; the request is malformed (R-29.2-j)"
      ),
    )
    return DispositionResult(
      ServerDisposition.REJECT_MALFORMED_ENVELOPE, error, "R-29.2-j"
    )
  # (3) required client capability declared? (R-29.2-i, R-29.4-k).
  declared = declared_client_capabilities or {}
  missing_caps = [
    c for c in (required_capabilities or []) if c not in declared
  ]
  if missing_caps:
    required_obj = {c: {} for c in missing_caps}
    error = build_missing_required_client_capability_error(required_obj)
    return DispositionResult(
      ServerDisposition.REJECT_MISSING_CAPABILITY, error, "R-29.2-i"
    )
  # (4) feature gated by an advertised capability? (R-29.2-m, R-29.2-n).
  if not feature_advertised:
    return DispositionResult(
      ServerDisposition.REFUSE_UNADVERTISED_FEATURE, None, "R-29.2-m"
    )
  return DispositionResult(ServerDisposition.SUCCESS, None, "R-29.2-k")


def assert_result_type_advertised(
  result_type: Any,
  *,
  advertised_extension_result_types: frozenset[str] | set[str] | None = None,
) -> str:
  """Validate that a server's ``resultType`` is set and within the advertised set.

  A server MUST set ``resultType`` on every successful result (R-29.2-k,
  AC-45.11), and its value MUST be drawn from the core set
  (:data:`mcp_sdk_py.extension_mechanism.CORE_RESULT_TYPES`) together with values
  contributed by extensions the server has advertised — and *only* those
  (R-29.2-l, R-29.4-i, AC-45.11, AC-45.20).

  Args:
    result_type: the ``resultType`` the result carries.
    advertised_extension_result_types: extra result-type values the server's
      advertised extensions contribute (empty/None when no extension is
      advertised).

  Returns:
    The validated ``result_type``.

  Raises:
    ConformanceViolation: ``result_type`` is absent/empty (R-29.2-k) or outside
      the core + advertised-extension set (R-29.2-l).
  """
  if not isinstance(result_type, str) or not result_type:
    raise ConformanceViolation(
      "R-29.2-k",
      "a successful result MUST set a non-empty resultType discriminator",
    )
  allowed = set(CORE_RESULT_TYPES) | set(advertised_extension_result_types or ())
  if result_type not in allowed:
    raise ConformanceViolation(
      "R-29.2-l",
      f"resultType {result_type!r} is outside the core set plus advertised "
      f"extension values {sorted(allowed)!r}",
    )
  return result_type


# ---------------------------------------------------------------------------
# §29.3  Baseline client conformance
# ---------------------------------------------------------------------------

def validate_client_request_envelope(envelope_fields: dict[str, Any]) -> None:
  """Assert a client request carries every §4-required per-request field (R-29.3-a).

  Every request a client sends MUST include, in its per-request metadata, the
  protocol revision, the client identity, and the client capabilities relevant
  to that request; these are REQUIRED on every request because the stateless
  model forbids relying on the server to remember them (R-29.3-a, AC-45.13).

  Raises:
    ConformanceViolation: a §4-required field is absent (atom R-29.3-a).
  """
  for f in REQUIRED_ENVELOPE_FIELDS:
    if f not in envelope_fields:
      raise ConformanceViolation(
        "R-29.3-a",
        f"a client request MUST carry the §4-required field {f!r} in its "
        "per-request metadata",
      )


def select_retry_revision(
  client_supported: list[str],
  server_supported: list[str],
) -> str | None:
  """Pick the revision a client retries with after a -32004 (R-29.3-b/c).

  On a -32004 rejection a client SHOULD select a revision from the server's
  advertised ``supported`` list that it also supports, preferring the client's
  own order; if no mutually supported revision exists the client surfaces an
  error to the user (returns None) (R-29.3-c, AC-45.14). The selection is the
  *first* client-supported revision that the server also supports.

  Args:
    client_supported: the revisions the client supports, most-preferred first.
    server_supported: the server's advertised ``data.supported`` list.

  Returns:
    The chosen mutually-supported revision, or None when there is no overlap.
  """
  server_set = set(server_supported)
  for revision in client_supported:
    if revision in server_set:
      return revision
  return None


def echo_opaque_value(value: Any) -> Any:
  """Echo a designated-opaque value back **unchanged** (R-29.3-d/e/f).

  A client MUST treat as opaque every value the spec designates opaque
  (pagination cursor, ``requestState``, subscription id, any continuation/handle
  in request metadata) and MUST NOT inspect, parse, modify, or assume anything
  about its contents (R-29.3-d/e, AC-45.15). When the protocol requires echoing
  one back, the client MUST echo the *exact* value unchanged (R-29.3-f). This
  helper is the conformant echo: it returns the value identically, never
  transforming it.

  Args:
    value: the opaque value received from the peer.

  Returns:
    The identical ``value`` (same object), guaranteeing a byte-for-byte echo.
  """
  return value


@dataclass(frozen=True)
class RetryEnvelope:
  """A conformant retry request built after an ``input_required`` result (§29.3 item 4).

  Fields:
    request_id: a FRESH id distinct from the original request's id (R-29.3-j).
    request_state: the ``requestState`` echoed exactly when one was provided,
      else None — and when None it MUST be omitted from the wire (R-29.3-j).
  """

  request_id: Any
  request_state: Any | None

  @property
  def includes_request_state(self) -> bool:
    """True iff a ``requestState`` was provided and so rides the retry (R-29.3-j)."""
    return self.request_state is not None

  def to_meta(self) -> dict[str, Any]:
    """The retry metadata fragment; omits ``requestState`` when none was provided."""
    out: dict[str, Any] = {}
    if self.request_state is not None:
      out["requestState"] = self.request_state
    return out


def build_input_required_retry(
  *,
  original_request_id: Any,
  new_request_id: Any,
  request_state: Any | None = None,
) -> RetryEnvelope:
  """Build the conformant retry after an ``input_required`` result (R-29.3-h/j).

  When a server returns an ``input_required`` result carrying input requests, a
  client MUST construct the requested inputs before retrying (R-29.3-h); when no
  input requests are present it MAY retry immediately (R-29.3-i). Either way the
  retry MUST use a request id distinct from the original (R-29.3-j, AC-45.17),
  MUST echo back any ``requestState`` exactly when one was provided, and MUST NOT
  include a ``requestState`` when none was provided (R-29.3-j).

  Args:
    original_request_id: the id of the request being retried.
    new_request_id: the fresh id for the retry; MUST differ from the original.
    request_state: the opaque ``requestState`` to echo, or None when the server
      provided none.

  Returns:
    A :class:`RetryEnvelope` carrying the fresh id and the echoed (or omitted)
    requestState.

  Raises:
    ConformanceViolation: ``new_request_id`` equals ``original_request_id``
      (R-29.3-j).
  """
  if new_request_id == original_request_id:
    raise ConformanceViolation(
      "R-29.3-j",
      "an input_required retry MUST use a request id distinct from the original",
    )
  echoed = echo_opaque_value(request_state) if request_state is not None else None
  return RetryEnvelope(request_id=new_request_id, request_state=echoed)


# ---------------------------------------------------------------------------
# §29.4 item 5  /  §29.7-d/e  — undeclared input requests & requestState integrity
# ---------------------------------------------------------------------------

def assert_input_request_kind_declared(
  input_request_kind: str,
  declared_client_capabilities: dict[str, Any] | frozenset[str] | set[str],
) -> None:
  """Assert an ``input_required`` input request matches a declared capability (R-29.4-l).

  A server MUST NOT place into an ``input_required`` result any input request of
  a kind the client has not declared support for — for example, it MUST NOT
  include an elicitation input request unless the client declared the
  ``elicitation`` capability (R-29.4-l, AC-45.22). The kind-to-capability
  mapping is the §11/§20 one (referenced): an ``elicitation/create`` input
  request requires the ``elicitation`` capability.

  Args:
    input_request_kind: the input request method/kind the server would emit.
    declared_client_capabilities: the capabilities the client declared (a
      ClientCapabilities object/dict or a set of capability identifiers).

  Raises:
    ConformanceViolation: the kind requires a capability the client did not
      declare (atom R-29.4-l).
  """
  required = _capability_for_input_kind(input_request_kind)
  if required is None:
    return
  if required not in declared_client_capabilities:
    raise ConformanceViolation(
      "R-29.4-l",
      f"a server MUST NOT include a {input_request_kind!r} input request unless "
      f"the client declared the {required!r} capability",
    )


def _capability_for_input_kind(input_request_kind: str) -> str | None:
  """Map an input-request kind to the client capability it requires (§11/§20).

  Returns the capability identifier an input request of this kind depends on, or
  None when the kind imposes no capability requirement here. Only the
  elicitation kind is gated by a baseline capability in this story's scope; other
  kinds (the deprecated roots/sampling) are governed by §21 / §29.4-m/n.
  """
  if input_request_kind == INPUT_REQUEST_ELICITATION:
    return "elicitation"
  return None


def make_request_state(payload: str, secret_key: bytes) -> str:
  """Mint an integrity-protected ``requestState`` token (R-29.7-d/e).

  When ``requestState`` influences authorization, resource access, or business
  logic, the server MUST protect its integrity (R-29.7-e, AC-45.33). This reuses
  S17's HMAC primitive (the integrity mechanism is owned there) so the server can
  later detect any client-side tampering.

  Args:
    payload: the server-defined continuation context to protect.
    secret_key: the server's confidential signing key.

  Returns:
    A signed, opaque ``requestState`` token the client echoes back unchanged.
  """
  return make_hmac_request_state(payload, secret_key)


def verify_request_state(token: str, secret_key: bytes) -> str:
  """Verify a passed-through ``requestState`` token and return its payload (R-29.7-d/e).

  A server MUST treat a ``requestState`` that passes through a client as
  attacker-controlled input (R-29.7-d) and MUST reject state that fails
  verification (R-29.7-e, AC-45.33). This reuses S17's constant-time HMAC
  verification; a tampered token raises (the integrity failure S17 owns).

  Args:
    token: the ``requestState`` echoed back by the client.
    secret_key: the server's confidential signing key.

  Returns:
    The original payload when the token verifies.

  Raises:
    Exception: S17's ``InvalidRequestStateError`` when the token is malformed or
      altered — the server MUST reject it (R-29.7-e).
  """
  return verify_hmac_request_state(token, secret_key)


# ---------------------------------------------------------------------------
# §29.6  Robustness and forward compatibility
# ---------------------------------------------------------------------------

def ignore_unknown_fields(
  obj: dict[str, Any],
  known_fields: frozenset[str] | set[str] | tuple[str, ...],
) -> dict[str, Any]:
  """Drop fields not in ``known_fields`` while preserving the understood ones (R-29.6-b/i).

  An implementation MUST ignore fields it does not recognize rather than
  rejecting the message (R-29.6-b, AC-45.27), and ignoring the unknown MUST NOT
  cause it to silently discard the semantically required content it *does*
  understand (R-29.6-i, AC-45.30). This returns the projection onto the
  recognized fields: unknown fields are dropped, every understood field is kept.

  Args:
    obj: the received object that may carry richer-than-understood fields.
    known_fields: the field names this receiver recognizes.

  Returns:
    A new dict containing exactly the recognized fields present in ``obj``; the
    unknown are silently ignored, never an error.
  """
  known = set(known_fields)
  return {k: v for k, v in obj.items() if k in known}


def tolerate_unknown_capabilities(
  advertised: list[str] | frozenset[str] | tuple[str, ...],
  recognized: frozenset[str] | set[str] | tuple[str, ...],
) -> tuple[str, ...]:
  """Return the recognized advertised capabilities, ignoring the unknown (R-29.6-c).

  An implementation MUST ignore advertised capabilities it does not recognize and
  MUST NOT treat their presence as an error (R-29.6-c, AC-45.27). The unrecognized
  are simply unsupported; this returns only the capabilities the receiver knows,
  never raising on an unknown one.
  """
  known = set(recognized)
  return tuple(c for c in advertised if c in known)


def tolerate_unknown_extensions(
  advertised: list[str] | frozenset[str] | tuple[str, ...],
  recognized: frozenset[str] | set[str] | tuple[str, ...],
) -> tuple[str, ...]:
  """Return the recognized advertised extension identifiers, ignoring the unknown (R-29.6-d).

  An implementation MUST ignore extension identifiers it does not recognize in
  the extensions map; an unrecognized extension is simply unsupported and
  triggers the §29.5 fallback (R-29.6-d, AC-45.27). This returns only the
  extensions the receiver knows, never raising on an unknown one.
  """
  known = set(recognized)
  return tuple(e for e in advertised if e in known)


def classify_unknown_error_code(code: int) -> str:
  """Classify an error with an unrecognized ``code`` as a request *failure* (R-29.6-e).

  A client MUST accept and handle error codes it does not specifically recognize,
  treating them as failures of the request without crashing or misclassifying
  them (R-29.6-e, AC-45.28). Every error code — recognized or not — denotes a
  failed request; this returns the constant classification ``"failure"`` so an
  unknown code is never mistaken for a success or a crash.

  Args:
    code: the (possibly unrecognized) error code received.

  Returns:
    The string ``"failure"``: an error response, whatever its code, is a failed
    request.
  """
  # The code is authoritative (S34) but its *recognition* never decides success:
  # any error response is a failure of the request (R-29.6-e).
  _ = code
  return "failure"


def is_result_type_actionable(
  result_type: Any,
  *,
  recognized_result_types: frozenset[str] | set[str] | None = None,
) -> bool:
  """True iff a result's ``resultType`` is recognized and may be acted on (R-29.6-f/g/h).

  A ``resultType`` value not recognized by the receiver MUST be treated as an
  error, and a client MUST NOT act on a result whose discriminator it cannot
  interpret (R-29.6-f, R-29.6-g, AC-45.29). Where the discriminator is *absent*,
  the §3 absence rule applies — an absent ``resultType`` is itself unrecognized
  and therefore not actionable here (R-29.6-h); :func:`resolve_absent_result_type`
  applies the §3 default for the cases that define one.

  Args:
    result_type: the ``resultType`` the result carries (may be absent/None).
    recognized_result_types: the discriminator values this receiver understands;
      defaults to the core set when None.

  Returns:
    True only when ``result_type`` is a recognized discriminator value.
  """
  if not isinstance(result_type, str) or not result_type:
    return False
  recognized = (
    set(recognized_result_types)
    if recognized_result_types is not None
    else set(CORE_RESULT_TYPES)
  )
  return result_type in recognized


def resolve_absent_result_type(result: dict[str, Any]) -> str:
  """Apply the §3 absence rule for a missing ``resultType`` discriminator (R-29.6-h).

  Where the ``resultType`` discriminator is absent on a result, the receiver MUST
  apply the absence rule defined in §3 (R-29.6-h, AC-45.29). The §3 default for an
  ordinary result is the core ``"complete"`` discriminator; this returns the
  present value unchanged when one exists, else the §3 default.

  Args:
    result: the received result object.

  Returns:
    The result's ``resultType`` when present, else the §3 absence default.
  """
  present = result.get("resultType")
  if isinstance(present, str) and present:
    return present
  return "complete"


# ---------------------------------------------------------------------------
# §29.7  Conformance and the stateless model
# ---------------------------------------------------------------------------

def assert_request_independent_of_connection(
  *,
  derived_from_connection: bool,
  atom: str = "R-29.1-e",
) -> None:
  """Assert no protocol-significant state was derived from connection identity.

  An implementation that derives any protocol-significant state (revision, peer
  identity, advertised capabilities) from the identity or prior traffic of a
  connection/process/stream — rather than from the per-request §4 envelope — is
  NOT conformant (R-29.1-e, R-29.7-a, AC-45.3, AC-45.31). A server MUST process
  each request independently (R-29.7-a) and MUST NOT treat the connection/process
  as the lifetime boundary of a conversation/task/subscription (R-29.7-c,
  AC-45.32).

  Args:
    derived_from_connection: True iff the implementation used connection/stream
      identity (rather than the request envelope) to determine protocol state.
    atom: the governing atom (defaults to R-29.1-e; pass R-29.7-a / R-29.7-c for
      the stateless-invariant variants).

  Raises:
    ConformanceViolation: state was derived from connection identity.
  """
  if derived_from_connection:
    raise ConformanceViolation(
      atom,
      "protocol-significant state MUST be read from the per-request §4 envelope, "
      "never inferred from connection/process/stream identity",
    )


def requires_explicit_continuation(state_spans_requests: bool) -> bool:
  """Return whether spanning state must ride an explicit client-supplied value (R-29.7-b).

  State that must span multiple requests — a long-running operation, an
  application-level handle, a multi-round-trip exchange — MUST be referenced by an
  explicit identifier or opaque value the client supplies on each request, never
  inferred from the connection (R-29.7-b, R-29.7-c, AC-45.31/32).

  Args:
    state_spans_requests: True iff the state outlives a single request/response.

  Returns:
    True exactly when an explicit client-supplied continuation value is required.
  """
  return state_spans_requests


# ---------------------------------------------------------------------------
# §29.8  Transport conformance
# ---------------------------------------------------------------------------

def assert_at_least_one_transport(
  transports: list[str] | frozenset[str] | tuple[str, ...],
) -> tuple[str, ...]:
  """Assert the implementation offers at least one §7 transport (R-29.8-a).

  A conformant implementation MUST implement at least one transport defined in §7
  (R-29.8-a, AC-45.34). Each named transport MUST be one of the defined transports
  (:data:`CONFORMANCE_TRANSPORTS`); an unknown transport name is rejected here so
  the profile stays well-formed.

  Args:
    transports: the transports the implementation offers.

  Returns:
    The transports as a tuple, preserving order.

  Raises:
    ConformanceViolation: the list is empty (R-29.8-a) or names an undefined
      transport.
  """
  ordered = tuple(transports)
  if not ordered:
    raise ConformanceViolation(
      "R-29.8-a", "a conformant implementation MUST implement at least one §7 transport"
    )
  for t in ordered:
    if t not in CONFORMANCE_TRANSPORTS:
      raise ConformanceViolation(
        "R-29.8-a",
        f"unknown transport {t!r}; must be one of {sorted(CONFORMANCE_TRANSPORTS)!r}",
      )
  return ordered


#: The transport whose protocol→HTTP status mapping §29.8 item 3 prescribes
#: (Streamable HTTP). The codes -32602 and -32003 each map to HTTP 400 on this
#: transport, per the §9 / §22.6 status table owned by S15 (R-29.8-c).
TRANSPORT_ERROR_HTTP_STATUS: dict[int, int] = {
  INVALID_PARAMS_CODE: 400,
  MISSING_REQUIRED_CLIENT_CAPABILITY_CODE: 400,
}


def http_status_for_protocol_error(code: int) -> int:
  """Map a protocol error code to its prescribed Streamable HTTP status (R-29.8-c).

  On the Streamable HTTP transport a malformed envelope / missing required field
  (-32602) and a missing required client capability (-32003) MUST produce the
  HTTP status §9 prescribes — HTTP 400 Bad Request (R-29.8-c, AC-45.35). The
  authoritative status table lives in S15 (§9.7 / §22.6); this references the two
  statuses §29.8 names explicitly.

  Args:
    code: the protocol-level JSON-RPC error code (-32602 or -32003).

  Returns:
    The prescribed HTTP status (400).

  Raises:
    KeyError: ``code`` is not one of the two §29.8-named codes; consult S15's
      full §9.7 table for any other condition.
  """
  return TRANSPORT_ERROR_HTTP_STATUS[code]


def transport_authorization_applies(transport: str) -> bool:
  """Return whether §23 authorization applies to ``transport`` (R-29.8-d/e).

  An implementation using an HTTP-based transport SHOULD conform to §23
  authorization (R-29.8-d); a stdio implementation SHOULD NOT apply that framework
  and instead obtains credentials from its environment (R-29.8-e, AC-45.36). This
  defers to S35's :func:`mcp_sdk_py.authorization.authorization_applies` so the
  HTTP-only rule lives in exactly one place.

  Args:
    transport: a transport name (:data:`CONFORMANCE_TRANSPORTS`).

  Returns:
    True for the Streamable HTTP transport; False for stdio.

  Raises:
    ConformanceViolation: ``transport`` is not a defined transport (R-29.8-a).
  """
  if transport == TRANSPORT_STREAMABLE_HTTP:
    return authorization_applies(TransportClass.HTTP)
  if transport == TRANSPORT_STDIO:
    return authorization_applies(TransportClass.STDIO)
  raise ConformanceViolation(
    "R-29.8-a",
    f"unknown transport {transport!r}; cannot determine authorization applicability",
  )


def assert_transports_independent(
  transports: list[str] | frozenset[str] | tuple[str, ...],
  *,
  cross_transport_contingency: bool = False,
) -> None:
  """Assert each transport satisfies its own requirements with no cross-contingency (R-29.8-f/g).

  An implementation MUST NOT make conformance of one transport contingent on
  another; each transport it offers MUST independently satisfy its own
  requirements (R-29.8-f, AC-45.37). Multiple transports MAY be offered
  concurrently (R-29.8-g). This validates the at-least-one rule then rejects any
  declared cross-transport contingency.

  Args:
    transports: the transports offered (validated to be non-empty & defined).
    cross_transport_contingency: True iff one transport's conformance was made to
      depend on another — a violation.

  Raises:
    ConformanceViolation: no transport offered (R-29.8-a) or a cross-transport
      contingency exists (R-29.8-f).
  """
  assert_at_least_one_transport(transports)
  if cross_transport_contingency:
    raise ConformanceViolation(
      "R-29.8-f",
      "no transport's conformance may be contingent on another; each must "
      "independently satisfy its own requirements",
    )


# ---------------------------------------------------------------------------
# §29.9  Determining conformance & the conformance profile
# ---------------------------------------------------------------------------

@dataclass
class ConformanceProfile:
  """The abstract tuple that fully describes an implementation's conformance (§29.9 item 3).

  This is the story's only structured artifact — **not a wire message**. It is
  the (roles, revisions, capabilities, extensions, transports) tuple that, with
  the §29 catalog, fully determines which requirements bind an implementation
  (R-29.9-c, AC-45.38).

  Fields:
    roles: the role(s) the implementation plays; binds each role's requirements
      (R-29.1-a/b). MUST be non-empty.
    revisions: the protocol revisions advertised; always includes the wire value
      :data:`WIRE_PROTOCOL_REVISION` (§29.9 item 3, R-29.9-c).
    capabilities: the advertised capability identifiers (Appendix D registry).
    extensions: the advertised extension identifiers; MAY be empty — zero
      extensions is fully conformant (R-29.5-a, AC-45.24).
    transports: the transports implemented; at least one, each independently
      conformant (R-29.8-a/f).
  """

  roles: frozenset[ConformanceRole]
  revisions: tuple[str, ...]
  capabilities: tuple[str, ...] = ()
  extensions: tuple[str, ...] = ()
  transports: tuple[str, ...] = (TRANSPORT_STDIO,)

  def __post_init__(self) -> None:
    self.roles = frozenset(self.roles)
    if not self.roles:
      raise ConformanceViolation(
        "R-29.1-a", "a conformance profile MUST name at least one role"
      )
    # §29.9 item 3 / R-29.9-c: the revision catalog always includes the wire value.
    self.revisions = tuple(self.revisions)
    if WIRE_PROTOCOL_REVISION not in self.revisions:
      self.revisions = (WIRE_PROTOCOL_REVISION, *self.revisions)
    self.capabilities = tuple(self.capabilities)
    self.extensions = tuple(self.extensions)
    # R-29.8-a / R-29.8-f: at least one defined transport, validated up front.
    self.transports = assert_at_least_one_transport(self.transports)

  @property
  def is_both_roles(self) -> bool:
    """True iff the profile plays both client and server (R-29.1-b, AC-45.1)."""
    return self.roles == frozenset(
      {ConformanceRole.CLIENT, ConformanceRole.SERVER}
    )

  @property
  def advertises_zero_extensions(self) -> bool:
    """True iff zero extensions are advertised — fully conformant (R-29.5-a, AC-45.24)."""
    return len(self.extensions) == 0

  def binding_requirements(self) -> tuple[ConformanceRequirement, ...]:
    """Every catalog atom that binds this profile's roles (R-29.1-a/b, §29.9).

    The union of each played role's requirements; role-agnostic atoms (empty
    :attr:`ConformanceRequirement.roles`) bind regardless of role.
    """
    out: dict[str, ConformanceRequirement] = {}
    for role in self.roles:
      for r in requirements_for_role(role):
        out[r.atom] = r
    return tuple(out.values())

  def capability_obligations(self) -> tuple[CapabilityObligation, ...]:
    """The §29.4 obligations this profile incurs from its advertised capabilities (R-29.4-a)."""
    return obligations_for_capabilities(self.capabilities)


def assert_no_partial_feature(
  *,
  advertised: bool,
  fully_implemented: bool,
  feature: str,
) -> None:
  """Assert there is no advertised-but-partially-implemented feature (R-29.9-b, R-29.4-j).

  An implementation either fully satisfies the MUST-level behavior of an
  advertised feature or MUST NOT advertise it; there is no conformant intermediate
  partially-implemented state (R-29.9-b, R-29.4-j, AC-45.21, AC-45.38). Advertising
  is a binding assertion of full conformance.

  Args:
    advertised: True iff the feature's capability is advertised.
    fully_implemented: True iff every MUST-level behavior of the feature is met.
    feature: the feature/capability name, for the diagnostic.

  Raises:
    ConformanceViolation: the feature is advertised yet not fully implemented
      (atom R-29.9-b).
  """
  if advertised and not fully_implemented:
    raise ConformanceViolation(
      "R-29.9-b",
      f"feature {feature!r} is advertised but not fully implemented; advertise a "
      "feature only when its full MUST-level behavior is satisfied",
    )


# ---------------------------------------------------------------------------
# §30  References — provenance only, never load-bearing
# ---------------------------------------------------------------------------

#: The §30 citation markers are provenance-only: they identify the external
#: source of a concept/format/term and are NEVER load-bearing. All normative
#: content is fully specified in the spec body and does not depend on any cited
#: work (R-30-a, AC-45.39). This module records the status as a constant so a
#: caller can assert it without re-deriving the rule.
CITATIONS_ARE_PROVENANCE_ONLY: bool = True


def citation_is_load_bearing(marker: str) -> bool:
  """Return whether a §30 citation marker is load-bearing — always False (R-30-a).

  Citation markers (e.g. ``[MCP]``, ``[RFC2119]``, ``[SEP-2575]``) are provenance
  only; stripping or altering a marker changes no required behavior, code, name,
  or wire format (R-30-a, AC-45.39). For every marker this returns False.

  Args:
    marker: the citation marker as it appears in the spec text.

  Returns:
    Always ``False`` — no protocol behavior depends on a citation's content.
  """
  _ = marker
  return False
