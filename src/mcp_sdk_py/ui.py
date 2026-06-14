"""Interactive UI Extension I: Negotiation, UI Declaration & UI Resource — S41.

Delivers the server-facing, *static* half of the OPTIONAL Interactive
User-Interface ("apps") extension (spec §26.1–§26.4). It models four things and
nothing dynamic:

  1. The fixed, normative division of server vs host responsibilities (§26.1) and
     the SDK-implementable-without-rendering guarantee — captured here as an
     auditable :class:`ResponsibilityRole` map (R-26.1-a…i).
  2. The extension *identifier* ``io.modelcontextprotocol/ui`` (opaque,
     case-sensitive), its negotiation through the ``extensions`` capability map,
     the host's :class:`UiHostExtensionCapability` advertisement, and the server
     gating rules that follow from it (§26.2, R-26.2-a…j). The verbatim,
     case-sensitive UI MIME type ``text/html;profile=mcp-app`` lives here too.
  3. The :class:`ToolUiMeta` declaration carried at a tool's ``_meta.ui``:
     ``resourceUri`` (a required ``ui://`` URI) and ``visibility`` (an optional
     ``"model"``/``"app"`` enum array defaulting to ``["model","app"]``), plus the
     visibility semantics and the forward-compatibility rules for receivers that
     do not negotiate the extension (§26.3, R-26.3-a…h).
  4. The UI *resource* model: ``ui://`` scheme opacity, the verbatim MIME type,
     and the optional :class:`ResourceUiMeta` presentation/security hints
     (:class:`UiContentSecurityPolicy`, :class:`UiPermissions`, ``domain``,
     ``prefersBorder``) carried on a ``resources/read`` content entry, together
     with the host's rendering-isolation obligations restated as auditable
     predicates (§26.4, R-26.4-a…p).

This story deliberately stops *before* the runtime UI-to-host message channel
(``ui/initialize``, ``ui/message``, the method/notification registry, consent and
mediation flows): all of that is owned by S42 (§26.5–§26.9) and is out of scope
here. A host renders, sandboxes, enforces policy, runs the channel, and obtains
consent; a server only declares (``_meta.ui``) and serves (``resources/read``).
Per R-26.1-i, this module has no rendering, browser, or UI-toolkit dependency.

This module REUSES the lower waves rather than re-implementing them:

  - S11 (``mcp_sdk_py.extensions``) owns identifier grammar, ``extensions``-map
    parsing, and the active-set intersection. The negotiation predicates here
    delegate to :func:`is_extension_active` / :func:`advertised_extension_ids`.
  - S38 (``mcp_sdk_py.extension_mechanism``) owns the general extension
    framework; :data:`UI_EXTENSION_DEFINITION` is an
    :class:`ExtensionDefinition` describing this extension's surface so it can be
    registered in an :class:`ExtensionRegistry` alongside others.
  - S05 (``mcp_sdk_py.meta_object``) owns the ``_meta`` key constants; the host
    advertisement is read from a request's
    ``io.modelcontextprotocol/clientCapabilities`` via
    :data:`KEY_CLIENT_CAPABILITIES`.
  - S21 (``mcp_sdk_py.content_types``) owns the ``ResourceContents`` family used
    to serve the UI document.

Spec: §26.1–§26.4 (lines 7762–7957)
Depends on: S38 (extension framework), S24 (Tool / ``_meta.ui`` placement),
  S11 (identifier grammar, active set), S10 (capability objects),
  S05 (``_meta`` key constants), S21 (ResourceContents)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp_sdk_py.content_types import (
  BlobResourceContents,
  ResourceContents,
  TextResourceContents,
  parse_resource_contents,
)
from mcp_sdk_py.extension_mechanism import (
  ExtensionClassification,
  ExtensionDefinition,
)
from mcp_sdk_py.extensions import (
  advertised_extension_ids,
  is_extension_active,
)
from mcp_sdk_py.meta_object import KEY_CLIENT_CAPABILITIES


# ---------------------------------------------------------------------------
# §26.2  The extension identifier and the UI MIME type  [R-26.2-b, R-26.2-e]
# ---------------------------------------------------------------------------

#: The exact, opaque, case-sensitive extension identifier of the Interactive UI
#: ("apps") extension (§26.2, R-26.2-b). Used as a key in the ``extensions``
#: capability map and matched verbatim — ``IO.ModelContextProtocol/UI`` is a
#: different string and MUST NOT match (R-26.2-b / AC-41.12).
UI_EXTENSION_IDENTIFIER: str = "io.modelcontextprotocol/ui"

#: The verbatim, case-sensitive MIME type a UI resource is served with and that a
#: host MUST advertise it can render (§26.2/§26.4, R-26.2-e, R-26.4-d). The string
#: is matched verbatim and case-sensitively, INCLUDING the ``;profile=mcp-app``
#: parameter and the ABSENCE of surrounding whitespace: ``"text/html; profile=
#: mcp-app"`` (extra space) and ``"TEXT/HTML;PROFILE=MCP-APP"`` (wrong case) both
#: fail the match (R-26.2-e / AC-41.15).
UI_MIME_TYPE: str = "text/html;profile=mcp-app"

#: The reserved nested key path at which a tool declares its UI association is
#: ``_meta.ui`` (§26.3). The nested key inside ``_meta`` is exactly ``"ui"``.
TOOL_UI_META_KEY: str = "ui"

#: The ``resources/read`` method by which a host serves/fetches the UI resource
#: (§26.4, R-26.1-c, R-26.3-c). Named here only for reference and gating; the
#: request/result mechanics are owned by S26/S27.
METHOD_RESOURCES_READ: str = "resources/read"

#: The URI scheme that designates an MCP UI resource (§26.4, R-26.4-b). The
#: authority/path after it are server-defined and opaque to the host.
UI_URI_SCHEME: str = "ui://"

#: The exact enum strings permitted as ``ToolUiMeta.visibility`` elements
#: (§26.3, R-26.3-d). A CLOSED set; any other token is invalid.
VISIBILITY_MODEL: str = "model"
VISIBILITY_APP: str = "app"
VALID_VISIBILITY: frozenset[str] = frozenset({VISIBILITY_MODEL, VISIBILITY_APP})

#: The effective ``visibility`` applied when the field is omitted (§26.3,
#: R-26.3-d): the tool is callable by both the model and the rendered UI.
DEFAULT_VISIBILITY: tuple[str, ...] = (VISIBILITY_MODEL, VISIBILITY_APP)

#: The exact member names permitted in a :class:`UiPermissions` object (§26.4,
#: R-26.4-i). A CLOSED set; each present member's value is an empty object ``{}``
#: and its presence requests that sandbox capability.
VALID_PERMISSIONS: frozenset[str] = frozenset({
  "camera",
  "microphone",
  "geolocation",
  "clipboardWrite",
})


# ---------------------------------------------------------------------------
# §26.1  Roles: the fixed, normative server/host responsibility split
#         [R-26-a, R-26.1-a…i]
# ---------------------------------------------------------------------------

class ResponsibilityRole(Enum):
  """Which party owns a responsibility in the apps extension (§26.1).

  The division of responsibilities is fixed and normative (R-26.1-b…h): the
  SERVER (and server-side SDK) declares and serves; the HOST renders, sandboxes,
  enforces policy, runs the channel, and obtains consent. ``NOT_SERVER_SDK``
  marks the responsibilities a server SDK explicitly does NOT carry — rendering,
  sandboxing, running the channel (R-26.1-d) — which is what lets a conforming
  server SDK be implemented with no rendering/browser/UI-toolkit dependency
  (R-26.1-i / AC-41.10).
  """

  SERVER = "server"
  HOST = "host"
  NOT_SERVER_SDK = "not-server-sdk"


#: The normative responsibility assignment of §26.1 (R-26.1-b…h), keyed by a
#: short responsibility token. Provided as an auditable, machine-checkable map so
#: a conformance suite can assert each obligation is attributed to the correct
#: party (AC-41.3…AC-41.9). The keys name the concrete obligations; the values
#: are the owning :class:`ResponsibilityRole`.
RESPONSIBILITY_ASSIGNMENT: dict[str, ResponsibilityRole] = {
  # Server / server-SDK obligations (R-26.1-b/c).
  "declare_ui_meta": ResponsibilityRole.SERVER,          # R-26.1-b (AC-41.3)
  "serve_ui_resource": ResponsibilityRole.SERVER,        # R-26.1-c (AC-41.4)
  # Explicitly NOT a server-SDK obligation (R-26.1-d).
  "render": ResponsibilityRole.HOST,                     # R-26.1-e (AC-41.6)
  "sandbox": ResponsibilityRole.HOST,                    # R-26.1-e (AC-41.6)
  "enforce_csp_permissions": ResponsibilityRole.HOST,    # R-26.1-f (AC-41.7)
  "run_message_channel": ResponsibilityRole.HOST,        # R-26.1-g (AC-41.8)
  "obtain_user_consent": ResponsibilityRole.HOST,        # R-26.1-h (AC-41.9)
}

#: The obligations a server SDK is explicitly NOT responsible for (R-26.1-d):
#: rendering, sandboxing, and running the message-channel dialect. These are the
#: HOST's job; a server SDK that omits them is still conformant (AC-41.5).
SERVER_SDK_NON_RESPONSIBILITIES: frozenset[str] = frozenset({
  "render",
  "sandbox",
  "run_message_channel",
})


def responsibility_of(obligation: str) -> ResponsibilityRole:
  """Return the party that owns ``obligation`` under §26.1 (R-26.1-b…h).

  Looks the obligation up in :data:`RESPONSIBILITY_ASSIGNMENT`. This makes the
  fixed responsibility split auditable: declaring/serving is the SERVER's
  (R-26.1-b/c), while rendering, sandboxing, CSP/permission enforcement, running
  the channel, and consent are the HOST's (R-26.1-e…h).

  Raises:
    KeyError: ``obligation`` is not one of the §26.1 responsibilities.
  """
  return RESPONSIBILITY_ASSIGNMENT[obligation]


def is_server_sdk_responsibility(obligation: str) -> bool:
  """Return True iff ``obligation`` is a server-SDK responsibility (R-26.1-b/c/d).

  Declaring the ``_meta.ui`` association and serving the ``ui://`` resource are
  server-SDK responsibilities (R-26.1-b/c). Rendering, sandboxing, and running
  the channel are NOT (R-26.1-d) — they belong to the host — so this returns
  False for those, which is exactly why a conforming server SDK needs no
  rendering/browser/UI-toolkit dependency (R-26.1-i / AC-41.5, AC-41.10). An
  unknown obligation token is treated as not a server-SDK responsibility.
  """
  return RESPONSIBILITY_ASSIGNMENT.get(obligation) is ResponsibilityRole.SERVER


def server_sdk_requires_rendering_dependency() -> bool:
  """Return False: a conforming server SDK needs no rendering dependency (R-26.1-i).

  Rendering is a host responsibility; a conforming server SDK MUST be
  implementable without any rendering, browser, or UI-toolkit dependency
  (R-26.1-i / AC-41.10). This module — the server-side SDK surface for the
  extension — imports nothing of the kind, so this invariant is stated directly
  and always returns False.
  """
  return False


# ---------------------------------------------------------------------------
# §26.2  UiHostExtensionCapability — the host's advertised value  [R-26.2-d/e]
# ---------------------------------------------------------------------------

class InvalidUiHostCapabilityError(ValueError):
  """A host's advertised :class:`UiHostExtensionCapability` is malformed (§26.2).

  Raised when the advertised value lacks the REQUIRED ``mimeTypes`` array, or it
  is not an array of strings (R-26.2-d). Note this is a *sender-side* construction
  guard for the host's own advertisement; a server merely *reading* an
  advertisement uses :func:`host_advertises_ui_extension`, which never raises for
  a malformed peer value (it simply reports the extension as not usable).
  """


@dataclass
class UiHostExtensionCapability:
  """The value a host advertises under ``io.modelcontextprotocol/ui`` (§26.2).

  This is the object a host (client) that supports rendering interactive UIs
  places under the :data:`UI_EXTENSION_IDENTIFIER` key in the ``extensions`` map
  of the ``io.modelcontextprotocol/clientCapabilities`` it carries in the
  ``_meta`` of every request (R-26.2-c). It declares which UI MIME types the host
  can render.

  Fields:
    mime_types: REQUIRED array of MIME type strings the host can render as
      interactive user interfaces (R-26.2-d). It MUST include the exact string
      :data:`UI_MIME_TYPE` (``text/html;profile=mcp-app``), matched verbatim and
      case-sensitively (R-26.2-e). Wire key: ``mimeTypes``.
  """

  mime_types: list[str]  # JSON key: mimeTypes

  def __post_init__(self) -> None:
    # R-26.2-d: mimeTypes is REQUIRED and is an array of MIME type strings.
    if not isinstance(self.mime_types, list):
      raise InvalidUiHostCapabilityError(
        "UiHostExtensionCapability.mimeTypes is REQUIRED and must be an array "
        "of MIME type strings (R-26.2-d)"
      )
    for entry in self.mime_types:
      if not isinstance(entry, str):
        raise InvalidUiHostCapabilityError(
          f"UiHostExtensionCapability.mimeTypes entries must be strings; got "
          f"{entry!r} (R-26.2-d)"
        )

  @property
  def renders_ui_mime_type(self) -> bool:
    """True iff ``mimeTypes`` contains the verbatim :data:`UI_MIME_TYPE` (R-26.2-e).

    The match is verbatim and case-sensitive, including the ``;profile=mcp-app``
    parameter and the absence of surrounding whitespace — ``"text/html; profile=
    mcp-app"`` or ``"TEXT/HTML;PROFILE=MCP-APP"`` does not satisfy it (R-26.2-e /
    AC-41.15).
    """
    return UI_MIME_TYPE in self.mime_types

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UiHostExtensionCapability:
    """Parse a wire ``UiHostExtensionCapability`` object (§26.2).

    Validates that ``mimeTypes`` is present and an array of strings (R-26.2-d).
    Unknown keys are ignored for forward compatibility (§6.6).

    Raises:
      InvalidUiHostCapabilityError: ``data`` is not an object, or ``mimeTypes``
        is absent or not an array of strings.
    """
    if not isinstance(data, dict):
      raise InvalidUiHostCapabilityError(
        f"UiHostExtensionCapability must be a JSON object; got "
        f"{type(data).__name__} (R-26.2-d)"
      )
    if "mimeTypes" not in data:
      raise InvalidUiHostCapabilityError(
        "UiHostExtensionCapability.mimeTypes is REQUIRED (R-26.2-d)"
      )
    return cls(mime_types=data["mimeTypes"])

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object: ``{"mimeTypes": [...]}`` (R-26.2-d)."""
    return {"mimeTypes": list(self.mime_types)}


def ui_extension_advertisement(*, extra_mime_types: list[str] | None = None) -> dict[str, Any]:
  """Build the ``extensions``-map entry a UI-capable host advertises (§26.2).

  Returns a single-key mapping ``{UI_EXTENSION_IDENTIFIER: {"mimeTypes": [...]}}``
  whose ``mimeTypes`` array always includes the verbatim :data:`UI_MIME_TYPE`
  first (R-26.2-c/d/e), optionally followed by ``extra_mime_types`` for hosts
  that can render additional UI profiles. This is the value a host merges into
  the ``extensions`` map of its
  ``io.modelcontextprotocol/clientCapabilities`` (R-26.2-c).

  Args:
    extra_mime_types: additional MIME type strings the host can render, appended
      after the mandatory :data:`UI_MIME_TYPE`.
  """
  mime_types = [UI_MIME_TYPE]
  if extra_mime_types:
    for entry in extra_mime_types:
      if entry != UI_MIME_TYPE:
        mime_types.append(entry)
  return {
    UI_EXTENSION_IDENTIFIER: UiHostExtensionCapability(mime_types=mime_types).to_dict()
  }


# ---------------------------------------------------------------------------
# §26.2  Identifier handling and negotiation  [R-26.2-a/b/c/f/g/h/i/j]
# ---------------------------------------------------------------------------

def is_ui_extension_identifier(identifier: str) -> bool:
  """Return True iff ``identifier`` is exactly :data:`UI_EXTENSION_IDENTIFIER` (R-26.2-b).

  A receiver MUST treat the identifier as an opaque, case-sensitive string, so
  the comparison is an exact, non-folding equality: ``IO.ModelContextProtocol/UI``
  does NOT match (R-26.2-b / AC-41.12).
  """
  return identifier == UI_EXTENSION_IDENTIFIER


def ui_capability_from_extensions(extensions_map: Any) -> UiHostExtensionCapability | None:
  """Extract the host's UI capability from an ``extensions`` map, or None (§26.2).

  Reads the value at :data:`UI_EXTENSION_IDENTIFIER` from a raw ``extensions``
  map and parses it as a :class:`UiHostExtensionCapability`. Returns None when the
  key is absent, the value is not an object, or it lacks a valid ``mimeTypes``
  array — a malformed advertisement is treated as "no usable UI capability"
  rather than raising, so a server degrades gracefully (§6.6, R-26.2-f/g).

  Args:
    extensions_map: a raw ``extensions`` field value (e.g. from the host's
      ``clientCapabilities``); ``None`` or a non-object yields None.
  """
  if not isinstance(extensions_map, dict):
    return None
  value = extensions_map.get(UI_EXTENSION_IDENTIFIER)
  if not isinstance(value, dict):
    return None
  try:
    return UiHostExtensionCapability.from_dict(value)
  except InvalidUiHostCapabilityError:
    return None


def host_capabilities_from_request_meta(request_meta: Any) -> Any:
  """Return the host's ``extensions`` map carried in a request's ``_meta`` (§26.2/§4).

  A UI-capable host advertises the extension in the ``extensions`` map of the
  ``io.modelcontextprotocol/clientCapabilities`` it carries in the ``_meta`` of
  every request (R-26.2-c). This pulls that nested ``extensions`` value out of a
  request's ``_meta`` object so the other negotiation helpers can consume it.
  Returns None when ``_meta`` or the client-capabilities/extensions path is
  absent or not an object.

  Args:
    request_meta: a request's ``_meta`` object (or ``None``).
  """
  if not isinstance(request_meta, dict):
    return None
  client_caps = request_meta.get(KEY_CLIENT_CAPABILITIES)
  if not isinstance(client_caps, dict):
    return None
  return client_caps.get("extensions")


def host_advertises_ui_extension(extensions_map: Any) -> bool:
  """Return True iff a host's ``extensions`` map advertises a renderable UI (§26.2).

  The host counts as advertising the extension only when the
  :data:`UI_EXTENSION_IDENTIFIER` key is present with a valid
  :class:`UiHostExtensionCapability` whose ``mimeTypes`` includes the verbatim
  :data:`UI_MIME_TYPE` (R-26.2-c/d/e). This is the predicate a server consults
  before declaring any UI association or expecting any rendering (R-26.2-f/g):
  if it is False, the host has not negotiated the extension with the required
  MIME type.

  Args:
    extensions_map: the host's raw ``extensions`` map (e.g. from
      ``clientCapabilities``); ``None``/non-object/malformed yields False.
  """
  capability = ui_capability_from_extensions(extensions_map)
  return capability is not None and capability.renders_ui_mime_type


def ui_extension_active(client_extensions: Any, server_extensions: Any) -> bool:
  """Return True iff the UI extension is active for this session (R-26.2-a).

  The extension is active only when it is negotiated through the ``extensions``
  map — i.e. advertised by BOTH peers (R-26.2-a). Delegates the intersection to
  S11's :func:`is_extension_active` for the :data:`UI_EXTENSION_IDENTIFIER`. When
  the key is absent from the negotiated set, the extension is inactive and both
  parties act under core behavior (AC-41.11).
  """
  return is_extension_active(
    UI_EXTENSION_IDENTIFIER, client_extensions, server_extensions
  )


# -- §26.2  Server gating rules  [R-26.2-f/g/h/i] --

class UiExtensionNotNegotiatedError(ValueError):
  """A server tried to declare/expect a UI though the host did not negotiate it.

  Raised by :func:`assert_may_declare_ui` when a server attempts to attach a UI
  association to a tool, or to expect a UI resource to be rendered, while the
  host has NOT advertised the extension with :data:`UI_MIME_TYPE` in its
  ``mimeTypes`` (R-26.2-f/g). The server MAY still expose the underlying tool as
  an ordinary tool (R-26.2-h) — it simply must not declare the UI.
  """


def server_may_declare_ui(host_extensions_map: Any) -> bool:
  """Return True iff a server may declare UI associations to this host (R-26.2-f/g).

  A server MUST NOT declare UI associations on tools, and MUST NOT expect any UI
  resource to be rendered, unless the host has advertised this extension with a
  ``mimeTypes`` array that includes the verbatim :data:`UI_MIME_TYPE`
  (R-26.2-f/g). This is exactly :func:`host_advertises_ui_extension`, surfaced
  under a server-intent name for the gate.

  Args:
    host_extensions_map: the host's advertised ``extensions`` map (or ``None``).
  """
  return host_advertises_ui_extension(host_extensions_map)


def assert_may_declare_ui(host_extensions_map: Any) -> None:
  """Raise if a server may not declare a UI to this host (R-26.2-f/g).

  Call this on the server before attaching ``_meta.ui`` to a tool or serving a
  UI resource as renderable.

  Raises:
    UiExtensionNotNegotiatedError: the host has not advertised the extension with
      :data:`UI_MIME_TYPE` in ``mimeTypes`` (R-26.2-f/g).
  """
  if not server_may_declare_ui(host_extensions_map):
    raise UiExtensionNotNegotiatedError(
      f"The host has not advertised {UI_EXTENSION_IDENTIFIER!r} with "
      f"{UI_MIME_TYPE!r} in its mimeTypes; a server MUST NOT declare UI "
      f"associations on tools or expect any UI to be rendered (R-26.2-f/g). It "
      f"MAY still expose the tools as ordinary tools (R-26.2-h)."
    )


def server_may_expose_plain_tool(host_extensions_map: Any) -> bool:
  """Return True: a server MAY always expose the tool as an ordinary tool (R-26.2-h).

  When the host has not negotiated the extension, a server MAY still expose the
  underlying tools as ordinary tools with no rendered UI (R-26.2-h / AC-41.18).
  Exposing a plain tool is never gated by the extension, so this is always True;
  the argument is accepted for symmetry with the declare-UI gate and documents
  that the decision does not depend on the host's advertisement.
  """
  return True


def receiver_ignores_ui_meta(client_extensions: Any, server_extensions: Any) -> bool:
  """Return True iff a receiver MUST ignore ``_meta.ui`` (extension inactive) (R-26.2-i).

  When the host has not negotiated the extension, the host treats the tool as a
  normal tool per §16 and ignores the UI metadata key per §24 (R-26.2-i /
  AC-41.19). A receiver that has not negotiated the extension MUST ignore the
  ``_meta.ui`` key (R-26.3-g / AC-41.27). This returns True exactly when the
  extension is NOT active for the session, signalling that ``_meta.ui`` must be
  ignored.
  """
  return not ui_extension_active(client_extensions, server_extensions)


# -- §26.2-j  Server acknowledgement in server/discover --

def server_ui_acknowledgement() -> dict[str, Any]:
  """Return the ``capabilities.extensions`` acknowledgement value (R-26.2-j).

  A server that supports the extension MAY acknowledge it in its
  ``server/discover`` result by including the same :data:`UI_EXTENSION_IDENTIFIER`
  key under ``capabilities.extensions``; the acknowledged value is an object that
  MAY be empty (``{}``) — presence of the key is the signal (R-26.2-j /
  AC-41.20). This returns ``{UI_EXTENSION_IDENTIFIER: {}}`` for a server to merge
  into its result's ``capabilities.extensions``.
  """
  return {UI_EXTENSION_IDENTIFIER: {}}


def server_acknowledges_ui(server_extensions_map: Any) -> bool:
  """Return True iff a server's ``extensions`` map acknowledges the UI extension (R-26.2-j).

  Acknowledgement is signalled by the *presence* of the
  :data:`UI_EXTENSION_IDENTIFIER` key with an object value (which MAY be empty);
  the value's contents are irrelevant (R-26.2-j). A ``null``/non-object value is
  malformed and does not count as advertised (R-6.5-i/j, via S11).

  Args:
    server_extensions_map: the server's ``capabilities.extensions`` map (or
      ``None``).
  """
  return UI_EXTENSION_IDENTIFIER in advertised_extension_ids(server_extensions_map)


# ---------------------------------------------------------------------------
# §26.3  ToolUiMeta — the ``_meta.ui`` declaration on a tool  [R-26.3-a…h]
# ---------------------------------------------------------------------------

class InvalidToolUiMetaError(ValueError):
  """A tool's ``_meta.ui`` declaration is malformed (§26.3).

  Raised when ``resourceUri`` is absent or not a ``ui://`` URI (R-26.3-a/b), or
  when ``visibility`` is present but is not an array drawn from the exact enum
  strings ``"model"`` / ``"app"`` (R-26.3-d). A non-``ui://`` URI is rejected as
  a UI association (R-26.3-b / AC-41.22).
  """


def is_ui_uri(uri: Any) -> bool:
  """Return True iff ``uri`` is a string using the ``ui://`` scheme (R-26.3-b, R-26.4-b).

  ``resourceUri`` MUST use the ``ui://`` scheme (R-26.3-b); the check is a
  case-sensitive scheme-prefix test against :data:`UI_URI_SCHEME`. A non-string,
  or a URI with any other scheme (e.g. ``https://``), is not a UI URI and a UI
  association built on it is rejected (R-26.3-b / AC-41.22).
  """
  return isinstance(uri, str) and uri.startswith(UI_URI_SCHEME)


@dataclass
class ToolUiMeta:
  """The value at a tool's ``_meta.ui``: its interactive-UI declaration (§26.3).

  Carried under the reserved nested key path ``_meta.ui`` on the tool shape of
  §16. It names the UI resource to render and declares which actors may invoke
  the tool.

  Fields:
    resource_uri: REQUIRED ``ui://`` URI of the UI resource to render for this
      tool (R-26.3-a/b). The host obtains the resource by issuing
      ``resources/read`` for this EXACT URI string (R-26.3-c). Wire key:
      ``resourceUri``.
    visibility: OPTIONAL array whose elements are drawn from the exact enum
      strings ``"model"`` and ``"app"`` (R-26.3-d). When ``None`` (omitted) the
      effective value is :data:`DEFAULT_VISIBILITY` (``["model","app"]``) — see
      :meth:`effective_visibility`. ``"model"`` = callable via ordinary
      tool-calling; ``"app"`` = callable by the rendered UI over the channel
      (§26.5).
  """

  resource_uri: str                      # JSON key: resourceUri
  visibility: list[str] | None = None    # JSON key: visibility

  def __post_init__(self) -> None:
    # R-26.3-a/b: resourceUri is REQUIRED and MUST use the ui:// scheme.
    if not isinstance(self.resource_uri, str) or not self.resource_uri:
      raise InvalidToolUiMetaError(
        "ToolUiMeta.resourceUri is REQUIRED and must be a non-empty string "
        "(R-26.3-a)"
      )
    if not is_ui_uri(self.resource_uri):
      raise InvalidToolUiMetaError(
        f"ToolUiMeta.resourceUri must use the {UI_URI_SCHEME!r} scheme; a "
        f"non-{UI_URI_SCHEME} URI ({self.resource_uri!r}) is rejected as a UI "
        f"association (R-26.3-b)"
      )
    # R-26.3-d: when present, every visibility element is one of the exact enum
    # strings "model" / "app".
    if self.visibility is not None:
      if not isinstance(self.visibility, list):
        raise InvalidToolUiMetaError(
          "ToolUiMeta.visibility must be an array when present (R-26.3-d)"
        )
      for entry in self.visibility:
        if entry not in VALID_VISIBILITY:
          raise InvalidToolUiMetaError(
            f"ToolUiMeta.visibility entries must be one of "
            f"{sorted(VALID_VISIBILITY)}; got {entry!r} (R-26.3-d)"
          )

  def effective_visibility(self) -> tuple[str, ...]:
    """Return the effective ``visibility``, applying the omitted-default (R-26.3-d).

    When ``visibility`` is omitted (``None``) the effective value is
    :data:`DEFAULT_VISIBILITY` (``["model","app"]``); otherwise it is the declared
    array reproduced verbatim (R-26.3-d / AC-41.24).
    """
    if self.visibility is None:
      return DEFAULT_VISIBILITY
    return tuple(self.visibility)

  def is_app_callable(self) -> bool:
    """True iff the rendered UI may call this tool — effective visibility ⊇ ``"app"`` (R-26.3-e).

    A host SHOULD reject a ``tools/call`` originating from a rendered UI for a
    tool whose effective ``visibility`` does not include ``"app"`` (R-26.3-e); see
    :func:`host_should_reject_ui_call`.
    """
    return VISIBILITY_APP in self.effective_visibility()

  def is_model_visible(self) -> bool:
    """True iff the tool appears in the model's tool list — effective visibility ⊇ ``"model"`` (R-26.3-f).

    A tool with ``visibility`` equal to ``["app"]`` is callable only by the UI and
    is hidden from the model's tool list (R-26.3-f / AC-41.26): this returns False
    for such a tool.
    """
    return VISIBILITY_MODEL in self.effective_visibility()

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolUiMeta:
    """Parse a wire ``ToolUiMeta`` object (the value at ``_meta.ui``) (§26.3).

    Validates ``resourceUri`` (REQUIRED ``ui://`` URI, R-26.3-a/b) and, when
    present, ``visibility`` (array of ``"model"``/``"app"``, R-26.3-d). Unknown
    keys are ignored for forward compatibility (§6.6).

    Raises:
      InvalidToolUiMetaError: ``resourceUri`` is absent/non-``ui://`` or
        ``visibility`` is malformed.
    """
    if not isinstance(data, dict):
      raise InvalidToolUiMetaError(
        f"_meta.ui must be a JSON object; got {type(data).__name__} (R-26.3-a)"
      )
    if "resourceUri" not in data:
      raise InvalidToolUiMetaError(
        "ToolUiMeta.resourceUri is REQUIRED (R-26.3-a)"
      )
    return cls(
      resource_uri=data["resourceUri"],
      visibility=data.get("visibility"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; omits ``visibility`` when absent (None).

    Omitting ``visibility`` is meaningful: it means the effective value is the
    default ``["model","app"]`` (R-26.3-d), so a None field is dropped rather than
    serialised as an explicit array.
    """
    out: dict[str, Any] = {"resourceUri": self.resource_uri}
    if self.visibility is not None:
      out["visibility"] = list(self.visibility)
    return out

  def to_tool_meta(self, base_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """Embed this declaration at the ``ui`` key of a tool's ``_meta`` map (§26.3).

    Returns a tool ``_meta`` object carrying ``{"ui": <this>}`` at the reserved
    :data:`TOOL_UI_META_KEY`. Any ``base_meta`` keys are preserved (the UI key is
    merged in), so a server can fold the UI declaration into an existing tool
    ``_meta`` without disturbing other metadata.

    Args:
      base_meta: an existing tool ``_meta`` map to merge into (left unmodified);
        ``None`` starts from an empty map.
    """
    meta: dict[str, Any] = dict(base_meta) if base_meta else {}
    meta[TOOL_UI_META_KEY] = self.to_dict()
    return meta


def tool_ui_meta_from_tool_meta(tool_meta: Any) -> ToolUiMeta | None:
  """Read the :class:`ToolUiMeta` from a tool's ``_meta`` map, or None (§26.3).

  Looks up the reserved :data:`TOOL_UI_META_KEY` (``"ui"``) inside a tool's
  ``_meta`` object and parses its value as a :class:`ToolUiMeta`. Returns None
  when ``_meta`` is absent/not an object or carries no ``ui`` key. A present but
  malformed ``ui`` value raises via :meth:`ToolUiMeta.from_dict`.

  Args:
    tool_meta: a tool's ``_meta`` object (or ``None``).

  Raises:
    InvalidToolUiMetaError: a ``ui`` value is present but malformed.
  """
  if not isinstance(tool_meta, dict):
    return None
  raw = tool_meta.get(TOOL_UI_META_KEY)
  if raw is None:
    return None
  return ToolUiMeta.from_dict(raw)


def host_should_reject_ui_call(ui_meta: ToolUiMeta) -> bool:
  """Return True iff a host SHOULD reject a UI-originated ``tools/call`` (R-26.3-e).

  A host SHOULD reject a ``tools/call`` request originating from a rendered UI for
  a tool whose effective ``visibility`` does not include ``"app"`` (R-26.3-e /
  AC-41.25). This returns True exactly when the tool is NOT app-callable.
  """
  return not ui_meta.is_app_callable()


def ordinary_call_behavior_unchanged_by_ui_meta(tool_meta: Any) -> bool:
  """Return True: ``_meta.ui`` never changes ordinary ``tools/call`` behavior (R-26.3-h).

  The presence of the ``_meta.ui`` key MUST NOT change the behavior of an ordinary
  ``tools/call`` (R-26.3-h / AC-41.28). The UI declaration is purely a rendering
  association consumed by the host; the core invocation path ignores it. This
  invariant holds whether or not a ``ui`` key is present, so it always returns
  True; the argument is accepted to document that the conclusion is independent
  of the metadata.
  """
  return True


# ---------------------------------------------------------------------------
# §26.4  UI resource hints — UiContentSecurityPolicy / UiPermissions
#         ResourceUiMeta  [R-26.4-e…m]
# ---------------------------------------------------------------------------

@dataclass
class UiContentSecurityPolicy:
  """A content-security-policy descriptor for a UI resource (§26.4, R-26.4-f).

  Each member is an OPTIONAL array of origin strings constraining what the UI may
  reach. An origin NOT listed in the applicable member MUST be blocked by the host
  (R-26.4-g); when the whole ``csp`` is omitted the host MUST apply a restrictive
  deny-by-default policy (R-26.4-h) — see :func:`host_blocks_origin` and
  :func:`host_default_policy_is_deny`.

  Fields:
    connect_domains: origins the UI MAY open network connections to. Wire key:
      ``connectDomains``.
    resource_domains: origins the UI MAY load resources (scripts, stylesheets,
      images, media) from. Wire key: ``resourceDomains``.
    frame_domains: origins the UI MAY embed in nested frames. Wire key:
      ``frameDomains``.
    base_uri_domains: origins permitted as the document base URI. Wire key:
      ``baseUriDomains``.
  """

  connect_domains: list[str] | None = None     # JSON: connectDomains
  resource_domains: list[str] | None = None    # JSON: resourceDomains
  frame_domains: list[str] | None = None       # JSON: frameDomains
  base_uri_domains: list[str] | None = None    # JSON: baseUriDomains

  def __post_init__(self) -> None:
    for label, value in (
      ("connectDomains", self.connect_domains),
      ("resourceDomains", self.resource_domains),
      ("frameDomains", self.frame_domains),
      ("baseUriDomains", self.base_uri_domains),
    ):
      if value is None:
        continue
      if not isinstance(value, list) or not all(isinstance(o, str) for o in value):
        raise ValueError(
          f"UiContentSecurityPolicy.{label} must be an array of origin strings "
          f"when present (R-26.4-f)"
        )

  def allowed_origins(self, member: str) -> tuple[str, ...]:
    """Return the origins listed in CSP ``member`` (empty when omitted) (R-26.4-f/g).

    ``member`` is one of ``"connectDomains"``, ``"resourceDomains"``,
    ``"frameDomains"``, ``"baseUriDomains"``. An omitted member yields an empty
    tuple, so every origin is blocked for that member (deny-by-default within the
    member, R-26.4-g).
    """
    mapping = {
      "connectDomains": self.connect_domains,
      "resourceDomains": self.resource_domains,
      "frameDomains": self.frame_domains,
      "baseUriDomains": self.base_uri_domains,
    }
    if member not in mapping:
      raise KeyError(
        f"unknown CSP member {member!r}; expected one of {sorted(mapping)}"
      )
    value = mapping[member]
    return tuple(value) if value is not None else ()

  def origin_allowed(self, member: str, origin: str) -> bool:
    """Return True iff ``origin`` is listed in CSP ``member`` (R-26.4-g).

    An origin that is not listed in the applicable member MUST be blocked by the
    host (R-26.4-g / AC-41.35); this is the allow-side of that test.
    """
    return origin in self.allowed_origins(member)

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UiContentSecurityPolicy:
    """Parse a wire ``UiContentSecurityPolicy`` object (§26.4). Unknown keys ignored."""
    if not isinstance(data, dict):
      raise ValueError(
        f"UiContentSecurityPolicy must be a JSON object; got "
        f"{type(data).__name__} (R-26.4-f)"
      )
    return cls(
      connect_domains=data.get("connectDomains"),
      resource_domains=data.get("resourceDomains"),
      frame_domains=data.get("frameDomains"),
      base_uri_domains=data.get("baseUriDomains"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire object; omits absent (None) members."""
    out: dict[str, Any] = {}
    if self.connect_domains is not None:
      out["connectDomains"] = list(self.connect_domains)
    if self.resource_domains is not None:
      out["resourceDomains"] = list(self.resource_domains)
    if self.frame_domains is not None:
      out["frameDomains"] = list(self.frame_domains)
    if self.base_uri_domains is not None:
      out["baseUriDomains"] = list(self.base_uri_domains)
    return out


def host_blocks_origin(
  origin: str,
  member: str,
  csp: UiContentSecurityPolicy | None,
) -> bool:
  """Return True iff the host MUST block ``origin`` for CSP ``member`` (R-26.4-g/h).

  An origin not listed in the applicable ``csp`` member MUST be blocked
  (R-26.4-g). When ``csp`` is omitted entirely (``None``) the host applies a
  restrictive deny-by-default policy, so EVERY origin is blocked (R-26.4-h /
  AC-41.36). Thus this returns True unless ``csp`` is present and ``origin`` is
  listed in ``member``.

  Args:
    origin: the origin the UI is attempting to use.
    member: the CSP member governing the attempt (e.g. ``"connectDomains"``).
    csp: the resource's declared CSP, or ``None`` when omitted.
  """
  if csp is None:
    return True  # deny-by-default when csp omitted (R-26.4-h)
  return not csp.origin_allowed(member, origin)


def host_default_policy_is_deny(csp: UiContentSecurityPolicy | None) -> bool:
  """Return True iff the host applies deny-by-default — i.e. ``csp`` omitted (R-26.4-h).

  When ``csp`` is omitted the host MUST apply a restrictive deny-by-default policy
  (R-26.4-h / AC-41.36). This states that condition directly: the policy is
  deny-by-default exactly when no CSP descriptor is present.
  """
  return csp is None


@dataclass
class UiPermissions:
  """Sandbox capabilities a UI resource requests (§26.4, R-26.4-i).

  An object whose PRESENT members request additional sandbox capabilities; each
  member value is an empty object ``{}`` and a member's presence requests that
  capability, while its absence means the capability is not requested
  (R-26.4-i). The host MUST NOT grant a capability that is not requested
  (R-26.4-j) and MAY decline a requested one (R-26.4-k) — see
  :func:`host_may_grant_permission`.

  Fields are modelled as booleans (presence flags). Each maps to a wire member of
  the exact name; ``True`` serialises to ``{}`` (request), ``False`` omits the
  member (not requested).

  Fields:
    camera: requests camera access when True.
    microphone: requests microphone access when True.
    geolocation: requests geolocation access when True.
    clipboard_write: requests clipboard-write access when True. Wire key:
      ``clipboardWrite``.
  """

  camera: bool = False
  microphone: bool = False
  geolocation: bool = False
  clipboard_write: bool = False  # JSON key: clipboardWrite

  def requested(self) -> frozenset[str]:
    """Return the exact wire member names this object requests (R-26.4-i).

    A capability is requested iff its presence flag is True; the returned tokens
    are drawn from :data:`VALID_PERMISSIONS`. The host MUST NOT grant any
    capability outside this set (R-26.4-j).
    """
    out: set[str] = set()
    if self.camera:
      out.add("camera")
    if self.microphone:
      out.add("microphone")
    if self.geolocation:
      out.add("geolocation")
    if self.clipboard_write:
      out.add("clipboardWrite")
    return frozenset(out)

  def is_requested(self, capability: str) -> bool:
    """Return True iff ``capability`` (a wire member name) is requested (R-26.4-i)."""
    return capability in self.requested()

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> UiPermissions:
    """Parse a wire ``UiPermissions`` object (§26.4, R-26.4-i).

    Each present member name MUST be one of :data:`VALID_PERMISSIONS` and its
    value MUST be an empty object ``{}``; a member's presence requests that
    capability. An unknown member name, or a non-``{}`` value, is rejected.

    Raises:
      ValueError: ``data`` is not an object, a member name is not one of the
        exact permitted strings, or a member value is not ``{}``.
    """
    if not isinstance(data, dict):
      raise ValueError(
        f"UiPermissions must be a JSON object; got {type(data).__name__} "
        f"(R-26.4-i)"
      )
    for name, value in data.items():
      if name not in VALID_PERMISSIONS:
        raise ValueError(
          f"UiPermissions member {name!r} is not one of the exact strings "
          f"{sorted(VALID_PERMISSIONS)} (R-26.4-i)"
        )
      if value != {}:
        raise ValueError(
          f"UiPermissions.{name} value must be an empty object {{}}; got "
          f"{value!r} (R-26.4-i)"
        )
    return cls(
      camera="camera" in data,
      microphone="microphone" in data,
      geolocation="geolocation" in data,
      clipboard_write="clipboardWrite" in data,
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire object; each requested capability maps to ``{}`` (R-26.4-i)."""
    out: dict[str, Any] = {}
    for name in self.requested():
      out[name] = {}
    return out


def host_may_grant_permission(capability: str, permissions: UiPermissions | None) -> bool:
  """Return True iff the host MAY grant ``capability`` — i.e. it was requested (R-26.4-j/k).

  The host MUST NOT grant a sandbox capability that is not requested (R-26.4-j /
  AC-41.38): when ``permissions`` is omitted, or does not request ``capability``,
  this returns False and the host must not grant it. When the capability IS
  requested the host MAY grant it — but MAY also decline (R-26.4-k / AC-41.39),
  which is a host policy decision this predicate does not force. So a True result
  means "grant is permitted", never "grant is required".

  Args:
    capability: the wire member name (e.g. ``"camera"``).
    permissions: the resource's declared :class:`UiPermissions`, or ``None``.
  """
  if permissions is None:
    return False
  return permissions.is_requested(capability)


@dataclass
class ResourceUiMeta:
  """Presentation/security hints at a UI resource content's ``_meta.ui`` (§26.4).

  A UI resource's ``contents`` entry MAY carry these hints under its own
  ``_meta.ui`` object; when present they take effect for rendering (R-26.4-e).
  All fields are OPTIONAL.

  Fields:
    csp: a :class:`UiContentSecurityPolicy` constraining the origins the UI may
      contact / load from / frame / use as base URI (R-26.4-f). When omitted the
      host applies deny-by-default (R-26.4-h).
    permissions: a :class:`UiPermissions` object requesting sandbox capabilities
      (R-26.4-i).
    domain: a string naming a dedicated origin under which the host SHOULD render
      the UI, isolating it from other UI resources (R-26.4-l).
    prefers_border: a boolean expressing the server's preference for a visible
      border; the host MAY honor or ignore it (R-26.4-m). Wire key:
      ``prefersBorder``.
  """

  csp: UiContentSecurityPolicy | None = None
  permissions: UiPermissions | None = None
  domain: str | None = None
  prefers_border: bool | None = None  # JSON key: prefersBorder

  def __post_init__(self) -> None:
    if self.csp is not None and not isinstance(self.csp, UiContentSecurityPolicy):
      raise TypeError(
        "ResourceUiMeta.csp must be a UiContentSecurityPolicy when present "
        "(R-26.4-f)"
      )
    if self.permissions is not None and not isinstance(self.permissions, UiPermissions):
      raise TypeError(
        "ResourceUiMeta.permissions must be a UiPermissions when present "
        "(R-26.4-i)"
      )
    if self.domain is not None and not isinstance(self.domain, str):
      raise TypeError(
        "ResourceUiMeta.domain must be a string when present (R-26.4-l)"
      )
    if self.prefers_border is not None and not isinstance(self.prefers_border, bool):
      raise TypeError(
        "ResourceUiMeta.prefersBorder must be a boolean when present (R-26.4-m)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ResourceUiMeta:
    """Parse a wire ``ResourceUiMeta`` object (§26.4). Unknown keys are ignored.

    Raises:
      ValueError / TypeError: a present sub-object is malformed (e.g. a bad CSP
        member, an unknown permission name, or a wrong-typed scalar).
    """
    if not isinstance(data, dict):
      raise ValueError(
        f"ResourceUiMeta must be a JSON object; got {type(data).__name__} "
        f"(R-26.4-e)"
      )
    raw_csp = data.get("csp")
    raw_perms = data.get("permissions")
    return cls(
      csp=UiContentSecurityPolicy.from_dict(raw_csp) if raw_csp is not None else None,
      permissions=UiPermissions.from_dict(raw_perms) if raw_perms is not None else None,
      domain=data.get("domain"),
      prefers_border=data.get("prefersBorder"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire object; omits absent (None) fields."""
    out: dict[str, Any] = {}
    if self.csp is not None:
      out["csp"] = self.csp.to_dict()
    if self.permissions is not None:
      out["permissions"] = self.permissions.to_dict()
    if self.domain is not None:
      out["domain"] = self.domain
    if self.prefers_border is not None:
      out["prefersBorder"] = self.prefers_border
    return out

  def to_resource_meta(self, base_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """Embed these hints at the ``ui`` key of a resource content's ``_meta`` (§26.4).

    Returns a resource-content ``_meta`` object carrying ``{"ui": <this>}`` at the
    reserved :data:`TOOL_UI_META_KEY`; ``base_meta`` keys are preserved.

    Args:
      base_meta: an existing resource-content ``_meta`` map to merge into (left
        unmodified); ``None`` starts from an empty map.
    """
    meta: dict[str, Any] = dict(base_meta) if base_meta else {}
    meta[TOOL_UI_META_KEY] = self.to_dict()
    return meta


def resource_ui_meta_from_content_meta(content_meta: Any) -> ResourceUiMeta | None:
  """Read the :class:`ResourceUiMeta` hints from a resource content's ``_meta`` (§26.4).

  Looks up the reserved :data:`TOOL_UI_META_KEY` (``"ui"``) inside a resource
  content entry's ``_meta`` object and parses its value as a
  :class:`ResourceUiMeta`. Returns None when ``_meta`` is absent/not an object or
  carries no ``ui`` key. When present, these hints take effect for rendering
  (R-26.4-e / AC-41.33).

  Args:
    content_meta: a resource-content ``_meta`` object (or ``None``).

  Raises:
    ValueError / TypeError: a ``ui`` value is present but malformed.
  """
  if not isinstance(content_meta, dict):
    return None
  raw = content_meta.get(TOOL_UI_META_KEY)
  if raw is None:
    return None
  return ResourceUiMeta.from_dict(raw)


# ---------------------------------------------------------------------------
# §26.4  The UI resource and the ``ui://`` scheme  [R-26.4-a/b/c/d]
# ---------------------------------------------------------------------------

def assert_ui_mime_type(mime_type: Any) -> None:
  """Assert a UI resource's MIME type is the verbatim :data:`UI_MIME_TYPE` (R-26.4-d).

  A UI resource's content MUST be served with the MIME type
  ``text/html;profile=mcp-app``, reproduced verbatim and case-sensitively
  (R-26.4-d / AC-41.32). Any other string — different case, extra whitespace, or
  a missing/extra parameter — is rejected.

  Raises:
    ValueError: ``mime_type`` is not exactly :data:`UI_MIME_TYPE`.
  """
  if mime_type != UI_MIME_TYPE:
    raise ValueError(
      f"A UI resource MUST be served with the MIME type {UI_MIME_TYPE!r}, "
      f"reproduced verbatim and case-sensitively; got {mime_type!r} (R-26.4-d)"
    )


def is_ui_resource_content(contents: ResourceContents) -> bool:
  """Return True iff a ``ResourceContents`` entry carries the UI MIME type (R-26.4-d).

  A UI resource content is identified by its ``mimeType`` being exactly
  :data:`UI_MIME_TYPE` (R-26.4-d). Accepts either ``ResourceContents`` variant
  (text or blob); the ``text``/``blob`` payload itself is the HTML document
  (§26.4).
  """
  return getattr(contents, "mime_type", None) == UI_MIME_TYPE


def host_derives_network_origin_from_ui_uri(uri: str) -> bool:
  """Return False: a host MUST NOT derive a network origin from a ``ui://`` URI (R-26.4-c).

  The authority/path components after ``ui://`` are server-defined and opaque; the
  host MUST treat the whole URI as an opaque identifier (R-26.4-b / AC-41.30) and
  MUST NOT derive a network origin from it (R-26.4-c / AC-41.31). A conforming
  host therefore never derives an origin, so this invariant always returns False
  regardless of the ``uri`` supplied.
  """
  return False


def ui_uri_is_opaque_identifier(uri: str) -> bool:
  """Return True iff ``uri`` is treated as an opaque ``ui://`` identifier (R-26.4-b).

  The host MUST treat the whole ``ui://`` URI as an opaque identifier — the
  authority and path after ``ui://`` are server-defined and are NOT parsed for any
  network meaning (R-26.4-b / AC-41.30). This returns True for any well-formed
  ``ui://`` URI, affirming it is consumed opaquely (and fetched by exact-string
  ``resources/read``, R-26.3-c).
  """
  return is_ui_uri(uri)


def host_may_preload_ui_resource() -> bool:
  """Return True: a host MAY preload the UI resource before the tool is called (R-26.4-a).

  The host MAY fetch (preload) the UI resource before the associated tool is
  called (R-26.4-a / AC-41.29). Preloading is always permitted, so this returns
  True; it is a plain ``resources/read`` for the exact ``resourceUri`` (R-26.3-c)
  carrying no dependency on the tool having been invoked.
  """
  return True


@dataclass
class UiResource:
  """A served UI resource: its ``ui://`` URI, HTML payload, and optional hints (§26.4).

  A convenience aggregate over the §26.4 model a server uses when answering
  ``resources/read`` (R-26.1-c): it pairs the ``ResourceContents`` (a
  :class:`TextResourceContents` carrying the HTML in ``text``, or a
  :class:`BlobResourceContents` carrying a Base64 payload in ``blob``, R-26.4-d)
  with the parsed :class:`ResourceUiMeta` hints, validating that the content's
  ``mimeType`` is the verbatim :data:`UI_MIME_TYPE` and that its ``uri`` uses the
  ``ui://`` scheme (R-26.4-b/d). This is a server-side helper only; it performs no
  rendering (R-26.1-i).

  Fields:
    contents: the ``ResourceContents`` entry (text or blob) for the UI document.
    ui_meta: the parsed :class:`ResourceUiMeta` hints, or ``None`` when the
      content carries no ``_meta.ui`` (R-26.4-e).
  """

  contents: ResourceContents
  ui_meta: ResourceUiMeta | None = None

  def __post_init__(self) -> None:
    if not isinstance(self.contents, (TextResourceContents, BlobResourceContents)):
      raise TypeError(
        "UiResource.contents must be a TextResourceContents or "
        "BlobResourceContents (R-26.4-d)"
      )
    # R-26.4-d: the content MUST carry the verbatim UI MIME type.
    assert_ui_mime_type(self.contents.mime_type)
    # R-26.4-b: the resource URI MUST use the ui:// scheme.
    if not is_ui_uri(self.contents.uri):
      raise ValueError(
        f"UiResource.contents.uri must use the {UI_URI_SCHEME!r} scheme; got "
        f"{self.contents.uri!r} (R-26.4-b)"
      )
    if self.ui_meta is not None and not isinstance(self.ui_meta, ResourceUiMeta):
      raise TypeError(
        "UiResource.ui_meta must be a ResourceUiMeta when present (R-26.4-e)"
      )

  @property
  def uri(self) -> str:
    """The opaque ``ui://`` URI identifying this resource (R-26.4-b)."""
    return self.contents.uri

  @classmethod
  def from_content_dict(cls, data: dict[str, Any]) -> UiResource:
    """Parse one ``resources/read`` ``contents`` entry as a UI resource (§26.4).

    Selects the ``ResourceContents`` variant by ``text``/``blob`` presence via
    S21's :func:`parse_resource_contents`, asserts the verbatim MIME type and
    ``ui://`` scheme (R-26.4-b/d), and parses any ``_meta.ui`` hints (R-26.4-e).

    Raises:
      ValueError / TypeError: the entry is malformed, carries the wrong MIME type,
        is not a ``ui://`` URI, or its ``_meta.ui`` is malformed.
    """
    if not isinstance(data, dict):
      raise ValueError(
        f"UI resource content must be a JSON object; got {type(data).__name__} "
        f"(R-26.4-d)"
      )
    contents = parse_resource_contents(data)
    ui_meta = resource_ui_meta_from_content_meta(data.get("_meta"))
    return cls(contents=contents, ui_meta=ui_meta)

  def to_content_dict(self) -> dict[str, Any]:
    """Serialise to a ``resources/read`` ``contents`` entry (§26.4).

    Emits the ``ResourceContents`` fields (``uri``, ``mimeType``, ``text``/``blob``
    and any pre-existing ``_meta``), then merges the UI hints under ``_meta.ui``
    when present (R-26.4-e), preserving any other ``_meta`` keys already on the
    content.
    """
    out = self.contents.to_dict()
    if self.ui_meta is not None:
      base = out.get("_meta")
      out["_meta"] = self.ui_meta.to_resource_meta(
        base if isinstance(base, dict) else None
      )
    return out


# ---------------------------------------------------------------------------
# §26.4  Host rendering-isolation obligations  [R-26.4-n/o/p]
# ---------------------------------------------------------------------------

#: The access a host's sandboxed, isolated browsing context MUST deny the rendered
#: UI (R-26.4-n): the embedding document, its cookies, its storage, and its
#: navigation. Provided as an auditable set so a conformance suite can assert each
#: is denied (AC-41.42).
SANDBOX_DENIED_ACCESS: frozenset[str] = frozenset({
  "embedding_document",
  "cookies",
  "storage",
  "navigation",
})


def host_must_sandbox_rendered_ui() -> bool:
  """Return True: rendered UI MUST run in a sandboxed, isolated context (R-26.4-n).

  The host MUST render the resource content in a sandboxed, isolated browsing
  context (a sandboxed iframe or equivalent) that denies the content access to
  the embedding document, its cookies, its storage, and its navigation
  (R-26.4-n / AC-41.42) — the set :data:`SANDBOX_DENIED_ACCESS`. This is an
  unconditional host obligation, so it always returns True.
  """
  return True


def sandbox_denies_access(access: str) -> bool:
  """Return True iff a conforming sandbox denies ``access`` to the rendered UI (R-26.4-n).

  Membership test against :data:`SANDBOX_DENIED_ACCESS`: the sandbox denies access
  to the embedding document, cookies, storage, and navigation (R-26.4-n /
  AC-41.42). Any other token is not among the enumerated denied accesses.
  """
  return access in SANDBOX_DENIED_ACCESS


def host_must_apply_restrictive_csp() -> bool:
  """Return True: the host MUST apply a restrictive CSP to rendered content (R-26.4-o).

  The host MUST apply a restrictive content-security policy to the rendered
  content, constrained by the declared ``csp`` descriptor (R-26.4-o / AC-41.43);
  when no ``csp`` is declared the policy is deny-by-default (R-26.4-h). This is an
  unconditional host obligation, so it always returns True.
  """
  return True


def rendered_ui_has_ambient_host_access() -> bool:
  """Return False: rendered content gets NO ambient access to host state (R-26.4-p).

  The rendered content MUST NOT be granted ambient access to host state or user
  data; the ONLY channel between the rendered content and the host is the
  message-channel dialect of §26.5 (R-26.4-p / AC-41.44) — which is owned by S42
  and out of scope here. A conforming host grants no ambient access, so this
  invariant always returns False.
  """
  return False


# ---------------------------------------------------------------------------
# §24 / §26  The extension as an ExtensionDefinition for the registry
# ---------------------------------------------------------------------------

#: The Interactive UI extension described as an :class:`ExtensionDefinition`
#: (S38, §24) so it can be registered in an :class:`ExtensionRegistry` alongside
#: other extensions and negotiated through the standard active-set machinery.
#: ``allow_reserved=True`` because this is one of the protocol's OWN official
#: extensions under the reserved ``io.modelcontextprotocol/`` family (R-24.2-e).
#: It is classified MODULAR — a discrete, self-contained capability — and declares
#: no contributed methods/notifications/resultTypes here: S41 contributes only the
#: ``_meta`` declaration surface (the ``ui`` key on a tool's / resource content's
#: ``_meta``), with the dynamic ``ui/*`` method channel owned by S42.
UI_EXTENSION_DEFINITION: ExtensionDefinition = ExtensionDefinition(
  identifier=UI_EXTENSION_IDENTIFIER,
  classification=ExtensionClassification.MODULAR,
  fallback_doc=(
    "When the io.modelcontextprotocol/ui extension is not active, a server "
    "exposes its tools as ordinary tools per §16 with no rendered UI, and a "
    "receiver ignores the _meta.ui key per §24 (R-26.2-h/i, R-26.3-g)."
  ),
  allow_reserved=True,
)


__all__ = [
  # §26.2  identifier, MIME type, and shared constants
  "UI_EXTENSION_IDENTIFIER",
  "UI_MIME_TYPE",
  "TOOL_UI_META_KEY",
  "METHOD_RESOURCES_READ",
  "UI_URI_SCHEME",
  "VISIBILITY_MODEL",
  "VISIBILITY_APP",
  "VALID_VISIBILITY",
  "DEFAULT_VISIBILITY",
  "VALID_PERMISSIONS",
  # §26.1  responsibility split
  "ResponsibilityRole",
  "RESPONSIBILITY_ASSIGNMENT",
  "SERVER_SDK_NON_RESPONSIBILITIES",
  "responsibility_of",
  "is_server_sdk_responsibility",
  "server_sdk_requires_rendering_dependency",
  # §26.2  host capability and negotiation
  "UiHostExtensionCapability",
  "InvalidUiHostCapabilityError",
  "ui_extension_advertisement",
  "is_ui_extension_identifier",
  "ui_capability_from_extensions",
  "host_capabilities_from_request_meta",
  "host_advertises_ui_extension",
  "ui_extension_active",
  "UiExtensionNotNegotiatedError",
  "server_may_declare_ui",
  "assert_may_declare_ui",
  "server_may_expose_plain_tool",
  "receiver_ignores_ui_meta",
  "server_ui_acknowledgement",
  "server_acknowledges_ui",
  # §26.3  ToolUiMeta
  "ToolUiMeta",
  "InvalidToolUiMetaError",
  "is_ui_uri",
  "tool_ui_meta_from_tool_meta",
  "host_should_reject_ui_call",
  "ordinary_call_behavior_unchanged_by_ui_meta",
  # §26.4  resource hints
  "UiContentSecurityPolicy",
  "UiPermissions",
  "ResourceUiMeta",
  "host_blocks_origin",
  "host_default_policy_is_deny",
  "host_may_grant_permission",
  "resource_ui_meta_from_content_meta",
  # §26.4  UI resource and ui:// scheme
  "assert_ui_mime_type",
  "is_ui_resource_content",
  "host_derives_network_origin_from_ui_uri",
  "ui_uri_is_opaque_identifier",
  "host_may_preload_ui_resource",
  "UiResource",
  # §26.4  host rendering isolation
  "SANDBOX_DENIED_ACCESS",
  "host_must_sandbox_rendered_ui",
  "sandbox_denies_access",
  "host_must_apply_restrictive_csp",
  "rendered_ui_has_ambient_host_access",
  # §24/§26  registry definition
  "UI_EXTENSION_DEFINITION",
]
