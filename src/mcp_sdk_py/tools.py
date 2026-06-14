"""Tools I: Capability, Listing & the Tool Type — S24.

Delivers the discovery half of MCP tools (§16.1–§16.4): how a server announces
that it offers tools, how a client lists the available tools (with pagination
and cache hints), the exact shape of a ``Tool`` definition, and the normative
JSON Schema rules that govern a tool's ``inputSchema`` and ``outputSchema``.
Calling a tool (``tools/call``) — invocation, the ``CallToolResult`` shape,
``isError``, ``ToolAnnotations`` field semantics, and the list-changed
notification — is deliberately deferred to S25 (§16.5–§16.9). Here
``outputSchema``, ``annotations``, and ``listChanged`` are *referenced* only as
fields; their behaviour lives in S25.

Public surface:

Capability & gating (§16.1):
  - ToolsCapability: the ``tools`` capability value with optional ``listChanged``
    sub-flag (R-16.1-a/b).
  - server_must_declare_tools(): gate — a server MUST NOT answer tools/list or
    tools/call unless it declared ``tools`` (R-16.1-c).
  - client_may_send_tool_request() / assert_client_may_send_tool_request():
    client gate — a client MUST NOT send tools/list or tools/call unless the
    server declared ``tools`` (R-16.1-d).
  - client_may_rely_on_list_changed(): a client MUST NOT rely on
    notifications/tools/list_changed unless ``tools.listChanged: true`` (R-16.1-e).

Listing (§16.2):
  - ListToolsRequestParams: the tools/list request params with optional opaque
    ``cursor`` (R-16.2-a) — a PaginatedRequestParams (§12).
  - ListToolsResult: the tools/list result — simultaneously a PaginatedResult
    (§12: ``nextCursor``) and a CacheableResult (§13: ``ttlMs``, ``cacheScope``)
    wrapping a page of ``Tool`` defs (R-16.2-b…o).

The Tool type (§16.3):
  - Tool: name/title (BaseMetadata, §14), description, inputSchema,
    outputSchema, annotations, icons, _meta (R-16.3-a…p).
  - tool_display_name(): title → annotations.title → name precedence (R-16.3-i).
  - tool_name_follows_conventions() / validate_tool_name_conventions(): the
    SHOULD-level naming conventions (R-16.3-b…f).
  - disambiguate_tool_name(): server-id prefixing for aggregated collisions
    (R-16.3-g/h).

JSON Schema rules (§16.4):
  - JSON_SCHEMA_2020_12_URI, SUPPORTED_SCHEMA_DIALECTS, schema_dialect(),
    is_supported_dialect() (R-16.4-a/b, R-16.4-s/t/u).
  - validate_input_schema() / validate_output_schema(): structural validation,
    root-type constraints, dialect support, depth/size bounds, and rejection of
    unsafe schemas (R-16.4-c…n).
  - reference_resolution: SchemaResolutionMode and resolve_references() enforce
    in-document-only ``$ref``/``$dynamicRef`` resolution with an opt-in,
    disabled-by-default external mode (R-16.4-f…k, R-16.4-r).
  - validate_arguments_against_input_schema() / produce/validate structured
    content roles (R-16.4-o/p/q).

Spec: §16.1–§16.4
Depends on: S10 (capabilities), S18 (pagination), S20 (BaseMetadata/Icon),
            S19 (caching hints), S04 (Result family).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from mcp_sdk_py.caching import (
  CACHE_SCOPE_PRIVATE,
  CACHE_SCOPE_PUBLIC,
  VALID_CACHE_SCOPES,
  is_valid_ttl_ms,
)
from mcp_sdk_py.capabilities import ServerCapabilities
from mcp_sdk_py.common_types import Icon, resolve_tool_display_name
from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE, ResultType


# ---------------------------------------------------------------------------
# §16  Method names & the list-changed notification reference
# ---------------------------------------------------------------------------

#: The paginated, cacheable discovery request defined here (§16.2).
METHOD_TOOLS_LIST: str = "tools/list"

#: The invocation request; defined in S25 (§16.5). Named here only for gating.
METHOD_TOOLS_CALL: str = "tools/call"

#: Methods gated by the ``tools`` capability (R-16.1-c, R-16.1-d).
TOOL_METHODS: frozenset[str] = frozenset({METHOD_TOOLS_LIST, METHOD_TOOLS_CALL})

#: The list-changed notification; its emission/handling is owned by S25 (§16.8).
#: Referenced here only by the reliance gate (R-16.1-e).
NOTIFICATION_TOOLS_LIST_CHANGED: str = "notifications/tools/list_changed"

#: The capability key under a server's capabilities object (§16.1).
TOOLS_CAPABILITY_KEY: str = "tools"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ToolsCapabilityNotDeclaredError(Exception):
  """A tools request was attempted though the ``tools`` capability was undeclared.

  Raised by the gating helpers (R-16.1-c, R-16.1-d): a server MUST NOT answer,
  and a client MUST NOT send, ``tools/list`` or ``tools/call`` unless the server
  declared the ``tools`` capability during version negotiation. This is a local
  conformance guard; it is distinct from any on-the-wire JSON-RPC error.

  Attributes:
    method: the tools method that was gated (``tools/list`` or ``tools/call``).
  """

  def __init__(self, method: str) -> None:
    super().__init__(
      f"Method {method!r} requires the 'tools' capability, which the server did "
      f"not declare; a server MUST NOT respond and a client MUST NOT send it "
      f"(R-16.1-c, R-16.1-d)"
    )
    self.method: str = method


class UnsupportedSchemaDialectError(Exception):
  """A schema declared a ``$schema`` dialect the implementation does not support.

  Per R-16.4-t the implementation MUST handle this gracefully by signalling that
  the dialect is unsupported, rather than silently ignoring the declaration or
  treating the schema as permissive.

  Attributes:
    dialect: the unsupported ``$schema`` URI from the schema document.
  """

  def __init__(self, dialect: str) -> None:
    super().__init__(
      f"Schema dialect {dialect!r} is not supported by this implementation; "
      f"the schema cannot be validated and is rejected rather than treated as "
      f"permissive (R-16.4-t)"
    )
    self.dialect: str = dialect


class UnsafeSchemaError(Exception):
  """A schema cannot be safely validated and MUST be rejected (R-16.4-n).

  Covers schemas that are not a valid JSON Schema object (e.g. ``null``), that
  exceed the configured depth/size/reference bounds (R-16.4-l/m), or that would
  require external dereferencing the implementation does not permit (R-16.4-f/g).
  A server MUST reject — or refuse to register — such a schema (R-16.4-n).

  Attributes:
    reason: a short machine-readable reason token.
  """

  def __init__(self, reason: str, detail: str = "") -> None:
    msg = f"Schema cannot be safely validated and is rejected ({reason}, R-16.4-n)"
    if detail:
      msg = f"{msg}: {detail}"
    super().__init__(msg)
    self.reason: str = reason
    self.detail: str = detail


class ExternalReferenceError(Exception):
  """A ``$ref``/``$dynamicRef`` targets a location outside the schema document.

  When external dereferencing is not enabled (the default), an external target
  MUST NOT be fetched over any network or file system (R-16.4-f, R-16.4-g); a
  schema that depends on such an unresolved reference SHOULD be rejected rather
  than treated as permissive (R-16.4-k).

  Attributes:
    ref: the offending reference URI.
  """

  def __init__(self, ref: str) -> None:
    super().__init__(
      f"Reference {ref!r} resolves outside the schema document; external "
      f"dereferencing is disabled, so it MUST NOT be fetched and the schema is "
      f"rejected rather than treated as permissive (R-16.4-f, R-16.4-g, R-16.4-k)"
    )
    self.ref: str = ref


# ---------------------------------------------------------------------------
# §16.1  The `tools` server capability  [R-16.1-a, R-16.1-b]
# ---------------------------------------------------------------------------

@dataclass
class ToolsCapability:
  """The value of the ``tools`` key inside a server's capabilities object (§16.1).

  Its presence declares that the server exposes tools and so MUST be present
  during version negotiation for a tools server (R-16.1-a). The object has one
  OPTIONAL boolean sub-flag:

  Fields:
    list_changed: when ``True`` the server MAY emit
      ``notifications/tools/list_changed`` when its tool set changes; absent
      (``None``) or ``False`` means it does not emit that notification
      (R-16.1-b). Wire key: ``listChanged``. The notification itself is defined
      in S25 (§16.8).
  """

  list_changed: bool | None = None  # JSON key: listChanged

  def __post_init__(self) -> None:
    if self.list_changed is not None and not isinstance(self.list_changed, bool):
      raise TypeError(
        "ToolsCapability.listChanged must be a boolean when present (R-16.1-b)"
      )

  @property
  def emits_list_changed(self) -> bool:
    """True only when ``listChanged`` is explicitly ``True`` (R-16.1-b).

    A server emits ``notifications/tools/list_changed`` only when this is True;
    a client MUST NOT rely on receiving it otherwise (R-16.1-e).
    """
    return self.list_changed is True

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ToolsCapability:
    """Parse a wire ToolsCapability object; an empty object ``{}`` is valid.

    Unknown keys are ignored (forward compatibility). ``listChanged`` must be a
    boolean if present.

    Raises:
      TypeError: data is not an object, or ``listChanged`` is not a boolean.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ToolsCapability must be a JSON object; got {type(data).__name__} "
        f"(R-16.1-a)"
      )
    raw = data.get("listChanged")
    if raw is not None and not isinstance(raw, bool):
      raise TypeError(
        "ToolsCapability.listChanged must be a boolean when present (R-16.1-b)"
      )
    return cls(list_changed=raw)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to the wire object; omits ``listChanged`` when absent (None)."""
    out: dict[str, Any] = {}
    if self.list_changed is not None:
      out["listChanged"] = self.list_changed
    return out


# ---------------------------------------------------------------------------
# §16.1  Capability gating  [R-16.1-c, R-16.1-d, R-16.1-e]
# ---------------------------------------------------------------------------

def server_declares_tools(
  server_capabilities: ServerCapabilities | dict[str, Any],
) -> bool:
  """Return True if a server's capabilities object declares the ``tools`` key.

  Presence-means-supported (§6.1): the ``tools`` field — even with an empty
  object value ``{}`` — declares the capability; absence declares it is not
  supported. This is the single gate consulted by every tools request
  (R-16.1-a, R-16.1-c, R-16.1-d).

  Accepts either the canonical ``ServerCapabilities`` object (S10, as learned
  from a ``server/discover`` result) or its raw capability-map dict form, so the
  gate composes with both shapes used across the SDK.
  """
  caps = (
    server_capabilities.to_dict()
    if isinstance(server_capabilities, ServerCapabilities)
    else server_capabilities
  )
  return TOOLS_CAPABILITY_KEY in caps


def server_must_declare_tools(
  server_capabilities: ServerCapabilities | dict[str, Any],
) -> None:
  """Assert a server may answer tool requests; raise otherwise (R-16.1-c).

  A server MUST NOT respond to ``tools/list`` or ``tools/call`` unless it has
  declared the ``tools`` capability. Call this on the server before answering.

  Raises:
    ToolsCapabilityNotDeclaredError: the server has not declared ``tools``.
  """
  if not server_declares_tools(server_capabilities):
    raise ToolsCapabilityNotDeclaredError(METHOD_TOOLS_LIST)


def client_may_send_tool_request(
  server_capabilities: ServerCapabilities | dict[str, Any],
  method: str = METHOD_TOOLS_LIST,
) -> bool:
  """Return True if a client may send ``method`` to this server (R-16.1-d).

  A client MUST NOT send ``tools/list`` or ``tools/call`` to a server that has
  not declared the ``tools`` capability. Only the two tool methods are gated;
  any other method passed here is treated as ungated (returns True).
  """
  if method not in TOOL_METHODS:
    return True
  return server_declares_tools(server_capabilities)


def assert_client_may_send_tool_request(
  server_capabilities: ServerCapabilities | dict[str, Any],
  method: str = METHOD_TOOLS_LIST,
) -> None:
  """Raise if a client may not send ``method`` to this server (R-16.1-d).

  Call this on the client before issuing ``tools/list`` or ``tools/call``.

  Raises:
    ToolsCapabilityNotDeclaredError: the server has not declared ``tools``.
  """
  if not client_may_send_tool_request(server_capabilities, method):
    raise ToolsCapabilityNotDeclaredError(method)


def client_may_rely_on_list_changed(
  server_capabilities: ServerCapabilities | dict[str, Any],
) -> bool:
  """Return True only if the server declared ``tools.listChanged: true`` (R-16.1-e).

  A client MUST NOT rely on receiving ``notifications/tools/list_changed``
  unless the server declared ``tools.listChanged: true``. When ``tools`` is
  absent, or ``listChanged`` is absent or ``false``, this returns False and the
  client MUST NOT depend on the notification (it can still re-fetch on its own
  schedule per the ``ttlMs`` hint). Accepts either the ``ServerCapabilities``
  object or its raw dict form.
  """
  caps = (
    server_capabilities.to_dict()
    if isinstance(server_capabilities, ServerCapabilities)
    else server_capabilities
  )
  tools = caps.get(TOOLS_CAPABILITY_KEY)
  if not isinstance(tools, dict):
    return False
  return tools.get("listChanged") is True


# ---------------------------------------------------------------------------
# §16.3  Tool name conventions  [R-16.3-b … R-16.3-h]
# ---------------------------------------------------------------------------

#: Minimum recommended tool-name length, inclusive (R-16.3-b).
TOOL_NAME_MIN_LENGTH: int = 1

#: Maximum recommended tool-name length, inclusive (R-16.3-b).
TOOL_NAME_MAX_LENGTH: int = 128

#: The recommended tool-name character set: ASCII letters, digits, ``_ - .``
#: (R-16.3-d). Names SHOULD contain only these characters and SHOULD NOT
#: contain spaces, commas, or other special characters (R-16.3-e).
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def tool_name_follows_conventions(name: str) -> bool:
  """Return True if ``name`` follows the §16.3 naming conventions (R-16.3-b/c/d/e).

  The conventions are SHOULD-level: a name SHOULD be 1–128 characters inclusive
  (R-16.3-b), treated case-sensitively (R-16.3-c — honoured by exact, non-folding
  comparison throughout), and SHOULD contain only ASCII letters, digits,
  underscore, hyphen, and dot, with no spaces, commas, or other special
  characters (R-16.3-d, R-16.3-e). Case-sensitivity is structural: this check
  never lower/upper-cases the name, so two names differing only in case are
  distinct.

  This is advisory: a non-conforming name is still a usable identifier, so
  ``Tool`` does not reject it; callers MAY warn or normalise.
  """
  if not isinstance(name, str):
    return False
  if not (TOOL_NAME_MIN_LENGTH <= len(name) <= TOOL_NAME_MAX_LENGTH):
    return False
  return bool(_TOOL_NAME_RE.match(name))


def validate_tool_name_conventions(name: str) -> list[str]:
  """Return a list of SHOULD-level convention violations for ``name`` (R-16.3-b…e).

  An empty list means the name follows every recommended convention. Each entry
  is a human-readable description of one violation, suitable for a warning. The
  conventions are advisory (SHOULD), so this reports rather than raises.
  """
  problems: list[str] = []
  if not isinstance(name, str):
    return [f"name must be a string; got {type(name).__name__}"]
  if len(name) < TOOL_NAME_MIN_LENGTH or len(name) > TOOL_NAME_MAX_LENGTH:
    problems.append(
      f"name SHOULD be {TOOL_NAME_MIN_LENGTH}–{TOOL_NAME_MAX_LENGTH} characters "
      f"inclusive; got length {len(name)} (R-16.3-b)"
    )
  if " " in name:
    problems.append("name SHOULD NOT contain spaces (R-16.3-e)")
  if "," in name:
    problems.append("name SHOULD NOT contain commas (R-16.3-e)")
  if name and not _TOOL_NAME_RE.match(name):
    problems.append(
      "name SHOULD contain only ASCII letters, digits, '_', '-', and '.' "
      "(R-16.3-d)"
    )
  return problems


def tool_names_are_unique(names: list[str]) -> bool:
  """Return True if every tool name is unique within one server (R-16.3-f).

  Uniqueness is scoped to a single server and is case-sensitive (R-16.3-c): two
  names differing only in case are considered distinct, so they do not collide.
  """
  return len(names) == len(set(names))


def disambiguate_tool_name(server_id: str, name: str, *, separator: str = ".") -> str:
  """Return a server-qualified tool name for cross-server aggregation (R-16.3-g/h).

  A client or proxy aggregating tools from multiple servers MAY encounter name
  collisions because uniqueness is only guaranteed within one server (R-16.3-g).
  Such a client/proxy SHOULD apply a disambiguation strategy; prefixing the name
  with a server identifier is the canonical example (R-16.3-h). The original
  ``name`` is preserved verbatim after the prefix so the underlying ``tools/call``
  identifier can be recovered.
  """
  return f"{server_id}{separator}{name}"


# ---------------------------------------------------------------------------
# §16.4  JSON Schema dialect support  [R-16.4-a, R-16.4-b, R-16.4-s/t/u]
# ---------------------------------------------------------------------------

#: The JSON Schema 2020-12 dialect URI — the REQUIRED default dialect (R-16.4-a).
JSON_SCHEMA_2020_12_URI: str = "https://json-schema.org/draft/2020-12/schema"

#: The dialects this implementation supports. Per R-16.4-u an implementation
#: SHOULD document which dialects it supports beyond the required 2020-12; this
#: set IS that documentation. This implementation supports only JSON Schema
#: 2020-12 (the required default) — no additional dialects. Both the canonical
#: ``https`` and the historical ``http`` form of the 2020-12 URI are accepted.
SUPPORTED_SCHEMA_DIALECTS: frozenset[str] = frozenset({
  JSON_SCHEMA_2020_12_URI,
  "http://json-schema.org/draft/2020-12/schema",
})


def schema_dialect(schema: dict[str, Any]) -> str:
  """Return the dialect URI governing ``schema`` (R-16.4-a, R-16.4-b).

  When no ``$schema`` keyword is present the document MUST be interpreted as
  JSON Schema 2020-12, so the default URI is returned (R-16.4-a). When a
  ``$schema`` keyword is present it declares the dialect that governs
  interpretation and is returned verbatim (R-16.4-b).
  """
  declared = schema.get("$schema")
  if isinstance(declared, str) and declared:
    return declared
  return JSON_SCHEMA_2020_12_URI


def is_supported_dialect(dialect: str) -> bool:
  """Return True if ``dialect`` is one this implementation can validate (R-16.4-s/u).

  An implementation MUST validate a schema according to its declared or default
  dialect (R-16.4-s); an unsupported dialect MUST be reported rather than
  silently ignored (R-16.4-t). The supported set is ``SUPPORTED_SCHEMA_DIALECTS``
  (R-16.4-u).
  """
  return dialect in SUPPORTED_SCHEMA_DIALECTS


# ---------------------------------------------------------------------------
# §16.4  Reference resolution & SSRF safety  [R-16.4-f … R-16.4-k, R-16.4-r]
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExternalDereferenceLimits:
  """Bounds enforced when the opt-in external-reference mode is enabled (R-16.4-j).

  When an implementation offers the opt-in external-fetch mode it SHOULD enforce
  a host allowlist (or at minimum reject loopback, link-local, and
  private-network addresses), apply request timeouts and response size limits,
  and log every dereferenced URI (R-16.4-j). These fields carry that policy.

  Fields:
    host_allowlist: hosts permitted as ``$ref`` targets; when non-empty, only
      these hosts are reachable and all others are rejected.
    reject_private_addresses: when True, loopback / link-local / private-network
      destinations are rejected even if no allowlist is configured (the SHOULD
      minimum).
    timeout_seconds: per-request timeout applied to each fetch.
    max_response_bytes: response-size cap applied to each fetch.
  """

  host_allowlist: frozenset[str] = frozenset()
  reject_private_addresses: bool = True
  timeout_seconds: float = 5.0
  max_response_bytes: int = 1_048_576


@dataclass
class SchemaResolutionMode:
  """Controls how ``$ref``/``$dynamicRef`` targets are resolved (R-16.4-f…k).

  By default only in-document references are resolved; external targets are
  never fetched over any network or file system (R-16.4-f, R-16.4-g). An
  implementation MAY offer an opt-in mode that fetches non-local targets
  (R-16.4-h), but that mode MUST be disabled by default (R-16.4-i) — which is why
  ``allow_external`` defaults to ``False`` here. When enabled, ``limits`` carries
  the host allowlist / private-address rejection / timeout / size-limit policy
  and ``dereference_log`` records every dereferenced URI (R-16.4-j).

  Fields:
    allow_external: opt-in flag; MUST default to False (R-16.4-i).
    limits: the safety policy applied only when ``allow_external`` is True.
    dereference_log: append-only audit log of every external URI dereferenced
      (R-16.4-j); populated only in external mode.
  """

  allow_external: bool = False
  limits: ExternalDereferenceLimits = field(default_factory=ExternalDereferenceLimits)
  dereference_log: list[str] = field(default_factory=list)

  def external_host_allowed(self, host: str) -> bool:
    """Return True if ``host`` may be dereferenced under this mode's policy (R-16.4-j).

    When external fetching is disabled, no host is allowed. When enabled, the
    host must pass the allowlist (when configured) and, by default, must not be a
    loopback, link-local, or private-network address.
    """
    if not self.allow_external:
      return False
    if self.limits.host_allowlist and host not in self.limits.host_allowlist:
      return False
    if self.limits.reject_private_addresses and _is_private_host(host):
      return False
    return True


def _is_private_host(host: str) -> bool:
  """Return True if ``host`` is a loopback, link-local, or private-network address.

  Used by the opt-in external-fetch mode to reject SSRF-prone destinations
  (R-16.4-j). A non-IP hostname (one that does not parse as an IP literal) is
  treated conservatively as not provably public and therefore private when the
  literal is ``localhost``; other hostnames are left to the allowlist.
  """
  if host == "localhost":
    return True
  try:
    addr = ipaddress.ip_address(host)
  except ValueError:
    return False
  return (
    addr.is_loopback
    or addr.is_link_local
    or addr.is_private
    or addr.is_reserved
    or addr.is_unspecified
  )


def reference_is_in_document(ref: str) -> bool:
  """Return True if a ``$ref`` value resolves within the same schema document.

  In-document references are document-local: a bare JSON Pointer fragment
  (``#`` or ``#/...``) or a same-document anchor (``#name``). A reference whose
  resolved target lies outside the document — for example an absolute URI with a
  scheme and authority — is NOT in-document and MUST NOT be auto-dereferenced
  when external fetching is disabled (R-16.4-f).
  """
  if not isinstance(ref, str) or not ref:
    return False
  if ref.startswith("#"):
    return True  # fragment-only: JSON Pointer or $anchor within this document
  parsed = urlparse(ref)
  # An absolute URI (scheme + authority/path) targets another document.
  return not (parsed.scheme or parsed.netloc)


def _iter_references(schema: Any) -> list[str]:
  """Collect every ``$ref`` / ``$dynamicRef`` string anywhere in ``schema``."""
  refs: list[str] = []

  def walk(node: Any) -> None:
    if isinstance(node, dict):
      for key in ("$ref", "$dynamicRef"):
        value = node.get(key)
        if isinstance(value, str):
          refs.append(value)
      for value in node.values():
        walk(value)
    elif isinstance(node, list):
      for item in node:
        walk(item)

  walk(schema)
  return refs


def resolve_references(
  schema: dict[str, Any],
  mode: SchemaResolutionMode | None = None,
) -> None:
  """Enforce the in-document-only reference-resolution rules (R-16.4-f…k, R-16.4-r).

  Walks every ``$ref`` / ``$dynamicRef`` in ``schema``. In the default mode
  (``mode`` None or ``allow_external`` False) any reference whose target lies
  outside the document is rejected: it MUST NOT be fetched over any network or
  file system (R-16.4-f, R-16.4-g), and a schema depending on such an unresolved
  external reference is rejected rather than treated as permissive (R-16.4-k).
  A client applying local argument validation MUST follow these same rules
  (R-16.4-r) — it uses this function with the default mode.

  When ``mode.allow_external`` is True (the opt-in mode, R-16.4-h), an external
  reference is permitted only if its host passes the configured policy
  (allowlist / private-address rejection, R-16.4-j); each permitted external URI
  is appended to ``mode.dereference_log`` (R-16.4-j). This function performs no
  actual I/O — it records the audit entry and enforces the policy gate, leaving
  the transport to the caller — so it never itself reaches the network.

  Raises:
    ExternalReferenceError: a reference targets outside the document while
      external dereferencing is disabled, or its host fails the enabled policy.
  """
  active = mode or SchemaResolutionMode()
  for ref in _iter_references(schema):
    if reference_is_in_document(ref):
      continue
    if not active.allow_external:
      raise ExternalReferenceError(ref)
    host = urlparse(ref).hostname or ""
    if not active.external_host_allowed(host):
      raise ExternalReferenceError(ref)
    active.dereference_log.append(ref)  # R-16.4-j: log every dereferenced URI


# ---------------------------------------------------------------------------
# §16.4  Resource bounds  [R-16.4-l, R-16.4-m]
# ---------------------------------------------------------------------------

#: Default cap on schema nesting depth so processing cannot exhaust the stack
#: (R-16.4-l). An implementation MAY impose this and similar bounds (R-16.4-m).
DEFAULT_MAX_SCHEMA_DEPTH: int = 64

#: Default cap on the number of nodes (objects/arrays) in a schema document so a
#: pathologically large schema cannot exhaust memory (R-16.4-l, R-16.4-m).
DEFAULT_MAX_SCHEMA_NODES: int = 10_000


@dataclass(frozen=True)
class SchemaBounds:
  """Resource bounds applied when processing a schema (R-16.4-l, R-16.4-m).

  An implementation MUST bound nesting depth and validation time so processing a
  schema cannot exhaust memory, stack, or CPU (R-16.4-l); it MAY impose limits on
  size, depth, reference-resolution count, and per-validation time (R-16.4-m).

  Fields:
    max_depth: maximum nesting depth of the schema document.
    max_nodes: maximum number of container nodes (objects + arrays).
  """

  max_depth: int = DEFAULT_MAX_SCHEMA_DEPTH
  max_nodes: int = DEFAULT_MAX_SCHEMA_NODES


def _measure_schema(node: Any, bounds: SchemaBounds, depth: int = 1) -> int:
  """Return the node count of ``node``, raising UnsafeSchemaError if bounds blow.

  Bounds nesting depth and total node count so a deeply nested or large schema
  cannot exhaust the stack or memory (R-16.4-l). Raises before recursing further
  on the first violation, so a hostile schema cannot drive unbounded recursion.
  """
  if depth > bounds.max_depth:
    raise UnsafeSchemaError(
      "depth_exceeded",
      f"schema nesting depth exceeds the bound of {bounds.max_depth} (R-16.4-l)",
    )
  count = 1
  if isinstance(node, dict):
    for value in node.values():
      count += _measure_schema(value, bounds, depth + 1)
      if count > bounds.max_nodes:
        raise UnsafeSchemaError(
          "size_exceeded",
          f"schema node count exceeds the bound of {bounds.max_nodes} (R-16.4-l)",
        )
  elif isinstance(node, list):
    for item in node:
      count += _measure_schema(item, bounds, depth + 1)
      if count > bounds.max_nodes:
        raise UnsafeSchemaError(
          "size_exceeded",
          f"schema node count exceeds the bound of {bounds.max_nodes} (R-16.4-l)",
        )
  return count


# ---------------------------------------------------------------------------
# §16.4  Schema validation  [R-16.4-c, R-16.4-d, R-16.4-e, R-16.4-n, R-16.4-v]
# ---------------------------------------------------------------------------

def _validate_schema_document(
  schema: Any,
  *,
  label: str,
  resolution_mode: SchemaResolutionMode | None,
  bounds: SchemaBounds,
) -> dict[str, Any]:
  """Shared structural validation for input/output schema documents (R-16.4-n).

  Rejects any schema that is not a valid JSON Schema object (e.g. ``null``)
  (R-16.4-n), enforces the resource bounds (R-16.4-l/m), checks the declared or
  default dialect is supported (R-16.4-s/t), and enforces in-document-only
  reference resolution (R-16.4-f…k). Returns the validated document.

  Raises:
    UnsafeSchemaError: not a JSON Schema object, or exceeds depth/size bounds.
    UnsupportedSchemaDialectError: declares an unsupported ``$schema`` dialect.
    ExternalReferenceError: depends on an unresolved external reference.
  """
  # R-16.4-n: a schema that is not a valid JSON Schema object (e.g. null) is
  # rejected — refuse to register it.
  if not isinstance(schema, dict):
    type_name = "null" if schema is None else type(schema).__name__
    raise UnsafeSchemaError(
      "not_an_object",
      f"{label} must be a JSON Schema object; got {type_name} (R-16.4-n)",
    )

  # R-16.4-l/m: bound depth and size before any deeper processing.
  _measure_schema(schema, bounds)

  # R-16.4-s/t: validate per declared/default dialect; reject unsupported ones.
  dialect = schema_dialect(schema)
  if not is_supported_dialect(dialect):
    raise UnsupportedSchemaDialectError(dialect)

  # R-16.4-f…k, R-16.4-r: enforce in-document-only reference resolution.
  resolve_references(schema, resolution_mode)
  return schema


def validate_input_schema(
  schema: Any,
  *,
  resolution_mode: SchemaResolutionMode | None = None,
  bounds: SchemaBounds = SchemaBounds(),
) -> dict[str, Any]:
  """Validate a tool ``inputSchema`` document and return it (R-16.3-k, R-16.4-c/d/n).

  Enforces every structural rule for an arguments schema:
    - it MUST be a valid JSON Schema object (R-16.4-n);
    - it MUST declare root ``type: "object"`` because tool arguments are always
      a JSON object (R-16.3-k, R-16.4-d);
    - any of the permitted 2020-12 keywords (``properties``, ``required``,
      ``additionalProperties``, …) MAY appear alongside the root type (R-16.4-c);
    - a no-parameter tool MUST still provide a valid object schema, e.g.
      ``{"type": "object", "additionalProperties": false}`` or ``{"type":
      "object"}`` (R-16.3-l) — both satisfy this check;
    - the declared/default dialect MUST be supported (R-16.4-s/t) and references
      MUST resolve in-document only (R-16.4-f…k).

  Raises:
    UnsafeSchemaError: not an object, root type is not ``"object"``, or bounds
      are exceeded (R-16.4-d, R-16.4-n).
    UnsupportedSchemaDialectError / ExternalReferenceError: as for the shared
      validator.
  """
  document = _validate_schema_document(
    schema,
    label="inputSchema",
    resolution_mode=resolution_mode,
    bounds=bounds,
  )
  # R-16.3-k, R-16.4-d: the arguments object means root type MUST be "object".
  root_type = document.get("type")
  if root_type != "object":
    raise UnsafeSchemaError(
      "bad_root_type",
      f"inputSchema root 'type' MUST be \"object\"; got {root_type!r} "
      f"(R-16.3-k, R-16.4-d)",
    )
  return document


def validate_output_schema(
  schema: Any,
  *,
  resolution_mode: SchemaResolutionMode | None = None,
  bounds: SchemaBounds = SchemaBounds(),
) -> dict[str, Any]:
  """Validate a tool ``outputSchema`` document and return it (R-16.3-m, R-16.4-e).

  ``outputSchema`` describes the ``structuredContent`` of a ``CallToolResult``
  (defined in S25). Unlike ``inputSchema`` its root ``type`` is NOT restricted to
  ``"object"`` — it MAY describe any JSON value, e.g. an ``"array"`` (R-16.4-e),
  matching that a ``structuredContent`` value MAY itself be any JSON type
  (R-16.4-v). The remaining structural rules (valid object, supported dialect,
  in-document references, resource bounds) are identical to ``inputSchema``.

  Raises:
    UnsafeSchemaError: not a valid JSON Schema object, or bounds exceeded
      (R-16.4-n).
    UnsupportedSchemaDialectError / ExternalReferenceError: as for the shared
      validator.
  """
  return _validate_schema_document(
    schema,
    label="outputSchema",
    resolution_mode=resolution_mode,
    bounds=bounds,
  )


# ---------------------------------------------------------------------------
# §16.3  The `Tool` type  [R-16.3-a … R-16.3-p]
# ---------------------------------------------------------------------------

@dataclass
class Tool:
  """A single tool definition: a named, schema-described server function (§16.3).

  Combines the ``name``/``title`` pair from ``BaseMetadata`` (§14) with the
  schema and display fields. Field names are exact and case-sensitive.

  Fields:
    name: REQUIRED unique programmatic identifier used to invoke the tool in a
      ``tools/call`` request (R-16.3-a). The SHOULD-level naming conventions
      (1–128 chars, case-sensitive, ``A–Z a–z 0–9 _ - .`` only, unique per
      server) are advisory — see :func:`tool_name_follows_conventions`
      (R-16.3-b…f); a non-conforming name is still accepted as an identifier.
    title: OPTIONAL human-readable display name (R-16.3-i). Display-name
      precedence is ``title`` → ``annotations.title`` → ``name`` — see
      :func:`tool_display_name`.
    description: OPTIONAL human-readable description; clients MAY pass it to the
      language model as a tool-selection hint (R-16.3-j).
    input_schema: REQUIRED JSON Schema (2020-12) for the arguments object; its
      root ``type`` MUST be ``"object"`` (R-16.3-k, R-16.4-d). Wire key:
      ``inputSchema``.
    output_schema: OPTIONAL JSON Schema for the ``structuredContent`` of a
      ``CallToolResult`` (S25); root type unrestricted (R-16.3-m, R-16.4-e).
      Wire key: ``outputSchema``.
    annotations: OPTIONAL untrusted behaviour hints; the ``ToolAnnotations``
      field semantics are owned by S25 — carried here as an opaque object only
      (R-16.3-n).
    icons: OPTIONAL list of display ``Icon`` objects from §14/S20 (R-16.3-o).
    meta: OPTIONAL reserved implementation/extension metadata map (R-16.3-p).
      Wire key: ``_meta``.
  """

  name: str
  input_schema: dict[str, Any]                       # JSON key: inputSchema
  title: str | None = None
  description: str | None = None
  output_schema: dict[str, Any] | None = None        # JSON key: outputSchema
  annotations: dict[str, Any] | None = None          # ToolAnnotations (S25)
  icons: list[Icon] | None = None
  meta: dict[str, Any] | None = None                 # JSON key: _meta

  def __post_init__(self) -> None:
    # R-16.3-a: name is REQUIRED and is the tools/call identifier.
    if not isinstance(self.name, str) or not self.name:
      raise ValueError(
        "Tool.name is REQUIRED and must be a non-empty string (R-16.3-a)"
      )
    if self.title is not None and not isinstance(self.title, str):
      raise TypeError("Tool.title must be a string when present (R-16.3-i)")
    if self.description is not None and not isinstance(self.description, str):
      raise TypeError("Tool.description must be a string when present (R-16.3-j)")
    # R-16.3-k, R-16.4-d: inputSchema is REQUIRED and root type MUST be object.
    validate_input_schema(self.input_schema)
    # R-16.3-m, R-16.4-e: outputSchema, when present, is validated (root type
    # unrestricted).
    if self.output_schema is not None:
      validate_output_schema(self.output_schema)
    if self.annotations is not None and not isinstance(self.annotations, dict):
      raise TypeError(
        "Tool.annotations must be a JSON object (ToolAnnotations) when present "
        "(R-16.3-n)"
      )
    if self.icons is not None:
      if not isinstance(self.icons, list):
        raise TypeError("Tool.icons must be a list when present (R-16.3-o)")
      for icon in self.icons:
        if not isinstance(icon, Icon):
          raise TypeError(
            f"Tool.icons entries must be Icon objects; got {icon!r} (R-16.3-o)"
          )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError("Tool._meta must be a JSON object when present (R-16.3-p)")

  @property
  def annotations_title(self) -> str | None:
    """The ``annotations.title`` value, if any (used by display-name precedence)."""
    if isinstance(self.annotations, dict):
      value = self.annotations.get("title")
      if isinstance(value, str):
        return value
    return None

  def display_name(self) -> str:
    """Resolve the display name: ``title`` → ``annotations.title`` → ``name`` (R-16.3-i).

    Delegates to the shared §14.1 precedence helper so tools, resources, and
    prompts resolve names identically.
    """
    return resolve_tool_display_name(self.name, self.title, self.annotations_title)

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> Tool:
    """Parse a wire ``Tool`` object (§16.3).

    Nested ``icons`` are converted to ``Icon`` objects (§14/S20); the camelCase
    wire keys ``inputSchema``/``outputSchema``/``_meta`` are mapped to the
    snake-case fields. Unknown top-level keys are ignored for forward
    compatibility. The schema rules (root ``type``, dialect, references, bounds)
    are enforced via ``__post_init__``.

    Raises:
      ValueError / TypeError / UnsafeSchemaError / ...: as for construction.
    """
    if not isinstance(data, dict):
      raise TypeError(f"Tool must be a JSON object; got {type(data).__name__}")
    if "inputSchema" not in data:
      raise ValueError(
        "Tool.inputSchema is REQUIRED (R-16.3-k); it was absent"
      )
    raw_icons = data.get("icons")
    icons: list[Icon] | None = (
      [Icon.from_dict(i) for i in raw_icons] if raw_icons is not None else None
    )
    return cls(
      name=data["name"],
      input_schema=data["inputSchema"],
      title=data.get("title"),
      description=data.get("description"),
      output_schema=data.get("outputSchema"),
      annotations=data.get("annotations"),
      icons=icons,
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields.

    Field order places ``name`` first; ``inputSchema`` always appears
    (REQUIRED); optional fields are emitted only when present.
    """
    out: dict[str, Any] = {"name": self.name}
    if self.title is not None:
      out["title"] = self.title
    if self.description is not None:
      out["description"] = self.description
    out["inputSchema"] = self.input_schema
    if self.output_schema is not None:
      out["outputSchema"] = self.output_schema
    if self.annotations is not None:
      out["annotations"] = self.annotations
    if self.icons is not None:
      out["icons"] = [i.to_dict() for i in self.icons]
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def tool_display_name(
  name: str,
  title: str | None = None,
  annotations: dict[str, Any] | None = None,
) -> str:
  """Resolve a tool's display name from raw fields (R-16.3-i).

  Precedence: ``title`` → ``annotations.title`` → ``name`` (R-16.3-i). ``title``
  is optional; when both ``title`` and ``annotations.title`` are absent the
  programmatic ``name`` is used. Convenience for callers holding the raw fields
  rather than a :class:`Tool`.
  """
  annotations_title: str | None = None
  if isinstance(annotations, dict):
    candidate = annotations.get("title")
    if isinstance(candidate, str):
      annotations_title = candidate
  return resolve_tool_display_name(name, title, annotations_title)


# ---------------------------------------------------------------------------
# §16.2  `tools/list` request params  [R-16.2-a]
# ---------------------------------------------------------------------------

@dataclass
class ListToolsRequestParams:
  """The params of a ``tools/list`` request (§16.2); a PaginatedRequestParams (§12).

  Fields:
    cursor: OPTIONAL opaque pagination position to resume from; absence requests
      the first page (R-16.2-a, §12). The value is opaque and is passed through
      verbatim — a client MUST NOT parse or construct it (R-16.2-e/f).
    meta: OPTIONAL reserved ``_meta`` map (§4/§14). Wire key: ``_meta``.
  """

  cursor: str | None = None
  meta: dict[str, Any] | None = None  # JSON key: _meta

  def __post_init__(self) -> None:
    if self.cursor is not None and not isinstance(self.cursor, str):
      raise TypeError(
        f"cursor must be an opaque string when present; got "
        f"{type(self.cursor).__name__} (R-16.2-a)"
      )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError("_meta must be a JSON object when present")

  @classmethod
  def from_dict(cls, data: dict[str, Any] | None) -> ListToolsRequestParams:
    """Parse ``tools/list`` request params; ``None`` or ``{}`` means the first page.

    ``cursor`` MUST be a string if present (and is treated as opaque, R-16.2-e/f);
    the empty string ``""`` is a valid, present cursor (§12). Unknown keys are
    ignored.

    Raises:
      TypeError: ``data`` is not an object, or a field has the wrong type.
    """
    if data is None:
      return cls()
    if not isinstance(data, dict):
      raise TypeError(
        f"tools/list params must be a JSON object; got {type(data).__name__}"
      )
    cursor = data.get("cursor")
    if cursor is not None and not isinstance(cursor, str):
      raise TypeError(
        f"cursor must be an opaque string; got {type(cursor).__name__} (R-16.2-a)"
      )
    meta = data.get("_meta")
    if meta is not None and not isinstance(meta, dict):
      raise TypeError("_meta must be a JSON object when present")
    return cls(cursor=cursor, meta=meta)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields."""
    out: dict[str, Any] = {}
    if self.cursor is not None:
      out["cursor"] = self.cursor
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def next_request_after(result: ListToolsResult) -> ListToolsRequestParams | None:
  """Build the follow-up ``tools/list`` params for the next page, or None (R-16.2-c/d/e).

  When ``result.next_cursor`` is present, more results MAY exist and the client
  MAY issue another ``tools/list`` with ``cursor`` set to that value (R-16.2-c,
  R-16.2-d). The value is passed through verbatim — never parsed or reconstructed
  (R-16.2-e, R-16.2-f). When ``next_cursor`` is absent this is the last page and
  None is returned (R-16.2-c).
  """
  if result.next_cursor is None:
    return None
  return ListToolsRequestParams(cursor=result.next_cursor)


# ---------------------------------------------------------------------------
# §16.2  `tools/list` result  [R-16.2-b … R-16.2-o]
# ---------------------------------------------------------------------------

@dataclass
class ListToolsResult:
  """The result of ``tools/list`` (§16.2).

  Simultaneously a PaginatedResult (§12: ``nextCursor``) and a CacheableResult
  (§13: ``ttlMs``, ``cacheScope``) wrapping a page of ``Tool`` definitions.

  Fields:
    tools: REQUIRED page of ``Tool`` definitions; MAY be empty (R-16.2-b,
      R-16.1-g).
    ttl_ms: REQUIRED non-negative client-cache freshness hint in milliseconds;
      ``0`` means immediately stale, a positive value means fresh for that many
      ms (R-16.2-g/i, §13). Wire key: ``ttlMs``.
    cache_scope: REQUIRED enum ``"public"`` | ``"private"`` giving the intended
      cache-sharing scope (R-16.2-j/k/l, §13). Wire key: ``cacheScope``.
    next_cursor: OPTIONAL opaque token for the position after the last returned
      tool; present ⇒ more MAY exist, absent ⇒ last page (R-16.2-c, §12). Wire
      key: ``nextCursor``.
    result_type: REQUIRED discriminator; for a tools list the value is
      ``"complete"`` (R-16.2-m, §3). Wire key: ``resultType``.
    meta: OPTIONAL reserved metadata map (R-16.2-n). Wire key: ``_meta``.
  """

  tools: list[Tool]
  ttl_ms: int
  cache_scope: str
  next_cursor: str | None = None                     # JSON key: nextCursor
  result_type: ResultType = RESULT_TYPE_COMPLETE     # JSON key: resultType
  meta: dict[str, Any] | None = None                 # JSON key: _meta

  def __post_init__(self) -> None:
    # R-16.2-b: tools is REQUIRED and is an array of Tool definitions.
    if not isinstance(self.tools, list):
      raise TypeError("ListToolsResult.tools must be a list (R-16.2-b)")
    for tool in self.tools:
      if not isinstance(tool, Tool):
        raise TypeError(
          f"ListToolsResult.tools entries must be Tool objects; got {tool!r} "
          f"(R-16.2-b)"
        )
    # R-16.2-g: ttlMs is REQUIRED, a non-negative integer.
    if not is_valid_ttl_ms(self.ttl_ms):
      raise ValueError(
        f"ttlMs is REQUIRED and must be a non-negative integer; got "
        f"{self.ttl_ms!r} (R-16.2-g)"
      )
    # R-16.2-j: cacheScope is REQUIRED, exactly "public" or "private".
    if self.cache_scope not in VALID_CACHE_SCOPES:
      raise ValueError(
        f"cacheScope is REQUIRED and must be exactly 'public' or 'private'; got "
        f"{self.cache_scope!r} (R-16.2-j)"
      )
    if self.next_cursor is not None and not isinstance(self.next_cursor, str):
      raise TypeError(
        f"nextCursor must be an opaque string when present; got "
        f"{type(self.next_cursor).__name__} (R-16.2-c)"
      )
    # R-16.2-m: resultType is the REQUIRED discriminator and for a tools/list
    # result its value MUST be exactly "complete" — a wrong value (e.g.
    # "input_required") is rejected, not silently accepted.
    if not isinstance(self.result_type, str):
      raise TypeError("resultType must be a string (R-16.2-m)")
    if self.result_type != RESULT_TYPE_COMPLETE:
      raise ValueError(
        f"resultType for a tools/list result MUST be {RESULT_TYPE_COMPLETE!r}; "
        f"got {self.result_type!r} (R-16.2-m, §3.6)"
      )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError("_meta must be a JSON object when present (R-16.2-n)")

  @property
  def is_last_page(self) -> bool:
    """True when ``nextCursor`` is absent — this is the final page (R-16.2-c, §12)."""
    return self.next_cursor is None

  @property
  def is_immediately_stale(self) -> bool:
    """True when ``ttlMs`` is 0 — the result SHOULD be considered immediately stale (R-16.2-i)."""
    return self.ttl_ms == 0

  @property
  def is_public(self) -> bool:
    """True when ``cacheScope`` is ``"public"`` — any client/intermediary MAY cache it (R-16.2-k)."""
    return self.cache_scope == CACHE_SCOPE_PUBLIC

  @property
  def is_private(self) -> bool:
    """True when ``cacheScope`` is ``"private"`` — shared caches MUST NOT serve it to others (R-16.2-l)."""
    return self.cache_scope == CACHE_SCOPE_PRIVATE

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ListToolsResult:
    """Parse a wire ``tools/list`` result (§16.2).

    Validates that ``tools`` is a present array (R-16.2-b), ``ttlMs`` is a
    present non-negative integer (R-16.2-g), ``cacheScope`` is present and
    exactly ``"public"``/``"private"`` (R-16.2-j), ``nextCursor`` is opaque when
    present (R-16.2-c), and ``resultType`` is present (R-16.2-m). Nested tools
    are parsed via :meth:`Tool.from_dict`.

    Raises:
      TypeError / ValueError: a required field is absent or a field has the
        wrong type/value.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"tools/list result must be a JSON object; got {type(data).__name__}"
      )
    if "tools" not in data:
      raise ValueError("ListToolsResult.tools is REQUIRED (R-16.2-b)")
    raw_tools = data["tools"]
    if not isinstance(raw_tools, list):
      raise TypeError("ListToolsResult.tools must be an array (R-16.2-b)")
    tools = [Tool.from_dict(t) for t in raw_tools]

    if "ttlMs" not in data:
      raise ValueError("ttlMs is REQUIRED on a tools/list result (R-16.2-g)")
    ttl_ms = data["ttlMs"]
    if "cacheScope" not in data:
      raise ValueError("cacheScope is REQUIRED on a tools/list result (R-16.2-j)")
    cache_scope = data["cacheScope"]

    if "resultType" not in data:
      raise ValueError("resultType is REQUIRED on a tools/list result (R-16.2-m)")
    result_type = data["resultType"]

    return cls(
      tools=tools,
      ttl_ms=ttl_ms,
      cache_scope=cache_scope,
      next_cursor=data.get("nextCursor"),
      result_type=result_type,
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields.

    ``resultType``, ``tools``, ``ttlMs``, and ``cacheScope`` are always present
    (all REQUIRED); ``nextCursor`` and ``_meta`` appear only when present.
    """
    out: dict[str, Any] = {
      "resultType": self.result_type,
      "tools": [t.to_dict() for t in self.tools],
      "ttlMs": self.ttl_ms,
      "cacheScope": self.cache_scope,
    }
    if self.next_cursor is not None:
      out["nextCursor"] = self.next_cursor
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


# ---------------------------------------------------------------------------
# §16.4  Validation roles  [R-16.4-o, R-16.4-p, R-16.4-q, R-16.4-r]
# ---------------------------------------------------------------------------

def validate_arguments_against_input_schema(
  tool: Tool,
  arguments: Any,
  *,
  resolution_mode: SchemaResolutionMode | None = None,
) -> bool:
  """Check a ``tools/call`` arguments object against ``tool.inputSchema`` (R-16.4-o).

  A server MUST validate any arguments object against the tool's ``inputSchema``
  before using it to execute the tool (R-16.4-o); a client applying argument
  validation locally MUST follow the same in-document-only ``$ref`` resolution
  rules (R-16.4-r) — enforced here by validating the schema's references with the
  default (in-document-only) resolution mode before checking the value. (The
  ``tools/call`` request that supplies these arguments is defined in S25.)

  Performs real JSON Schema 2020-12 evaluation of ``arguments`` against the
  tool's ``inputSchema`` — ``type``, ``required``, ``properties``,
  ``additionalProperties``, and the other keywords (see ``_json_schema_validate``)
  — returning False when the arguments do not conform (wrong type, missing
  required property, property barred by ``additionalProperties: false``, etc.) so
  a server never executes a tool with invalid arguments (R-16.4-o). References
  are resolved in-document only (R-16.4-r).

  Returns:
    True iff ``arguments`` conforms to the tool's ``inputSchema``.

  Raises:
    ExternalReferenceError: the schema depends on an unresolved external
      reference (R-16.4-r); validation MUST NOT silently treat it as permissive.
  """
  # R-16.4-r: apply the same in-document-only reference rules during local
  # validation. The default resolution_mode forbids external dereferencing.
  resolve_references(tool.input_schema, resolution_mode)
  # R-16.4-o: evaluate the arguments object against the full inputSchema.
  return _json_schema_validate(
    arguments, tool.input_schema, tool.input_schema, resolution_mode=resolution_mode
  )


def structured_content_conforms(
  tool: Tool,
  structured_content: Any,
  *,
  resolution_mode: SchemaResolutionMode | None = None,
) -> bool:
  """Check ``structuredContent`` against ``tool.outputSchema`` when present (R-16.4-p/q).

  When ``outputSchema`` is present a server MUST produce a ``structuredContent``
  value conforming to it (R-16.4-p), and a client SHOULD validate received
  ``structuredContent`` against it (R-16.4-q); local validation MUST use the same
  in-document-only ``$ref`` rules (R-16.4-r). (The ``CallToolResult`` carrying
  ``structuredContent`` is defined in S25.)

  When no ``outputSchema`` is declared, ``structuredContent`` MAY be any JSON
  value of any type (R-16.4-v), so this returns True. When an ``outputSchema``
  is present, its root ``type`` is unrestricted (R-16.4-e) and the value is
  evaluated against the full schema via real JSON Schema 2020-12 validation,
  with in-document-only ``$ref`` resolution (R-16.4-r).

  Returns:
    True iff the value conforms to the ``outputSchema`` (always True when no
    ``outputSchema`` is declared).

  Raises:
    ExternalReferenceError: the output schema depends on an unresolved external
      reference (R-16.4-r).
  """
  if tool.output_schema is None:
    # R-16.4-v: with no outputSchema, structuredContent MAY be any JSON value.
    return True
  # R-16.4-r: in-document-only reference rules during local validation.
  resolve_references(tool.output_schema, resolution_mode)
  # R-16.4-p/q: structuredContent MUST conform to the declared outputSchema.
  return _json_schema_validate(
    structured_content, tool.output_schema, tool.output_schema, resolution_mode=resolution_mode
  )


#: Maps a JSON Schema ``type`` keyword to the Python types that satisfy it.
_JSON_TYPE_PREDICATES: dict[str, Any] = {
  "object": lambda v: isinstance(v, dict),
  "array": lambda v: isinstance(v, list),
  "string": lambda v: isinstance(v, str),
  "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
  "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
  "boolean": lambda v: isinstance(v, bool),
  "null": lambda v: v is None,
}


def _value_matches_json_type(value: Any, declared_type: Any) -> bool:
  """Return True if ``value`` matches a JSON Schema ``type`` keyword (R-16.4-e/v).

  Supports both a single type string and the array-of-types form. An unknown
  type token is treated permissively (returns True) since deeper validation is
  the schema engine's responsibility.
  """
  if isinstance(declared_type, list):
    return any(_value_matches_json_type(value, t) for t in declared_type)
  predicate = _JSON_TYPE_PREDICATES.get(declared_type)
  if predicate is None:
    return True
  return predicate(value)


# ---------------------------------------------------------------------------
# §16.4  JSON Schema 2020-12 value validation  [R-16.4-o, R-16.4-p, R-16.4-r]
# ---------------------------------------------------------------------------
#
# A dependency-free evaluator for the JSON Schema 2020-12 keywords used by tool
# argument/output schemas. It is the engine behind R-16.4-o (a server MUST
# validate arguments against inputSchema) and R-16.4-p/q (structuredContent
# conforms to outputSchema). References are resolved in-document only, per the
# same rule R-16.4-r requires of local validation: a ``$ref`` whose target is
# outside the document is never fetched — it raises ExternalReferenceError —
# and an unresolved in-document ``$ref`` is rejected rather than treated as
# permissive (R-16.4-k).

#: Cap on validation recursion so a pathological recursive ``$ref`` cannot
#: exhaust the stack (R-16.4-l); finite data normally bounds depth well below.
_MAX_VALIDATION_DEPTH: int = 200


def _json_equal(a: Any, b: Any) -> bool:
  """JSON value equality for ``enum`` / ``const`` (distinguishes booleans from numbers).

  JSON treats ``true`` and ``1`` as distinct values; Python's ``True == 1`` would
  conflate them, so booleans only compare equal to booleans.
  """
  if isinstance(a, bool) or isinstance(b, bool):
    return type(a) is bool and type(b) is bool and a == b
  if isinstance(a, list) and isinstance(b, list):
    return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
  if isinstance(a, dict) and isinstance(b, dict):
    return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
  if isinstance(a, (int, float)) and isinstance(b, (int, float)):
    return a == b
  return type(a) is type(b) and a == b


def _find_anchor(node: Any, anchor: str) -> Any:
  """Find the in-document subschema declaring ``$anchor: anchor`` (R-16.4-f)."""
  if isinstance(node, dict):
    if node.get("$anchor") == anchor:
      return node
    for value in node.values():
      found = _find_anchor(value, anchor)
      if found is not None:
        return found
  elif isinstance(node, list):
    for item in node:
      found = _find_anchor(item, anchor)
      if found is not None:
        return found
  return None


def _resolve_in_document_ref(ref: str, root: Any) -> Any:
  """Resolve an in-document ``$ref`` (JSON Pointer or ``$anchor``) against ``root``.

  Returns the target subschema, or None when it does not resolve within the
  document (an unresolved in-document reference, rejected by the caller per
  R-16.4-k rather than treated as permissive).
  """
  if ref in ("#", ""):
    return root
  if ref.startswith("#/"):
    node: Any = root
    for raw in ref[2:].split("/"):
      token = raw.replace("~1", "/").replace("~0", "~")
      if isinstance(node, dict) and token in node:
        node = node[token]
      elif isinstance(node, list):
        try:
          node = node[int(token)]
        except (ValueError, IndexError):
          return None
      else:
        return None
    return node
  if ref.startswith("#"):
    return _find_anchor(root, ref[1:])
  return None


def _json_schema_validate(
  value: Any,
  schema: Any,
  root: Any,
  *,
  resolution_mode: SchemaResolutionMode | None = None,
  depth: int = 0,
) -> bool:
  """Validate ``value`` against a JSON Schema 2020-12 ``schema`` (R-16.4-o/p).

  Evaluates the structural and constraint keywords commonly used by tool
  schemas: ``type``, ``enum``, ``const``, object keywords (``properties``,
  ``required``, ``additionalProperties``, ``patternProperties``,
  ``min/maxProperties``), array keywords (``prefixItems``, ``items``,
  ``min/maxItems``), string keywords (``min/maxLength``, ``pattern``), numeric
  keywords (``minimum``/``maximum``/exclusive bounds, ``multipleOf``), and the
  ``allOf``/``anyOf``/``oneOf``/``not`` combinators. ``$ref`` is resolved
  in-document only (R-16.4-r); an external ``$ref`` raises ExternalReferenceError
  unless an opt-in external mode is configured (R-16.4-h).

  Returns True iff the value conforms.

  Raises:
    ExternalReferenceError: a ``$ref`` targets outside the document while
      external dereferencing is disabled (R-16.4-r).
    UnsafeSchemaError: validation recursion exceeds the safety bound (R-16.4-l).
  """
  if depth > _MAX_VALIDATION_DEPTH:
    raise UnsafeSchemaError(
      "validation_depth_exceeded",
      f"value validation recursion exceeds the bound of {_MAX_VALIDATION_DEPTH} (R-16.4-l)",
    )
  # Boolean schemas: ``true`` accepts anything, ``false`` rejects everything.
  if schema is True:
    return True
  if schema is False:
    return False
  if not isinstance(schema, dict):
    return True  # not a schema object — nothing to assert

  # $ref — resolve in-document; external refs are never fetched (R-16.4-f/r).
  ref = schema.get("$ref")
  if isinstance(ref, str):
    if reference_is_in_document(ref):
      target = _resolve_in_document_ref(ref, root)
      if target is None:
        return False  # unresolved in-document ref → reject (R-16.4-k)
      if not _json_schema_validate(
        value, target, root, resolution_mode=resolution_mode, depth=depth + 1
      ):
        return False
    elif resolution_mode is None or not resolution_mode.allow_external:
      raise ExternalReferenceError(ref)
    # else: opt-in external mode is configured but this SDK performs no fetch,
    # so the external target cannot be evaluated locally and is not asserted.

  # type
  declared_type = schema.get("type")
  if declared_type is not None and not _value_matches_json_type(value, declared_type):
    return False

  # enum / const
  if "enum" in schema and not any(_json_equal(value, e) for e in schema["enum"]):
    return False
  if "const" in schema and not _json_equal(value, schema["const"]):
    return False

  # object keywords
  if isinstance(value, dict):
    if not _validate_object_keywords(value, schema, root, resolution_mode, depth):
      return False

  # array keywords
  if isinstance(value, list):
    if not _validate_array_keywords(value, schema, root, resolution_mode, depth):
      return False

  # string keywords
  if isinstance(value, str):
    min_len = schema.get("minLength")
    max_len = schema.get("maxLength")
    if isinstance(min_len, int) and len(value) < min_len:
      return False
    if isinstance(max_len, int) and len(value) > max_len:
      return False
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and re.search(pattern, value) is None:
      return False

  # numeric keywords (booleans are not numbers in JSON Schema)
  if isinstance(value, (int, float)) and not isinstance(value, bool):
    if not _validate_numeric_keywords(value, schema):
      return False

  # combinators
  for sub in schema.get("allOf", []) or []:
    if not _json_schema_validate(value, sub, root, resolution_mode=resolution_mode, depth=depth + 1):
      return False
  if "anyOf" in schema and not any(
    _json_schema_validate(value, sub, root, resolution_mode=resolution_mode, depth=depth + 1)
    for sub in schema["anyOf"]
  ):
    return False
  if "oneOf" in schema:
    matches = sum(
      1
      for sub in schema["oneOf"]
      if _json_schema_validate(value, sub, root, resolution_mode=resolution_mode, depth=depth + 1)
    )
    if matches != 1:
      return False
  if "not" in schema and _json_schema_validate(
    value, schema["not"], root, resolution_mode=resolution_mode, depth=depth + 1
  ):
    return False

  return True


def _validate_object_keywords(
  value: dict[str, Any],
  schema: dict[str, Any],
  root: Any,
  resolution_mode: SchemaResolutionMode | None,
  depth: int,
) -> bool:
  """Apply the object-applicator keywords (``required``/``properties``/etc.)."""
  for name in schema.get("required", []) or []:
    if name not in value:
      return False  # missing required property (R-16.4-o)

  properties = schema.get("properties")
  properties = properties if isinstance(properties, dict) else {}
  pattern_properties = schema.get("patternProperties")
  pattern_properties = pattern_properties if isinstance(pattern_properties, dict) else {}
  additional = schema.get("additionalProperties", True)

  for key, item in value.items():
    handled = False
    if key in properties:
      handled = True
      if not _json_schema_validate(
        item, properties[key], root, resolution_mode=resolution_mode, depth=depth + 1
      ):
        return False
    for pattern, subschema in pattern_properties.items():
      if re.search(pattern, key) is not None:
        handled = True
        if not _json_schema_validate(
          item, subschema, root, resolution_mode=resolution_mode, depth=depth + 1
        ):
          return False
    if not handled:
      if additional is False:
        return False  # extra property barred by additionalProperties:false
      if isinstance(additional, dict) and not _json_schema_validate(
        item, additional, root, resolution_mode=resolution_mode, depth=depth + 1
      ):
        return False

  min_props = schema.get("minProperties")
  max_props = schema.get("maxProperties")
  if isinstance(min_props, int) and len(value) < min_props:
    return False
  if isinstance(max_props, int) and len(value) > max_props:
    return False
  return True


def _validate_array_keywords(
  value: list[Any],
  schema: dict[str, Any],
  root: Any,
  resolution_mode: SchemaResolutionMode | None,
  depth: int,
) -> bool:
  """Apply the array-applicator keywords (``prefixItems``/``items``/etc.)."""
  prefix = schema.get("prefixItems")
  if isinstance(prefix, list):
    for i, subschema in enumerate(prefix):
      if i < len(value) and not _json_schema_validate(
        value[i], subschema, root, resolution_mode=resolution_mode, depth=depth + 1
      ):
        return False
    remainder = value[len(prefix):]
  else:
    remainder = value

  items = schema.get("items")
  if items is False:
    if remainder:
      return False
  elif isinstance(items, dict):
    for element in remainder:
      if not _json_schema_validate(
        element, items, root, resolution_mode=resolution_mode, depth=depth + 1
      ):
        return False

  min_items = schema.get("minItems")
  max_items = schema.get("maxItems")
  if isinstance(min_items, int) and len(value) < min_items:
    return False
  if isinstance(max_items, int) and len(value) > max_items:
    return False
  return True


def _validate_numeric_keywords(value: int | float, schema: dict[str, Any]) -> bool:
  """Apply the numeric-constraint keywords (bounds and ``multipleOf``)."""
  minimum = schema.get("minimum")
  maximum = schema.get("maximum")
  exclusive_min = schema.get("exclusiveMinimum")
  exclusive_max = schema.get("exclusiveMaximum")
  if isinstance(minimum, (int, float)) and not isinstance(minimum, bool) and value < minimum:
    return False
  if isinstance(maximum, (int, float)) and not isinstance(maximum, bool) and value > maximum:
    return False
  if isinstance(exclusive_min, (int, float)) and not isinstance(exclusive_min, bool) and value <= exclusive_min:
    return False
  if isinstance(exclusive_max, (int, float)) and not isinstance(exclusive_max, bool) and value >= exclusive_max:
    return False
  multiple_of = schema.get("multipleOf")
  if isinstance(multiple_of, (int, float)) and not isinstance(multiple_of, bool) and multiple_of > 0:
    quotient = value / multiple_of
    if abs(quotient - round(quotient)) > 1e-9:
      return False
  return True


# ---------------------------------------------------------------------------
# §16  Model-control & human oversight  [R-16-a]
# ---------------------------------------------------------------------------

def human_can_deny_invocation(*, can_deny: bool) -> bool:
  """Return whether a human-in-the-loop can deny a tool invocation (R-16-a).

  The protocol mandates no particular user-interaction model, but for trust,
  safety, and security there SHOULD always be a human in the loop able to deny a
  tool invocation (R-16-a). This helper simply surfaces a host's policy flag so
  callers and conformance tests can assert the safeguard exists; a conforming
  host SHOULD pass ``can_deny=True``.
  """
  return can_deny
