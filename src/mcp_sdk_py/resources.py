"""Resources I: Capability, Listing, Templates & Types — S26.

Delivers the discovery surface for **resources** — server-provided units of
context (files, database schemas, documents, or any application-specific data)
that a client may find and later read to supply context to a language model.

This story owns:
  - ``ResourcesServerCapability``: the value of the ``resources`` key inside a
    server's capabilities object, carrying the OPTIONAL boolean sub-flags
    ``listChanged`` and ``subscribe`` (§17.1).
  - ``Resource`` and ``ResourceTemplate``: the two data types describing a
    concrete readable resource and a parameterized URI-Template family (§17.4).
  - ``ListResourcesRequest`` / ``ListResourcesResult`` and
    ``ListResourceTemplatesRequest`` / ``ListResourceTemplatesResult``: the two
    paginated, cacheable discovery exchanges (§17.2, §17.3).
  - The capability-gating predicates that bind capability declaration to which
    requests a server may accept and which notifications it may emit (§17.1).

It REUSES rather than re-implements earlier-wave types:
  - ``BaseMetadata`` / ``Icon`` (S20, common_types) for ``name``/``title``/``icons``.
  - ``Annotations`` (S21, content_types) for the ``annotations`` hints.
  - ``ServerCapabilities`` (S10, capabilities) for capability-presence gating.
  - ``PaginatedRequestParams`` / pagination helpers (S18, pagination) for the
    ``cursor``/``nextCursor`` mechanics shared by both list methods.
  - ``CacheableResult`` constants/validation (S19, caching) for ``ttlMs`` and
    ``cacheScope``, and ``RESULT_TYPE_COMPLETE`` (S04) for ``resultType``.

Out of scope (owned elsewhere): ``resources/read`` and reading contents,
resource-not-found errors, subscription mechanics and the
``notifications/resources/*`` payloads, and common-URI-scheme catalogs — all
S27 (Resources II).

Spec: §17.1–§17.4
Depends on: S10 (capability gating), S18 (pagination), S19 (caching),
            S20 (BaseMetadata/Icon), S21 (Annotations)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.caching import VALID_CACHE_SCOPES, is_valid_ttl_ms
from mcp_sdk_py.capabilities import ServerCapabilities, capability_is_present
from mcp_sdk_py.common_types import BaseMetadata, Icon
from mcp_sdk_py.content_types import Annotations
from mcp_sdk_py.pagination import PaginatedRequestParams
from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE, ResultType


# ---------------------------------------------------------------------------
# §17  Method-name constants
# ---------------------------------------------------------------------------

#: Method name for the paginated resource-discovery request (§17.2).
METHOD_RESOURCES_LIST: str = "resources/list"

#: Method name for the paginated resource-template-discovery request (§17.3).
METHOD_RESOURCES_TEMPLATES_LIST: str = "resources/templates/list"

#: The ``resources/read`` request (defined in S27) — named here only because
#: capability gating (R-17.1-h/j) governs all three resource requests together.
METHOD_RESOURCES_READ: str = "resources/read"

#: The notification a server MAY emit when its available-resource set changes.
#: Gated on the ``listChanged`` sub-flag (R-17.1-d/k); payload owned by S27.
NOTIFICATION_RESOURCES_LIST_CHANGED: str = "notifications/resources/list_changed"

#: The per-resource update notification a ``subscribe``-declaring server supports.
#: Gated on the ``subscribe`` sub-flag (R-17.1-e/l); payload owned by S27.
NOTIFICATION_RESOURCES_UPDATED: str = "notifications/resources/updated"

#: The three requests a server MUST NOT accept, and a client MUST NOT issue,
#: unless the ``resources`` capability is declared (R-17.1-h/j).
RESOURCE_GATED_REQUESTS: frozenset[str] = frozenset({
  METHOD_RESOURCES_LIST,
  METHOD_RESOURCES_TEMPLATES_LIST,
  METHOD_RESOURCES_READ,
})


# ---------------------------------------------------------------------------
# §17.1  ResourcesServerCapability  [R-17.1-a–g]
# ---------------------------------------------------------------------------

@dataclass
class ResourcesServerCapability:
  """The value of the ``resources`` key in a server's capabilities object (§17.1).

  Presence of this object (even empty) declares the ``resources`` feature; a
  server exposing no resources omits the key entirely (R-17.1-a, AC-26.1). The
  object carries two OPTIONAL boolean sub-flags, each declaring an optional
  notification behavior only when set to ``true`` (R-17.1-b/c/e):

    - ``listChanged``: when ``true``, the server MAY emit
      ``notifications/resources/list_changed`` when the available-resource set
      changes (R-17.1-c/d).
    - ``subscribe``: when ``true``, the server supports per-resource
      ``notifications/resources/updated`` for resources a client subscribes to
      (R-17.1-e).

  A server MAY advertise either sub-flag independently, both, or neither, and an
  empty object ``{}`` is a valid declaration carrying neither (R-17.1-f/g,
  AC-26.2). The fields are ``None`` when absent; only an explicit ``True``
  enables the corresponding behavior.
  """

  list_changed: bool | None = None  # R-17.1-c: JSON key "listChanged"
  subscribe: bool | None = None     # R-17.1-e: JSON key "subscribe"

  def __post_init__(self) -> None:
    if self.list_changed is not None and not isinstance(self.list_changed, bool):
      raise TypeError(
        "ResourcesServerCapability.listChanged must be a boolean when present "
        "(R-17.1-c)"
      )
    if self.subscribe is not None and not isinstance(self.subscribe, bool):
      raise TypeError(
        "ResourcesServerCapability.subscribe must be a boolean when present "
        "(R-17.1-e)"
      )

  @property
  def supports_list_changed(self) -> bool:
    """True only when ``listChanged`` is explicitly ``true`` (R-17.1-c/d, AC-26.3).

    The server MUST NOT emit ``notifications/resources/list_changed`` unless
    this returns True (R-17.1-k).
    """
    return self.list_changed is True

  @property
  def supports_subscribe(self) -> bool:
    """True only when ``subscribe`` is explicitly ``true`` (R-17.1-e, AC-26.3).

    The server MUST NOT emit ``notifications/resources/updated`` unless this
    returns True (R-17.1-l).
    """
    return self.subscribe is True

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "ResourcesServerCapability":
    """Parse the ``resources`` capability object from a wire dict (§17.1).

    An empty object ``{}`` is valid and declares neither sub-flag (R-17.1-g).
    Sub-flags MUST be booleans when present (R-17.1-c/e). Unknown keys are
    ignored for forward compatibility.

    Raises:
      TypeError: ``data`` is not a dict, or a sub-flag is a non-boolean.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"resources capability must be a JSON object; got {type(data).__name__} "
        f"(R-17.1-b)"
      )
    return cls(
      list_changed=data.get("listChanged"),
      subscribe=data.get("subscribe"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire dict; omits absent sub-flags (R-17.1-g).

    A capability with neither sub-flag serialises to an empty object ``{}``.
    """
    out: dict[str, Any] = {}
    if self.list_changed is not None:
      out["listChanged"] = self.list_changed
    if self.subscribe is not None:
      out["subscribe"] = self.subscribe
    return out


# ---------------------------------------------------------------------------
# §17.1  Capability gating predicates  [R-17.1-h–l]
# ---------------------------------------------------------------------------

def resources_capability_declared(server_caps: ServerCapabilities) -> bool:
  """True if the server declared the ``resources`` capability (R-17.1-a, §6.1).

  Presence — even of an empty ``{}`` — means the feature is supported (S10).
  This is the single gate that opens the three resource requests and the two
  notifications (R-17.1-h/i/j, AC-26.4).
  """
  return capability_is_present(server_caps.to_dict(), "resources")


def server_may_accept_request(server_caps: ServerCapabilities, method: str) -> bool:
  """True if the server may accept ``method`` given its declared capabilities.

  A server MUST NOT accept ``resources/list``, ``resources/templates/list``, or
  ``resources/read`` unless it declared ``resources`` (R-17.1-h, AC-26.4). Any
  method outside that gated set is not governed by this story and returns True.
  """
  if method not in RESOURCE_GATED_REQUESTS:
    return True
  return resources_capability_declared(server_caps)


def client_may_issue_request(server_caps: ServerCapabilities, method: str) -> bool:
  """True if a conformant client may issue ``method`` against this server.

  A client MUST NOT issue ``resources/list``, ``resources/templates/list``, or
  ``resources/read`` unless the server declared ``resources`` (R-17.1-j,
  AC-26.4). Mirrors :func:`server_may_accept_request` from the client side.
  """
  if method not in RESOURCE_GATED_REQUESTS:
    return True
  return resources_capability_declared(server_caps)


def _resources_subcapability(server_caps: ServerCapabilities) -> ResourcesServerCapability | None:
  """Return the parsed ``resources`` sub-capability, or None when undeclared."""
  raw = server_caps.resources
  if raw is None:
    return None
  return ResourcesServerCapability.from_dict(raw)


def server_may_emit_list_changed(server_caps: ServerCapabilities) -> bool:
  """True if the server may emit ``notifications/resources/list_changed``.

  Requires BOTH that ``resources`` is declared (R-17.1-i) and that the
  ``listChanged`` sub-flag is ``true`` (R-17.1-k, AC-26.5). When ``resources``
  is undeclared this is False even if a stray sub-flag value is present.
  """
  sub = _resources_subcapability(server_caps)
  if sub is None:
    return False
  return sub.supports_list_changed


def server_may_emit_updated(server_caps: ServerCapabilities) -> bool:
  """True if the server may emit ``notifications/resources/updated``.

  Requires BOTH that ``resources`` is declared (R-17.1-i) and that the
  ``subscribe`` sub-flag is ``true`` (R-17.1-l, AC-26.5).
  """
  sub = _resources_subcapability(server_caps)
  if sub is None:
    return False
  return sub.supports_subscribe


# ---------------------------------------------------------------------------
# §17.4  Resource  [R-17.4-a–l]
# ---------------------------------------------------------------------------

@dataclass
class Resource:
  """A concrete, directly readable unit of context identified by a URI (§17.4).

  Composes ``BaseMetadata`` (``name``/``title``, S20) and the icon field set
  (S20). ``uri`` and ``name`` are REQUIRED; everything else is OPTIONAL
  (AC-26.13).

  Fields:
    uri: REQUIRED RFC3986 URI uniquely identifying the resource; MAY use any
      scheme, server-defined meaning (R-17.4-a/b).
    name: REQUIRED programmatic identifier, from BaseMetadata (R-17.4-c).
    title: OPTIONAL human-readable display name, from BaseMetadata (R-17.4-d).
      Use :meth:`display_name` for the title→name preference (R-17.4-e).
    description: OPTIONAL prose hint to the model (R-17.4-f).
    mime_type: OPTIONAL MIME type of the content; JSON key ``mimeType``
      (R-17.4-g).
    size: OPTIONAL raw-content byte count measured BEFORE base64 encoding or
      tokenization; hosts MAY use it for file sizes and context estimation
      (R-17.4-h/i, AC-26.14).
    annotations: OPTIONAL ``Annotations`` hints, e.g. audience/priority/
      lastModified (R-17.4-j).
    icons: OPTIONAL list of ``Icon`` for UI display (R-17.4-k).
    meta: OPTIONAL reserved metadata map; JSON key ``_meta`` (R-17.4-l).
  """

  uri: str                                # R-17.4-a: REQUIRED
  name: str                               # R-17.4-c: REQUIRED (BaseMetadata)
  title: str | None = None                # R-17.4-d: OPTIONAL (BaseMetadata)
  description: str | None = None          # R-17.4-f: OPTIONAL
  mime_type: str | None = None            # R-17.4-g: OPTIONAL; JSON: mimeType
  size: float | None = None               # R-17.4-h: OPTIONAL; bytes pre-base64
  annotations: Annotations | None = None  # R-17.4-j: OPTIONAL
  icons: list[Icon] | None = None         # R-17.4-k: OPTIONAL
  meta: dict[str, Any] | None = None      # R-17.4-l: OPTIONAL; JSON: _meta

  def __post_init__(self) -> None:
    if not isinstance(self.uri, str) or not self.uri:
      raise ValueError(
        "Resource.uri is REQUIRED and must be a non-empty string (R-17.4-a)"
      )
    # Validate name/title via BaseMetadata so the identity contract (R-14.1)
    # and the REQUIRED-name rule (R-17.4-c) are enforced consistently.
    BaseMetadata(name=self.name, title=self.title)
    if self.description is not None and not isinstance(self.description, str):
      raise TypeError("Resource.description must be a string when present (R-17.4-f)")
    if self.mime_type is not None and not isinstance(self.mime_type, str):
      raise TypeError("Resource.mimeType must be a string when present (R-17.4-g)")
    if self.size is not None:
      if isinstance(self.size, bool) or not isinstance(self.size, (int, float)):
        raise TypeError("Resource.size must be a number when present (R-17.4-h)")
      if self.size < 0:
        raise ValueError("Resource.size must be non-negative when present (R-17.4-h)")
    if self.annotations is not None and not isinstance(self.annotations, Annotations):
      raise TypeError(
        "Resource.annotations must be an Annotations object when present (R-17.4-j)"
      )
    if self.icons is not None:
      if not isinstance(self.icons, list):
        raise TypeError("Resource.icons must be a list when present (R-17.4-k)")
      for entry in self.icons:
        if not isinstance(entry, Icon):
          raise TypeError(
            f"Resource.icons entries must be Icon objects; got {entry!r} (R-17.4-k)"
          )

  def display_name(self) -> str:
    """Resolve the user-facing label: prefer ``title``, fall back to ``name`` (R-17.4-e)."""
    return self.title if self.title is not None else self.name

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "Resource":
    """Deserialise a ``Resource`` from a JSON-decoded dict (§17.4).

    Nested ``annotations`` and ``icons`` are converted to their typed objects;
    unknown keys are ignored for forward compatibility.

    Raises:
      TypeError: ``data`` is not a dict.
      KeyError/ValueError: a REQUIRED field is missing or invalid.
    """
    if not isinstance(data, dict):
      raise TypeError(f"Resource must be a JSON object; got {type(data).__name__}")
    raw_ann = data.get("annotations")
    raw_icons = data.get("icons")
    return cls(
      uri=data["uri"],
      name=data["name"],
      title=data.get("title"),
      description=data.get("description"),
      mime_type=data.get("mimeType"),
      size=data.get("size"),
      annotations=Annotations.from_dict(raw_ann) if raw_ann is not None else None,
      icons=[Icon.from_dict(i) for i in raw_icons] if raw_icons is not None else None,
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields (§17.4)."""
    result: dict[str, Any] = {"uri": self.uri, "name": self.name}
    if self.title is not None:
      result["title"] = self.title
    if self.description is not None:
      result["description"] = self.description
    if self.mime_type is not None:
      result["mimeType"] = self.mime_type
    if self.size is not None:
      result["size"] = self.size
    if self.annotations is not None:
      result["annotations"] = self.annotations.to_dict()
    if self.icons is not None:
      result["icons"] = [i.to_dict() for i in self.icons]
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


# ---------------------------------------------------------------------------
# §17.4  ResourceTemplate  [R-17.4-m–u]
# ---------------------------------------------------------------------------

@dataclass
class ResourceTemplate:
  """A family of resources whose URIs come from expanding a URI Template (§17.4).

  Composes ``BaseMetadata`` and the icon field set, like ``Resource``, but
  carries ``uriTemplate`` instead of ``uri`` and has **no** ``size`` field —
  size is a property of a concrete resource, not of a template (R-17.4-u,
  AC-26.16).

  Fields:
    uri_template: REQUIRED RFC6570 URI Template with ``{…}`` variable
      expressions; the client expands it into a concrete ``uri`` for
      ``resources/read``. Variable values MAY come from the user, computation,
      or the completion mechanism (R-17.4-m/n, AC-26.15). JSON key
      ``uriTemplate``.
    name: REQUIRED programmatic identifier, from BaseMetadata (R-17.4-o).
    title: OPTIONAL display name, from BaseMetadata (R-17.4-p).
    description: OPTIONAL prose hint to the model (R-17.4-q).
    mime_type: OPTIONAL MIME type shared by ALL resources matching the
      template; SHOULD be set only when every match shares it (R-17.4-r/s).
      JSON key ``mimeType``.
    annotations: OPTIONAL ``Annotations`` hints, as for ``Resource`` (R-17.4-t).
    icons: OPTIONAL list of ``Icon``, as for ``Resource`` (R-17.4-t).
    meta: OPTIONAL reserved metadata map; JSON key ``_meta`` (R-17.4-t).
  """

  uri_template: str                       # R-17.4-m: REQUIRED; JSON: uriTemplate
  name: str                               # R-17.4-o: REQUIRED (BaseMetadata)
  title: str | None = None                # R-17.4-p: OPTIONAL (BaseMetadata)
  description: str | None = None          # R-17.4-q: OPTIONAL
  mime_type: str | None = None            # R-17.4-r: OPTIONAL; JSON: mimeType
  annotations: Annotations | None = None  # R-17.4-t: OPTIONAL
  icons: list[Icon] | None = None         # R-17.4-t: OPTIONAL
  meta: dict[str, Any] | None = None      # R-17.4-t: OPTIONAL; JSON: _meta

  def __post_init__(self) -> None:
    if not isinstance(self.uri_template, str) or not self.uri_template:
      raise ValueError(
        "ResourceTemplate.uriTemplate is REQUIRED and must be a non-empty "
        "string (R-17.4-m)"
      )
    BaseMetadata(name=self.name, title=self.title)  # R-17.4-o/p
    if self.description is not None and not isinstance(self.description, str):
      raise TypeError(
        "ResourceTemplate.description must be a string when present (R-17.4-q)"
      )
    if self.mime_type is not None and not isinstance(self.mime_type, str):
      raise TypeError(
        "ResourceTemplate.mimeType must be a string when present (R-17.4-r)"
      )
    if self.annotations is not None and not isinstance(self.annotations, Annotations):
      raise TypeError(
        "ResourceTemplate.annotations must be an Annotations object when "
        "present (R-17.4-t)"
      )
    if self.icons is not None:
      if not isinstance(self.icons, list):
        raise TypeError("ResourceTemplate.icons must be a list when present (R-17.4-t)")
      for entry in self.icons:
        if not isinstance(entry, Icon):
          raise TypeError(
            f"ResourceTemplate.icons entries must be Icon objects; got {entry!r} "
            f"(R-17.4-t)"
          )

  def display_name(self) -> str:
    """Resolve the user-facing label: prefer ``title``, fall back to ``name`` (R-17.4-p)."""
    return self.title if self.title is not None else self.name

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "ResourceTemplate":
    """Deserialise a ``ResourceTemplate`` from a JSON-decoded dict (§17.4).

    Has no ``size`` field; any ``size`` key on the wire is ignored as an unknown
    member rather than read (R-17.4-u). Unknown keys are ignored.

    Raises:
      TypeError: ``data`` is not a dict.
      KeyError/ValueError: a REQUIRED field is missing or invalid.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ResourceTemplate must be a JSON object; got {type(data).__name__}"
      )
    raw_ann = data.get("annotations")
    raw_icons = data.get("icons")
    return cls(
      uri_template=data["uriTemplate"],
      name=data["name"],
      title=data.get("title"),
      description=data.get("description"),
      mime_type=data.get("mimeType"),
      annotations=Annotations.from_dict(raw_ann) if raw_ann is not None else None,
      icons=[Icon.from_dict(i) for i in raw_icons] if raw_icons is not None else None,
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields (§17.4).

    Never emits a ``size`` key — a template has no size (R-17.4-u).
    """
    result: dict[str, Any] = {"uriTemplate": self.uri_template, "name": self.name}
    if self.title is not None:
      result["title"] = self.title
    if self.description is not None:
      result["description"] = self.description
    if self.mime_type is not None:
      result["mimeType"] = self.mime_type
    if self.annotations is not None:
      result["annotations"] = self.annotations.to_dict()
    if self.icons is not None:
      result["icons"] = [i.to_dict() for i in self.icons]
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


# ---------------------------------------------------------------------------
# §17.2 / §17.3  List request params  [R-17.2-a, R-17.2-i, R-17.3-a]
# ---------------------------------------------------------------------------

@dataclass
class ListResourcesRequestParams(PaginatedRequestParams):
  """``params`` for a ``resources/list`` request (§17.2).

  Extends the paginated-request shape (S18): ``cursor`` is OPTIONAL (R-17.2-a)
  and ``_meta`` (``meta``) is OPTIONAL (R-17.2-i, AC-26.8). No additional
  members are defined by this method. The client MUST treat any ``cursor`` as
  opaque (R-17.2-d/e); construct one only by passing back a server-issued
  ``nextCursor`` verbatim.
  """

  @classmethod
  def from_dict(cls, raw: dict[str, Any]) -> "ListResourcesRequestParams":
    """Parse list-request params from a wire dict; both fields are optional (R-17.2-a/i)."""
    if not isinstance(raw, dict):
      raise TypeError(
        f"resources/list params must be a JSON object; got {type(raw).__name__}"
      )
    cursor = raw.get("cursor")
    if cursor is not None and not isinstance(cursor, str):
      raise TypeError(f"cursor must be a string when present; got {type(cursor).__name__}")
    meta = raw.get("_meta")
    if meta is not None and not isinstance(meta, dict):
      raise TypeError(f"_meta must be an object when present; got {type(meta).__name__}")
    extra = {k: v for k, v in raw.items() if k not in {"cursor", "_meta"}}
    return cls(cursor=cursor, meta=meta, extra=extra)


@dataclass
class ListResourceTemplatesRequestParams(PaginatedRequestParams):
  """``params`` for a ``resources/templates/list`` request (§17.3).

  Identical in shape to :class:`ListResourcesRequestParams`: ``cursor`` and
  ``_meta`` are both OPTIONAL; the request is paginated and cacheable
  (R-17.3-a, AC-26.12).
  """

  @classmethod
  def from_dict(cls, raw: dict[str, Any]) -> "ListResourceTemplatesRequestParams":
    """Parse template-list-request params from a wire dict; both fields optional (R-17.3-a)."""
    if not isinstance(raw, dict):
      raise TypeError(
        f"resources/templates/list params must be a JSON object; "
        f"got {type(raw).__name__}"
      )
    cursor = raw.get("cursor")
    if cursor is not None and not isinstance(cursor, str):
      raise TypeError(f"cursor must be a string when present; got {type(cursor).__name__}")
    meta = raw.get("_meta")
    if meta is not None and not isinstance(meta, dict):
      raise TypeError(f"_meta must be an object when present; got {type(meta).__name__}")
    extra = {k: v for k, v in raw.items() if k not in {"cursor", "_meta"}}
    return cls(cursor=cursor, meta=meta, extra=extra)


# ---------------------------------------------------------------------------
# §17.2  ListResourcesResult  [R-17.2-b–j]
# ---------------------------------------------------------------------------

def _validate_list_result_caching(
  result_type: ResultType,
  ttl_ms: int,
  cache_scope: str,
  *,
  context: str,
) -> None:
  """Validate the shared resultType/ttlMs/cacheScope contract of a list result.

  - ``resultType`` is REQUIRED; for a list result it is ``"complete"``
    (R-17.2-f, R-17.3-c).
  - ``ttlMs`` is REQUIRED and MUST be a non-negative integer (R-17.2-g).
  - ``cacheScope`` is REQUIRED and MUST be exactly ``"public"`` or ``"private"``
    (R-17.2-h).

  Raises:
    TypeError/ValueError: any caching field is missing or out of contract.
  """
  if not isinstance(result_type, str) or not result_type:
    raise ValueError(f"{context}.resultType is REQUIRED (R-17.2-f)")
  if result_type != RESULT_TYPE_COMPLETE:
    raise ValueError(
      f"{context}.resultType for a list result MUST be {RESULT_TYPE_COMPLETE!r}; "
      f"got {result_type!r} (R-17.2-f)"
    )
  if not is_valid_ttl_ms(ttl_ms):
    raise ValueError(
      f"{context}.ttlMs is REQUIRED and must be a non-negative integer; "
      f"got {ttl_ms!r} (R-17.2-g)"
    )
  if cache_scope not in VALID_CACHE_SCOPES:
    raise ValueError(
      f"{context}.cacheScope is REQUIRED and must be exactly 'public' or "
      f"'private'; got {cache_scope!r} (R-17.2-h)"
    )


@dataclass
class ListResourcesResult:
  """Server response to ``resources/list`` (§17.2).

  Is both a paginated result (S18) and a cacheable result (S19). Carries the
  REQUIRED ``resources`` array (MAY be empty), an OPTIONAL ``nextCursor`` whose
  absence means the listing is complete, and the REQUIRED caching trio
  ``resultType``/``ttlMs``/``cacheScope`` (AC-26.9, AC-26.10).

  A server MUST NOT assume the client has seen any particular page; each result
  stands alone (R-17.2-j, AC-26.11). The ``resources`` set is the set currently
  available to the requesting client and MUST NOT vary per-connection or as a
  side effect of other requests, though it MAY vary by per-request
  authorization (R-17.1-m/n/o/p, AC-26.6, AC-26.7).

  Fields:
    resources: REQUIRED list of ``Resource``; MAY be empty (R-17.2-b).
    next_cursor: OPTIONAL opaque next-page cursor; JSON key ``nextCursor``.
      Absent ⇒ listing complete (R-17.2-c). The client MUST pass it back
      verbatim and MUST NOT parse or construct it (R-17.2-d/e).
    result_type: REQUIRED discriminator, ``"complete"`` for a list (R-17.2-f).
      JSON key ``resultType``.
    ttl_ms: REQUIRED non-negative cache TTL in ms; JSON key ``ttlMs`` (R-17.2-g).
    cache_scope: REQUIRED ``"public"``/``"private"``; JSON key ``cacheScope``
      (R-17.2-h).
    meta: OPTIONAL reserved metadata map; JSON key ``_meta`` (R-17.2-i).
  """

  resources: list[Resource]
  ttl_ms: int
  cache_scope: str
  next_cursor: str | None = None
  result_type: ResultType = RESULT_TYPE_COMPLETE
  meta: dict[str, Any] | None = None

  def __post_init__(self) -> None:
    if not isinstance(self.resources, list):
      raise TypeError(
        "ListResourcesResult.resources is REQUIRED and must be a list (R-17.2-b)"
      )
    for entry in self.resources:
      if not isinstance(entry, Resource):
        raise TypeError(
          f"ListResourcesResult.resources entries must be Resource objects; "
          f"got {entry!r} (R-17.2-b)"
        )
    if self.next_cursor is not None and not isinstance(self.next_cursor, str):
      raise TypeError(
        "ListResourcesResult.nextCursor must be a string when present (R-17.2-c)"
      )
    _validate_list_result_caching(
      self.result_type, self.ttl_ms, self.cache_scope, context="ListResourcesResult"
    )

  @property
  def is_last_page(self) -> bool:
    """True when ``nextCursor`` is absent — this is the final page (R-17.2-c)."""
    return self.next_cursor is None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "ListResourcesResult":
    """Deserialise a ``ListResourcesResult`` from a JSON-decoded dict (§17.2).

    Validates the REQUIRED ``resources`` array and the REQUIRED caching trio.
    A conformant client passes ``nextCursor`` back verbatim and never parses it
    (R-17.2-d/e).

    Raises:
      TypeError: ``data`` is not a dict or a field has the wrong type.
      ValueError: a REQUIRED field is missing or out of contract.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ListResourcesResult must be a JSON object; got {type(data).__name__}"
      )
    if "resources" not in data:
      raise ValueError("ListResourcesResult.resources is REQUIRED (R-17.2-b)")
    raw_resources = data["resources"]
    if not isinstance(raw_resources, list):
      raise TypeError("ListResourcesResult.resources must be an array (R-17.2-b)")
    if "ttlMs" not in data:
      raise ValueError("ListResourcesResult.ttlMs is REQUIRED (R-17.2-g)")
    if "cacheScope" not in data:
      raise ValueError("ListResourcesResult.cacheScope is REQUIRED (R-17.2-h)")
    return cls(
      resources=[Resource.from_dict(r) for r in raw_resources],
      ttl_ms=data["ttlMs"],
      cache_scope=data["cacheScope"],
      next_cursor=data.get("nextCursor"),
      result_type=data.get("resultType", RESULT_TYPE_COMPLETE),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields (§17.2)."""
    out: dict[str, Any] = {
      "resources": [r.to_dict() for r in self.resources],
      "resultType": self.result_type,
      "ttlMs": self.ttl_ms,
      "cacheScope": self.cache_scope,
    }
    if self.next_cursor is not None:
      out["nextCursor"] = self.next_cursor
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


# ---------------------------------------------------------------------------
# §17.3  ListResourceTemplatesResult  [R-17.3-b, R-17.3-c]
# ---------------------------------------------------------------------------

@dataclass
class ListResourceTemplatesResult:
  """Server response to ``resources/templates/list`` (§17.3).

  Paginated (S18) and cacheable (S19); the pagination and caching fields behave
  exactly as in :class:`ListResourcesResult` (R-17.3-c, AC-26.12). Carries the
  REQUIRED ``resourceTemplates`` array (MAY be empty).

  Fields:
    resource_templates: REQUIRED list of ``ResourceTemplate``; MAY be empty
      (R-17.3-b). JSON key ``resourceTemplates``.
    next_cursor: OPTIONAL opaque next-page cursor; JSON key ``nextCursor``.
    result_type: REQUIRED ``"complete"`` discriminator; JSON key ``resultType``.
    ttl_ms: REQUIRED non-negative cache TTL in ms; JSON key ``ttlMs``.
    cache_scope: REQUIRED ``"public"``/``"private"``; JSON key ``cacheScope``.
    meta: OPTIONAL reserved metadata map; JSON key ``_meta``.
  """

  resource_templates: list[ResourceTemplate]
  ttl_ms: int
  cache_scope: str
  next_cursor: str | None = None
  result_type: ResultType = RESULT_TYPE_COMPLETE
  meta: dict[str, Any] | None = None

  def __post_init__(self) -> None:
    if not isinstance(self.resource_templates, list):
      raise TypeError(
        "ListResourceTemplatesResult.resourceTemplates is REQUIRED and must be "
        "a list (R-17.3-b)"
      )
    for entry in self.resource_templates:
      if not isinstance(entry, ResourceTemplate):
        raise TypeError(
          f"ListResourceTemplatesResult.resourceTemplates entries must be "
          f"ResourceTemplate objects; got {entry!r} (R-17.3-b)"
        )
    if self.next_cursor is not None and not isinstance(self.next_cursor, str):
      raise TypeError(
        "ListResourceTemplatesResult.nextCursor must be a string when present "
        "(R-17.3-c)"
      )
    _validate_list_result_caching(
      self.result_type,
      self.ttl_ms,
      self.cache_scope,
      context="ListResourceTemplatesResult",
    )

  @property
  def is_last_page(self) -> bool:
    """True when ``nextCursor`` is absent — this is the final page (R-17.3-c)."""
    return self.next_cursor is None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "ListResourceTemplatesResult":
    """Deserialise a ``ListResourceTemplatesResult`` from a JSON-decoded dict (§17.3).

    Raises:
      TypeError: ``data`` is not a dict or a field has the wrong type.
      ValueError: a REQUIRED field is missing or out of contract.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ListResourceTemplatesResult must be a JSON object; "
        f"got {type(data).__name__}"
      )
    if "resourceTemplates" not in data:
      raise ValueError(
        "ListResourceTemplatesResult.resourceTemplates is REQUIRED (R-17.3-b)"
      )
    raw_templates = data["resourceTemplates"]
    if not isinstance(raw_templates, list):
      raise TypeError(
        "ListResourceTemplatesResult.resourceTemplates must be an array (R-17.3-b)"
      )
    if "ttlMs" not in data:
      raise ValueError("ListResourceTemplatesResult.ttlMs is REQUIRED (R-17.3-c)")
    if "cacheScope" not in data:
      raise ValueError("ListResourceTemplatesResult.cacheScope is REQUIRED (R-17.3-c)")
    return cls(
      resource_templates=[ResourceTemplate.from_dict(t) for t in raw_templates],
      ttl_ms=data["ttlMs"],
      cache_scope=data["cacheScope"],
      next_cursor=data.get("nextCursor"),
      result_type=data.get("resultType", RESULT_TYPE_COMPLETE),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields (§17.3)."""
    out: dict[str, Any] = {
      "resourceTemplates": [t.to_dict() for t in self.resource_templates],
      "resultType": self.result_type,
      "ttlMs": self.ttl_ms,
      "cacheScope": self.cache_scope,
    }
    if self.next_cursor is not None:
      out["nextCursor"] = self.next_cursor
    if self.meta is not None:
      out["_meta"] = self.meta
    return out
