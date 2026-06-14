"""Resources II: Reading, Not-Found, Subscriptions & URI Schemes — S27.

Delivers the **read side** of the Resources feature: how a client turns a
discovered or template-expanded ``uri`` into actual bytes or text via
``resources/read``, how a server reports that a requested resource does not
exist, how resource change notifications and per-resource update notifications
are delivered, and the set of standard URI schemes a resource URI may use. It
completes the Resources feature begun in S26.

This story owns:
  - ``ReadResourceRequestParams``: the params of a ``resources/read`` request —
    the REQUIRED ``uri`` plus the OPTIONAL multi-round-trip retry fields
    ``inputResponses``/``requestState`` and the reserved ``_meta`` map (§17.5).
  - ``ReadResourceResult``: the ``CacheableResult`` carrying the ``contents``
    array, ``resultType``, ``ttlMs`` and ``cacheScope`` (§17.5).
  - ``parse_read_resource_response``: the discriminator-first branch that returns
    either a completed ``ReadResourceResult`` or an ``InputRequiredResult`` (§17.5).
  - ``ResourceNotFoundError`` and the not-found / internal-error code mapping
    (``-32602``, legacy ``-32002``, ``-32603``) (§17.6).
  - ``ResourceUpdatedNotificationParams`` / ``ResourceUpdatedNotification`` and
    ``ResourceListChangedNotification``: the two server-to-client notifications,
    plus the gating helpers that bind them to the §10 / S16 filters (§17.7).
  - The common-URI-scheme catalog and scheme-selection guidance (§17.9).

It REUSES rather than re-implements earlier-wave work:
  - ``TextResourceContents`` / ``BlobResourceContents`` / ``parse_resource_contents``
    (S21, content_types) for the ``contents`` entries.
  - ``VALID_CACHE_SCOPES`` / ``is_valid_ttl_ms`` (S19, caching) for ``ttlMs`` /
    ``cacheScope``, and ``RESULT_TYPE_COMPLETE`` / ``RESULT_TYPE_INPUT_REQUIRED``
    (S04) for ``resultType``.
  - ``InputRequiredResult`` / ``validate_input_required_result`` (S17,
    multi_round_trip) for the ``input_required`` alternative and the retry.
  - ``SubscriptionFilter`` / ``build_resource_updated_notification`` /
    ``gate_change_notification`` / ``RESOURCES_*`` method names and the
    ``SUBSCRIPTION_ID_META_KEY`` (S16, subscriptions) for the notification
    delivery and filter gating.
  - ``METHOD_RESOURCES_READ`` / ``NOTIFICATION_RESOURCES_*`` (S26, resources) for
    the shared method-name constants.

Out of scope (owned elsewhere): the ``resources`` capability and its
``subscribe``/``listChanged`` sub-flags, ``resources/list``,
``resources/templates/list``, ``Resource`` and ``ResourceTemplate`` (S26); the
subscription stream, ``subscriptions/listen``, filter acknowledgment and the
subscription-id correlation mechanics (S16); the multi-round-trip algorithm and
``input_required`` payload structure (S17); the caching semantics of
``ttlMs``/``cacheScope`` (S19); the ``TextResourceContents``/
``BlobResourceContents`` definitions (S21); and the full error-code registry (S34).

Spec: §17.5–§17.9
Depends on: S04 (resultType), S16 (subscriptions/filters), S17 (multi-round-trip),
            S19 (caching), S21 (ResourceContents), S26 (method-name constants)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from mcp_sdk_py.caching import VALID_CACHE_SCOPES, is_valid_ttl_ms
from mcp_sdk_py.content_types import (
  BlobResourceContents,
  ResourceContents,
  TextResourceContents,
  parse_resource_contents,
)
from mcp_sdk_py.multi_round_trip import (
  InputRequiredResult,
  validate_input_required_result,
)
from mcp_sdk_py.resources import (
  METHOD_RESOURCES_READ,
  NOTIFICATION_RESOURCES_LIST_CHANGED,
  NOTIFICATION_RESOURCES_UPDATED,
)
from mcp_sdk_py.result_error import (
  RESULT_TYPE_COMPLETE,
  RESULT_TYPE_INPUT_REQUIRED,
  ResultType,
)
from mcp_sdk_py.subscriptions import (
  SUBSCRIPTION_ID_META_KEY,
  SubscriptionFilter,
  build_resource_updated_notification,
  gate_change_notification,
)


# ---------------------------------------------------------------------------
# §17.5 / §17.6  Method name & JSON-RPC error codes
# ---------------------------------------------------------------------------

#: The ``resources/read`` request method (§17.5). Re-exported from S26 so a
#: reader of this story sees the literal it operates on; capability gating of
#: the method itself is owned by S26 (R-17.1-h/j).
METHOD_READ: str = METHOD_RESOURCES_READ

#: JSON-RPC error code for Invalid params — the resource-not-found condition: a
#: ``uri`` that does not correspond to a readable resource (R-17.6-a).
JSONRPC_INVALID_PARAMS: int = -32602

#: Legacy resource-not-found code from an earlier protocol revision. A client
#: SHOULD also accept this as resource-not-found alongside ``-32602`` (R-17.6-c).
JSONRPC_RESOURCE_NOT_FOUND_LEGACY: int = -32002

#: JSON-RPC error code for Internal error — used for internal failures unrelated
#: to the validity of the requested ``uri`` (R-17.6-d).
JSONRPC_INTERNAL_ERROR: int = -32603

#: The two codes a client SHOULD treat as resource-not-found (R-17.6-a/c). The
#: current code is ``-32602``; ``-32002`` is accepted for interoperability.
RESOURCE_NOT_FOUND_CODES: frozenset[int] = frozenset({
  JSONRPC_INVALID_PARAMS,
  JSONRPC_RESOURCE_NOT_FOUND_LEGACY,
})


# ---------------------------------------------------------------------------
# §17.9  Common URI schemes  [R-17.9-a–f]
# ---------------------------------------------------------------------------

#: A resource available on the web (§17.9). A server SHOULD use this scheme only
#: when the client can fetch and load the resource directly from the web on its
#: own, without reading via the MCP server (R-17.9-b).
SCHEME_HTTPS: str = "https"

#: A resource that behaves like a filesystem; it need not map to a physical
#: filesystem (§17.9).
SCHEME_FILE: str = "file"

#: Git version-control integration (§17.9).
SCHEME_GIT: str = "git"

#: The standard URI schemes named by the protocol (§17.9). This list is NOT
#: exhaustive — an implementation MAY use additional custom schemes (R-17.9-a).
STANDARD_URI_SCHEMES: frozenset[str] = frozenset({
  SCHEME_HTTPS,
  SCHEME_FILE,
  SCHEME_GIT,
})

#: The XDG shared-MIME-info type a server MAY use to identify a non-regular
#: ``file://`` resource (e.g. a directory) that has no other standard MIME type
#: (R-17.9-d).
MIME_TYPE_INODE_DIRECTORY: str = "inode/directory"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ResourceNotFoundError(Exception):
  """The requested ``uri`` does not correspond to a readable resource (§17.6).

  A server MUST return a JSON-RPC error (NOT a result) with code ``-32602``
  (Invalid params) when a ``uri`` is not readable (R-17.6-a); the error's
  ``data`` SHOULD include the offending ``uri`` so the client can correlate the
  failure (R-17.6-b). A server MUST NOT instead return an empty ``contents``
  array to signal non-existence (R-17.5-z, R-17.5-aa).

  Use :meth:`to_error_object` to build the wire error. A client receiving an
  error SHOULD treat both ``-32602`` and the legacy ``-32002`` as resource-not-
  found (R-17.6-c) — see :func:`is_resource_not_found_code`.

  Attributes:
    uri: the offending resource URI, surfaced in ``data.uri`` (R-17.6-b).
    json_rpc_code: always ``-32602`` for callers building error responses.
  """

  json_rpc_code: int = JSONRPC_INVALID_PARAMS

  def __init__(self, uri: str, message: str = "Resource not found") -> None:
    super().__init__(
      f"{message}: {uri!r} does not correspond to a readable resource; the "
      f"server MUST return JSON-RPC {JSONRPC_INVALID_PARAMS} (Invalid params), "
      f"never an empty contents array (R-17.5-z, R-17.6-a, R-17.6-b)"
    )
    self.uri: str = uri
    self._message: str = message

  def to_error_object(self) -> dict[str, Any]:
    """Build the wire JSON-RPC error object with the offending ``uri`` in ``data``.

    Produces ``{code: -32602, message, data: {uri}}`` per R-17.6-a/b. The full
    error-envelope structure and code registry are owned by S34; this only
    populates the resource-not-found shape (R-17.6-a, R-17.6-b).
    """
    return {
      "code": JSONRPC_INVALID_PARAMS,
      "message": self._message,
      "data": {"uri": self.uri},
    }


# ---------------------------------------------------------------------------
# §17.6  Resource-not-found code helpers  [R-17.6-a, R-17.6-c]
# ---------------------------------------------------------------------------

def is_resource_not_found_code(code: int) -> bool:
  """Return True if ``code`` is a resource-not-found code (R-17.6-a/c).

  The current code is ``-32602`` (Invalid params) (R-17.6-a). For
  interoperability a client SHOULD ALSO accept the legacy ``-32002`` used by an
  earlier protocol revision (R-17.6-c, AC-27.11). Any other code — including
  ``-32603`` (Internal error, R-17.6-d) — is not a resource-not-found signal.
  """
  return code in RESOURCE_NOT_FOUND_CODES


def not_found_uri(error: dict[str, Any]) -> str | None:
  """Extract the offending ``uri`` from a resource-not-found error's ``data`` (R-17.6-b).

  The error's ``data`` SHOULD include the ``uri`` so the client can correlate
  the failure (R-17.6-b). Returns the URI string when present, else None. Does
  not itself check the code; pair with :func:`is_resource_not_found_code`.
  """
  data = error.get("data")
  if not isinstance(data, dict):
    return None
  uri = data.get("uri")
  return uri if isinstance(uri, str) else None


# ---------------------------------------------------------------------------
# §17.5  ReadResourceRequestParams  [R-17.5-a–h]
# ---------------------------------------------------------------------------

@dataclass
class ReadResourceRequestParams:
  """The ``params`` of a ``resources/read`` request (§17.5).

  Names the concrete resource to read and MAY participate in a multi-round-trip
  exchange (§11 / S17): the OPTIONAL ``inputResponses`` and ``requestState``
  fields carry the retry payload (R-17.5-a). On a first attempt both are omitted.

  Fields:
    uri: REQUIRED exact resource to read, in URI format. MAY be a concrete
      resource from ``resources/list`` or a URI produced by expanding a
      ``ResourceTemplate`` (R-17.5-b/c, AC-27.1, AC-27.2). Wire key: ``uri``.
    input_responses: OPTIONAL multi-round-trip retry responses (§11). Present
      only on a retry that satisfies a server's request for additional input;
      for each key in the server's earlier ``inputRequests`` the same key MUST
      appear here with its response (R-17.5-d/e, AC-27.3). Wire key:
      ``inputResponses``.
    request_state: OPTIONAL opaque continuation token the server returned in an
      earlier ``input_required`` result, echoed back unchanged on retry; the
      client MUST treat it as an opaque blob and MUST NOT interpret or modify it
      (R-17.5-f/g/h, AC-27.3). Wire key: ``requestState``.
    meta: OPTIONAL reserved metadata map (§14 / S21). Wire key: ``_meta``.
  """

  uri: str
  input_responses: dict[str, Any] | None = None  # JSON key: inputResponses
  request_state: str | None = None               # JSON key: requestState
  meta: dict[str, Any] | None = None             # JSON key: _meta

  def __post_init__(self) -> None:
    # R-17.5-b: uri is REQUIRED and must be a non-empty string in URI format.
    if not isinstance(self.uri, str) or not self.uri:
      raise ValueError(
        "ReadResourceRequestParams.uri is REQUIRED and must be a non-empty "
        "string (R-17.5-b)"
      )
    if self.input_responses is not None and not isinstance(self.input_responses, dict):
      raise TypeError(
        "ReadResourceRequestParams.inputResponses must be a JSON object when "
        "present (R-17.5-d)"
      )
    if self.request_state is not None and not isinstance(self.request_state, str):
      raise TypeError(
        "ReadResourceRequestParams.requestState must be an opaque string when "
        "present (R-17.5-f/g)"
      )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError(
        "ReadResourceRequestParams._meta must be a JSON object when present "
        "(§14 / S21)"
      )

  @property
  def is_retry(self) -> bool:
    """True when this carries multi-round-trip retry fields (§11, R-17.5-a/d/f).

    A retry supplies ``inputResponses`` and/or echoes ``requestState``; a first
    attempt carries neither.
    """
    return self.input_responses is not None or self.request_state is not None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ReadResourceRequestParams:
    """Parse ``resources/read`` request params from a wire dict (§17.5).

    ``uri`` is REQUIRED (R-17.5-b). The multi-round-trip ``inputResponses`` /
    ``requestState`` fields are OPTIONAL and omitted on a first attempt
    (R-17.5-a/d/f). Unknown keys are ignored for forward compatibility.

    Raises:
      TypeError: ``data`` is not a dict, or a field has the wrong type.
      ValueError/KeyError: ``uri`` is missing or invalid.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"resources/read params must be a JSON object; got {type(data).__name__}"
      )
    if "uri" not in data:
      raise ValueError("ReadResourceRequestParams.uri is REQUIRED (R-17.5-b)")
    return cls(
      uri=data["uri"],
      input_responses=data.get("inputResponses"),
      request_state=data.get("requestState"),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields (§17.5).

    On a retry ``inputResponses`` and ``requestState`` (echoed verbatim) appear;
    on a first attempt they are omitted (R-17.5-a/d/f).
    """
    out: dict[str, Any] = {"uri": self.uri}
    if self.input_responses is not None:
      out["inputResponses"] = self.input_responses
    if self.request_state is not None:
      out["requestState"] = self.request_state
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


# ---------------------------------------------------------------------------
# §17.5  ReadResourceResult  [R-17.5-i–v, R-17.5-z]
# ---------------------------------------------------------------------------

@dataclass
class ReadResourceResult:
  """The result of a successful, completed ``resources/read`` (§17.5).

  A ``CacheableResult`` (§13 / S19) carrying the resource's ``contents``. When
  the server needs more input it returns an ``InputRequiredResult`` instead
  (§11 / S17), signalled by ``resultType: "input_required"`` — see
  :func:`parse_read_resource_response` and :func:`is_input_required` (R-17.5-w).

  The contents array MAY hold multiple entries (e.g. several files when a
  directory/container resource is read) and an entry's ``uri`` MAY differ from
  the requested ``uri`` (a sub-resource) — each entry identifies the specific
  (sub-)resource it carries (R-17.5-j/p, AC-27.5). Each entry is a
  ``TextResourceContents`` (text) or ``BlobResourceContents`` (base64 blob);
  these variants and their per-field rules are owned and validated by S21
  (R-17.5-k–v).

  A server MUST NOT return an empty ``contents`` array to signal that a resource
  does not exist; non-existence is the error in §17.6 (R-17.5-z/aa). This type
  does NOT reject an empty list at construction — an empty contents array can be
  a legitimate "exists but no content" result — but :meth:`signals_non_existence`
  and the server-side guard make the prohibition checkable (AC-27.10).

  Fields:
    contents: REQUIRED array of ``TextResourceContents`` | ``BlobResourceContents``;
      MAY hold multiple entries (R-17.5-i/j, AC-27.4, AC-27.5).
    ttl_ms: REQUIRED non-negative cache-freshness hint in milliseconds (R-17.5-r,
      §13, AC-27.4). Wire key: ``ttlMs``.
    cache_scope: REQUIRED enum ``"public"`` | ``"private"`` (R-17.5-r, §13,
      AC-27.4). Wire key: ``cacheScope``.
    result_type: REQUIRED discriminator; for a completed read it is
      ``"complete"`` (R-17.5-q, §3, AC-27.4). Wire key: ``resultType``.
    meta: OPTIONAL reserved metadata map. Wire key: ``_meta``.
  """

  contents: list[ResourceContents]
  ttl_ms: int
  cache_scope: str
  result_type: ResultType = RESULT_TYPE_COMPLETE  # JSON key: resultType
  meta: dict[str, Any] | None = None              # JSON key: _meta

  def __post_init__(self) -> None:
    # R-17.5-i: contents is REQUIRED and is an array of resource-content entries.
    if not isinstance(self.contents, list):
      raise TypeError(
        "ReadResourceResult.contents is REQUIRED and must be a list (R-17.5-i)"
      )
    # R-17.5-k/n: each entry MUST be exactly one of text or binary; a blob entry
    # MUST NOT carry a text field. The variant types validate their own fields
    # (uri/text/blob/base64) per S21 (R-17.5-l/m/o/s/t/u/v).
    for entry in self.contents:
      if not isinstance(entry, (TextResourceContents, BlobResourceContents)):
        raise TypeError(
          f"ReadResourceResult.contents entries must be TextResourceContents or "
          f"BlobResourceContents; got {entry!r} (R-17.5-k)"
        )
    # R-17.5-r: ttlMs is REQUIRED, a non-negative integer (minimum 0).
    if not is_valid_ttl_ms(self.ttl_ms):
      raise ValueError(
        f"ReadResourceResult.ttlMs is REQUIRED and must be a non-negative "
        f"integer; got {self.ttl_ms!r} (R-17.5-r)"
      )
    # R-17.5-r: cacheScope is REQUIRED, exactly "public" or "private".
    if self.cache_scope not in VALID_CACHE_SCOPES:
      raise ValueError(
        f"ReadResourceResult.cacheScope is REQUIRED and must be exactly "
        f"'public' or 'private'; got {self.cache_scope!r} (R-17.5-r)"
      )
    # R-17.5-q: resultType is REQUIRED; for a completed read it is "complete".
    if not isinstance(self.result_type, str) or not self.result_type:
      raise ValueError("ReadResourceResult.resultType is REQUIRED (R-17.5-q)")
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError(
        "ReadResourceResult._meta must be a JSON object when present (§14 / S21)"
      )

  @property
  def signals_non_existence(self) -> bool:
    """True when ``contents`` is empty — which a server MUST NOT use for non-existence.

    An empty array is ambiguous (it could mean "exists but no content"); a server
    MUST report non-existence as the §17.6 error instead (R-17.5-z/aa). A server
    SHOULD call :func:`assert_contents_present` before emitting a non-existence
    result.
    """
    return len(self.contents) == 0

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ReadResourceResult:
    """Parse a wire completed ``resources/read`` result (§17.5).

    Validates that ``contents`` is a present array (R-17.5-i), each entry is a
    text-or-blob ResourceContents dispatched via S21's
    :func:`parse_resource_contents` (R-17.5-k), and ``ttlMs``/``cacheScope`` are
    present and well-formed (R-17.5-r). A result lacking ``resultType`` is
    treated as ``"complete"`` (R-17.5-q). A caller that has not already
    discriminated on ``resultType`` SHOULD use
    :func:`parse_read_resource_response` to branch on ``input_required`` first.

    Raises:
      TypeError / ValueError: a required field is absent or has the wrong type.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"resources/read result must be a JSON object; got {type(data).__name__}"
      )
    if "contents" not in data:
      raise ValueError("ReadResourceResult.contents is REQUIRED (R-17.5-i)")
    raw_contents = data["contents"]
    if not isinstance(raw_contents, list):
      raise TypeError("ReadResourceResult.contents must be an array (R-17.5-i)")
    if "ttlMs" not in data:
      raise ValueError("ReadResourceResult.ttlMs is REQUIRED (R-17.5-r)")
    if "cacheScope" not in data:
      raise ValueError("ReadResourceResult.cacheScope is REQUIRED (R-17.5-r)")
    return cls(
      contents=[_parse_contents_entry(c) for c in raw_contents],
      ttl_ms=data["ttlMs"],
      cache_scope=data["cacheScope"],
      result_type=data.get("resultType", RESULT_TYPE_COMPLETE),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields (§17.5).

    ``resultType``, ``contents``, ``ttlMs`` and ``cacheScope`` are always present
    (all REQUIRED); ``_meta`` appears only when present.
    """
    out: dict[str, Any] = {
      "resultType": self.result_type,
      "contents": [c.to_dict() for c in self.contents],
      "ttlMs": self.ttl_ms,
      "cacheScope": self.cache_scope,
    }
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def _parse_contents_entry(raw: Any) -> ResourceContents:
  """Parse one ``contents`` entry as a text-or-blob ResourceContents (R-17.5-k).

  Each entry MUST be exactly one of text or binary; a blob entry MUST NOT carry
  a ``text`` field (R-17.5-k/n). Selection and the both-present / neither-present
  rejection are owned by S21's :func:`parse_resource_contents` (R-14.5-g/h).

  Raises:
    TypeError: ``raw`` is not a JSON object.
    ValueError: the entry carries both or neither of ``text``/``blob``.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"ReadResourceResult.contents entry must be a JSON object; "
      f"got {type(raw).__name__} (R-17.5-k)"
    )
  return parse_resource_contents(raw)


# ---------------------------------------------------------------------------
# §17.5  Empty-array prohibition guard  [R-17.5-z, R-17.5-aa]
# ---------------------------------------------------------------------------

def assert_contents_present(
  contents: list[ResourceContents],
  uri: str,
) -> None:
  """Raise if ``contents`` is empty, mapping it to the §17.6 not-found error.

  A server MUST NOT use an empty ``contents`` array to signify that a resource
  does not exist (R-17.5-z); non-existence MUST be reported as the §17.6 error
  (R-17.5-aa, R-17.6-a). A server building a read result SHOULD call this so an
  empty result becomes a :class:`ResourceNotFoundError` (code ``-32602``) rather
  than an ambiguous empty array (AC-27.10).

  Raises:
    ResourceNotFoundError: ``contents`` is empty (json_rpc_code ``-32602``).
  """
  if len(contents) == 0:
    raise ResourceNotFoundError(uri)


# ---------------------------------------------------------------------------
# §17.5  Multi-round-trip discrimination & retry  [R-17.5-w, R-17.5-x]
# ---------------------------------------------------------------------------

def is_input_required(data: dict[str, Any]) -> bool:
  """Return True if a ``resources/read`` response is an ``InputRequiredResult`` (R-17.5-w).

  A client MUST inspect ``resultType`` to determine whether a response is a
  ``ReadResourceResult`` (``"complete"``) or an ``InputRequiredResult``
  (``"input_required"``) BEFORE parsing the body (R-17.5-w, AC-27.8). This is the
  discriminator-only check; an absent ``resultType`` is treated as ``"complete"``
  and therefore returns False.
  """
  return data.get("resultType") == RESULT_TYPE_INPUT_REQUIRED


def parse_read_resource_response(
  data: dict[str, Any],
) -> ReadResourceResult | InputRequiredResult:
  """Branch a ``resources/read`` response on ``resultType`` then parse it (R-17.5-w).

  A client MUST inspect ``resultType`` before parsing the body (R-17.5-w):
    - ``"input_required"`` ⇒ parse as an ``InputRequiredResult`` (S17), then run
      the multi-round-trip retry of the same ``resources/read`` (§11, R-17.5-x);
    - ``"complete"`` or absent ⇒ parse as a ``ReadResourceResult``.

  Args:
    data: the raw ``result`` object from the ``resources/read`` response.

  Returns:
    An ``InputRequiredResult`` when ``resultType`` is ``"input_required"``,
    otherwise a ``ReadResourceResult``.

  Raises:
    TypeError / ValueError: the body does not match the discriminated shape.
  """
  if not isinstance(data, dict):
    raise TypeError(
      f"resources/read response must be a JSON object; got {type(data).__name__}"
    )
  if is_input_required(data):
    # R-17.5-w: parse the §11/S17 InputRequiredResult shape; drives the retry.
    return validate_input_required_result(data)
  # R-17.5-q: "complete" or absent → a completed ReadResourceResult.
  return ReadResourceResult.from_dict(data)


def build_read_resource_retry(
  original: ReadResourceRequestParams,
  input_responses: dict[str, Any],
  request_state: str | None,
) -> ReadResourceRequestParams:
  """Build the retry ``resources/read`` params after an ``input_required`` result (§11).

  The retry reuses the same ``uri`` (and ``_meta``) as the original request and
  adds the gathered ``inputResponses`` plus the echoed ``requestState``
  (R-17.5-e/x, AC-27.3):
    - for each key in the server's prior ``inputRequests`` the same key MUST be
      present in ``input_responses`` (R-17.5-e; validated by the caller against
      the server's ``inputRequests``);
    - ``request_state`` MUST be the exact opaque value the server supplied — it
      is echoed verbatim and never interpreted or modified (R-17.5-g/h).

  Args:
    original: the first-attempt ``resources/read`` params (uri + meta).
    input_responses: the responses keyed identically to the server's
      ``inputRequests`` (R-17.5-e).
    request_state: the opaque ``requestState`` from the server's
      ``input_required`` result, echoed verbatim (R-17.5-f); None only when the
      server supplied none.

  Returns:
    A new ``ReadResourceRequestParams`` carrying the retry fields.
  """
  return ReadResourceRequestParams(
    uri=original.uri,
    input_responses=input_responses,
    request_state=request_state,
    meta=original.meta,
  )


# ---------------------------------------------------------------------------
# §17.5 / §17.9  Direct https fetch alternative  [R-17.5-y, R-17.9-b]
# ---------------------------------------------------------------------------

def uri_scheme(uri: str) -> str:
  """Return the lower-cased scheme component of ``uri`` [RFC3986] (§17.9).

  A custom URI scheme MUST conform to RFC3986 (R-17.9-e); RFC3986 schemes are
  case-insensitive, so the scheme is normalised to lower case for comparison.

  Raises:
    ValueError: ``uri`` has no scheme component (not an absolute URI [RFC3986]).
  """
  scheme = urlsplit(uri).scheme
  if not scheme:
    raise ValueError(
      f"{uri!r} has no scheme component; a resource URI must be an absolute URI "
      f"[RFC3986] (R-17.9-e)"
    )
  return scheme.lower()


def client_may_fetch_directly(uri: str) -> bool:
  """Return True if a client MAY fetch ``uri`` from the web instead of reading it (R-17.5-y).

  When the scheme of ``uri`` is ``https`` the client MAY fetch the resource
  directly from the web rather than via ``resources/read`` (R-17.5-y, R-17.9-b,
  AC-27.9). For any other scheme the client reads through the MCP server. This
  is a MAY: the client always retains the option of ``resources/read``.
  """
  try:
    return uri_scheme(uri) == SCHEME_HTTPS
  except ValueError:
    return False


def is_standard_scheme(scheme: str) -> bool:
  """Return True if ``scheme`` is one of the protocol's named standard schemes (§17.9).

  The standard set (``https``/``file``/``git``) is NOT exhaustive — an
  implementation MAY use additional custom schemes (R-17.9-a, AC-27.18). The
  comparison is case-insensitive [RFC3986].
  """
  return scheme.lower() in STANDARD_URI_SCHEMES


# ---------------------------------------------------------------------------
# §17.7  Change & per-resource update notifications  [R-17.7-a–k]
# ---------------------------------------------------------------------------

#: There is NO per-resource subscribe/unsubscribe request method; subscription
#: is governed entirely by §10 / S16 (R-17.7-a, AC-27.13). This catalog names
#: the (non-existent) methods so a conformance check can assert their absence.
NO_SUBSCRIBE_METHODS: frozenset[str] = frozenset()


def has_subscribe_method() -> bool:
  """Return False: there is no per-resource subscribe/unsubscribe method (R-17.7-a).

  Subscription to resource notifications is governed entirely by the §10 / S16
  subscription stream and its filters — there is no ``resources/subscribe`` or
  ``resources/unsubscribe`` request (R-17.7-a, AC-27.13). This predicate exists so
  a caller searching for such a method gets an authoritative "none" answer.
  """
  return bool(NO_SUBSCRIBE_METHODS)


@dataclass
class ResourceUpdatedNotificationParams:
  """The ``params`` of a ``notifications/resources/updated`` notification (§17.7).

  Identifies the specific subscribed resource that changed and may need
  re-reading. Delivered on the §10 / S16 subscription stream; the
  subscription-id correlation rides in ``_meta`` under
  ``io.modelcontextprotocol/subscriptionId`` (owned by S16).

  Fields:
    uri: REQUIRED URI of the updated resource, in URI format. MAY be a
      sub-resource of the URI the client actually subscribed to (R-17.7-g/h,
      AC-27.16). Wire key: ``uri``.
    meta: OPTIONAL reserved metadata map; carries the subscription-id
      correlation per §10 / S16. Wire key: ``_meta``.
  """

  uri: str
  meta: dict[str, Any] | None = None  # JSON key: _meta

  def __post_init__(self) -> None:
    # R-17.7-g: uri is REQUIRED and must be a non-empty string in URI format.
    if not isinstance(self.uri, str) or not self.uri:
      raise ValueError(
        "ResourceUpdatedNotificationParams.uri is REQUIRED and must be a "
        "non-empty string (R-17.7-g)"
      )
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError(
        "ResourceUpdatedNotificationParams._meta must be a JSON object when "
        "present (§10 / S16)"
      )

  @property
  def subscription_id(self) -> str | None:
    """The correlated subscription id from ``_meta``, or None when absent (§10/S16).

    Reads ``io.modelcontextprotocol/subscriptionId`` from ``_meta`` — the
    correlation key the client uses to route the update to its originating
    subscription (owned by S16). Returns None when no ``_meta`` or key is present.
    """
    if not isinstance(self.meta, dict):
      return None
    value = self.meta.get(SUBSCRIPTION_ID_META_KEY)
    return value if isinstance(value, str) else None

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ResourceUpdatedNotificationParams:
    """Parse ``notifications/resources/updated`` params from a wire dict (§17.7).

    ``uri`` is REQUIRED (R-17.7-g). Unknown keys other than ``_meta`` are ignored
    for forward compatibility.

    Raises:
      TypeError: ``data`` is not a dict, or a field has the wrong type.
      ValueError/KeyError: ``uri`` is missing or invalid.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"resources/updated params must be a JSON object; "
        f"got {type(data).__name__}"
      )
    if "uri" not in data:
      raise ValueError("ResourceUpdatedNotificationParams.uri is REQUIRED (R-17.7-g)")
    return cls(uri=data["uri"], meta=data.get("_meta"))

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits ``_meta`` when absent (§17.7)."""
    out: dict[str, Any] = {"uri": self.uri}
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


@dataclass
class ResourceUpdatedNotification:
  """A ``notifications/resources/updated`` notification (§17.7).

  A one-way notification (no ``id``, no response) a ``subscribe``-declaring
  server MAY send when a specific subscribed resource changes and may need
  re-reading (R-17.7-f). It is delivered only for resources the client opted
  into via the ``resourceSubscriptions`` filter of §10 (R-17.7-i); the server
  MUST NOT send it for any resource the client did not opt into (R-17.7-j). On
  receipt a client that wants the current contents re-issues ``resources/read``
  for the named ``uri`` (R-17.7-k).

  Fields:
    params: REQUIRED ``ResourceUpdatedNotificationParams`` carrying the updated
      ``uri`` (R-17.7-g).
  """

  params: ResourceUpdatedNotificationParams

  #: The notification method; REQUIRED to be exactly this string (§17.7).
  method: str = field(default=NOTIFICATION_RESOURCES_UPDATED, init=False)

  def __post_init__(self) -> None:
    if not isinstance(self.params, ResourceUpdatedNotificationParams):
      raise TypeError(
        "ResourceUpdatedNotification.params must be a "
        "ResourceUpdatedNotificationParams (R-17.7-g)"
      )

  @property
  def uri(self) -> str:
    """The URI of the updated resource (R-17.7-g)."""
    return self.params.uri

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ResourceUpdatedNotification:
    """Parse a wire ``notifications/resources/updated`` notification (§17.7).

    Validates the ``method`` is exactly ``notifications/resources/updated`` and
    that ``params`` is present with a REQUIRED ``uri`` (R-17.7-g).

    Raises:
      TypeError: ``data``/``params`` has the wrong type.
      ValueError: ``method`` is wrong, or ``params``/``uri`` is missing.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ResourceUpdatedNotification must be a JSON object; "
        f"got {type(data).__name__}"
      )
    method = data.get("method")
    if method != NOTIFICATION_RESOURCES_UPDATED:
      raise ValueError(
        f"method MUST be exactly {NOTIFICATION_RESOURCES_UPDATED!r}; "
        f"got {method!r} (§17.7)"
      )
    raw_params = data.get("params")
    if not isinstance(raw_params, dict):
      raise ValueError(
        "ResourceUpdatedNotification.params is REQUIRED and must be an object "
        "(R-17.7-g)"
      )
    return cls(params=ResourceUpdatedNotificationParams.from_dict(raw_params))

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible JSON-RPC notification object (§17.7).

    Emits ``jsonrpc``/``method``/``params``; no ``id`` (one-way).
    """
    return {
      "jsonrpc": "2.0",
      "method": self.method,
      "params": self.params.to_dict(),
    }


@dataclass
class ResourceListChangedNotification:
  """A ``notifications/resources/list_changed`` notification (§17.7).

  A one-way notification a server that declared the ``listChanged`` sub-flag
  SHOULD send when the set of available resources changes (R-17.7-b). It MAY be
  issued without any prior subscription action beyond the client opting into the
  ``resourcesListChanged`` filter of §10 (R-17.7-c); the server MUST NOT deliver
  it on a stream whose filter did not request ``resourcesListChanged``
  (R-17.7-e). The notification carries no resource data — only an OPTIONAL
  ``_meta`` map (R-17.7 / §17.7).

  Fields:
    meta: OPTIONAL reserved ``_meta`` map; when ``params`` is present it MAY
      carry only this map. Wire key: ``params._meta``.
  """

  meta: dict[str, Any] | None = None  # JSON key: params._meta

  #: The notification method; REQUIRED to be exactly this string (§17.7).
  method: str = field(default=NOTIFICATION_RESOURCES_LIST_CHANGED, init=False)

  def __post_init__(self) -> None:
    if self.meta is not None and not isinstance(self.meta, dict):
      raise TypeError(
        "ResourceListChangedNotification params._meta must be a JSON object "
        "when present (§17.7)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> ResourceListChangedNotification:
    """Parse a wire ``notifications/resources/list_changed`` notification (§17.7).

    Validates the ``method`` is exactly ``notifications/resources/list_changed``
    and that ``params``, when present, carries only ``_meta`` and no resource
    data (§17.7).

    Raises:
      TypeError: ``data``/``params``/``_meta`` has the wrong type.
      ValueError: ``method`` is wrong, or ``params`` carries members other than
        ``_meta``.
    """
    if not isinstance(data, dict):
      raise TypeError(
        f"ResourceListChangedNotification must be a JSON object; "
        f"got {type(data).__name__}"
      )
    method = data.get("method")
    if method != NOTIFICATION_RESOURCES_LIST_CHANGED:
      raise ValueError(
        f"method MUST be exactly {NOTIFICATION_RESOURCES_LIST_CHANGED!r}; "
        f"got {method!r} (§17.7)"
      )
    params = data.get("params")
    if params is None:
      return cls()
    if not isinstance(params, dict):
      raise TypeError(
        "ResourceListChangedNotification.params must be an object when present "
        "(§17.7)"
      )
    extra = {k for k in params if k != "_meta"}
    if extra:
      raise ValueError(
        f"ResourceListChangedNotification.params may carry only '_meta'; "
        f"unexpected members {sorted(extra)!r} (§17.7)"
      )
    meta = params.get("_meta")
    if meta is not None and not isinstance(meta, dict):
      raise TypeError(
        "ResourceListChangedNotification params._meta must be an object when "
        "present (§17.7)"
      )
    return cls(meta=meta)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible JSON-RPC notification object (§17.7).

    Emits ``jsonrpc``/``method`` and includes ``params`` only when a ``_meta``
    map is present; a bare notification carries just the method, with no ``id``.
    """
    out: dict[str, Any] = {
      "jsonrpc": "2.0",
      "method": self.method,
    }
    if self.meta is not None:
      out["params"] = {"_meta": self.meta}
    return out


# ---------------------------------------------------------------------------
# §17.7  Notification gating against the §10 / S16 filter  [R-17.7-d–j]
# ---------------------------------------------------------------------------

def server_may_send_list_changed(honored: SubscriptionFilter) -> bool:
  """Return True if the server MAY send list_changed on a stream (R-17.7-d/e).

  A client opts in by setting ``resourcesListChanged: true`` in its subscription
  filter (R-17.7-d); the server MUST NOT deliver
  ``notifications/resources/list_changed`` on a stream whose honored filter did
  not request it (R-17.7-e, AC-27.14, AC-27.15). Delegates the gate to S16's
  :func:`gate_change_notification`.
  """
  return gate_change_notification(
    NOTIFICATION_RESOURCES_LIST_CHANGED, honored
  )


def server_may_send_updated(honored: SubscriptionFilter, uri: str) -> bool:
  """Return True if the server MAY send a resources/updated for ``uri`` (R-17.7-i/j).

  A client opts into per-resource updates by listing the resource URIs it wants
  to watch in the ``resourceSubscriptions`` filter of §10 (R-17.7-i); the server
  MUST NOT send ``notifications/resources/updated`` for any resource the client
  did not opt into (R-17.7-j, AC-27.16, AC-27.17). The honored ``uri`` MAY be a
  sub-resource of a subscribed container URI (R-17.7-h). Delegates the gate —
  including the sub-resource coverage check — to S16's
  :func:`gate_change_notification`.
  """
  return gate_change_notification(
    NOTIFICATION_RESOURCES_UPDATED, honored, uri=uri
  )


def make_resource_updated_notification(
  subscription_request_id: Any,
  uri: str,
  *,
  honored: SubscriptionFilter | None = None,
):
  """Build a ``notifications/resources/updated`` JSON-RPC notification (§17.7).

  Stamps the subscription-id correlation into ``_meta`` (owned by S16) and sets
  the REQUIRED ``uri`` (R-17.7-g). The ``uri`` MAY be a sub-resource of a
  subscribed container URI (R-17.7-h). When ``honored`` is provided, the URI is
  first gated against the honored ``resourceSubscriptions`` filter so the server
  cannot send an update for a resource the client did not opt into (R-17.7-j).

  Args:
    subscription_request_id: the JSON-RPC id of the originating
      ``subscriptions/listen`` request; doubles as the subscription identifier.
    uri: the URI of the updated resource (R-17.7-g).
    honored: when provided, the honored filter to gate ``uri`` against (R-17.7-j).

  Returns:
    A ``JSONRPCNotification`` (from S03) for ``notifications/resources/updated``.

  Raises:
    ValueError: ``honored`` is provided and ``uri`` is not covered by it
      (R-17.7-j), or ``uri`` is not an absolute URI (R-17.7-g).
    TypeError: ``uri`` is not a string.
  """
  if honored is not None and not server_may_send_updated(honored, uri):
    raise ValueError(
      f"server MUST NOT send notifications/resources/updated for {uri!r}; the "
      f"client did not opt into it via resourceSubscriptions (R-17.7-j)"
    )
  return build_resource_updated_notification(subscription_request_id, uri)


def client_should_reread(notification_method: str) -> bool:
  """Return True if a notification means the client MAY re-read the named resource (R-17.7-k).

  Upon receiving ``notifications/resources/updated`` a client that wants the
  current contents re-issues ``resources/read`` for the named ``uri`` (R-17.7-k,
  AC-27.16). This is the predicate a client's update handler consults; it is a
  MAY — the client is never obliged to re-read.
  """
  return notification_method == NOTIFICATION_RESOURCES_UPDATED
