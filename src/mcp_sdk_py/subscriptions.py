"""Server-to-Client Streaming & Subscriptions — S16.

Delivers the single, transport-agnostic mechanism by which a client opts in to
server-initiated change notifications: the ``subscriptions/listen`` request,
whose response is one long-lived stream that carries only the notification kinds
the client explicitly requested.

This module models:
  - ``SubscriptionFilter`` — the explicit opt-in (§10.2).
  - ``SubscriptionsListenRequestParams`` / ``SubscriptionsListenRequest`` — the
    request that opens a subscription (§10.2).
  - ``SubscriptionsAcknowledgedNotificationParams`` /
    ``SubscriptionsAcknowledgedNotification`` — the mandatory first message on
    the stream (§10.3).
  - The reserved correlation key ``io.modelcontextprotocol/subscriptionId``
    (§10.4) and helpers to stamp/extract it on every subscription notification.
  - Builders for the four change-notification kinds gated by the filter (§10.5).
  - Boundary helpers separating subscription notifications from request-scoped
    progress/logging notifications (§10.6).
  - A ``Subscription`` lifecycle object plus a client-side
    ``SubscriptionRegistry`` that routes notifications by subscription id and
    enforces no-resumption / no-retained-state (§10.1, §10.7).

It REUSES JSON-RPC envelopes from S03 (``mcp_sdk_py.jsonrpc``), the per-request
``_meta`` conventions from S04/S05, and the ``notifications/cancelled`` shape
from S22 (``mcp_sdk_py.progress``).

Spec: §10 (§10.1–§10.7)
Depends on: S14 (Streamable HTTP request/response surface), S04 (Result/Error base)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from mcp_sdk_py.jsonrpc import (
  JSONRPCNotification,
  JSONRPCRequest,
  RequestId,
  validate_request_id,
)


# ---------------------------------------------------------------------------
# §10  Method / notification names  [R-10.2-a, R-10.3-a, R-10.5-a]
# ---------------------------------------------------------------------------

#: The literal request method that opens a subscription stream (§10.2, R-10.2-a).
SUBSCRIPTIONS_LISTEN_METHOD: str = "subscriptions/listen"

#: The literal method of the mandatory first stream message (§10.3, R-10.3-a).
ACKNOWLEDGED_NOTIFICATION_METHOD: str = "notifications/subscriptions/acknowledged"

#: The four change-notification kinds that flow on a subscription stream (§10.5).
TOOLS_LIST_CHANGED_METHOD: str = "notifications/tools/list_changed"
PROMPTS_LIST_CHANGED_METHOD: str = "notifications/prompts/list_changed"
RESOURCES_LIST_CHANGED_METHOD: str = "notifications/resources/list_changed"
RESOURCES_UPDATED_METHOD: str = "notifications/resources/updated"

#: The exact set of methods permitted on a `subscriptions/listen` stream after
#: the acknowledgement: the four change-notification kinds (§10.5, R-10.5-a).
CHANGE_NOTIFICATION_METHODS: frozenset[str] = frozenset({
  TOOLS_LIST_CHANGED_METHOD,
  PROMPTS_LIST_CHANGED_METHOD,
  RESOURCES_LIST_CHANGED_METHOD,
  RESOURCES_UPDATED_METHOD,
})

#: Request-scoped notification methods that MUST NOT appear on a subscription
#: stream — they belong to the response stream of a specific request (§10.6).
PROGRESS_NOTIFICATION_METHOD: str = "notifications/progress"
MESSAGE_NOTIFICATION_METHOD: str = "notifications/message"
REQUEST_SCOPED_NOTIFICATION_METHODS: frozenset[str] = frozenset({
  PROGRESS_NOTIFICATION_METHOD,
  MESSAGE_NOTIFICATION_METHOD,
})


# ---------------------------------------------------------------------------
# §10.4  Subscription correlation key  [R-10.4-a, R-10.4-b, R-10.4-f]
# ---------------------------------------------------------------------------

#: Reserved ``_meta`` key carried on EVERY notification delivered for a
#: subscription, including the acknowledgement. Its value is the
#: ``subscriptions/listen`` request ``id`` serialized as a JSON string. The key
#: is case-sensitive and MUST be reproduced verbatim (R-10.4-a/b/f).
SUBSCRIPTION_ID_META_KEY: str = "io.modelcontextprotocol/subscriptionId"


def subscription_id_for(request_id: RequestId) -> str:
  """Derive the subscription identifier string from a `subscriptions/listen` id.

  The subscription identifier is the JSON-RPC ``id`` of the request that opened
  the stream, serialized as a JSON string (e.g. ``1`` → ``"1"``) (R-10.4-b).

  Integer-valued floats serialize without a fractional part (``1.0`` → ``"1"``)
  so the wire form matches JSON's single number type.

  Args:
    request_id: The validated JSON-RPC id of the `subscriptions/listen` request.

  Returns:
    The subscription identifier as a string.
  """
  validate_request_id(request_id)
  if isinstance(request_id, float) and request_id.is_integer():
    return str(int(request_id))
  return str(request_id)


# ---------------------------------------------------------------------------
# §10.2  Absolute-URI validation for resourceSubscriptions  [R-10.2-i]
# ---------------------------------------------------------------------------

def validate_absolute_uri(value: Any, field_name: str = "resourceSubscriptions") -> str:
  """Validate that value is an absolute URI string [RFC3986] (R-10.2-i).

  An absolute URI has a scheme component and is not a bare relative reference;
  per RFC3986 the scheme is required and the fragment is forbidden in an
  *absolute-URI*. Each element of ``resourceSubscriptions`` MUST satisfy this
  (R-10.2-i, R-10.5-i).

  Args:
    value: The candidate URI.
    field_name: Name used in error messages.

  Returns:
    value unchanged when valid.

  Raises:
    TypeError: value is not a string.
    ValueError: value is not an absolute URI (no scheme, or a fragment present).
  """
  if not isinstance(value, str):
    raise TypeError(
      f"{field_name} element must be a string; got {type(value).__name__} (R-10.2-i)"
    )
  parts = urlsplit(value)
  if not parts.scheme:
    raise ValueError(
      f"{field_name} element {value!r} is not an absolute URI: a scheme "
      f"component is REQUIRED [RFC3986] (R-10.2-i)"
    )
  # RFC3986 absolute-URI = scheme ":" hier-part [ "?" query ] — no fragment.
  if parts.fragment:
    raise ValueError(
      f"{field_name} element {value!r} is not an absolute URI: a fragment "
      f"component is not permitted [RFC3986] (R-10.2-i)"
    )
  return value


# ---------------------------------------------------------------------------
# §10.2  SubscriptionFilter  [R-10.2-b, R-10.2-e–k]
# ---------------------------------------------------------------------------

@dataclass
class SubscriptionFilter:
  """The explicit opt-in describing which change notifications a client wants.

  Used both in the request (the requested filter) and in the acknowledgement
  (the honored subset). All fields are OPTIONAL (§10.2):

    toolsListChanged: when ``True``, request ``notifications/tools/list_changed``
      (R-10.2-e).
    promptsListChanged: when ``True``, request
      ``notifications/prompts/list_changed`` (R-10.2-f).
    resourcesListChanged: when ``True``, request
      ``notifications/resources/list_changed`` (R-10.2-g).
    resourceSubscriptions: absolute URI strings [RFC3986] for which per-resource
      ``notifications/resources/updated`` are requested; an absent or empty
      array means none (R-10.2-h, R-10.2-i).

  Omitting a field — or setting a boolean to ``False``, or an absent/empty
  ``resourceSubscriptions`` — is equivalent to not subscribing to that kind
  (R-10.2-j). A client SHOULD set at least one field; a filter with no kinds
  yields an acknowledgement-only stream (R-10.2-k).
  """

  tools_list_changed: bool = False
  prompts_list_changed: bool = False
  resources_list_changed: bool = False
  resource_subscriptions: tuple[str, ...] = ()

  def __post_init__(self) -> None:
    # Normalize the URI tuple and validate every element (R-10.2-i).
    normalized = tuple(self.resource_subscriptions)
    for uri in normalized:
      validate_absolute_uri(uri)
    object.__setattr__(self, "resource_subscriptions", normalized)

  @property
  def has_any_kind(self) -> bool:
    """True when at least one notification kind is requested (R-10.2-k).

    A filter for which this is False yields a stream carrying only the
    acknowledgement and no further notifications.
    """
    return bool(
      self.tools_list_changed
      or self.prompts_list_changed
      or self.resources_list_changed
      or self.resource_subscriptions
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits unset/false/empty fields.

    A boolean field is emitted only when ``True`` and the URI array only when
    non-empty, so the wire form follows R-10.2-j (omission == not subscribing).
    """
    out: dict[str, Any] = {}
    if self.tools_list_changed:
      out["toolsListChanged"] = True
    if self.prompts_list_changed:
      out["promptsListChanged"] = True
    if self.resources_list_changed:
      out["resourcesListChanged"] = True
    if self.resource_subscriptions:
      out["resourceSubscriptions"] = list(self.resource_subscriptions)
    return out

  def covers_resource(self, uri: str) -> bool:
    """True when ``uri`` is a subscribed resource or a sub-resource of one.

    A client that subscribed to a container URI (e.g. a directory) MAY receive
    updates whose ``uri`` is a contained resource (R-10.2-l, R-10.5-h/j). A
    contained resource is recognised when its path is at or below a subscribed
    URI's path under the same scheme and authority.
    """
    target = urlsplit(uri)
    for sub in self.resource_subscriptions:
      base = urlsplit(sub)
      if uri == sub:
        return True
      if target.scheme != base.scheme or target.netloc != base.netloc:
        continue
      base_path = base.path
      if not base_path.endswith("/"):
        base_path = base_path + "/"
      if target.path.startswith(base_path):
        return True
    return False


def parse_subscription_filter(raw: Any) -> SubscriptionFilter:
  """Parse and validate a `SubscriptionFilter` from a wire dict (§10.2).

  All fields are OPTIONAL (R-10.2-j); booleans must be booleans when present
  and ``resourceSubscriptions`` must be an array of absolute URI strings
  (R-10.2-e/f/g/h/i). Unknown members are ignored for forward compatibility.

  Raises:
    TypeError: raw is not an object, or a field has the wrong JSON type.
    ValueError: a ``resourceSubscriptions`` element is not an absolute URI.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"SubscriptionFilter must be a JSON object; got {type(raw).__name__}"
    )

  def _bool(key: str) -> bool:
    if key not in raw:
      return False
    val = raw[key]
    if not isinstance(val, bool):
      raise TypeError(
        f"{key} must be a boolean if present; got {type(val).__name__}"
      )
    return val

  subs_raw = raw.get("resourceSubscriptions")
  if subs_raw is None:
    subs: tuple[str, ...] = ()
  elif isinstance(subs_raw, list):
    # Every element MUST be an absolute URI string (R-10.2-i); __post_init__
    # re-validates, but doing it here yields a precise per-element message.
    for el in subs_raw:
      validate_absolute_uri(el)
    subs = tuple(subs_raw)
  else:
    raise TypeError(
      f"resourceSubscriptions must be an array if present; "
      f"got {type(subs_raw).__name__} (R-10.2-h)"
    )

  return SubscriptionFilter(
    tools_list_changed=_bool("toolsListChanged"),
    prompts_list_changed=_bool("promptsListChanged"),
    resources_list_changed=_bool("resourcesListChanged"),
    resource_subscriptions=subs,
  )


# ---------------------------------------------------------------------------
# §10.2  SubscriptionsListenRequest(Params)  [R-10.2-a–d]
# ---------------------------------------------------------------------------

@dataclass
class SubscriptionsListenRequestParams:
  """Parameters of a `subscriptions/listen` request (§10.2).

  Fields:
    notifications: REQUIRED `SubscriptionFilter` — the kinds the client opts in
      to on this stream; the server MUST NOT send kinds not requested here
      (R-10.2-b, R-10.2-c).
    meta: OPTIONAL request metadata per §4 (R-10.2-d). Wire key ``_meta``.
  """

  notifications: SubscriptionFilter
  meta: dict[str, Any] | None = None

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits ``_meta`` when absent."""
    out: dict[str, Any] = {"notifications": self.notifications.to_dict()}
    if self.meta is not None:
      out["_meta"] = self.meta
    return out


def parse_subscriptions_listen_request_params(
  raw: Any,
) -> SubscriptionsListenRequestParams:
  """Parse and validate `subscriptions/listen` params (§10.2).

  ``notifications`` is REQUIRED (R-10.2-b); the requested kinds are taken solely
  from this filter — there are no implicit or default subscriptions (R-10.1-c).
  ``_meta``, if present, is OPTIONAL request metadata (R-10.2-d).

  Raises:
    TypeError: raw or a field has the wrong JSON type.
    ValueError: ``notifications`` is absent.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"params must be a JSON object; got {type(raw).__name__} (R-10.2-a)"
    )
  if "notifications" not in raw:
    raise ValueError(
      "params.notifications (a SubscriptionFilter) is REQUIRED; the client MUST "
      "explicitly specify the kinds it wants (R-10.2-b, R-10.1-c)"
    )
  notifications = parse_subscription_filter(raw["notifications"])

  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__} (R-10.2-d)"
    )

  return SubscriptionsListenRequestParams(notifications=notifications, meta=meta)


def build_subscriptions_listen_request(
  request_id: RequestId,
  notifications: SubscriptionFilter,
  *,
  meta: dict[str, Any] | None = None,
) -> JSONRPCRequest:
  """Build the `subscriptions/listen` JSON-RPC request that opens a stream.

  The request is a JSON-RPC request (it carries an ``id``) and MUST carry a
  ``params`` object (R-10.2-a). Its ``id`` becomes the subscription identifier
  (R-10.4-b). The response is one long-lived stream carrying only the requested
  kinds, regardless of transport (R-10-a, R-10.1-a, R-10.1-b).

  Args:
    request_id: The JSON-RPC id; doubles as the subscription identifier.
    notifications: The opt-in filter.
    meta: OPTIONAL request metadata (R-10.2-d).

  Returns:
    A `JSONRPCRequest` for ``subscriptions/listen``.
  """
  validate_request_id(request_id)
  params = SubscriptionsListenRequestParams(notifications=notifications, meta=meta)
  return JSONRPCRequest(
    id=request_id,
    method=SUBSCRIPTIONS_LISTEN_METHOD,
    params=params.to_dict(),
  )


# ---------------------------------------------------------------------------
# §10.3  Acknowledgement  [R-10.3-a–f]
# ---------------------------------------------------------------------------

@dataclass
class SubscriptionsAcknowledgedNotificationParams:
  """Parameters of the `notifications/subscriptions/acknowledged` message (§10.3).

  Fields:
    notifications: REQUIRED `SubscriptionFilter` reflecting the subset of the
      requested filter the server actually supports and agreed to honor;
      unsupported kinds are omitted (R-10.3-c/d).
    subscription_id: REQUIRED subscription identifier carried in ``_meta`` under
      ``io.modelcontextprotocol/subscriptionId`` (R-10.3-e).
    extra_meta: any additional ``_meta`` members to carry alongside the
      reserved key.
  """

  notifications: SubscriptionFilter
  subscription_id: str
  extra_meta: dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict.

    Always stamps ``io.modelcontextprotocol/subscriptionId`` into ``_meta``
    verbatim (R-10.3-e, R-10.4-a/f).
    """
    meta: dict[str, Any] = dict(self.extra_meta)
    meta[SUBSCRIPTION_ID_META_KEY] = self.subscription_id
    return {
      "_meta": meta,
      "notifications": self.notifications.to_dict(),
    }


def build_acknowledgement(
  request_id: RequestId,
  honored: SubscriptionFilter,
  *,
  extra_meta: dict[str, Any] | None = None,
) -> JSONRPCNotification:
  """Build the mandatory first stream message: the acknowledgement (§10.3).

  This MUST be the FIRST message on the stream and MUST precede any change
  notification (R-10.1-e, R-10.3-a/b). Its ``notifications`` reflects the
  honored subset of the request (R-10.3-c/d) and it carries the subscription id
  in ``_meta`` (R-10.3-e, R-10.4-a).

  Args:
    request_id: The id of the originating `subscriptions/listen` request.
    honored: The `SubscriptionFilter` the server agreed to honor (a subset of
      the requested filter, with unsupported kinds omitted).
    extra_meta: any additional ``_meta`` members to include.

  Returns:
    A `JSONRPCNotification` for ``notifications/subscriptions/acknowledged``.
  """
  params = SubscriptionsAcknowledgedNotificationParams(
    notifications=honored,
    subscription_id=subscription_id_for(request_id),
    extra_meta=dict(extra_meta or {}),
  )
  return JSONRPCNotification(
    method=ACKNOWLEDGED_NOTIFICATION_METHOD,
    params=params.to_dict(),
  )


def honored_filter(
  requested: SubscriptionFilter,
  *,
  supports_tools_list_changed: bool = True,
  supports_prompts_list_changed: bool = True,
  supports_resources_list_changed: bool = True,
  supported_resource_uris: frozenset[str] | None = None,
) -> SubscriptionFilter:
  """Compute the honored subset of ``requested`` for the acknowledgement (§10.3).

  A notification kind the server does not support MUST be omitted from the
  acknowledged filter (R-10.3-d). A kind is honored only when it was both
  requested AND is supported by the server (R-10.5-l). The honored
  ``resourceSubscriptions`` reflects the subset of requested URIs the server
  will deliver updates for; when ``supported_resource_uris`` is None, every
  requested URI is honored.

  Args:
    requested: The filter the client sent.
    supports_*: Whether the server supports each list-changed kind.
    supported_resource_uris: When provided, only these requested URIs are
      honored; when None, all requested URIs are honored.

  Returns:
    A new `SubscriptionFilter` carrying only honored kinds.
  """
  if supported_resource_uris is None:
    honored_uris = requested.resource_subscriptions
  else:
    honored_uris = tuple(
      u for u in requested.resource_subscriptions if u in supported_resource_uris
    )
  return SubscriptionFilter(
    tools_list_changed=requested.tools_list_changed and supports_tools_list_changed,
    prompts_list_changed=(
      requested.prompts_list_changed and supports_prompts_list_changed
    ),
    resources_list_changed=(
      requested.resources_list_changed and supports_resources_list_changed
    ),
    resource_subscriptions=honored_uris,
  )


def declined_kinds(
  requested: SubscriptionFilter,
  acknowledged: SubscriptionFilter,
) -> frozenset[str]:
  """Return the requested kinds the server declined (omitted) in the ack (R-10.3-f).

  Clients SHOULD compare the acknowledged filter to what they requested and
  handle declined kinds gracefully — e.g. not waiting indefinitely for a kind
  the server omitted (R-10.3-f). Returned values are the change-notification
  method names that were requested but not honored. A requested resource URI is
  treated as declined when it is absent from the acknowledged URI set.
  """
  declined: set[str] = set()
  if requested.tools_list_changed and not acknowledged.tools_list_changed:
    declined.add(TOOLS_LIST_CHANGED_METHOD)
  if requested.prompts_list_changed and not acknowledged.prompts_list_changed:
    declined.add(PROMPTS_LIST_CHANGED_METHOD)
  if requested.resources_list_changed and not acknowledged.resources_list_changed:
    declined.add(RESOURCES_LIST_CHANGED_METHOD)
  acked_uris = set(acknowledged.resource_subscriptions)
  if any(u not in acked_uris for u in requested.resource_subscriptions):
    declined.add(RESOURCES_UPDATED_METHOD)
  return frozenset(declined)


# ---------------------------------------------------------------------------
# §10.4  Subscription correlation: stamp / extract  [R-10.4-a–f]
# ---------------------------------------------------------------------------

def stamp_subscription_id(
  params: dict[str, Any] | None,
  subscription_id: str,
) -> dict[str, Any]:
  """Return params with ``io.modelcontextprotocol/subscriptionId`` in ``_meta``.

  Every notification delivered for a subscription MUST carry the reserved key
  verbatim in ``params._meta`` (R-10.4-a/f). This is a pure function: it does
  not mutate the input.

  Args:
    params: The notification params (may be None → a fresh dict is made).
    subscription_id: The subscription identifier string (already serialized).

  Returns:
    A new params dict whose ``_meta`` carries the reserved key.
  """
  out: dict[str, Any] = dict(params or {})
  meta = dict(out.get("_meta") or {})
  meta[SUBSCRIPTION_ID_META_KEY] = subscription_id
  out["_meta"] = meta
  return out


def extract_subscription_id(notification: JSONRPCNotification) -> str | None:
  """Extract the subscription identifier from a notification's ``params._meta``.

  Returns the verbatim, case-sensitive value of
  ``io.modelcontextprotocol/subscriptionId`` (R-10.4-a/f), or None when absent.
  A client uses this to correlate each notification with its originating
  subscription — mandatory on stdio where one channel is shared (R-10.4-c) and
  still present on Streamable HTTP (R-10.4-d).
  """
  params = notification.params
  if not isinstance(params, dict):
    return None
  meta = params.get("_meta")
  if not isinstance(meta, dict):
    return None
  value = meta.get(SUBSCRIPTION_ID_META_KEY)
  return value if isinstance(value, str) else None


def has_subscription_id(notification: JSONRPCNotification) -> bool:
  """True when the notification carries the subscription correlation key (R-10.4-a)."""
  return extract_subscription_id(notification) is not None


# ---------------------------------------------------------------------------
# §10.5  Change-notification builders  [R-10.5-a–k]
# ---------------------------------------------------------------------------

def build_change_notification(
  method: str,
  request_id: RequestId,
  *,
  params: dict[str, Any] | None = None,
) -> JSONRPCNotification:
  """Build a change notification stamped with the subscription id (§10.5).

  Each change notification is a JSON-RPC notification (no ``id``) and MUST carry
  ``io.modelcontextprotocol/subscriptionId`` in ``params._meta`` (R-10.5-a). The
  carried payload shape (beyond the correlation key) is owned by the feature
  story; this stamps only the correlation key.

  Args:
    method: One of the four change-notification methods.
    request_id: The originating `subscriptions/listen` id.
    params: The notification payload (without the correlation key).

  Raises:
    ValueError: ``method`` is not one of the four change kinds.
  """
  if method not in CHANGE_NOTIFICATION_METHODS:
    raise ValueError(
      f"{method!r} is not a subscription change-notification kind; "
      f"expected one of {sorted(CHANGE_NOTIFICATION_METHODS)} (R-10.5-a)"
    )
  stamped = stamp_subscription_id(params, subscription_id_for(request_id))
  return JSONRPCNotification(method=method, params=stamped)


def build_resource_updated_notification(
  request_id: RequestId,
  uri: str,
  *,
  extra_params: dict[str, Any] | None = None,
) -> JSONRPCNotification:
  """Build a `notifications/resources/updated` notification (§10.5).

  The ``uri`` field is REQUIRED and MUST be an absolute URI string [RFC3986]
  identifying the resource that changed (R-10.5-i). The ``uri`` MAY be a
  sub-resource of a subscribed container URI (R-10.5-j); the client correlates
  via the subscription id, not solely via ``uri`` (R-10.5-k). The notification
  carries the subscription id in ``_meta`` (R-10.5-a).

  Raises:
    TypeError: ``uri`` is not a string.
    ValueError: ``uri`` is not an absolute URI.
  """
  validate_absolute_uri(uri, field_name="uri")
  payload: dict[str, Any] = dict(extra_params or {})
  payload["uri"] = uri
  return build_change_notification(
    RESOURCES_UPDATED_METHOD, request_id, params=payload
  )


def gate_change_notification(
  method: str,
  honored: SubscriptionFilter,
  *,
  uri: str | None = None,
) -> bool:
  """Return True iff the server MAY send ``method`` given the honored filter.

  A server MUST NOT send any of the four change kinds unless the corresponding
  filter field was both requested by the client and reflected in the
  acknowledged (honored) filter (R-10.1-d, R-10.2-c, R-10.5-b/d/f/h/l). For
  ``notifications/resources/updated``, the ``uri`` MUST be covered by the
  honored ``resourceSubscriptions`` — exactly or as a sub-resource of a
  subscribed container URI (R-10.2-l, R-10.2-m, R-10.5-h/j).

  Args:
    method: The change-notification method under consideration.
    honored: The filter the server acknowledged.
    uri: For ``notifications/resources/updated``, the URI that changed.

  Returns:
    Whether the notification is permitted on the stream.

  Raises:
    ValueError: ``method`` is not a change-notification kind, or ``uri`` is
      missing for a resource-updated notification.
  """
  if method == TOOLS_LIST_CHANGED_METHOD:
    return honored.tools_list_changed
  if method == PROMPTS_LIST_CHANGED_METHOD:
    return honored.prompts_list_changed
  if method == RESOURCES_LIST_CHANGED_METHOD:
    return honored.resources_list_changed
  if method == RESOURCES_UPDATED_METHOD:
    if uri is None:
      raise ValueError(
        "uri is REQUIRED to gate a resources/updated notification (R-10.5-i)"
      )
    return honored.covers_resource(uri)
  raise ValueError(
    f"{method!r} is not a subscription change-notification kind (R-10.5-a)"
  )


# ---------------------------------------------------------------------------
# §10.6  Boundary between subscription and request-scoped notifications
# ---------------------------------------------------------------------------

class StreamKind(Enum):
  """Which kind of stream a notification was observed on (§10.6).

  SUBSCRIPTION: the long-lived `subscriptions/listen` response stream.
  REQUEST_RESPONSE: the per-request response stream of some other request.
  """

  SUBSCRIPTION = "subscription"
  REQUEST_RESPONSE = "request_response"


class StreamBoundaryViolation(Exception):
  """Raised when a notification appears on the wrong stream (§10.6).

  A client receiving a notification on the wrong stream SHOULD treat it as a
  protocol violation (R-10.6-g). This is raised when:
    - a request-scoped notification (progress/message) appears on a subscription
      stream (R-10.6-b/e), or
    - one of the four change-notification kinds appears on the response stream
      of a request other than `subscriptions/listen` (R-10.6-d/f).

  Attributes:
    method: The offending notification method.
    stream_kind: The stream it was (wrongly) observed on.
  """

  def __init__(self, method: str, stream_kind: StreamKind) -> None:
    super().__init__(
      f"Notification {method!r} appeared on the wrong stream "
      f"({stream_kind.value}); SHOULD be treated as a protocol violation "
      f"(R-10.6-g)"
    )
    self.method: str = method
    self.stream_kind: StreamKind = stream_kind


def is_change_notification(method: str) -> bool:
  """True when ``method`` is one of the four subscription change kinds (§10.5)."""
  return method in CHANGE_NOTIFICATION_METHODS


def is_request_scoped_notification(method: str) -> bool:
  """True when ``method`` is a request-scoped notification (progress/message) (§10.6)."""
  return method in REQUEST_SCOPED_NOTIFICATION_METHODS


def check_stream_boundary(method: str, stream_kind: StreamKind) -> None:
  """Enforce the §10.6 boundary; raise on a wrong-stream notification.

  Rules (R-10.6-a–f), surfaced as `StreamBoundaryViolation` per R-10.6-g:
    - progress/message MUST NOT appear on a subscription stream (R-10.6-b/e).
    - the four change kinds MUST NOT appear on a non-`subscriptions/listen`
      request response stream (R-10.6-d/f).

  Other methods (e.g. unrelated notifications) are not constrained by this
  boundary and pass through.

  Raises:
    StreamBoundaryViolation: the notification is on the wrong stream.
  """
  if stream_kind is StreamKind.SUBSCRIPTION and is_request_scoped_notification(method):
    raise StreamBoundaryViolation(method, stream_kind)
  if stream_kind is StreamKind.REQUEST_RESPONSE and is_change_notification(method):
    raise StreamBoundaryViolation(method, stream_kind)


# ---------------------------------------------------------------------------
# §10.7  Subscription lifecycle  [R-10.7-a–f]
# ---------------------------------------------------------------------------

class SubscriptionState(Enum):
  """Lifecycle states of a subscription (§10.7).

  OPENING: the `subscriptions/listen` request has been sent; awaiting the ack.
  ACTIVE: the acknowledgement arrived first; the stream delivers opted-in kinds.
  CLOSED: the stream ended (client cancel, server teardown, or transport loss);
    the server retains NO state (R-10.7-d).
  """

  OPENING = "opening"
  ACTIVE = "active"
  CLOSED = "closed"


class SubscriptionClosedError(Exception):
  """Raised when operating on a subscription whose stream has already ended.

  A closed subscription is not resumable; the client must open a NEW one via a
  fresh `subscriptions/listen`, yielding a new identifier (R-10.1-h, R-10.7-f).
  """


@dataclass
class Subscription:
  """A single client-side subscription and its lifecycle (§10.1, §10.7).

  A subscription is opened by one `subscriptions/listen` request and bound to
  one long-lived stream (R-10.1-b). It is identified by the JSON-RPC ``id`` of
  that request (R-10.1-i, R-10.4-b). It carries no retained state once closed
  (R-10.7-d); it is re-established only by a NEW `subscriptions/listen`
  (R-10.1-h, R-10.7-f) — never by ``Last-Event-ID`` or a GET endpoint
  (R-10.1-g, R-10.7-f).

  Fields:
    request_id: The id of the opening request.
    requested: The filter the client requested.
    state: Current lifecycle state.
    acknowledged: The honored filter (set once the ack arrives).
  """

  request_id: RequestId
  requested: SubscriptionFilter
  state: SubscriptionState = SubscriptionState.OPENING
  acknowledged: SubscriptionFilter | None = None

  def __post_init__(self) -> None:
    validate_request_id(self.request_id)

  @property
  def subscription_id(self) -> str:
    """The subscription identifier string (request id serialized) (R-10.4-b)."""
    return subscription_id_for(self.request_id)

  def acknowledge(self, ack: JSONRPCNotification) -> SubscriptionFilter:
    """Consume the mandatory first message and transition OPENING → ACTIVE.

    The first message MUST be a `notifications/subscriptions/acknowledged`
    carrying the matching subscription id (R-10.1-e, R-10.3-a/b, R-10.4-a).

    Returns:
      The honored `SubscriptionFilter`.

    Raises:
      SubscriptionClosedError: the subscription is already closed.
      StreamBoundaryViolation: the first message is not the acknowledgement.
      ValueError: the ack's subscription id does not match this subscription,
        or it lacks the required ``notifications`` filter.
    """
    if self.state is SubscriptionState.CLOSED:
      raise SubscriptionClosedError(
        f"subscription {self.subscription_id!r} is closed and not resumable "
        f"(R-10.1-h, R-10.7-f)"
      )
    if ack.method != ACKNOWLEDGED_NOTIFICATION_METHOD:
      # The first message MUST be the acknowledgement (R-10.1-e, R-10.3-a/b).
      raise StreamBoundaryViolation(ack.method, StreamKind.SUBSCRIPTION)
    sid = extract_subscription_id(ack)
    if sid != self.subscription_id:
      raise ValueError(
        f"acknowledgement subscription id {sid!r} does not match subscription "
        f"{self.subscription_id!r} (R-10.4-a/b)"
      )
    params = ack.params if isinstance(ack.params, dict) else {}
    if "notifications" not in params:
      raise ValueError(
        "acknowledgement params.notifications is REQUIRED (R-10.3-c)"
      )
    honored = parse_subscription_filter(params["notifications"])
    self.acknowledged = honored
    self.state = SubscriptionState.ACTIVE
    return honored

  def close(self) -> None:
    """Mark the subscription CLOSED (client cancel, teardown, or transport loss).

    Idempotent. Once closed there is no resumption: re-establish with a NEW
    `subscriptions/listen` (R-10.7-a/b/c/d/f).
    """
    self.state = SubscriptionState.CLOSED
    # The server retains no state; the client keeps only enough to know it is
    # gone (R-10.7-d). The honored filter is cleared so nothing is implicitly
    # reused on a later, distinct subscription.
    self.acknowledged = None

  def accepts(self, notification: JSONRPCNotification) -> bool:
    """True when ``notification`` belongs to this active subscription (R-10.4-c).

    Correlates strictly by ``io.modelcontextprotocol/subscriptionId``, never by
    URI alone (R-10.4-c, R-10.5-k). A closed subscription accepts nothing.
    """
    if self.state is SubscriptionState.CLOSED:
      return False
    return extract_subscription_id(notification) == self.subscription_id


class SubscriptionRegistry:
  """Client-side router for concurrent subscriptions over one channel (§10.1, §10.4).

  A client MAY hold multiple active subscriptions concurrently, each independent
  and identified by its `subscriptions/listen` id (R-10.1-i). On stdio, where
  all messages share one channel, the client MUST route each incoming
  notification to the correct subscription using
  ``io.modelcontextprotocol/subscriptionId`` (R-10.4-c). The registry keeps NO
  resumable state: a dropped subscription is removed and re-established only by a
  fresh `subscriptions/listen` (R-10.7-d/e/f).
  """

  def __init__(self) -> None:
    self._subscriptions: dict[str, Subscription] = {}

  def open(
    self,
    request_id: RequestId,
    requested: SubscriptionFilter,
  ) -> Subscription:
    """Register a new subscription for a `subscriptions/listen` request.

    Each subscription is independent and keyed by its own id (R-10.1-i).

    Raises:
      ValueError: a live (non-closed) subscription with this id already exists.
    """
    sid = subscription_id_for(request_id)
    existing = self._subscriptions.get(sid)
    if existing is not None and existing.state is not SubscriptionState.CLOSED:
      raise ValueError(
        f"a subscription with id {sid!r} is already active (R-10.1-i)"
      )
    sub = Subscription(request_id=request_id, requested=requested)
    self._subscriptions[sid] = sub
    return sub

  def get(self, subscription_id: str) -> Subscription | None:
    """Return the subscription for an id string, or None."""
    return self._subscriptions.get(subscription_id)

  def route(self, notification: JSONRPCNotification) -> Subscription:
    """Route an incoming subscription notification to its subscription (R-10.4-c).

    Correlates by ``io.modelcontextprotocol/subscriptionId`` (R-10.4-a/c). The
    notification MUST be one permitted on a subscription stream — the
    acknowledgement or one of the four change kinds; a request-scoped
    notification here is a boundary violation (R-10.6-b/e/g).

    Raises:
      StreamBoundaryViolation: a request-scoped notification arrived here.
      ValueError: the notification lacks the correlation key, or no open
        subscription matches it.
    """
    check_stream_boundary(notification.method, StreamKind.SUBSCRIPTION)
    sid = extract_subscription_id(notification)
    if sid is None:
      raise ValueError(
        f"notification {notification.method!r} on a subscription stream MUST "
        f"carry {SUBSCRIPTION_ID_META_KEY!r} (R-10.4-a)"
      )
    sub = self._subscriptions.get(sid)
    if sub is None or sub.state is SubscriptionState.CLOSED:
      raise ValueError(
        f"no open subscription matches id {sid!r}; subscriptions are not "
        f"resumable and must be re-opened (R-10.7-d/f)"
      )
    return sub

  def close(self, subscription_id: str) -> None:
    """Close and forget a subscription, retaining no resumable state (R-10.7-d).

    Idempotent. After closing, the id is no longer routable; re-establishment
    requires a NEW `subscriptions/listen` (R-10.7-e/f).
    """
    sub = self._subscriptions.pop(subscription_id, None)
    if sub is not None:
      sub.close()

  def clear(self) -> None:
    """Drop all subscriptions, e.g. on transport closure (R-10.7-c/d).

    When the underlying connection is lost, every subscription ends and no
    state is retained; the client MUST re-issue each `subscriptions/listen` it
    wants on reconnect (R-10.7-c/d/e).
    """
    for sub in self._subscriptions.values():
      sub.close()
    self._subscriptions.clear()

  @property
  def active_ids(self) -> frozenset[str]:
    """The ids of all currently tracked (non-closed) subscriptions."""
    return frozenset(
      sid
      for sid, sub in self._subscriptions.items()
      if sub.state is not SubscriptionState.CLOSED
    )


# ---------------------------------------------------------------------------
# §10.7  Cancellation helpers  [R-10.7-a, R-10.7-b]
# ---------------------------------------------------------------------------

def build_subscription_cancellation(request_id: RequestId) -> JSONRPCNotification:
  """Build the stdio cancellation/teardown signal for a subscription (§10.7).

  On stdio, a client cancels a subscription — and a server signals teardown — by
  sending a `notifications/cancelled` referencing the ``id`` of the
  `subscriptions/listen` request (R-10.7-a/b). On Streamable HTTP, cancellation
  and teardown are instead performed by closing the ``text/event-stream``
  response (no message); see `close_streamable_http_subscription`.

  This reuses the `notifications/cancelled` shape from S22.
  """
  validate_request_id(request_id)
  return JSONRPCNotification(
    method="notifications/cancelled",
    params={"requestId": request_id},
  )


def close_streamable_http_subscription(subscription: Subscription) -> None:
  """Cancel/tear down a Streamable HTTP subscription by closing its SSE stream.

  On Streamable HTTP, both client cancellation and server teardown are performed
  by closing the ``text/event-stream`` response of the `subscriptions/listen`
  POST — there is no cancellation message on the wire (R-10.7-a/b). The actual
  socket close is owned by the transport (S14/S15); this records the resulting
  lifecycle transition.
  """
  subscription.close()
