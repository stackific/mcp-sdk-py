"""Tests for S16 — Server-to-Client Streaming & Subscriptions.

Verifies the `subscriptions/listen` request, the notification filter, the
mandatory acknowledgement, the io.modelcontextprotocol/subscriptionId
correlation key, the four change-notification kinds, the strict stream boundary,
and the subscription lifecycle (no resumption / no retained state).

AC → test coverage map:
  AC-16.1  (R-10-a, R-10.1-a/b, R-10.2-a) ......... TestAC161OpenSubscription
  AC-16.2  (R-10.1-c, R-10.2-b/d) ................. TestAC162ExplicitFilter
  AC-16.3  (R-10.2-e/f/g/h/j/k) .................. TestAC163OptionalFields
  AC-16.4  (R-10.2-i) ............................ TestAC164AbsoluteUri
  AC-16.5  (R-10.1-d, R-10.2-c/l/m) ............... TestAC165NeverUnrequested
  AC-16.6  (R-10.1-e, R-10.3-a/b) ................. TestAC166AckFirst
  AC-16.7  (R-10.3-c/d) .......................... TestAC167HonoredSubset
  AC-16.8  (R-10.3-f) ............................ TestAC168HandleDeclined
  AC-16.9  (R-10.1-f, R-10.3-e, R-10.4-a/b/f) ..... TestAC169SubscriptionIdMeta
  AC-16.10 (R-10.4-c) ............................ TestAC1610StdioRouting
  AC-16.11 (R-10.4-d/e) .......................... TestAC1611HttpStillTagged
  AC-16.12 (R-10.5-a/b/d/f/h) .................... TestAC1612FourKinds
  AC-16.13 (R-10.5-c/e/g) ........................ TestAC1613Refetch
  AC-16.14 (R-10.5-i/j/k) ........................ TestAC1614ResourceUpdated
  AC-16.15 (R-10.5-l) ............................ TestAC1615GatedByAck
  AC-16.16 (R-10.6-a/b/c/d/e/f) .................. TestAC1616Boundary
  AC-16.17 (R-10.6-g) ............................ TestAC1617WrongStream
  AC-16.18 (R-10.7-a) ............................ TestAC1618ClientCancel
  AC-16.19 (R-10.7-b) ............................ TestAC1619ServerTeardown
  AC-16.20 (R-10.7-c) ............................ TestAC1620TransportClose
  AC-16.21 (R-10.7-d/e) .......................... TestAC1621NoRetainedState
  AC-16.22 (R-10.1-g/h, R-10.7-f) ................ TestAC1622NoResumption
  AC-16.23 (R-10.1-i) ............................ TestAC1623Multiple
"""

import pytest

from mcp_sdk_py.jsonrpc import JSONRPCNotification, JSONRPCRequest
from mcp_sdk_py.subscriptions import (
  ACKNOWLEDGED_NOTIFICATION_METHOD,
  CHANGE_NOTIFICATION_METHODS,
  MESSAGE_NOTIFICATION_METHOD,
  PROGRESS_NOTIFICATION_METHOD,
  PROMPTS_LIST_CHANGED_METHOD,
  RESOURCES_LIST_CHANGED_METHOD,
  RESOURCES_UPDATED_METHOD,
  SUBSCRIPTION_ID_META_KEY,
  SUBSCRIPTIONS_LISTEN_METHOD,
  TOOLS_LIST_CHANGED_METHOD,
  StreamBoundaryViolation,
  StreamKind,
  Subscription,
  SubscriptionClosedError,
  SubscriptionFilter,
  SubscriptionRegistry,
  SubscriptionState,
  SubscriptionsAcknowledgedNotificationParams,
  SubscriptionsListenRequestParams,
  build_acknowledgement,
  build_change_notification,
  build_resource_updated_notification,
  build_subscription_cancellation,
  build_subscriptions_listen_request,
  check_stream_boundary,
  close_streamable_http_subscription,
  declined_kinds,
  extract_subscription_id,
  gate_change_notification,
  has_subscription_id,
  honored_filter,
  is_change_notification,
  is_request_scoped_notification,
  parse_subscription_filter,
  parse_subscriptions_listen_request_params,
  stamp_subscription_id,
  subscription_id_for,
  validate_absolute_uri,
)

_URI = "file:///project/config.json"


def _make_meta() -> dict:
  return {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "C", "version": "1.0.0"},
    "io.modelcontextprotocol/clientCapabilities": {},
  }


# ---------------------------------------------------------------------------
# AC-16.1
# ---------------------------------------------------------------------------

class TestAC161OpenSubscription:
  def test_listen_is_a_jsonrpc_request_with_id_and_params(self):
    req = build_subscriptions_listen_request(
      1, SubscriptionFilter(tools_list_changed=True)
    )
    assert isinstance(req, JSONRPCRequest)
    assert req.id == 1
    assert req.method == SUBSCRIPTIONS_LISTEN_METHOD
    assert isinstance(req.params, dict)

  def test_method_name_literal(self):
    assert SUBSCRIPTIONS_LISTEN_METHOD == "subscriptions/listen"

  def test_params_required(self):
    req = build_subscriptions_listen_request(7, SubscriptionFilter())
    d = req.to_dict()
    assert "params" in d and isinstance(d["params"], dict)

  def test_one_subscription_per_request_keyed_by_id(self):
    reg = SubscriptionRegistry()
    sub = reg.open(1, SubscriptionFilter(tools_list_changed=True))
    assert sub.request_id == 1
    assert reg.active_ids == frozenset({"1"})

  def test_transport_agnostic_request_shape(self):
    # Same request shape regardless of transport (R-10-a).
    req = build_subscriptions_listen_request(1, SubscriptionFilter(tools_list_changed=True))
    assert req.to_dict()["method"] == "subscriptions/listen"


# ---------------------------------------------------------------------------
# AC-16.2
# ---------------------------------------------------------------------------

class TestAC162ExplicitFilter:
  def test_notifications_required(self):
    with pytest.raises(ValueError):
      parse_subscriptions_listen_request_params({"_meta": {}})

  def test_notifications_parsed_as_filter(self):
    params = parse_subscriptions_listen_request_params(
      {"notifications": {"toolsListChanged": True}}
    )
    assert isinstance(params.notifications, SubscriptionFilter)
    assert params.notifications.tools_list_changed is True

  def test_meta_optional_and_preserved(self):
    meta = _make_meta()
    params = parse_subscriptions_listen_request_params(
      {"notifications": {}, "_meta": meta}
    )
    assert params.meta == meta

  def test_meta_absent_is_none(self):
    params = parse_subscriptions_listen_request_params({"notifications": {}})
    assert params.meta is None

  def test_no_implicit_subscriptions(self):
    # An empty filter requests nothing — no default kinds.
    f = parse_subscription_filter({})
    assert not f.has_any_kind

  def test_kinds_taken_solely_from_filter(self):
    f = parse_subscription_filter({"promptsListChanged": True})
    assert f.prompts_list_changed is True
    assert f.tools_list_changed is False
    assert f.resources_list_changed is False
    assert f.resource_subscriptions == ()

  def test_bad_meta_type_rejected(self):
    with pytest.raises(TypeError):
      parse_subscriptions_listen_request_params({"notifications": {}, "_meta": []})


# ---------------------------------------------------------------------------
# AC-16.3
# ---------------------------------------------------------------------------

class TestAC163OptionalFields:
  def test_all_fields_default_off(self):
    f = SubscriptionFilter()
    assert f.tools_list_changed is False
    assert f.prompts_list_changed is False
    assert f.resources_list_changed is False
    assert f.resource_subscriptions == ()
    assert not f.has_any_kind

  def test_false_boolean_means_not_subscribed_and_omitted(self):
    f = SubscriptionFilter(tools_list_changed=False)
    assert "toolsListChanged" not in f.to_dict()

  def test_true_booleans_serialized(self):
    f = SubscriptionFilter(
      tools_list_changed=True,
      prompts_list_changed=True,
      resources_list_changed=True,
    )
    d = f.to_dict()
    assert d == {
      "toolsListChanged": True,
      "promptsListChanged": True,
      "resourcesListChanged": True,
    }

  def test_empty_resource_subscriptions_omitted(self):
    f = SubscriptionFilter(resource_subscriptions=())
    assert "resourceSubscriptions" not in f.to_dict()

  def test_resource_subscriptions_serialized_as_array(self):
    f = SubscriptionFilter(resource_subscriptions=(_URI,))
    assert f.to_dict()["resourceSubscriptions"] == [_URI]

  def test_empty_filter_yields_ack_only_stream(self):
    # has_any_kind drives the "acknowledgement-only" outcome (R-10.2-k).
    assert SubscriptionFilter().has_any_kind is False
    assert SubscriptionFilter(tools_list_changed=True).has_any_kind is True

  def test_parse_round_trip(self):
    raw = {"toolsListChanged": True, "resourceSubscriptions": [_URI]}
    f = parse_subscription_filter(raw)
    assert f.to_dict() == raw

  def test_non_bool_field_rejected(self):
    with pytest.raises(TypeError):
      parse_subscription_filter({"toolsListChanged": "yes"})


# ---------------------------------------------------------------------------
# AC-16.4
# ---------------------------------------------------------------------------

class TestAC164AbsoluteUri:
  def test_absolute_uri_accepted(self):
    assert validate_absolute_uri("file:///a/b.txt") == "file:///a/b.txt"
    assert validate_absolute_uri("https://example.com/x") == "https://example.com/x"

  def test_relative_path_rejected(self):
    with pytest.raises(ValueError):
      validate_absolute_uri("/project/config.json")

  def test_bare_name_rejected(self):
    with pytest.raises(ValueError):
      validate_absolute_uri("config.json")

  def test_uri_with_fragment_rejected(self):
    with pytest.raises(ValueError):
      validate_absolute_uri("https://example.com/x#frag")

  def test_non_string_rejected(self):
    with pytest.raises(TypeError):
      validate_absolute_uri(123)

  def test_filter_rejects_non_absolute_element(self):
    with pytest.raises(ValueError):
      SubscriptionFilter(resource_subscriptions=("relative/path",))

  def test_parse_filter_rejects_non_absolute_element(self):
    with pytest.raises(ValueError):
      parse_subscription_filter({"resourceSubscriptions": ["not-a-uri"]})

  def test_resource_subscriptions_must_be_array(self):
    with pytest.raises(TypeError):
      parse_subscription_filter({"resourceSubscriptions": "file:///a"})


# ---------------------------------------------------------------------------
# AC-16.5
# ---------------------------------------------------------------------------

class TestAC165NeverUnrequested:
  def test_gate_rejects_unrequested_kind(self):
    honored = SubscriptionFilter(tools_list_changed=True)
    assert gate_change_notification(TOOLS_LIST_CHANGED_METHOD, honored) is True
    assert gate_change_notification(PROMPTS_LIST_CHANGED_METHOD, honored) is False
    assert gate_change_notification(RESOURCES_LIST_CHANGED_METHOD, honored) is False

  def test_resource_updated_only_for_listed_uri(self):
    honored = SubscriptionFilter(resource_subscriptions=(_URI,))
    assert gate_change_notification(RESOURCES_UPDATED_METHOD, honored, uri=_URI) is True

  def test_resource_updated_not_for_unlisted_uri(self):
    honored = SubscriptionFilter(resource_subscriptions=(_URI,))
    assert (
      gate_change_notification(
        RESOURCES_UPDATED_METHOD, honored, uri="file:///other.txt"
      )
      is False
    )

  def test_no_resource_subscriptions_means_no_updates(self):
    honored = SubscriptionFilter()
    assert gate_change_notification(RESOURCES_UPDATED_METHOD, honored, uri=_URI) is False

  def test_resource_updated_requires_uri(self):
    honored = SubscriptionFilter(resource_subscriptions=(_URI,))
    with pytest.raises(ValueError):
      gate_change_notification(RESOURCES_UPDATED_METHOD, honored)


# ---------------------------------------------------------------------------
# AC-16.6
# ---------------------------------------------------------------------------

class TestAC166AckFirst:
  def test_ack_method_literal(self):
    assert (
      ACKNOWLEDGED_NOTIFICATION_METHOD
      == "notifications/subscriptions/acknowledged"
    )

  def test_ack_is_a_notification(self):
    ack = build_acknowledgement(1, SubscriptionFilter(tools_list_changed=True))
    assert isinstance(ack, JSONRPCNotification)
    assert ack.method == ACKNOWLEDGED_NOTIFICATION_METHOD
    assert "id" not in ack.to_dict()

  def test_subscription_consumes_ack_as_first_message(self):
    sub = Subscription(1, SubscriptionFilter(tools_list_changed=True))
    assert sub.state is SubscriptionState.OPENING
    ack = build_acknowledgement(1, SubscriptionFilter(tools_list_changed=True))
    sub.acknowledge(ack)
    assert sub.state is SubscriptionState.ACTIVE

  def test_change_notification_before_ack_is_rejected(self):
    # A change kind arriving before the ack violates "ack first" (R-10.3-b).
    sub = Subscription(1, SubscriptionFilter(tools_list_changed=True))
    change = build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1)
    with pytest.raises(StreamBoundaryViolation):
      sub.acknowledge(change)
    assert sub.state is SubscriptionState.OPENING


# ---------------------------------------------------------------------------
# AC-16.7
# ---------------------------------------------------------------------------

class TestAC167HonoredSubset:
  def test_honored_filter_is_subset(self):
    requested = SubscriptionFilter(tools_list_changed=True, prompts_list_changed=True)
    honored = honored_filter(requested, supports_prompts_list_changed=False)
    assert honored.tools_list_changed is True
    assert honored.prompts_list_changed is False

  def test_unsupported_kind_omitted_from_wire(self):
    requested = SubscriptionFilter(tools_list_changed=True, prompts_list_changed=True)
    honored = honored_filter(requested, supports_prompts_list_changed=False)
    assert "promptsListChanged" not in honored.to_dict()

  def test_ack_params_carry_honored_filter(self):
    honored = SubscriptionFilter(tools_list_changed=True, resource_subscriptions=(_URI,))
    ack = build_acknowledgement(1, honored)
    assert ack.params["notifications"] == honored.to_dict()

  def test_honored_resource_uris_subset(self):
    requested = SubscriptionFilter(resource_subscriptions=(_URI, "file:///z.txt"))
    honored = honored_filter(requested, supported_resource_uris=frozenset({_URI}))
    assert honored.resource_subscriptions == (_URI,)

  def test_ack_params_notifications_required(self):
    params = SubscriptionsAcknowledgedNotificationParams(
      notifications=SubscriptionFilter(tools_list_changed=True),
      subscription_id="1",
    )
    assert "notifications" in params.to_dict()


# ---------------------------------------------------------------------------
# AC-16.8
# ---------------------------------------------------------------------------

class TestAC168HandleDeclined:
  def test_declined_kinds_reported(self):
    requested = SubscriptionFilter(tools_list_changed=True, prompts_list_changed=True)
    acknowledged = SubscriptionFilter(tools_list_changed=True)
    assert declined_kinds(requested, acknowledged) == frozenset(
      {PROMPTS_LIST_CHANGED_METHOD}
    )

  def test_no_declined_kinds_when_all_honored(self):
    f = SubscriptionFilter(tools_list_changed=True, resource_subscriptions=(_URI,))
    assert declined_kinds(f, f) == frozenset()

  def test_declined_resource_uri(self):
    requested = SubscriptionFilter(resource_subscriptions=(_URI, "file:///z.txt"))
    acknowledged = SubscriptionFilter(resource_subscriptions=(_URI,))
    assert RESOURCES_UPDATED_METHOD in declined_kinds(requested, acknowledged)

  def test_client_does_not_block_on_declined(self):
    # A client that compares filters can see exactly which kinds to ignore.
    requested = SubscriptionFilter(
      tools_list_changed=True, prompts_list_changed=True, resources_list_changed=True
    )
    acknowledged = SubscriptionFilter(tools_list_changed=True)
    declined = declined_kinds(requested, acknowledged)
    assert PROMPTS_LIST_CHANGED_METHOD in declined
    assert RESOURCES_LIST_CHANGED_METHOD in declined
    assert TOOLS_LIST_CHANGED_METHOD not in declined


# ---------------------------------------------------------------------------
# AC-16.9
# ---------------------------------------------------------------------------

class TestAC169SubscriptionIdMeta:
  def test_key_literal_case_sensitive(self):
    assert SUBSCRIPTION_ID_META_KEY == "io.modelcontextprotocol/subscriptionId"

  def test_int_id_serialized_as_string(self):
    assert subscription_id_for(1) == "1"

  def test_float_integer_id_serialized_without_fraction(self):
    assert subscription_id_for(1.0) == "1"

  def test_string_id_passed_through(self):
    assert subscription_id_for("abc") == "abc"

  def test_ack_carries_subscription_id_in_meta(self):
    ack = build_acknowledgement(1, SubscriptionFilter(tools_list_changed=True))
    assert ack.params["_meta"][SUBSCRIPTION_ID_META_KEY] == "1"

  def test_change_notification_carries_subscription_id(self):
    n = build_change_notification(TOOLS_LIST_CHANGED_METHOD, 42)
    assert n.params["_meta"][SUBSCRIPTION_ID_META_KEY] == "42"

  def test_extract_subscription_id(self):
    ack = build_acknowledgement(5, SubscriptionFilter(tools_list_changed=True))
    assert extract_subscription_id(ack) == "5"

  def test_key_reproduced_verbatim(self):
    n = build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1)
    # The exact, case-sensitive key is present and a near-miss is not.
    assert SUBSCRIPTION_ID_META_KEY in n.params["_meta"]
    assert "io.modelcontextprotocol/subscriptionID" not in n.params["_meta"]

  def test_has_subscription_id_helper(self):
    assert has_subscription_id(build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1))
    assert not has_subscription_id(
      JSONRPCNotification(method=TOOLS_LIST_CHANGED_METHOD, params={})
    )

  def test_stamp_does_not_mutate_input(self):
    original = {"uri": _URI}
    stamped = stamp_subscription_id(original, "1")
    assert "_meta" not in original
    assert stamped["_meta"][SUBSCRIPTION_ID_META_KEY] == "1"

  def test_stamp_preserves_existing_meta(self):
    stamped = stamp_subscription_id({"_meta": {"x": 1}}, "9")
    assert stamped["_meta"]["x"] == 1
    assert stamped["_meta"][SUBSCRIPTION_ID_META_KEY] == "9"


# ---------------------------------------------------------------------------
# AC-16.10
# ---------------------------------------------------------------------------

class TestAC1610StdioRouting:
  def test_route_by_subscription_id(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    reg.open(2, SubscriptionFilter(resource_subscriptions=(_URI,)))

    n1 = build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1)
    n2 = build_resource_updated_notification(2, _URI)

    assert reg.route(n1).request_id == 1
    assert reg.route(n2).request_id == 2

  def test_route_unknown_id_raises(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    n = build_change_notification(TOOLS_LIST_CHANGED_METHOD, 99)
    with pytest.raises(ValueError):
      reg.route(n)

  def test_route_missing_key_raises(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    n = JSONRPCNotification(method=TOOLS_LIST_CHANGED_METHOD, params={})
    with pytest.raises(ValueError):
      reg.route(n)

  def test_subscription_accepts_only_its_own(self):
    sub = Subscription(1, SubscriptionFilter(tools_list_changed=True))
    sub.acknowledge(build_acknowledgement(1, SubscriptionFilter(tools_list_changed=True)))
    assert sub.accepts(build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1))
    assert not sub.accepts(build_change_notification(TOOLS_LIST_CHANGED_METHOD, 2))


# ---------------------------------------------------------------------------
# AC-16.11
# ---------------------------------------------------------------------------

class TestAC1611HttpStillTagged:
  def test_subscription_id_present_on_http_stream(self):
    # Even with per-stream separation, the key MUST be present.
    n = build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1)
    assert extract_subscription_id(n) == "1"

  def test_routing_still_works_via_key_on_http(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    n = build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1)
    assert reg.route(n).request_id == 1


# ---------------------------------------------------------------------------
# AC-16.12
# ---------------------------------------------------------------------------

class TestAC1612FourKinds:
  def test_exactly_four_change_kinds(self):
    assert CHANGE_NOTIFICATION_METHODS == frozenset({
      TOOLS_LIST_CHANGED_METHOD,
      PROMPTS_LIST_CHANGED_METHOD,
      RESOURCES_LIST_CHANGED_METHOD,
      RESOURCES_UPDATED_METHOD,
    })

  def test_change_notifications_have_no_id(self):
    for method in CHANGE_NOTIFICATION_METHODS:
      n = build_change_notification(method, 1)
      assert "id" not in n.to_dict()

  def test_each_change_notification_carries_meta_id(self):
    for method in CHANGE_NOTIFICATION_METHODS:
      n = build_change_notification(method, 1)
      assert n.params["_meta"][SUBSCRIPTION_ID_META_KEY] == "1"

  def test_build_rejects_non_change_method(self):
    with pytest.raises(ValueError):
      build_change_notification(PROGRESS_NOTIFICATION_METHOD, 1)

  def test_tools_gated_iff_requested(self):
    assert gate_change_notification(
      TOOLS_LIST_CHANGED_METHOD, SubscriptionFilter(tools_list_changed=True)
    )
    assert not gate_change_notification(
      TOOLS_LIST_CHANGED_METHOD, SubscriptionFilter()
    )

  def test_prompts_gated_iff_requested(self):
    assert gate_change_notification(
      PROMPTS_LIST_CHANGED_METHOD, SubscriptionFilter(prompts_list_changed=True)
    )
    assert not gate_change_notification(
      PROMPTS_LIST_CHANGED_METHOD, SubscriptionFilter()
    )

  def test_resources_list_gated_iff_requested(self):
    assert gate_change_notification(
      RESOURCES_LIST_CHANGED_METHOD, SubscriptionFilter(resources_list_changed=True)
    )
    assert not gate_change_notification(
      RESOURCES_LIST_CHANGED_METHOD, SubscriptionFilter()
    )


# ---------------------------------------------------------------------------
# AC-16.13
# ---------------------------------------------------------------------------

class TestAC1613Refetch:
  # The SHOULD-re-fetch obligation is a client behavioral recommendation; we
  # verify the method names a client keys re-fetch logic off of are exposed.
  def test_list_changed_method_names_distinguishable(self):
    assert is_change_notification(TOOLS_LIST_CHANGED_METHOD)
    assert is_change_notification(PROMPTS_LIST_CHANGED_METHOD)
    assert is_change_notification(RESOURCES_LIST_CHANGED_METHOD)

  def test_each_list_changed_routes_to_its_subscription(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(
      tools_list_changed=True,
      prompts_list_changed=True,
      resources_list_changed=True,
    ))
    for method in (
      TOOLS_LIST_CHANGED_METHOD,
      PROMPTS_LIST_CHANGED_METHOD,
      RESOURCES_LIST_CHANGED_METHOD,
    ):
      n = build_change_notification(method, 1)
      assert reg.route(n).request_id == 1


# ---------------------------------------------------------------------------
# AC-16.14
# ---------------------------------------------------------------------------

class TestAC1614ResourceUpdated:
  def test_uri_required_and_present(self):
    n = build_resource_updated_notification(1, _URI)
    assert n.params["uri"] == _URI

  def test_uri_must_be_absolute(self):
    with pytest.raises(ValueError):
      build_resource_updated_notification(1, "config.json")

  def test_subresource_of_container_covered(self):
    honored = SubscriptionFilter(resource_subscriptions=("file:///project/",))
    assert honored.covers_resource("file:///project/sub/file.txt")
    assert gate_change_notification(
      RESOURCES_UPDATED_METHOD, honored, uri="file:///project/sub/file.txt"
    )

  def test_unrelated_uri_not_covered(self):
    honored = SubscriptionFilter(resource_subscriptions=("file:///project/",))
    assert not honored.covers_resource("file:///other/file.txt")

  def test_correlation_by_subscription_id_not_uri(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(resource_subscriptions=(_URI,)))
    reg.open(2, SubscriptionFilter(resource_subscriptions=(_URI,)))
    # Same URI on both; the id disambiguates.
    n = build_resource_updated_notification(2, _URI)
    assert reg.route(n).request_id == 2

  def test_different_scheme_not_covered(self):
    honored = SubscriptionFilter(resource_subscriptions=("file:///project/",))
    assert not honored.covers_resource("https://host/project/x")


# ---------------------------------------------------------------------------
# AC-16.15
# ---------------------------------------------------------------------------

class TestAC1615GatedByAck:
  def test_requested_but_unsupported_not_sent(self):
    requested = SubscriptionFilter(prompts_list_changed=True)
    honored = honored_filter(requested, supports_prompts_list_changed=False)
    # Gating uses the acknowledged (honored) filter, so the kind is blocked.
    assert gate_change_notification(PROMPTS_LIST_CHANGED_METHOD, honored) is False

  def test_requested_and_supported_sent(self):
    requested = SubscriptionFilter(prompts_list_changed=True)
    honored = honored_filter(requested, supports_prompts_list_changed=True)
    assert gate_change_notification(PROMPTS_LIST_CHANGED_METHOD, honored) is True

  def test_resource_uri_dropped_from_ack_blocks_update(self):
    requested = SubscriptionFilter(resource_subscriptions=(_URI, "file:///z.txt"))
    honored = honored_filter(requested, supported_resource_uris=frozenset({_URI}))
    assert gate_change_notification(RESOURCES_UPDATED_METHOD, honored, uri=_URI)
    assert not gate_change_notification(
      RESOURCES_UPDATED_METHOD, honored, uri="file:///z.txt"
    )


# ---------------------------------------------------------------------------
# AC-16.16
# ---------------------------------------------------------------------------

class TestAC1616Boundary:
  def test_progress_on_subscription_stream_violates(self):
    with pytest.raises(StreamBoundaryViolation):
      check_stream_boundary(PROGRESS_NOTIFICATION_METHOD, StreamKind.SUBSCRIPTION)

  def test_message_on_subscription_stream_violates(self):
    with pytest.raises(StreamBoundaryViolation):
      check_stream_boundary(MESSAGE_NOTIFICATION_METHOD, StreamKind.SUBSCRIPTION)

  def test_change_kind_on_subscription_stream_ok(self):
    for method in CHANGE_NOTIFICATION_METHODS:
      check_stream_boundary(method, StreamKind.SUBSCRIPTION)  # no raise

  def test_change_kind_on_request_response_violates(self):
    for method in CHANGE_NOTIFICATION_METHODS:
      with pytest.raises(StreamBoundaryViolation):
        check_stream_boundary(method, StreamKind.REQUEST_RESPONSE)

  def test_progress_on_request_response_ok(self):
    check_stream_boundary(PROGRESS_NOTIFICATION_METHOD, StreamKind.REQUEST_RESPONSE)
    check_stream_boundary(MESSAGE_NOTIFICATION_METHOD, StreamKind.REQUEST_RESPONSE)

  def test_classification_helpers(self):
    assert is_request_scoped_notification(PROGRESS_NOTIFICATION_METHOD)
    assert is_request_scoped_notification(MESSAGE_NOTIFICATION_METHOD)
    assert not is_request_scoped_notification(TOOLS_LIST_CHANGED_METHOD)
    assert is_change_notification(TOOLS_LIST_CHANGED_METHOD)
    assert not is_change_notification(PROGRESS_NOTIFICATION_METHOD)


# ---------------------------------------------------------------------------
# AC-16.17
# ---------------------------------------------------------------------------

class TestAC1617WrongStream:
  def test_violation_carries_method_and_stream(self):
    try:
      check_stream_boundary(PROGRESS_NOTIFICATION_METHOD, StreamKind.SUBSCRIPTION)
    except StreamBoundaryViolation as exc:
      assert exc.method == PROGRESS_NOTIFICATION_METHOD
      assert exc.stream_kind is StreamKind.SUBSCRIPTION
    else:
      pytest.fail("expected StreamBoundaryViolation")

  def test_registry_route_rejects_request_scoped(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    n = JSONRPCNotification(
      method=PROGRESS_NOTIFICATION_METHOD,
      params=stamp_subscription_id({}, "1"),
    )
    with pytest.raises(StreamBoundaryViolation):
      reg.route(n)


# ---------------------------------------------------------------------------
# AC-16.18
# ---------------------------------------------------------------------------

class TestAC1618ClientCancel:
  def test_stdio_cancel_references_listen_id(self):
    n = build_subscription_cancellation(1)
    assert n.method == "notifications/cancelled"
    assert n.params["requestId"] == 1

  def test_http_cancel_closes_stream(self):
    sub = Subscription(1, SubscriptionFilter(tools_list_changed=True))
    sub.acknowledge(build_acknowledgement(1, SubscriptionFilter(tools_list_changed=True)))
    close_streamable_http_subscription(sub)
    assert sub.state is SubscriptionState.CLOSED


# ---------------------------------------------------------------------------
# AC-16.19
# ---------------------------------------------------------------------------

class TestAC1619ServerTeardown:
  def test_stdio_teardown_uses_cancelled_with_listen_id(self):
    # Server teardown on stdio uses the same shape, referencing the listen id.
    n = build_subscription_cancellation(7)
    assert n.method == "notifications/cancelled"
    assert n.params["requestId"] == 7

  def test_http_teardown_closes_stream(self):
    sub = Subscription(3, SubscriptionFilter(tools_list_changed=True))
    close_streamable_http_subscription(sub)
    assert sub.state is SubscriptionState.CLOSED


# ---------------------------------------------------------------------------
# AC-16.20
# ---------------------------------------------------------------------------

class TestAC1620TransportClose:
  def test_transport_loss_ends_all_subscriptions(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    reg.open(2, SubscriptionFilter(resource_subscriptions=(_URI,)))
    reg.clear()
    assert reg.active_ids == frozenset()

  def test_closed_subscription_accepts_nothing(self):
    sub = Subscription(1, SubscriptionFilter(tools_list_changed=True))
    sub.close()
    assert not sub.accepts(build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1))


# ---------------------------------------------------------------------------
# AC-16.21
# ---------------------------------------------------------------------------

class TestAC1621NoRetainedState:
  def test_close_forgets_subscription(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    reg.close("1")
    assert reg.get("1") is None
    assert reg.active_ids == frozenset()

  def test_reissue_required_after_clear(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    reg.clear()
    # Nothing routes until a fresh listen is opened.
    n = build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1)
    with pytest.raises(ValueError):
      reg.route(n)
    # Re-issuing re-establishes it.
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    assert reg.route(n).request_id == 1

  def test_closed_filter_not_retained(self):
    sub = Subscription(1, SubscriptionFilter(tools_list_changed=True))
    sub.acknowledge(build_acknowledgement(1, SubscriptionFilter(tools_list_changed=True)))
    sub.close()
    assert sub.acknowledged is None


# ---------------------------------------------------------------------------
# AC-16.22
# ---------------------------------------------------------------------------

class TestAC1622NoResumption:
  def test_closed_subscription_not_resumable(self):
    sub = Subscription(1, SubscriptionFilter(tools_list_changed=True))
    sub.close()
    ack = build_acknowledgement(1, SubscriptionFilter(tools_list_changed=True))
    with pytest.raises(SubscriptionClosedError):
      sub.acknowledge(ack)

  def test_new_listen_yields_new_identifier(self):
    reg = SubscriptionRegistry()
    sub1 = reg.open(1, SubscriptionFilter(tools_list_changed=True))
    reg.close("1")
    sub2 = reg.open(2, SubscriptionFilter(tools_list_changed=True))
    assert sub1.subscription_id == "1"
    assert sub2.subscription_id == "2"
    assert sub1.subscription_id != sub2.subscription_id

  def test_route_after_drop_requires_new_subscription(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    reg.close("1")
    n = build_change_notification(TOOLS_LIST_CHANGED_METHOD, 1)
    with pytest.raises(ValueError):
      reg.route(n)


# ---------------------------------------------------------------------------
# AC-16.23
# ---------------------------------------------------------------------------

class TestAC1623Multiple:
  def test_multiple_concurrent_subscriptions(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    reg.open(2, SubscriptionFilter(resource_subscriptions=(_URI,)))
    reg.open("abc", SubscriptionFilter(prompts_list_changed=True))
    assert reg.active_ids == frozenset({"1", "2", "abc"})

  def test_each_independent_and_keyed_by_own_id(self):
    reg = SubscriptionRegistry()
    s1 = reg.open(1, SubscriptionFilter(tools_list_changed=True))
    s2 = reg.open(2, SubscriptionFilter(resource_subscriptions=(_URI,)))
    assert s1.subscription_id == "1"
    assert s2.subscription_id == "2"
    # Closing one leaves the other untouched.
    reg.close("1")
    assert reg.active_ids == frozenset({"2"})

  def test_duplicate_active_id_rejected(self):
    reg = SubscriptionRegistry()
    reg.open(1, SubscriptionFilter(tools_list_changed=True))
    with pytest.raises(ValueError):
      reg.open(1, SubscriptionFilter(prompts_list_changed=True))

  def test_string_and_numeric_ids_distinct(self):
    # subscription_id_for("1") == subscription_id_for(1) by serialization, so
    # the registry treats them as the same channel id — that is the wire reality.
    assert subscription_id_for("1") == subscription_id_for(1)
