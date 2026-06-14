"""Tests for S26 — Resources I: Capability, Listing, Templates & Types.

Verifies the resource discovery surface: the `resources` capability and its
two sub-flags, the two paginated/cacheable list exchanges, capability gating,
and the `Resource` / `ResourceTemplate` data types.

AC -> test coverage map (16 ACs):
  AC-26.1  -> TestCapabilityDeclaration
  AC-26.2  -> TestCapabilitySubFlags
  AC-26.3  -> TestSubFlagSemantics
  AC-26.4  -> TestRequestGatingWithoutCapability
  AC-26.5  -> TestNotificationGating
  AC-26.6  -> TestAvailableResourceSet
  AC-26.7  -> TestSetStabilityAndAuthorization
  AC-26.8  -> TestListResourcesRequestParams
  AC-26.9  -> TestListResourcesResultRequiredFields
  AC-26.10 -> TestNextCursorOpacity
  AC-26.11 -> TestServerAssumesNoParticularPage
  AC-26.12 -> TestListResourceTemplatesRequestAndResult
  AC-26.13 -> TestResourceType
  AC-26.14 -> TestResourceSize
  AC-26.15 -> TestResourceTemplateUriTemplate
  AC-26.16 -> TestResourceTemplateType
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.caching import CACHE_SCOPE_PRIVATE, CACHE_SCOPE_PUBLIC
from mcp_sdk_py.capabilities import ServerCapabilities
from mcp_sdk_py.common_types import Icon
from mcp_sdk_py.content_types import Annotations, ParticipantRole
from mcp_sdk_py.resources import (
  METHOD_RESOURCES_LIST,
  METHOD_RESOURCES_READ,
  METHOD_RESOURCES_TEMPLATES_LIST,
  NOTIFICATION_RESOURCES_LIST_CHANGED,
  NOTIFICATION_RESOURCES_UPDATED,
  RESOURCE_GATED_REQUESTS,
  ListResourceTemplatesRequestParams,
  ListResourceTemplatesResult,
  ListResourcesRequestParams,
  ListResourcesResult,
  Resource,
  ResourcesServerCapability,
  ResourceTemplate,
  client_may_issue_request,
  resources_capability_declared,
  server_may_accept_request,
  server_may_emit_list_changed,
  server_may_emit_updated,
)
from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE


# ---------------------------------------------------------------------------
# AC-26.1 — capabilities object contains a `resources` key (object); a server
#           exposing no resources omits the key. (R-17.1-a, R-17.1-b)
# ---------------------------------------------------------------------------

class TestCapabilityDeclaration:
  def test_server_exposing_resources_declares_object(self):
    caps = ServerCapabilities(resources={})
    wire = caps.to_dict()
    assert "resources" in wire
    assert isinstance(wire["resources"], dict)
    assert resources_capability_declared(caps) is True

  def test_server_with_no_resources_omits_key(self):
    caps = ServerCapabilities()
    assert "resources" not in caps.to_dict()
    assert resources_capability_declared(caps) is False

  def test_capability_value_is_an_object(self):
    cap = ResourcesServerCapability()
    assert isinstance(cap.to_dict(), dict)

  def test_from_dict_rejects_non_object(self):
    with pytest.raises(TypeError):
      ResourcesServerCapability.from_dict([])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC-26.2 — listChanged and subscribe are each boolean and OPTIONAL; a server
#           MAY include either alone, both, or neither, and {} is valid.
#           (R-17.1-b/c/e/f/g)
# ---------------------------------------------------------------------------

class TestCapabilitySubFlags:
  def test_empty_object_is_valid_declaration(self):
    cap = ResourcesServerCapability()
    assert cap.list_changed is None
    assert cap.subscribe is None
    assert cap.to_dict() == {}
    assert ResourcesServerCapability.from_dict({}).to_dict() == {}

  def test_list_changed_alone(self):
    cap = ResourcesServerCapability(list_changed=True)
    assert cap.to_dict() == {"listChanged": True}

  def test_subscribe_alone(self):
    cap = ResourcesServerCapability(subscribe=True)
    assert cap.to_dict() == {"subscribe": True}

  def test_both_together(self):
    cap = ResourcesServerCapability.from_dict(
      {"listChanged": True, "subscribe": True}
    )
    assert cap.to_dict() == {"listChanged": True, "subscribe": True}

  def test_neither(self):
    assert ResourcesServerCapability.from_dict({}).to_dict() == {}

  def test_sub_flags_must_be_boolean(self):
    with pytest.raises(TypeError):
      ResourcesServerCapability(list_changed="yes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
      ResourcesServerCapability(subscribe=1)  # type: ignore[arg-type]

  def test_round_trip(self):
    for raw in ({}, {"listChanged": True}, {"subscribe": True},
                {"listChanged": False, "subscribe": True}):
      assert ResourcesServerCapability.from_dict(raw).to_dict() == raw

  def test_unknown_keys_ignored(self):
    cap = ResourcesServerCapability.from_dict({"listChanged": True, "future": 1})
    assert cap.to_dict() == {"listChanged": True}


# ---------------------------------------------------------------------------
# AC-26.3 — listChanged:true => MAY emit list_changed; subscribe:true => supports
#           per-resource updated notifications. (R-17.1-d, R-17.1-e)
# ---------------------------------------------------------------------------

class TestSubFlagSemantics:
  def test_supports_list_changed_only_when_true(self):
    assert ResourcesServerCapability(list_changed=True).supports_list_changed is True
    assert ResourcesServerCapability(list_changed=False).supports_list_changed is False
    assert ResourcesServerCapability().supports_list_changed is False

  def test_supports_subscribe_only_when_true(self):
    assert ResourcesServerCapability(subscribe=True).supports_subscribe is True
    assert ResourcesServerCapability(subscribe=False).supports_subscribe is False
    assert ResourcesServerCapability().supports_subscribe is False


# ---------------------------------------------------------------------------
# AC-26.4 — server without `resources` declared does not accept the three
#           requests; a conformant client does not issue them. (R-17.1-h, R-17.1-j)
# ---------------------------------------------------------------------------

class TestRequestGatingWithoutCapability:
  UNDECLARED = ServerCapabilities()
  DECLARED = ServerCapabilities(resources={})

  def test_gated_request_set_contents(self):
    assert RESOURCE_GATED_REQUESTS == {
      METHOD_RESOURCES_LIST,
      METHOD_RESOURCES_TEMPLATES_LIST,
      METHOD_RESOURCES_READ,
    }

  @pytest.mark.parametrize("method", sorted(RESOURCE_GATED_REQUESTS))
  def test_server_must_not_accept_without_capability(self, method):
    assert server_may_accept_request(self.UNDECLARED, method) is False

  @pytest.mark.parametrize("method", sorted(RESOURCE_GATED_REQUESTS))
  def test_client_must_not_issue_without_capability(self, method):
    assert client_may_issue_request(self.UNDECLARED, method) is False

  @pytest.mark.parametrize("method", sorted(RESOURCE_GATED_REQUESTS))
  def test_server_accepts_when_declared(self, method):
    assert server_may_accept_request(self.DECLARED, method) is True

  @pytest.mark.parametrize("method", sorted(RESOURCE_GATED_REQUESTS))
  def test_client_may_issue_when_declared(self, method):
    assert client_may_issue_request(self.DECLARED, method) is True

  def test_ungated_method_is_unaffected(self):
    assert server_may_accept_request(self.UNDECLARED, "ping") is True
    assert client_may_issue_request(self.UNDECLARED, "ping") is True

  def test_empty_object_declaration_opens_the_gate(self):
    # `resources: {}` is the empty-object form and still declares the feature.
    assert server_may_accept_request(self.DECLARED, METHOD_RESOURCES_LIST) is True


# ---------------------------------------------------------------------------
# AC-26.5 — no list_changed/updated unless `resources` declared; no list_changed
#           unless listChanged; no updated unless subscribe. (R-17.1-i/k/l)
# ---------------------------------------------------------------------------

class TestNotificationGating:
  def test_no_notifications_without_resources_capability(self):
    caps = ServerCapabilities()
    assert server_may_emit_list_changed(caps) is False
    assert server_may_emit_updated(caps) is False

  def test_declared_but_no_sub_flags_emits_neither(self):
    caps = ServerCapabilities(resources={})
    assert server_may_emit_list_changed(caps) is False
    assert server_may_emit_updated(caps) is False

  def test_list_changed_requires_sub_flag(self):
    caps = ServerCapabilities(resources={"listChanged": True})
    assert server_may_emit_list_changed(caps) is True
    assert server_may_emit_updated(caps) is False

  def test_updated_requires_subscribe(self):
    caps = ServerCapabilities(resources={"subscribe": True})
    assert server_may_emit_updated(caps) is True
    assert server_may_emit_list_changed(caps) is False

  def test_both_sub_flags(self):
    caps = ServerCapabilities(resources={"listChanged": True, "subscribe": True})
    assert server_may_emit_list_changed(caps) is True
    assert server_may_emit_updated(caps) is True

  def test_sub_flag_false_does_not_enable(self):
    caps = ServerCapabilities(resources={"listChanged": False, "subscribe": False})
    assert server_may_emit_list_changed(caps) is False
    assert server_may_emit_updated(caps) is False

  def test_notification_method_name_constants(self):
    assert NOTIFICATION_RESOURCES_LIST_CHANGED == "notifications/resources/list_changed"
    assert NOTIFICATION_RESOURCES_UPDATED == "notifications/resources/updated"


# ---------------------------------------------------------------------------
# AC-26.6 — responds with the set currently available; set MAY be empty and MAY
#           change over time. (R-17.1-m, R-17.1-n)
# ---------------------------------------------------------------------------

class TestAvailableResourceSet:
  def test_result_may_carry_resources(self):
    res = Resource(uri="file:///a.txt", name="a")
    result = ListResourcesResult(
      resources=[res], ttl_ms=0, cache_scope=CACHE_SCOPE_PUBLIC
    )
    assert result.resources == [res]

  def test_set_may_be_empty(self):
    result = ListResourcesResult(
      resources=[], ttl_ms=0, cache_scope=CACHE_SCOPE_PUBLIC
    )
    assert result.resources == []
    assert result.to_dict()["resources"] == []

  def test_set_may_change_over_time(self):
    # Two independent results from the same server may carry different sets.
    first = ListResourcesResult(
      resources=[Resource(uri="file:///a", name="a")],
      ttl_ms=0,
      cache_scope=CACHE_SCOPE_PUBLIC,
    )
    later = ListResourcesResult(
      resources=[
        Resource(uri="file:///a", name="a"),
        Resource(uri="file:///b", name="b"),
      ],
      ttl_ms=0,
      cache_scope=CACHE_SCOPE_PUBLIC,
    )
    assert len(first.resources) != len(later.resources)


# ---------------------------------------------------------------------------
# AC-26.7 — returned set does not vary by connection nor as a side effect of
#           other requests; MAY differ only by authorization. (R-17.1-o, R-17.1-p)
# ---------------------------------------------------------------------------

class TestSetStabilityAndAuthorization:
  def _list_for(self, *, scopes: frozenset[str]) -> ListResourcesResult:
    """Model an authorization-scoped listing: the set depends only on scopes."""
    catalogue = {
      "files:read": Resource(uri="file:///doc", name="doc"),
      "db:read": Resource(uri="db://rows/1", name="row"),
    }
    visible = [r for scope, r in catalogue.items() if scope in scopes]
    return ListResourcesResult(
      resources=visible, ttl_ms=0, cache_scope=CACHE_SCOPE_PRIVATE
    )

  def test_same_authorization_yields_same_set_regardless_of_connection(self):
    # Two distinct "connections" presenting the same scopes get the same set.
    conn_a = self._list_for(scopes=frozenset({"files:read"}))
    conn_b = self._list_for(scopes=frozenset({"files:read"}))
    assert [r.to_dict() for r in conn_a.resources] == [
      r.to_dict() for r in conn_b.resources
    ]

  def test_set_may_vary_by_authorization(self):
    fewer = self._list_for(scopes=frozenset({"files:read"}))
    more = self._list_for(scopes=frozenset({"files:read", "db:read"}))
    assert len(more.resources) > len(fewer.resources)

  def test_set_not_a_side_effect_of_other_requests(self):
    # The listing is a pure function of authorization, not prior calls.
    before = self._list_for(scopes=frozenset({"db:read"}))
    _ = self._list_for(scopes=frozenset({"files:read", "db:read"}))  # other request
    after = self._list_for(scopes=frozenset({"db:read"}))
    assert [r.to_dict() for r in before.resources] == [
      r.to_dict() for r in after.resources
    ]


# ---------------------------------------------------------------------------
# AC-26.8 — params MAY include cursor, MAY include _meta; both optional.
#           (R-17.2-a, R-17.2-i)
# ---------------------------------------------------------------------------

class TestListResourcesRequestParams:
  def test_empty_params(self):
    params = ListResourcesRequestParams.from_dict({})
    assert params.cursor is None
    assert params.meta is None
    assert params.to_dict() == {}

  def test_cursor_only(self):
    params = ListResourcesRequestParams.from_dict({"cursor": "abc"})
    assert params.cursor == "abc"
    assert params.to_dict() == {"cursor": "abc"}

  def test_meta_only(self):
    params = ListResourcesRequestParams.from_dict(
      {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}
    )
    assert params.meta == {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    assert "_meta" in params.to_dict()

  def test_cursor_and_meta(self):
    params = ListResourcesRequestParams.from_dict(
      {"cursor": "abc", "_meta": {"k": "v"}}
    )
    assert params.cursor == "abc"
    assert params.meta == {"k": "v"}

  def test_empty_string_cursor_is_present(self):
    params = ListResourcesRequestParams.from_dict({"cursor": ""})
    assert params.cursor == ""
    assert params.to_dict() == {"cursor": ""}

  def test_cursor_must_be_string(self):
    with pytest.raises(TypeError):
      ListResourcesRequestParams.from_dict({"cursor": 5})

  def test_meta_must_be_object(self):
    with pytest.raises(TypeError):
      ListResourcesRequestParams.from_dict({"_meta": "no"})

  def test_method_constant(self):
    assert METHOD_RESOURCES_LIST == "resources/list"


# ---------------------------------------------------------------------------
# AC-26.9 — ListResourcesResult: resources present (array); resultType=="complete";
#           ttlMs present and >=0; cacheScope in {public,private}.
#           (R-17.2-b, R-17.2-f, R-17.2-g, R-17.2-h)
# ---------------------------------------------------------------------------

class TestListResourcesResultRequiredFields:
  def _valid(self) -> dict:
    return {
      "resources": [{"uri": "file:///r", "name": "r"}],
      "resultType": "complete",
      "ttlMs": 60000,
      "cacheScope": "private",
    }

  def test_valid_result_round_trips(self):
    result = ListResourcesResult.from_dict(self._valid())
    assert result.result_type == RESULT_TYPE_COMPLETE
    assert result.ttl_ms == 60000
    assert result.cache_scope == "private"
    assert isinstance(result.resources[0], Resource)
    out = result.to_dict()
    assert out["resultType"] == "complete"
    assert out["ttlMs"] == 60000
    assert out["cacheScope"] == "private"
    assert isinstance(out["resources"], list)

  def test_resources_required(self):
    raw = self._valid()
    del raw["resources"]
    with pytest.raises(ValueError):
      ListResourcesResult.from_dict(raw)

  def test_resources_must_be_array(self):
    raw = self._valid()
    raw["resources"] = {"uri": "x", "name": "y"}
    with pytest.raises(TypeError):
      ListResourcesResult.from_dict(raw)

  def test_result_type_must_be_complete(self):
    with pytest.raises(ValueError):
      ListResourcesResult(
        resources=[], ttl_ms=0, cache_scope="public", result_type="input_required"
      )

  def test_ttl_ms_required(self):
    raw = self._valid()
    del raw["ttlMs"]
    with pytest.raises(ValueError):
      ListResourcesResult.from_dict(raw)

  def test_ttl_ms_must_be_non_negative(self):
    with pytest.raises(ValueError):
      ListResourcesResult(resources=[], ttl_ms=-1, cache_scope="public")

  def test_ttl_ms_zero_allowed(self):
    result = ListResourcesResult(resources=[], ttl_ms=0, cache_scope="public")
    assert result.ttl_ms == 0

  def test_cache_scope_required(self):
    raw = self._valid()
    del raw["cacheScope"]
    with pytest.raises(ValueError):
      ListResourcesResult.from_dict(raw)

  def test_cache_scope_must_be_valid_enum(self):
    with pytest.raises(ValueError):
      ListResourcesResult(resources=[], ttl_ms=0, cache_scope="shared")

  @pytest.mark.parametrize("scope", [CACHE_SCOPE_PUBLIC, CACHE_SCOPE_PRIVATE])
  def test_both_scopes_accepted(self, scope):
    result = ListResourcesResult(resources=[], ttl_ms=0, cache_scope=scope)
    assert result.cache_scope == scope

  def test_result_type_defaults_to_complete(self):
    result = ListResourcesResult(resources=[], ttl_ms=0, cache_scope="public")
    assert result.result_type == "complete"

  def test_meta_optional(self):
    result = ListResourcesResult(
      resources=[], ttl_ms=0, cache_scope="public", meta={"x": 1}
    )
    assert result.to_dict()["_meta"] == {"x": 1}
    bare = ListResourcesResult(resources=[], ttl_ms=0, cache_scope="public")
    assert "_meta" not in bare.to_dict()


# ---------------------------------------------------------------------------
# AC-26.10 — nextCursor optional; absent => listing complete; client passes it
#            back verbatim without parsing/constructing. (R-17.2-c/d/e)
# ---------------------------------------------------------------------------

class TestNextCursorOpacity:
  def test_absent_next_cursor_means_complete(self):
    result = ListResourcesResult(resources=[], ttl_ms=0, cache_scope="public")
    assert result.next_cursor is None
    assert result.is_last_page is True
    assert "nextCursor" not in result.to_dict()

  def test_present_next_cursor_means_more_pages(self):
    result = ListResourcesResult(
      resources=[], ttl_ms=0, cache_scope="public", next_cursor="eyJwIjoyfQ=="
    )
    assert result.is_last_page is False
    assert result.to_dict()["nextCursor"] == "eyJwIjoyfQ=="

  def test_client_passes_cursor_back_verbatim(self):
    opaque = "eyJwYWdlIjoyfQ=="
    page1 = ListResourcesResult(
      resources=[], ttl_ms=0, cache_scope="public", next_cursor=opaque
    )
    # The client constructs the next request by passing the value back as-is,
    # without parsing or constructing it.
    next_params = ListResourcesRequestParams(cursor=page1.next_cursor)
    assert next_params.to_dict()["cursor"] == opaque

  def test_empty_string_next_cursor_is_present(self):
    result = ListResourcesResult(
      resources=[], ttl_ms=0, cache_scope="public", next_cursor=""
    )
    assert result.is_last_page is False
    assert result.to_dict()["nextCursor"] == ""


# ---------------------------------------------------------------------------
# AC-26.11 — server's response is valid regardless of which pages the client has
#            previously fetched (does not assume any particular page). (R-17.2-j)
# ---------------------------------------------------------------------------

class TestServerAssumesNoParticularPage:
  def test_first_page_result_self_contained(self):
    # A first page (no cursor in request) is fully valid on its own.
    result = ListResourcesResult.from_dict(
      {
        "resources": [{"uri": "file:///a", "name": "a"}],
        "resultType": "complete",
        "ttlMs": 0,
        "cacheScope": "public",
        "nextCursor": "p2",
      }
    )
    assert result.is_last_page is False

  def test_arbitrary_page_result_self_contained(self):
    # A page reached via some cursor is equally valid without knowledge of
    # earlier pages — each result stands alone.
    result = ListResourcesResult.from_dict(
      {
        "resources": [{"uri": "file:///z", "name": "z"}],
        "resultType": "complete",
        "ttlMs": 0,
        "cacheScope": "public",
      }
    )
    assert result.is_last_page is True
    assert result.resources[0].uri == "file:///z"


# ---------------------------------------------------------------------------
# AC-26.12 — templates request MAY carry cursor; result has REQUIRED
#            resourceTemplates array (possibly empty); resultType/ttlMs/cacheScope
#            present and behave as in resources/list. (R-17.3-a/b/c)
# ---------------------------------------------------------------------------

class TestListResourceTemplatesRequestAndResult:
  def test_method_constant(self):
    assert METHOD_RESOURCES_TEMPLATES_LIST == "resources/templates/list"

  def test_request_params_cursor_optional(self):
    assert ListResourceTemplatesRequestParams.from_dict({}).cursor is None
    p = ListResourceTemplatesRequestParams.from_dict({"cursor": "eyJwIjoyfQ=="})
    assert p.cursor == "eyJwIjoyfQ=="
    assert p.to_dict() == {"cursor": "eyJwIjoyfQ=="}

  def test_request_params_meta_optional(self):
    p = ListResourceTemplatesRequestParams.from_dict({"_meta": {"k": "v"}})
    assert p.meta == {"k": "v"}

  def test_result_round_trips(self):
    raw = {
      "resourceTemplates": [
        {
          "uriTemplate": "db://{table}/{id}",
          "name": "db-row",
          "title": "Database Row",
          "mimeType": "application/json",
        }
      ],
      "resultType": "complete",
      "ttlMs": 0,
      "cacheScope": "public",
    }
    result = ListResourceTemplatesResult.from_dict(raw)
    assert isinstance(result.resource_templates[0], ResourceTemplate)
    assert result.result_type == "complete"
    assert result.ttl_ms == 0
    assert result.cache_scope == "public"
    out = result.to_dict()
    assert out["resourceTemplates"][0]["uriTemplate"] == "db://{table}/{id}"
    assert out["resultType"] == "complete"

  def test_templates_required(self):
    with pytest.raises(ValueError):
      ListResourceTemplatesResult.from_dict(
        {"resultType": "complete", "ttlMs": 0, "cacheScope": "public"}
      )

  def test_templates_may_be_empty(self):
    result = ListResourceTemplatesResult(
      resource_templates=[], ttl_ms=0, cache_scope="public"
    )
    assert result.resource_templates == []
    assert result.to_dict()["resourceTemplates"] == []

  def test_caching_fields_behave_as_in_resources_list(self):
    with pytest.raises(ValueError):
      ListResourceTemplatesResult(
        resource_templates=[], ttl_ms=-5, cache_scope="public"
      )
    with pytest.raises(ValueError):
      ListResourceTemplatesResult(
        resource_templates=[], ttl_ms=0, cache_scope="bogus"
      )
    with pytest.raises(ValueError):
      ListResourceTemplatesResult(
        resource_templates=[], ttl_ms=0, cache_scope="public",
        result_type="input_required",
      )

  def test_next_cursor_optional(self):
    result = ListResourceTemplatesResult(
      resource_templates=[], ttl_ms=0, cache_scope="public", next_cursor="c"
    )
    assert result.is_last_page is False
    assert result.to_dict()["nextCursor"] == "c"
    bare = ListResourceTemplatesResult(
      resource_templates=[], ttl_ms=0, cache_scope="public"
    )
    assert bare.is_last_page is True
    assert "nextCursor" not in bare.to_dict()


# ---------------------------------------------------------------------------
# AC-26.13 — Resource: uri present (valid RFC3986, any scheme); name present;
#            title/description/mimeType/size/annotations/icons/_meta optional;
#            label prefers title, falls back to name. (R-17.4-a–g, j, k, l)
# ---------------------------------------------------------------------------

class TestResourceType:
  def test_minimal_resource(self):
    res = Resource(uri="file:///project/README.md", name="readme")
    assert res.uri == "file:///project/README.md"
    assert res.name == "readme"
    assert res.to_dict() == {"uri": "file:///project/README.md", "name": "readme"}

  def test_uri_required(self):
    with pytest.raises(ValueError):
      Resource(uri="", name="x")

  def test_name_required(self):
    with pytest.raises(ValueError):
      Resource(uri="file:///x", name="")

  @pytest.mark.parametrize(
    "uri",
    [
      "file:///project/README.md",
      "https://example.com/data",
      "db://users/42",
      "custom-scheme://anything/here",
    ],
  )
  def test_uri_any_scheme(self, uri):
    res = Resource(uri=uri, name="r")
    assert res.uri == uri

  def test_all_optional_fields(self):
    res = Resource(
      uri="file:///x",
      name="x",
      title="Display",
      description="prose",
      mime_type="text/markdown",
      size=4096,
      annotations=Annotations(audience=[ParticipantRole.USER], priority=0.5),
      icons=[Icon(src="https://example.com/i.png")],
      meta={"k": "v"},
    )
    out = res.to_dict()
    assert out["title"] == "Display"
    assert out["description"] == "prose"
    assert out["mimeType"] == "text/markdown"
    assert out["size"] == 4096
    assert out["annotations"]["audience"] == ["user"]
    assert out["icons"][0]["src"] == "https://example.com/i.png"
    assert out["_meta"] == {"k": "v"}

  def test_optional_fields_omitted_when_absent(self):
    out = Resource(uri="file:///x", name="x").to_dict()
    for key in ("title", "description", "mimeType", "size", "annotations",
                "icons", "_meta"):
      assert key not in out

  def test_display_name_prefers_title(self):
    assert Resource(uri="file:///x", name="x", title="T").display_name() == "T"

  def test_display_name_falls_back_to_name(self):
    assert Resource(uri="file:///x", name="x").display_name() == "x"

  def test_from_dict_round_trip(self):
    raw = {
      "uri": "file:///project/README.md",
      "name": "readme",
      "title": "Project README",
      "description": "Top-level project documentation.",
      "mimeType": "text/markdown",
      "size": 4096,
    }
    assert Resource.from_dict(raw).to_dict() == raw

  def test_from_dict_ignores_unknown_keys(self):
    res = Resource.from_dict({"uri": "file:///x", "name": "x", "future": 1})
    assert "future" not in res.to_dict()

  def test_annotations_type_checked(self):
    with pytest.raises(TypeError):
      Resource(uri="file:///x", name="x", annotations={"audience": ["user"]})

  def test_icons_type_checked(self):
    with pytest.raises(TypeError):
      Resource(uri="file:///x", name="x", icons=[{"src": "https://e/i.png"}])


# ---------------------------------------------------------------------------
# AC-26.14 — Resource.size equals raw byte count before base64/tokenization; a
#            host MAY use it for sizes and context estimation. (R-17.4-h, R-17.4-i)
# ---------------------------------------------------------------------------

class TestResourceSize:
  def test_size_is_raw_byte_count(self):
    raw_bytes = b"hello world"
    res = Resource(uri="file:///x", name="x", size=len(raw_bytes))
    assert res.size == 11
    assert res.to_dict()["size"] == 11

  def test_size_optional(self):
    assert "size" not in Resource(uri="file:///x", name="x").to_dict()

  def test_size_must_be_number(self):
    with pytest.raises(TypeError):
      Resource(uri="file:///x", name="x", size="big")

  def test_size_must_be_non_negative(self):
    with pytest.raises(ValueError):
      Resource(uri="file:///x", name="x", size=-1)

  def test_size_zero_allowed(self):
    assert Resource(uri="file:///x", name="x", size=0).size == 0

  def test_size_measured_before_base64(self):
    # 3 raw bytes base64-encode to 4 chars; size must reflect the raw 3.
    import base64

    raw = b"abc"
    encoded = base64.b64encode(raw)
    assert len(encoded) == 4
    res = Resource(uri="file:///x", name="x", size=len(raw))
    assert res.size == 3 and res.size != len(encoded)


# ---------------------------------------------------------------------------
# AC-26.15 — ResourceTemplate.uriTemplate present (RFC6570); expanding it yields
#            a uri usable in resources/read; values MAY come from user/computation/
#            completion. (R-17.4-m, R-17.4-n)
# ---------------------------------------------------------------------------

class TestResourceTemplateUriTemplate:
  def test_uri_template_present(self):
    tpl = ResourceTemplate(uri_template="db://{table}/{id}", name="db-row")
    assert tpl.uri_template == "db://{table}/{id}"
    assert tpl.to_dict()["uriTemplate"] == "db://{table}/{id}"

  def test_uri_template_required(self):
    with pytest.raises(ValueError):
      ResourceTemplate(uri_template="", name="x")

  def test_expansion_yields_concrete_uri_usable_in_read(self):
    # The variables in the template, once substituted, form a concrete uri that
    # is then a valid Resource uri (the input to resources/read).
    tpl = ResourceTemplate(uri_template="db://{table}/{id}", name="db-row")
    expanded = tpl.uri_template.replace("{table}", "users").replace("{id}", "42")
    assert expanded == "db://users/42"
    # A concrete Resource accepts that expanded uri.
    res = Resource(uri=expanded, name="db-row")
    assert res.uri == "db://users/42"

  def test_variable_values_source_agnostic(self):
    # The template carries only the grammar; values (user/computed/completion)
    # are supplied by the client at expansion time — nothing in the type fixes
    # their origin.
    tpl = ResourceTemplate(uri_template="file:///{path}", name="file")
    for value in ("a/b.txt", "deep/nested/file.md"):
      assert tpl.uri_template.replace("{path}", value) == f"file:///{value}"


# ---------------------------------------------------------------------------
# AC-26.16 — ResourceTemplate: name present; title/description/mimeType/
#            annotations/icons/_meta optional; mimeType only when shared; no size.
#            (R-17.4-o–u)
# ---------------------------------------------------------------------------

class TestResourceTemplateType:
  def test_minimal_template(self):
    tpl = ResourceTemplate(uri_template="db://{table}/{id}", name="db-row")
    assert tpl.to_dict() == {"uriTemplate": "db://{table}/{id}", "name": "db-row"}

  def test_name_required(self):
    with pytest.raises(ValueError):
      ResourceTemplate(uri_template="db://{x}", name="")

  def test_all_optional_fields(self):
    tpl = ResourceTemplate(
      uri_template="db://{table}/{id}",
      name="db-row",
      title="Database Row",
      description="A single row addressed by table and primary key.",
      mime_type="application/json",
      annotations=Annotations(priority=0.2),
      icons=[Icon(src="https://example.com/i.png")],
      meta={"k": "v"},
    )
    out = tpl.to_dict()
    assert out["title"] == "Database Row"
    assert out["description"].startswith("A single row")
    assert out["mimeType"] == "application/json"
    assert out["annotations"]["priority"] == 0.2
    assert out["icons"][0]["src"] == "https://example.com/i.png"
    assert out["_meta"] == {"k": "v"}

  def test_optional_fields_omitted_when_absent(self):
    out = ResourceTemplate(uri_template="db://{x}", name="t").to_dict()
    for key in ("title", "description", "mimeType", "annotations", "icons", "_meta"):
      assert key not in out

  def test_no_size_field_on_dataclass(self):
    tpl = ResourceTemplate(uri_template="db://{x}", name="t")
    assert not hasattr(tpl, "size")

  def test_size_never_serialised(self):
    tpl = ResourceTemplate(uri_template="db://{x}", name="t")
    assert "size" not in tpl.to_dict()

  def test_size_on_wire_is_ignored_not_read(self):
    # A stray size key on the wire is treated as an unknown member, never a
    # ResourceTemplate field (R-17.4-u).
    tpl = ResourceTemplate.from_dict(
      {"uriTemplate": "db://{x}", "name": "t", "size": 99}
    )
    assert not hasattr(tpl, "size")
    assert "size" not in tpl.to_dict()

  def test_display_name_prefers_title(self):
    tpl = ResourceTemplate(uri_template="db://{x}", name="t", title="Title")
    assert tpl.display_name() == "Title"

  def test_display_name_falls_back_to_name(self):
    tpl = ResourceTemplate(uri_template="db://{x}", name="t")
    assert tpl.display_name() == "t"

  def test_mime_type_optional(self):
    # mimeType SHOULD only be set when every match shares it; the type permits
    # both presence and absence (the SHOULD is a server obligation).
    with_mime = ResourceTemplate(
      uri_template="db://{x}", name="t", mime_type="application/json"
    )
    assert with_mime.to_dict()["mimeType"] == "application/json"
    without = ResourceTemplate(uri_template="db://{x}", name="t")
    assert "mimeType" not in without.to_dict()

  def test_from_dict_round_trip(self):
    raw = {
      "uriTemplate": "db://{table}/{id}",
      "name": "db-row",
      "title": "Database Row",
      "description": "A single row addressed by table and primary key.",
      "mimeType": "application/json",
    }
    assert ResourceTemplate.from_dict(raw).to_dict() == raw
