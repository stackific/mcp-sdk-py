"""Tests for S27 — Resources II: Reading, Not-Found, Subscriptions & URI Schemes.

Exercises ``mcp_sdk_py.resources_read`` against every normative atom of §17.5–
§17.9 and every numbered acceptance criterion of the story.

AC → test coverage map:
  AC-27.1  (R-17.5-a/b/d/f) — request params: uri required + optional fields
           → test_ac_27_1_uri_required_and_optional_fields,
             test_ac_27_1_uri_missing_rejected,
             test_ac_27_1_uri_empty_rejected
  AC-27.2  (R-17.5-c) — uri from list or expanded template accepted
           → test_ac_27_2_uri_from_list_or_template_accepted
  AC-27.3  (R-17.5-e/g/h/x) — retry echoes inputResponses + opaque requestState
           → test_ac_27_3_retry_carries_input_responses,
             test_ac_27_3_request_state_echoed_verbatim,
             test_ac_27_3_request_state_treated_opaque
  AC-27.4  (R-17.5-i/q/r) — result: contents present, complete, ttl/scope present
           → test_ac_27_4_complete_result_fields,
             test_ac_27_4_ttl_must_be_non_negative,
             test_ac_27_4_cache_scope_must_be_enum,
             test_ac_27_4_contents_required
  AC-27.5  (R-17.5-j/p) — multiple entries, sub-resource uri may differ
           → test_ac_27_5_multiple_entries_and_subresource_uri
  AC-27.6  (R-17.5-k/l/s/t) — text entry: TextResourceContents, uri+text required
           → test_ac_27_6_text_entry_shape,
             test_ac_27_6_text_uri_required
  AC-27.7  (R-17.5-k/m/n/o/u/v) — binary entry: blob base64, no text field
           → test_ac_27_7_blob_entry_shape,
             test_ac_27_7_blob_rejects_invalid_base64,
             test_ac_27_7_blob_and_text_both_rejected
  AC-27.8  (R-17.5-w) — input_required result instead of ReadResourceResult
           → test_ac_27_8_input_required_branch,
             test_ac_27_8_complete_branch
  AC-27.9  (R-17.5-y) — https uri MAY be fetched directly
           → test_ac_27_9_https_may_fetch_directly,
             test_ac_27_9_non_https_not_directly_fetchable
  AC-27.10 (R-17.5-z/aa, R-17.6-a/b) — not-found error -32602 with data.uri;
           no empty-array signal
           → test_ac_27_10_not_found_error_object,
             test_ac_27_10_empty_contents_signals_non_existence,
             test_ac_27_10_assert_contents_present_raises,
             test_ac_27_10_not_found_uri_extraction
  AC-27.11 (R-17.6-c) — legacy -32002 accepted as not-found
           → test_ac_27_11_legacy_code_accepted,
             test_ac_27_11_unrelated_code_not_not_found
  AC-27.12 (R-17.6-d) — internal failure SHOULD use -32603
           → test_ac_27_12_internal_error_code
  AC-27.13 (R-17.7-a) — no subscribe/unsubscribe method exists
           → test_ac_27_13_no_subscribe_method
  AC-27.14 (R-17.7-b/c/d) — list_changed delivered on opted-in stream
           → test_ac_27_14_list_changed_delivered_when_opted_in,
             test_ac_27_14_list_changed_notification_roundtrip
  AC-27.15 (R-17.7-e) — list_changed not delivered when filter did not opt in
           → test_ac_27_15_list_changed_blocked_without_optin
  AC-27.16 (R-17.7-f/g/h/i/k) — updated for subscribed uri (incl sub-resource),
           client may re-read
           → test_ac_27_16_updated_for_subscribed_uri,
             test_ac_27_16_updated_for_subresource,
             test_ac_27_16_updated_params_uri_required,
             test_ac_27_16_updated_notification_roundtrip,
             test_ac_27_16_client_should_reread,
             test_ac_27_16_subscription_id_correlation
  AC-27.17 (R-17.7-j) — updated not sent for non-subscribed uri
           → test_ac_27_17_updated_blocked_for_unsubscribed,
             test_ac_27_17_make_notification_rejects_unsubscribed
  AC-27.18 (R-17.9-a/e/f) — scheme registry non-exhaustive; custom RFC3986
           → test_ac_27_18_registry_non_exhaustive,
             test_ac_27_18_custom_scheme_recognised,
             test_ac_27_18_scheme_requires_rfc3986
  AC-27.19 (R-17.9-b/c) — https for direct fetch; otherwise prefer other scheme
           → test_ac_27_19_https_for_direct_fetch,
             test_ac_27_19_non_web_prefers_other_scheme
  AC-27.20 (R-17.9-d) — file:// directory may use inode/directory MIME type
           → test_ac_27_20_inode_directory_mime_type
"""

from __future__ import annotations

import pytest

from mcp_sdk_py.content_types import (
  BlobResourceContents,
  TextResourceContents,
)
from mcp_sdk_py.multi_round_trip import InputRequiredResult
from mcp_sdk_py.subscriptions import (
  SUBSCRIPTION_ID_META_KEY,
  SubscriptionFilter,
  extract_subscription_id,
)
from mcp_sdk_py.resources_read import (
  JSONRPC_INTERNAL_ERROR,
  JSONRPC_INVALID_PARAMS,
  JSONRPC_RESOURCE_NOT_FOUND_LEGACY,
  METHOD_READ,
  MIME_TYPE_INODE_DIRECTORY,
  RESOURCE_NOT_FOUND_CODES,
  SCHEME_FILE,
  SCHEME_GIT,
  SCHEME_HTTPS,
  STANDARD_URI_SCHEMES,
  ReadResourceRequestParams,
  ReadResourceResult,
  ResourceListChangedNotification,
  ResourceNotFoundError,
  ResourceUpdatedNotification,
  ResourceUpdatedNotificationParams,
  assert_contents_present,
  build_read_resource_retry,
  client_may_fetch_directly,
  client_should_reread,
  has_subscribe_method,
  is_input_required,
  is_resource_not_found_code,
  is_standard_scheme,
  make_resource_updated_notification,
  not_found_uri,
  parse_read_resource_response,
  server_may_send_list_changed,
  server_may_send_updated,
  uri_scheme,
)


# A tiny valid base64 payload (decodes to b"hi"); vendor-neutral test data.
_VALID_B64 = "aGk="
# A 1x1 transparent PNG, base64 — used as a representative binary blob.
_PNG_B64 = (
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAE"
  "hQGAhKmMIQAAAABJRU5ErkJggg=="
)

_REQUESTED_URI = "file:///project/src/main.rs"


def _complete_result_dict() -> dict:
  """A minimal valid completed resources/read result dict."""
  return {
    "resultType": "complete",
    "contents": [
      {"uri": _REQUESTED_URI, "mimeType": "text/x-rust", "text": "fn main() {}"}
    ],
    "ttlMs": 60000,
    "cacheScope": "private",
  }


# ---------------------------------------------------------------------------
# AC-27.1 — request params: uri required, optional retry fields & _meta
# ---------------------------------------------------------------------------

def test_ac_27_1_uri_required_and_optional_fields() -> None:
  params = ReadResourceRequestParams(
    uri=_REQUESTED_URI,
    input_responses={"k": {"action": "accept"}},
    request_state="opaque-token",
    meta={"trace": "x"},
  )
  assert params.uri == _REQUESTED_URI
  wire = params.to_dict()
  assert wire["uri"] == _REQUESTED_URI
  assert wire["inputResponses"] == {"k": {"action": "accept"}}
  assert wire["requestState"] == "opaque-token"
  assert wire["_meta"] == {"trace": "x"}
  # A first attempt carries neither retry field.
  bare = ReadResourceRequestParams(uri=_REQUESTED_URI)
  assert bare.to_dict() == {"uri": _REQUESTED_URI}
  assert bare.is_retry is False


def test_ac_27_1_uri_missing_rejected() -> None:
  with pytest.raises(ValueError):
    ReadResourceRequestParams.from_dict({"inputResponses": {}})


def test_ac_27_1_uri_empty_rejected() -> None:
  with pytest.raises(ValueError):
    ReadResourceRequestParams(uri="")


def test_ac_27_1_method_constant() -> None:
  assert METHOD_READ == "resources/read"


# ---------------------------------------------------------------------------
# AC-27.2 — uri from resources/list or expanded ResourceTemplate accepted
# ---------------------------------------------------------------------------

def test_ac_27_2_uri_from_list_or_template_accepted() -> None:
  # From resources/list (a concrete listed uri).
  listed = ReadResourceRequestParams.from_dict({"uri": _REQUESTED_URI})
  assert listed.uri == _REQUESTED_URI
  # From expanding a ResourceTemplate "file:///{path}" → concrete uri.
  expanded = ReadResourceRequestParams.from_dict({"uri": "file:///docs/readme.md"})
  assert expanded.uri == "file:///docs/readme.md"


# ---------------------------------------------------------------------------
# AC-27.3 — retry: inputResponses for every key K, requestState echoed verbatim
# ---------------------------------------------------------------------------

def test_ac_27_3_retry_carries_input_responses() -> None:
  original = ReadResourceRequestParams(uri=_REQUESTED_URI, meta={"m": 1})
  responses = {"k1": {"action": "accept"}, "k2": {"roots": []}}
  retry = build_read_resource_retry(original, responses, "state-token")
  assert retry.uri == _REQUESTED_URI
  assert retry.input_responses == responses
  assert retry.meta == {"m": 1}
  assert retry.is_retry is True


def test_ac_27_3_request_state_echoed_verbatim() -> None:
  original = ReadResourceRequestParams(uri=_REQUESTED_URI)
  token = "Zm9vLmJhcg=="  # an opaque server-minted blob
  retry = build_read_resource_retry(original, {"k": {"action": "accept"}}, token)
  # Echoed back byte-for-byte unchanged.
  assert retry.request_state == token
  assert retry.to_dict()["requestState"] == token


def test_ac_27_3_request_state_treated_opaque() -> None:
  # The client never interprets/modifies requestState — round-trips unchanged.
  weird = "::not-json::{}[]"
  params = ReadResourceRequestParams(uri=_REQUESTED_URI, request_state=weird)
  reparsed = ReadResourceRequestParams.from_dict(params.to_dict())
  assert reparsed.request_state == weird


# ---------------------------------------------------------------------------
# AC-27.4 — ReadResourceResult: contents present, complete, ttl>=0 + scope enum
# ---------------------------------------------------------------------------

def test_ac_27_4_complete_result_fields() -> None:
  result = ReadResourceResult.from_dict(_complete_result_dict())
  assert isinstance(result.contents, list)
  assert len(result.contents) == 1
  assert result.result_type == "complete"
  assert result.ttl_ms == 60000
  assert result.cache_scope == "private"
  # Round-trip preserves the required fields.
  wire = result.to_dict()
  assert wire["resultType"] == "complete"
  assert wire["ttlMs"] == 60000
  assert wire["cacheScope"] == "private"
  assert wire["contents"][0]["text"] == "fn main() {}"


def test_ac_27_4_ttl_must_be_non_negative() -> None:
  with pytest.raises(ValueError):
    ReadResourceResult(
      contents=[TextResourceContents(uri=_REQUESTED_URI, text="x")],
      ttl_ms=-1,
      cache_scope="private",
    )
  # ttlMs of 0 is valid (immediately stale).
  ok = ReadResourceResult(
    contents=[TextResourceContents(uri=_REQUESTED_URI, text="x")],
    ttl_ms=0,
    cache_scope="public",
  )
  assert ok.ttl_ms == 0


def test_ac_27_4_cache_scope_must_be_enum() -> None:
  with pytest.raises(ValueError):
    ReadResourceResult(
      contents=[TextResourceContents(uri=_REQUESTED_URI, text="x")],
      ttl_ms=1,
      cache_scope="Public",  # wrong case — must be exact
    )


def test_ac_27_4_contents_required() -> None:
  raw = _complete_result_dict()
  del raw["contents"]
  with pytest.raises(ValueError):
    ReadResourceResult.from_dict(raw)


def test_ac_27_4_caching_fields_required() -> None:
  raw = _complete_result_dict()
  del raw["ttlMs"]
  with pytest.raises(ValueError):
    ReadResourceResult.from_dict(raw)
  raw2 = _complete_result_dict()
  del raw2["cacheScope"]
  with pytest.raises(ValueError):
    ReadResourceResult.from_dict(raw2)


# ---------------------------------------------------------------------------
# AC-27.5 — directory: multiple entries; entry uri MAY differ from requested
# ---------------------------------------------------------------------------

def test_ac_27_5_multiple_entries_and_subresource_uri() -> None:
  container = "file:///project/notes/"
  raw = {
    "resultType": "complete",
    "contents": [
      {"uri": "file:///project/notes/readme.txt", "mimeType": "text/plain",
       "text": "see logo.png"},
      {"uri": "file:///project/notes/logo.png", "mimeType": "image/png",
       "blob": _PNG_B64},
    ],
    "ttlMs": 0,
    "cacheScope": "private",
  }
  result = ReadResourceResult.from_dict(raw)
  assert len(result.contents) == 2
  # Each entry's uri differs from the requested container uri (sub-resources).
  uris = {c.uri for c in result.contents}
  assert container not in uris
  assert "file:///project/notes/readme.txt" in uris
  assert "file:///project/notes/logo.png" in uris
  # Mixed text + binary entries.
  assert isinstance(result.contents[0], TextResourceContents)
  assert isinstance(result.contents[1], BlobResourceContents)


# ---------------------------------------------------------------------------
# AC-27.6 — text entry: TextResourceContents with required uri + text
# ---------------------------------------------------------------------------

def test_ac_27_6_text_entry_shape() -> None:
  raw = {
    "resultType": "complete",
    "contents": [{"uri": _REQUESTED_URI, "text": "hello"}],
    "ttlMs": 10,
    "cacheScope": "public",
  }
  result = ReadResourceResult.from_dict(raw)
  entry = result.contents[0]
  assert isinstance(entry, TextResourceContents)
  assert entry.uri == _REQUESTED_URI
  assert entry.text == "hello"


def test_ac_27_6_text_uri_required() -> None:
  # A text entry without the REQUIRED uri is rejected (R-17.5-s); the S21 variant
  # surfaces the missing required key as a KeyError.
  with pytest.raises((KeyError, ValueError)):
    ReadResourceResult.from_dict({
      "resultType": "complete",
      "contents": [{"text": "no uri here"}],
      "ttlMs": 10,
      "cacheScope": "public",
    })


# ---------------------------------------------------------------------------
# AC-27.7 — binary entry: BlobResourceContents, base64 blob, no text field
# ---------------------------------------------------------------------------

def test_ac_27_7_blob_entry_shape() -> None:
  raw = {
    "resultType": "complete",
    "contents": [{"uri": "file:///logo.png", "mimeType": "image/png",
                  "blob": _PNG_B64}],
    "ttlMs": 10,
    "cacheScope": "public",
  }
  result = ReadResourceResult.from_dict(raw)
  entry = result.contents[0]
  assert isinstance(entry, BlobResourceContents)
  assert entry.uri == "file:///logo.png"
  assert entry.blob == _PNG_B64
  # No text field on a blob entry.
  assert "text" not in entry.to_dict()


def test_ac_27_7_blob_rejects_invalid_base64() -> None:
  with pytest.raises(ValueError):
    ReadResourceResult.from_dict({
      "resultType": "complete",
      "contents": [{"uri": "file:///x.bin", "blob": "not valid base64!!!"}],
      "ttlMs": 1,
      "cacheScope": "public",
    })


def test_ac_27_7_blob_and_text_both_rejected() -> None:
  # An entry carrying BOTH text and blob is rejected by the S21 variant dispatch.
  with pytest.raises(ValueError):
    ReadResourceResult.from_dict({
      "resultType": "complete",
      "contents": [{"uri": "file:///x", "text": "t", "blob": _VALID_B64}],
      "ttlMs": 1,
      "cacheScope": "public",
    })


def test_ac_27_7_neither_text_nor_blob_rejected() -> None:
  with pytest.raises(ValueError):
    ReadResourceResult.from_dict({
      "resultType": "complete",
      "contents": [{"uri": "file:///x", "mimeType": "application/octet-stream"}],
      "ttlMs": 1,
      "cacheScope": "public",
    })


# ---------------------------------------------------------------------------
# AC-27.8 — input_required result instead of ReadResourceResult (R-17.5-w)
# ---------------------------------------------------------------------------

def test_ac_27_8_input_required_branch() -> None:
  raw = {
    "resultType": "input_required",
    "inputRequests": {
      "elicit1": {"method": "elicitation/create"},
    },
    "requestState": "continue-token",
  }
  assert is_input_required(raw) is True
  parsed = parse_read_resource_response(raw)
  assert isinstance(parsed, InputRequiredResult)
  assert parsed.request_state == "continue-token"


def test_ac_27_8_complete_branch() -> None:
  raw = _complete_result_dict()
  assert is_input_required(raw) is False
  parsed = parse_read_resource_response(raw)
  assert isinstance(parsed, ReadResourceResult)


def test_ac_27_8_absent_result_type_is_complete() -> None:
  raw = _complete_result_dict()
  del raw["resultType"]
  assert is_input_required(raw) is False
  parsed = parse_read_resource_response(raw)
  assert isinstance(parsed, ReadResourceResult)
  assert parsed.result_type == "complete"


# ---------------------------------------------------------------------------
# AC-27.9 — https uri MAY be fetched directly (R-17.5-y)
# ---------------------------------------------------------------------------

def test_ac_27_9_https_may_fetch_directly() -> None:
  assert client_may_fetch_directly("https://example.com/data.json") is True
  # Scheme comparison is case-insensitive [RFC3986].
  assert client_may_fetch_directly("HTTPS://example.com/x") is True


def test_ac_27_9_non_https_not_directly_fetchable() -> None:
  assert client_may_fetch_directly(_REQUESTED_URI) is False
  assert client_may_fetch_directly("git://host/repo") is False
  # http (not https) is not the direct-fetch scheme.
  assert client_may_fetch_directly("http://example.com/x") is False
  # A relative reference (no scheme) is not directly fetchable.
  assert client_may_fetch_directly("/just/a/path") is False


# ---------------------------------------------------------------------------
# AC-27.10 — not-found error -32602 with data.uri; no empty-array signalling
# ---------------------------------------------------------------------------

def test_ac_27_10_not_found_error_object() -> None:
  err = ResourceNotFoundError("file:///nonexistent.txt")
  assert err.uri == "file:///nonexistent.txt"
  assert err.json_rpc_code == JSONRPC_INVALID_PARAMS == -32602
  obj = err.to_error_object()
  assert obj["code"] == -32602
  assert obj["data"]["uri"] == "file:///nonexistent.txt"
  assert isinstance(obj["message"], str) and obj["message"]


def test_ac_27_10_empty_contents_signals_non_existence() -> None:
  # An empty contents array is the ambiguous non-existence signal the server
  # MUST NOT use — the result type surfaces it for a server-side guard.
  result = ReadResourceResult(contents=[], ttl_ms=0, cache_scope="private")
  assert result.signals_non_existence is True
  nonempty = ReadResourceResult(
    contents=[TextResourceContents(uri=_REQUESTED_URI, text="x")],
    ttl_ms=0,
    cache_scope="private",
  )
  assert nonempty.signals_non_existence is False


def test_ac_27_10_assert_contents_present_raises() -> None:
  # The server-side guard converts an empty array into the -32602 error.
  with pytest.raises(ResourceNotFoundError):
    assert_contents_present([], _REQUESTED_URI)
  # A non-empty array passes.
  assert_contents_present(
    [TextResourceContents(uri=_REQUESTED_URI, text="x")], _REQUESTED_URI
  )


def test_ac_27_10_not_found_uri_extraction() -> None:
  obj = ResourceNotFoundError("file:///gone.txt").to_error_object()
  assert not_found_uri(obj) == "file:///gone.txt"
  # No data → None.
  assert not_found_uri({"code": -32602, "message": "x"}) is None
  # data without uri → None.
  assert not_found_uri({"code": -32602, "message": "x", "data": {}}) is None


# ---------------------------------------------------------------------------
# AC-27.11 — legacy -32002 accepted as resource-not-found (R-17.6-c)
# ---------------------------------------------------------------------------

def test_ac_27_11_legacy_code_accepted() -> None:
  assert is_resource_not_found_code(-32602) is True
  assert is_resource_not_found_code(JSONRPC_RESOURCE_NOT_FOUND_LEGACY) is True
  assert JSONRPC_RESOURCE_NOT_FOUND_LEGACY == -32002
  assert RESOURCE_NOT_FOUND_CODES == frozenset({-32602, -32002})


def test_ac_27_11_unrelated_code_not_not_found() -> None:
  assert is_resource_not_found_code(-32603) is False
  assert is_resource_not_found_code(-32601) is False
  assert is_resource_not_found_code(0) is False


# ---------------------------------------------------------------------------
# AC-27.12 — internal failure SHOULD use -32603 (R-17.6-d)
# ---------------------------------------------------------------------------

def test_ac_27_12_internal_error_code() -> None:
  assert JSONRPC_INTERNAL_ERROR == -32603
  # An internal-error code is NOT a resource-not-found code.
  assert is_resource_not_found_code(JSONRPC_INTERNAL_ERROR) is False


# ---------------------------------------------------------------------------
# AC-27.13 — no per-resource subscribe/unsubscribe method exists (R-17.7-a)
# ---------------------------------------------------------------------------

def test_ac_27_13_no_subscribe_method() -> None:
  # Subscription is governed entirely by §10 / S16; no request method exists.
  assert has_subscribe_method() is False


# ---------------------------------------------------------------------------
# AC-27.14 — list_changed delivered on a stream that opted into the filter
# ---------------------------------------------------------------------------

def test_ac_27_14_list_changed_delivered_when_opted_in() -> None:
  honored = SubscriptionFilter(resources_list_changed=True)
  assert server_may_send_list_changed(honored) is True


def test_ac_27_14_list_changed_notification_roundtrip() -> None:
  notif = ResourceListChangedNotification(meta={"k": "v"})
  wire = notif.to_dict()
  assert wire["method"] == "notifications/resources/list_changed"
  assert wire["params"] == {"_meta": {"k": "v"}}
  parsed = ResourceListChangedNotification.from_dict(wire)
  assert parsed.meta == {"k": "v"}
  # A bare notification carries just the method (no params).
  bare = ResourceListChangedNotification()
  assert bare.to_dict() == {
    "jsonrpc": "2.0",
    "method": "notifications/resources/list_changed",
  }
  assert ResourceListChangedNotification.from_dict(bare.to_dict()).meta is None


def test_ac_27_14_list_changed_rejects_extra_params() -> None:
  with pytest.raises(ValueError):
    ResourceListChangedNotification.from_dict({
      "method": "notifications/resources/list_changed",
      "params": {"resources": []},  # carries non-_meta data
    })


def test_ac_27_14_list_changed_rejects_wrong_method() -> None:
  with pytest.raises(ValueError):
    ResourceListChangedNotification.from_dict({"method": "notifications/other"})


# ---------------------------------------------------------------------------
# AC-27.15 — list_changed NOT delivered when filter did not opt in (R-17.7-e)
# ---------------------------------------------------------------------------

def test_ac_27_15_list_changed_blocked_without_optin() -> None:
  # Filter did not set resourcesListChanged.
  not_opted = SubscriptionFilter(resources_list_changed=False)
  assert server_may_send_list_changed(not_opted) is False
  # An empty filter likewise blocks it.
  assert server_may_send_list_changed(SubscriptionFilter()) is False


# ---------------------------------------------------------------------------
# AC-27.16 — updated for subscribed uri (incl. sub-resource); client may re-read
# ---------------------------------------------------------------------------

def test_ac_27_16_updated_for_subscribed_uri() -> None:
  honored = SubscriptionFilter(resource_subscriptions=(_REQUESTED_URI,))
  assert server_may_send_updated(honored, _REQUESTED_URI) is True


def test_ac_27_16_updated_for_subresource() -> None:
  # Subscribed to a container directory; an update for a contained file is allowed.
  honored = SubscriptionFilter(
    resource_subscriptions=("file:///project/notes/",)
  )
  assert server_may_send_updated(honored, "file:///project/notes/logo.png") is True


def test_ac_27_16_updated_params_uri_required() -> None:
  with pytest.raises(ValueError):
    ResourceUpdatedNotificationParams.from_dict({"_meta": {}})
  with pytest.raises(ValueError):
    ResourceUpdatedNotificationParams(uri="")


def test_ac_27_16_updated_notification_roundtrip() -> None:
  params = ResourceUpdatedNotificationParams(
    uri=_REQUESTED_URI,
    meta={SUBSCRIPTION_ID_META_KEY: "4"},
  )
  notif = ResourceUpdatedNotification(params=params)
  wire = notif.to_dict()
  assert wire["method"] == "notifications/resources/updated"
  assert wire["params"]["uri"] == _REQUESTED_URI
  assert wire["params"]["_meta"][SUBSCRIPTION_ID_META_KEY] == "4"
  parsed = ResourceUpdatedNotification.from_dict(wire)
  assert parsed.uri == _REQUESTED_URI


def test_ac_27_16_client_should_reread() -> None:
  # On receiving the update the client MAY re-issue resources/read for the uri.
  assert client_should_reread("notifications/resources/updated") is True
  assert client_should_reread("notifications/resources/list_changed") is False


def test_ac_27_16_subscription_id_correlation() -> None:
  notif = make_resource_updated_notification(4, _REQUESTED_URI)
  # The S16 builder stamps the subscription id correlation into _meta.
  assert notif.method == "notifications/resources/updated"
  assert notif.params["uri"] == _REQUESTED_URI
  assert extract_subscription_id(notif) == "4"
  # The params helper reads the same correlation key back.
  params = ResourceUpdatedNotificationParams.from_dict(notif.params)
  assert params.subscription_id == "4"


def test_ac_27_16_make_notification_gated_allows_subscribed() -> None:
  honored = SubscriptionFilter(resource_subscriptions=(_REQUESTED_URI,))
  notif = make_resource_updated_notification(7, _REQUESTED_URI, honored=honored)
  assert notif.params["uri"] == _REQUESTED_URI
  assert extract_subscription_id(notif) == "7"


# ---------------------------------------------------------------------------
# AC-27.17 — updated NOT sent for a non-subscribed uri (R-17.7-j)
# ---------------------------------------------------------------------------

def test_ac_27_17_updated_blocked_for_unsubscribed() -> None:
  honored = SubscriptionFilter(resource_subscriptions=("file:///watched.txt",))
  assert server_may_send_updated(honored, "file:///other.txt") is False
  # No subscriptions at all → nothing allowed.
  assert server_may_send_updated(SubscriptionFilter(), _REQUESTED_URI) is False


def test_ac_27_17_make_notification_rejects_unsubscribed() -> None:
  honored = SubscriptionFilter(resource_subscriptions=("file:///watched.txt",))
  with pytest.raises(ValueError):
    make_resource_updated_notification(
      1, "file:///not-watched.txt", honored=honored
    )


# ---------------------------------------------------------------------------
# AC-27.18 — scheme registry non-exhaustive; custom scheme RFC3986-conformant
# ---------------------------------------------------------------------------

def test_ac_27_18_registry_non_exhaustive() -> None:
  # The named standard schemes.
  assert STANDARD_URI_SCHEMES == frozenset({"https", "file", "git"})
  assert is_standard_scheme(SCHEME_HTTPS)
  assert is_standard_scheme(SCHEME_FILE)
  assert is_standard_scheme(SCHEME_GIT)


def test_ac_27_18_custom_scheme_recognised() -> None:
  # A custom scheme is NOT in the standard set but is a valid RFC3986 scheme.
  assert is_standard_scheme("acme") is False
  # urlsplit extracts the custom scheme; it conforms to RFC3986 grammar.
  assert uri_scheme("acme://service/object-42") == "acme"


def test_ac_27_18_scheme_requires_rfc3986() -> None:
  # A URI with no scheme component is not an absolute URI [RFC3986].
  with pytest.raises(ValueError):
    uri_scheme("no-scheme-relative/path")


# ---------------------------------------------------------------------------
# AC-27.19 — https for direct fetch; otherwise prefer another/custom scheme
# ---------------------------------------------------------------------------

def test_ac_27_19_https_for_direct_fetch() -> None:
  # https signals the client can fetch directly — and so it may.
  assert uri_scheme("https://example.com/a") == "https"
  assert client_may_fetch_directly("https://example.com/a") is True


def test_ac_27_19_non_web_prefers_other_scheme() -> None:
  # For non-direct-fetch cases a server uses another scheme (e.g. file/git/custom);
  # such schemes are not directly fetchable by the client.
  for uri in ("file:///x", "git://host/r", "acme://thing"):
    assert client_may_fetch_directly(uri) is False


# ---------------------------------------------------------------------------
# AC-27.20 — file:// directory MAY use the inode/directory MIME type (R-17.9-d)
# ---------------------------------------------------------------------------

def test_ac_27_20_inode_directory_mime_type() -> None:
  assert MIME_TYPE_INODE_DIRECTORY == "inode/directory"
  # A directory entry carried in a read result MAY use this XDG MIME type.
  raw = {
    "resultType": "complete",
    "contents": [{
      "uri": "file:///project/notes/",
      "mimeType": MIME_TYPE_INODE_DIRECTORY,
      "text": "",
    }],
    "ttlMs": 0,
    "cacheScope": "private",
  }
  result = ReadResourceResult.from_dict(raw)
  assert result.contents[0].mime_type == "inode/directory"
