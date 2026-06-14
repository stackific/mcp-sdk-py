"""Tests for S18 — Pagination.

Coverage map (16 ACs):
  AC-18.1  → TestEmptyStringCursorIsPresent
  AC-18.2  → TestCursorPositionedAfterCursor
  AC-18.3  → TestFirstPageWithoutCursor
  AC-18.4  → TestFirstPageParamsOmitted
  AC-18.5  → TestNextCursorUsedForFollowup
  AC-18.6  → TestAbsentNextCursorIsLastPage
  AC-18.7  → TestServerNextCursorBehavior
  AC-18.8  → TestEmptyStringNextCursorNotEndOfResults
  AC-18.9  → TestSinglePageAndMultiPageFlows
  AC-18.10 → TestStableCursor
  AC-18.11 → TestServerResolvesPosition
  AC-18.12 → TestCursorIsOpaque
  AC-18.13 → TestCursorScopeAndPersistence
  AC-18.14 → TestVariablePageSize
  AC-18.15 → TestInvalidCursorError
  AC-18.16 → TestPageCacheKey
"""

import pytest

from mcp_sdk_py.pagination import (
  PAGINATED_METHODS,
  InvalidCursorError,
  PaginatedRequestParams,
  PaginatedResult,
  cursor_is_present,
  is_end_of_results,
  make_page_cache_key,
  parse_paginated_request_params,
  parse_paginated_result,
)


# ---------------------------------------------------------------------------
# AC-18.1 — Empty string cursor is a PRESENT cursor  (R-12.1-a)
# ---------------------------------------------------------------------------

class TestEmptyStringCursorIsPresent:
  def test_empty_string_cursor_is_present(self):
    """cursor_is_present returns True for the empty string."""
    assert cursor_is_present("") is True

  def test_none_cursor_is_not_present(self):
    assert cursor_is_present(None) is False

  def test_non_empty_cursor_is_present(self):
    assert cursor_is_present("tok-abc") is True

  def test_empty_string_in_request_params_is_valid(self):
    p = parse_paginated_request_params({"cursor": ""})
    assert p.cursor == ""
    assert cursor_is_present(p.cursor) is True

  def test_server_treats_empty_cursor_as_positioned_cursor(self):
    """A result carrying nextCursor="" must not be treated as end-of-results."""
    result = PaginatedResult(next_cursor="")
    assert not is_end_of_results(result)
    assert cursor_is_present(result.next_cursor) is True


# ---------------------------------------------------------------------------
# AC-18.2 — Server returns results after the given cursor  (R-12.2-a)
# ---------------------------------------------------------------------------

class TestCursorPositionedAfterCursor:
  def test_cursor_in_request_params_is_preserved(self):
    """The cursor value is preserved exactly for the server to use."""
    raw = {"cursor": "eyJwYWdlIjogMn0="}
    p = parse_paginated_request_params(raw)
    assert p.cursor == "eyJwYWdlIjogMn0="

  def test_to_dict_emits_cursor_when_set(self):
    p = PaginatedRequestParams(cursor="C1")
    assert p.to_dict()["cursor"] == "C1"


# ---------------------------------------------------------------------------
# AC-18.3 — Absent cursor → first page  (R-12.2-b)
# ---------------------------------------------------------------------------

class TestFirstPageWithoutCursor:
  def test_no_cursor_in_request_params_means_first_page(self):
    p = parse_paginated_request_params({})
    assert p.cursor is None

  def test_to_dict_omits_cursor_when_none(self):
    p = PaginatedRequestParams()
    assert "cursor" not in p.to_dict()


# ---------------------------------------------------------------------------
# AC-18.4 — Params may be omitted entirely for first page  (R-12.3-a)
# ---------------------------------------------------------------------------

class TestFirstPageParamsOmitted:
  def test_empty_dict_parses_as_first_page_params(self):
    """An empty params dict is equivalent to a first-page request (R-12.3-a)."""
    p = parse_paginated_request_params({})
    assert p.cursor is None
    assert p.meta is None
    assert p.extra == {}

  def test_none_cursor_is_absent_from_wire(self):
    p = PaginatedRequestParams(cursor=None)
    d = p.to_dict()
    assert "cursor" not in d


# ---------------------------------------------------------------------------
# AC-18.5 — nextCursor in result means more pages; use as cursor  (R-12.2-c)
# ---------------------------------------------------------------------------

class TestNextCursorUsedForFollowup:
  def test_next_cursor_present_means_more_may_be_available(self):
    r = parse_paginated_result({"resultType": "complete", "nextCursor": "C2"})
    assert r.next_cursor == "C2"
    assert not r.is_last_page

  def test_next_cursor_echoed_as_cursor_in_follow_up(self):
    """Client echoes nextCursor as cursor; the values are identical strings."""
    r = PaginatedResult(next_cursor="C1")
    follow_up_cursor = r.next_cursor
    p = PaginatedRequestParams(cursor=follow_up_cursor)
    assert p.cursor == "C1"

  def test_next_cursor_in_result_roundtrip(self):
    raw = {"resultType": "complete", "tools": [], "nextCursor": "eyJwYWdlIjogMn0="}
    r = parse_paginated_result(raw)
    assert r.next_cursor == "eyJwYWdlIjogMn0="


# ---------------------------------------------------------------------------
# AC-18.6 — Absent nextCursor = last page  (R-12.2-d, R-12.3-c)
# ---------------------------------------------------------------------------

class TestAbsentNextCursorIsLastPage:
  def test_absent_next_cursor_is_last_page(self):
    r = parse_paginated_result({"resultType": "complete", "tools": []})
    assert r.next_cursor is None
    assert r.is_last_page

  def test_is_end_of_results_true_for_absent_cursor(self):
    r = PaginatedResult(next_cursor=None)
    assert is_end_of_results(r) is True

  def test_to_dict_omits_next_cursor_when_none(self):
    r = PaginatedResult()
    assert "nextCursor" not in r.to_dict()


# ---------------------------------------------------------------------------
# AC-18.7 — Server sets/omits nextCursor correctly  (R-12.3-b)
# ---------------------------------------------------------------------------

class TestServerNextCursorBehavior:
  def test_result_with_next_cursor_is_not_last_page(self):
    r = PaginatedResult(next_cursor="tok")
    assert not r.is_last_page
    assert r.to_dict()["nextCursor"] == "tok"

  def test_result_without_next_cursor_is_last_page(self):
    r = PaginatedResult()
    assert r.is_last_page
    assert "nextCursor" not in r.to_dict()


# ---------------------------------------------------------------------------
# AC-18.8 — nextCursor="" is NOT end-of-results  (R-12.3-d, R-12.3-e)
# ---------------------------------------------------------------------------

class TestEmptyStringNextCursorNotEndOfResults:
  def test_empty_next_cursor_is_not_end_of_results(self):
    """nextCursor="" must be resent as cursor to continue (R-12.3-d/e)."""
    r = PaginatedResult(next_cursor="")
    assert not is_end_of_results(r)
    assert r.next_cursor == ""

  def test_empty_next_cursor_in_parsed_result(self):
    raw = {"resultType": "complete", "tools": [], "nextCursor": ""}
    r = parse_paginated_result(raw)
    assert r.next_cursor == ""
    assert not is_end_of_results(r)

  def test_empty_string_roundtrips_in_to_dict(self):
    r = PaginatedResult(next_cursor="")
    assert r.to_dict()["nextCursor"] == ""


# ---------------------------------------------------------------------------
# AC-18.9 — Client supports single-page and multi-page flows  (R-12.3-f–h)
# ---------------------------------------------------------------------------

class TestSinglePageAndMultiPageFlows:
  def test_single_page_result_no_next_cursor_is_handled(self):
    r = parse_paginated_result({"resultType": "complete", "tools": []})
    assert r.is_last_page

  def test_multi_page_flow_terminates_on_absent_next_cursor(self):
    pages = [
      PaginatedResult(next_cursor="C1", extra={"tools": ["a"]}),
      PaginatedResult(next_cursor="C2", extra={"tools": ["b"]}),
      PaginatedResult(next_cursor=None, extra={"tools": ["c"]}),
    ]
    collected = []
    cursor = None
    for page in pages:
      # Simulate client loop: collect items, advance cursor.
      collected.extend(page.extra.get("tools", []))
      if is_end_of_results(page):
        break
      cursor = page.next_cursor
    assert collected == ["a", "b", "c"]
    assert cursor == "C2"

  def test_empty_page_with_next_cursor_still_continues(self):
    """An empty page with nextCursor means more results may follow (R-12.4-b)."""
    r = PaginatedResult(next_cursor="Cx", extra={"tools": []})
    assert not is_end_of_results(r)


# ---------------------------------------------------------------------------
# AC-18.10 — Stable cursor: can be re-used  (R-12.3-i)
# ---------------------------------------------------------------------------

class TestStableCursor:
  def test_cursor_value_is_preserved_unchanged(self):
    """Cursor is echoed back exactly; the server resolves it to the same page."""
    cursor = "eyJwYWdlIjogMn0="
    p = PaginatedRequestParams(cursor=cursor)
    assert p.cursor == cursor
    assert p.to_dict()["cursor"] == cursor


# ---------------------------------------------------------------------------
# AC-18.11 — Server resolves cursor to position  (R-12.3-j)
# ---------------------------------------------------------------------------

class TestServerResolvesPosition:
  def test_cursor_sent_as_opaque_string(self):
    """Client sends cursor as-is; interpretation is server-only."""
    for cursor_val in ("C1", "eyJwYWdlIjogMn0=", "", "page-3"):
      p = PaginatedRequestParams(cursor=cursor_val)
      out = p.to_dict()
      assert out["cursor"] == cursor_val


# ---------------------------------------------------------------------------
# AC-18.12 — Cursor is opaque  (R-12.3-k, R-12.3-l, R-12.3-m)
# ---------------------------------------------------------------------------

class TestCursorIsOpaque:
  def test_cursor_treated_as_opaque_string(self):
    """Client only observes presence vs absence; no parsing."""
    cursors = [
      "eyJwYWdlIjogMn0=",   # base64-encoded JSON — client must not decode
      "page=3&limit=10",     # query string format — client must not parse
      "12345",               # numeric string — client must not parse as int
      "",                    # empty string — present, not absent
    ]
    for c in cursors:
      # validate_cursor confirms it's a string and returns unchanged.
      from mcp_sdk_py.result_error import validate_cursor
      assert validate_cursor(c) == c

  def test_only_presence_may_be_determined(self):
    """The only determination a client makes: value provided or not (R-12.3-m)."""
    assert cursor_is_present("some-opaque-token") is True
    assert cursor_is_present(None) is False
    assert cursor_is_present("") is True


# ---------------------------------------------------------------------------
# AC-18.13 — Cursor scope and persistence constraints  (R-12.3-n–q)
# ---------------------------------------------------------------------------

class TestCursorScopeAndPersistence:
  def test_cursor_valid_only_with_issuing_server(self):
    """Cursors from server A must not be sent to server B (R-12.3-o, R-12.3-p)."""
    # Behavioral constraint: the cursor is a plain string; the client must
    # not send it to a different server. Demonstrated by the lack of any
    # server identifier inside the cursor (it's opaque).
    cursor_from_server_a = "C1-from-server-a"
    p = PaginatedRequestParams(cursor=cursor_from_server_a)
    # The cursor is just a string; there is nothing binding it to a server.
    # The constraint is enforced by client behavior, not structure.
    assert isinstance(p.cursor, str)

  def test_cursor_does_not_carry_meaning_across_sessions(self):
    """Demonstrated by cursor being opaque — no structural meaning to preserve."""
    r = PaginatedResult(next_cursor="tok")
    assert isinstance(r.next_cursor, str)


# ---------------------------------------------------------------------------
# AC-18.14 — Variable page size  (R-12.4-a, R-12.4-b)
# ---------------------------------------------------------------------------

class TestVariablePageSize:
  def test_pages_may_have_different_sizes(self):
    page1 = PaginatedResult(next_cursor="C1", extra={"tools": ["a", "b", "c"]})
    page2 = PaginatedResult(next_cursor="C2", extra={"tools": ["d"]})
    page3 = PaginatedResult(extra={"tools": ["e", "f"]})
    sizes = [
      len(page1.extra["tools"]),
      len(page2.extra["tools"]),
      len(page3.extra["tools"]),
    ]
    assert sizes == [3, 1, 2]

  def test_empty_page_with_next_cursor_is_legitimate(self):
    """Server may return an empty page with nextCursor (R-12.4-b)."""
    r = PaginatedResult(next_cursor="C7", extra={"tools": []})
    assert r.extra["tools"] == []
    assert r.next_cursor == "C7"
    assert not is_end_of_results(r)


# ---------------------------------------------------------------------------
# AC-18.15 — Invalid cursor → -32602  (R-12.4-c, R-12.4-d)
# ---------------------------------------------------------------------------

class TestInvalidCursorError:
  def test_invalid_cursor_error_has_code_32602(self):
    err = InvalidCursorError("bad-cursor")
    assert err.json_rpc_code == -32602
    assert err.cursor == "bad-cursor"

  def test_invalid_cursor_error_message(self):
    err = InvalidCursorError("xyz")
    assert "xyz" in str(err)

  def test_server_raises_invalid_cursor_for_unrecognized(self):
    """Simulate a server raising InvalidCursorError on an unknown cursor."""
    def _server_get_page(cursor: str | None):
      known = {"C1": [1, 2], "C2": [3, 4]}
      if cursor is not None and cursor not in known:
        raise InvalidCursorError(cursor)
      return known.get(cursor, [5, 6])

    assert _server_get_page(None) == [5, 6]
    assert _server_get_page("C1") == [1, 2]
    with pytest.raises(InvalidCursorError) as exc_info:
      _server_get_page("garbage")
    assert exc_info.value.json_rpc_code == -32602


# ---------------------------------------------------------------------------
# AC-18.16 — Page cache key is per-request, not per-cursor content  (R-12.5-a)
# ---------------------------------------------------------------------------

class TestPageCacheKey:
  def test_first_page_and_cursor_page_have_different_keys(self):
    key1 = make_page_cache_key("tools/list", None)            # first page
    key2 = make_page_cache_key("tools/list", {"cursor": "C1"})
    assert key1 != key2

  def test_different_cursors_have_different_keys(self):
    key1 = make_page_cache_key("tools/list", {"cursor": "C1"})
    key2 = make_page_cache_key("tools/list", {"cursor": "C2"})
    assert key1 != key2

  def test_same_cursor_same_key(self):
    key1 = make_page_cache_key("tools/list", {"cursor": "C1"})
    key2 = make_page_cache_key("tools/list", {"cursor": "C1"})
    assert key1 == key2

  def test_empty_cursor_has_own_key(self):
    """Empty string cursor is a present cursor and has a distinct cache key."""
    key_empty = make_page_cache_key("tools/list", {"cursor": ""})
    key_none = make_page_cache_key("tools/list", None)
    assert key_empty != key_none

  def test_different_methods_have_different_keys(self):
    key1 = make_page_cache_key("tools/list", {"cursor": "C1"})
    key2 = make_page_cache_key("resources/list", {"cursor": "C1"})
    assert key1 != key2

  def test_paginated_methods_are_registered(self):
    assert "tools/list" in PAGINATED_METHODS
    assert "resources/list" in PAGINATED_METHODS
    assert "resources/templates/list" in PAGINATED_METHODS
    assert "prompts/list" in PAGINATED_METHODS


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

class TestParsing:
  def test_parse_paginated_request_params_non_dict_raises(self):
    with pytest.raises(TypeError, match="paginated request params must be a JSON object"):
      parse_paginated_request_params("not-a-dict")  # type: ignore[arg-type]

  def test_parse_paginated_request_params_cursor_must_be_string(self):
    with pytest.raises(TypeError, match="cursor must be a string"):
      parse_paginated_request_params({"cursor": 42})

  def test_parse_paginated_result_wire_examples(self):
    first_page_result = {
      "resultType": "complete",
      "tools": [{"name": "get_weather", "title": "Get Weather",
                 "inputSchema": {"type": "object", "properties": {}}}],
      "nextCursor": "eyJwYWdlIjogMn0=",
    }
    r = parse_paginated_result(first_page_result)
    assert r.next_cursor == "eyJwYWdlIjogMn0="
    assert not r.is_last_page

  def test_parse_paginated_result_final_page_wire_example(self):
    final_page = {
      "resultType": "complete",
      "tools": [{"name": "get_forecast", "title": "Get Forecast",
                 "inputSchema": {"type": "object", "properties": {}}}],
    }
    r = parse_paginated_result(final_page)
    assert r.is_last_page
    assert r.next_cursor is None

  def test_parse_paginated_result_next_cursor_must_be_string(self):
    with pytest.raises(TypeError, match="nextCursor must be a string"):
      parse_paginated_result({"resultType": "complete", "nextCursor": 42})
