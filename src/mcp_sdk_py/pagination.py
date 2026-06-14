"""Pagination — S18.

Delivers cursor-based pagination: the opaque Cursor token, PaginatedRequestParams
(with optional cursor field), PaginatedResult (with optional nextCursor field),
exchange semantics, cursor opacity rules, and an invalid-cursor exception.

Spec: §12
Depends on: S04
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE, ResultType


# ---------------------------------------------------------------------------
# §12  Paginated methods registry  [R-12.2-a]
# ---------------------------------------------------------------------------

#: The set of list methods that use the paginated request/result shapes.
PAGINATED_METHODS: frozenset[str] = frozenset({
  "tools/list",
  "resources/list",
  "resources/templates/list",
  "prompts/list",
})


# ---------------------------------------------------------------------------
# §12  Exception for invalid cursors  [R-12.4-c, R-12.4-d]
# ---------------------------------------------------------------------------

class InvalidCursorError(Exception):
  """The client supplied a cursor that is not recognized by the server.

  Server SHOULD respond with JSON-RPC error code -32602 (Invalid params)
  and handle the condition gracefully (R-12.4-c, R-12.4-d).

  Attributes:
    cursor: The cursor value that was not recognized.
    json_rpc_code: Always -32602 for callers building error responses.
  """

  json_rpc_code: int = -32602

  def __init__(self, cursor: str) -> None:
    super().__init__(
      f"Cursor {cursor!r} is not recognized or is malformed (R-12.4-c); "
      f"respond with JSON-RPC -32602"
    )
    self.cursor: str = cursor


# ---------------------------------------------------------------------------
# §12  Data structures  [§12 §6]
# ---------------------------------------------------------------------------

@dataclass
class PaginatedRequestParams:
  """Base params shape for any paginated list request (§12).

  cursor is OPTIONAL; when absent the server returns the first page (R-12.2-b).
  When present, the server returns results positioned strictly after that cursor
  (R-12.2-a). Wire key: "cursor".

  meta carries the _meta object per §4/S05 rules (optional here; requests
  carry it via RequestParams from S04). Wire key: "_meta".

  extra holds method-specific members (e.g. a filter field) beyond the base.
  """

  cursor: str | None = None
  meta: dict[str, Any] | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields."""
    out: dict[str, Any] = {}
    if self.meta is not None:
      out["_meta"] = self.meta
    if self.cursor is not None:
      out["cursor"] = self.cursor
    out.update(self.extra)
    return out


@dataclass
class PaginatedResult:
  """Base result shape for paginated list results (§12).

  nextCursor OPTIONAL: when present, more results MAY follow and the client
  uses this value as cursor on the next request (R-12.2-c).  When absent,
  the client MUST treat the current page as the last page (R-12.2-d).
  Wire key: "nextCursor".

  result_type follows the Result base shape (S04). Wire key: "resultType".
  meta: optional _meta. Wire key: "_meta".
  extra: method-specific list payload and any other members.
  """

  result_type: ResultType = RESULT_TYPE_COMPLETE
  next_cursor: str | None = None
  meta: dict[str, Any] | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  @property
  def is_last_page(self) -> bool:
    """True when nextCursor is absent — this is the final page (R-12.2-d, R-12.3-c)."""
    return self.next_cursor is None

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a wire-compatible dict; omits absent optional fields."""
    out: dict[str, Any] = {"resultType": self.result_type}
    if self.meta is not None:
      out["_meta"] = self.meta
    if self.next_cursor is not None:
      out["nextCursor"] = self.next_cursor
    out.update(self.extra)
    return out


# ---------------------------------------------------------------------------
# §12  Cursor helpers  [R-12.1-a, R-12.3-d, R-12.3-e]
# ---------------------------------------------------------------------------

def cursor_is_present(cursor: str | None) -> bool:
  """Return True when cursor represents a present (non-absent) cursor value.

  The empty string ``""`` is a PRESENT cursor — it MUST be sent back as
  cursor on the next request and MUST NOT be treated as absent (R-12.1-a,
  R-12.3-d, R-12.3-e).  Only ``None`` represents absence.
  """
  return cursor is not None


def is_end_of_results(result: PaginatedResult) -> bool:
  """Return True when result is the last page (nextCursor absent) (R-12.2-d, R-12.3-c).

  A nextCursor of ``""`` is a PRESENT cursor; this returns False in that case
  (R-12.3-d) — the caller MUST continue paginating.
  """
  return result.next_cursor is None


# ---------------------------------------------------------------------------
# §12  Parsing helpers
# ---------------------------------------------------------------------------

def parse_paginated_request_params(raw: dict[str, Any]) -> PaginatedRequestParams:
  """Parse paginated request params from a wire dict.

  Accepts an empty dict (first-page request with no cursor, R-12.2-b).
  Cursor MUST be a string if present; empty string ``""`` is valid (R-12.1-a).

  Raises:
    TypeError: raw is not a dict, or cursor/_meta has the wrong type.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"paginated request params must be a JSON object; got {type(raw).__name__}"
    )
  cursor = raw.get("cursor")
  if cursor is not None and not isinstance(cursor, str):
    raise TypeError(
      f"cursor must be a string; got {type(cursor).__name__}"
    )
  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"_meta must be a JSON object if present; got {type(meta).__name__}"
    )
  extra = {k: v for k, v in raw.items() if k not in {"cursor", "_meta"}}
  return PaginatedRequestParams(cursor=cursor, meta=meta, extra=extra)


def parse_paginated_result(
  raw: dict[str, Any],
  *,
  interop_fallback: bool = False,
) -> PaginatedResult:
  """Parse a paginated result from a wire dict.

  nextCursor MUST be a string if present; empty string is valid (R-12.1-a).
  Delegates resultType handling to the S04 result model (absent resultType
  raises unless interop_fallback=True).

  Raises:
    TypeError: raw is not a dict, or a field has the wrong type.
    ValueError: resultType absent in strict mode.
  """
  from mcp_sdk_py.result_error import parse_result

  if not isinstance(raw, dict):
    raise TypeError(
      f"paginated result must be a JSON object; got {type(raw).__name__}"
    )
  # Validate resultType via S04 parse_result (also checks for unknown types).
  base = parse_result(raw, interop_fallback=interop_fallback)

  next_cursor = raw.get("nextCursor")
  if next_cursor is not None and not isinstance(next_cursor, str):
    raise TypeError(
      f"nextCursor must be a string; got {type(next_cursor).__name__}"
    )

  # Remove pagination-specific and base keys to compute extra.
  reserved = {"resultType", "_meta", "nextCursor"}
  extra = {k: v for k, v in raw.items() if k not in reserved}

  return PaginatedResult(
    result_type=base.result_type,
    next_cursor=next_cursor,
    meta=base.meta,
    extra=extra,
  )


# ---------------------------------------------------------------------------
# §12.5  Cache-key helper  [R-12.5-a]
# ---------------------------------------------------------------------------

def make_page_cache_key(method: str, params: dict[str, Any] | None) -> tuple:
  """Return a hashable cache key for a paginated request.

  Each page is an independent response identified by its full request
  (including the cursor value).  Two requests that differ only in cursor
  MUST NOT share a cache entry (R-12.5-a).

  The key is a tuple of (method, cursor_value_or_None) where cursor is
  extracted from params.  Callers that need richer key components (e.g.
  additional params) should extend this tuple.
  """
  cursor: str | None = None
  if params is not None:
    raw_cursor = params.get("cursor")
    if isinstance(raw_cursor, str):
      cursor = raw_cursor
  return (method, cursor)
