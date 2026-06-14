"""Discovery via server/discover — S08.

Delivers:
  - DiscoverResult: the server's advertisement (versions, capabilities, serverInfo)
  - DiscoverResultResponse: JSON-RPC success wrapper for a DiscoverResult
  - MissingDiscoverMetaKeyError: a required _meta key is absent on the request
  - EmptySupportedVersionsError: supportedVersions must be non-empty
  - InvalidServerInfoError: serverInfo missing name or version string
  - validate_discover_request_meta(): validates three required _meta keys (R-5.3.1-a–d)
  - validate_discover_result(): parses and validates a raw discover result (R-5.3.2-a–k)
  - build_unsupported_version_error_data(): builds data payload for the -32004 error (R-5.3.1-g)
  - check_discover_revision(): extracts and validates the requested revision against supported list

Spec: §5.3
Depends on: S04, S07
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_sdk_py.meta_object import (
  KEY_CLIENT_CAPABILITIES,
  KEY_CLIENT_INFO,
  KEY_PROTOCOL_VERSION,
)
from mcp_sdk_py.progress import DISCOVER_METHOD
from mcp_sdk_py.result_error import RESULT_TYPE_COMPLETE
from mcp_sdk_py.revision import UnsupportedRevisionError


# ---------------------------------------------------------------------------
# §5.3  Method name
# ---------------------------------------------------------------------------

#: Re-export for convenience; the canonical definition lives in progress.py
#: (required there for non-cancellability enforcement, R-15.2.2-b).
DISCOVER_METHOD_NAME: str = DISCOVER_METHOD


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class MissingDiscoverMetaKeyError(Exception):
  """A required _meta key is absent on a server/discover request (R-5.3.1-a–d).

  Attributes:
    missing_key: the key name that was expected but absent.
    json_rpc_code: -32602 (Invalid params); signals the error code to the caller.
  """

  json_rpc_code: int = -32602

  def __init__(self, missing_key: str) -> None:
    super().__init__(
      f"server/discover request _meta is missing required key {missing_key!r} "
      f"(R-5.3.1-a–d); reject with JSON-RPC -32602"
    )
    self.missing_key: str = missing_key


class EmptySupportedVersionsError(Exception):
  """supportedVersions must be a non-empty list (R-5.3.2-b).

  Attributes:
    json_rpc_code: -32600 (generic protocol error from the server side).
  """

  json_rpc_code: int = -32600

  def __init__(self) -> None:
    super().__init__(
      "DiscoverResult.supportedVersions MUST be a non-empty array of strings (R-5.3.2-b)"
    )


class InvalidServerInfoError(Exception):
  """serverInfo is missing the required name or version string (R-5.3.2-f).

  Attributes:
    missing_field: "name" or "version" — whichever is absent or not a string.
    json_rpc_code: -32600 (generic protocol error from the server side).
  """

  json_rpc_code: int = -32600

  def __init__(self, missing_field: str) -> None:
    super().__init__(
      f"DiscoverResult.serverInfo is missing or has a non-string {missing_field!r} "
      f"(R-5.3.2-f)"
    )
    self.missing_field: str = missing_field


# ---------------------------------------------------------------------------
# §5.3.2  DiscoverResult data structure
# ---------------------------------------------------------------------------

@dataclass
class DiscoverResult:
  """The server's advertisement returned by a successful server/discover (§5.3.2).

  Fields:
    result_type: discriminator, normally ``"complete"`` (R-5.3.2-a).
    supported_versions: non-empty list of YYYY-MM-DD revision strings the server
      accepts; ordering carries no preference (R-5.3.2-b/c/d).
    capabilities: server capability map; empty dict ``{}`` is valid (R-5.3.2-e).
    server_info: server identity — REQUIRES ``name`` and ``version`` strings (R-5.3.2-f).
    instructions: optional natural-language guidance for effective server use (R-5.3.2-g/h/i).
    meta: optional result-level metadata object (R-5.3.2-k).
  """

  result_type: str
  supported_versions: list[str]
  capabilities: dict[str, Any]
  server_info: dict[str, Any]
  instructions: str | None = None
  meta: dict[str, Any] | None = None

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    d: dict[str, Any] = {
      "resultType": self.result_type,
      "supportedVersions": list(self.supported_versions),
      "capabilities": dict(self.capabilities),
      "serverInfo": dict(self.server_info),
    }
    if self.instructions is not None:
      d["instructions"] = self.instructions
    if self.meta is not None:
      d["_meta"] = self.meta
    return d


# ---------------------------------------------------------------------------
# §5.3  DiscoverResultResponse — JSON-RPC success wrapper
# ---------------------------------------------------------------------------

@dataclass
class DiscoverResultResponse:
  """JSON-RPC 2.0 success envelope carrying a DiscoverResult (§5.3).

  Fields:
    id: matches the originating request id.
    result: the DiscoverResult payload.
    jsonrpc: always ``"2.0"`` (set automatically).
  """

  id: str | int | float
  result: DiscoverResult
  jsonrpc: str = field(default="2.0", init=False)

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict."""
    return {
      "jsonrpc": self.jsonrpc,
      "id": self.id,
      "result": self.result.to_dict(),
    }


# ---------------------------------------------------------------------------
# §5.3.1  Request meta validation (client-side construction rule)
# ---------------------------------------------------------------------------

#: The three _meta keys required on every server/discover request (R-5.3.1-a–d).
DISCOVER_REQUIRED_META_KEYS: frozenset[str] = frozenset({
  KEY_PROTOCOL_VERSION,
  KEY_CLIENT_INFO,
  KEY_CLIENT_CAPABILITIES,
})


def validate_discover_request_meta(meta: Any) -> dict[str, Any]:
  """Validate the three required _meta keys on a server/discover request (R-5.3.1-a–d).

  Additional keys beyond the required three are permitted (R-5.3.1-e).

  Args:
    meta: the raw _meta object from the request params; must be a dict.

  Returns:
    meta, unchanged, when all required keys are present.

  Raises:
    TypeError: meta is not a dict.
    MissingDiscoverMetaKeyError: one of the three required keys is absent.
  """
  if not isinstance(meta, dict):
    raise TypeError(
      f"request _meta must be a JSON object (dict); got {type(meta).__name__}"
    )
  for key in sorted(DISCOVER_REQUIRED_META_KEYS):
    if key not in meta:
      raise MissingDiscoverMetaKeyError(key)
  return meta


# ---------------------------------------------------------------------------
# §5.3.2  DiscoverResult validation (server-side response parsing)
# ---------------------------------------------------------------------------

def validate_discover_result(raw: Any) -> DiscoverResult:
  """Parse and validate a raw dict as a DiscoverResult (R-5.3.2-a–k).

  Args:
    raw: JSON-decoded dict from the ``result`` member of a discover response.

  Returns:
    A validated DiscoverResult instance.

  Raises:
    TypeError: raw is not a dict, or a field has the wrong type.
    ValueError: resultType is missing or supportedVersions is empty.
    EmptySupportedVersionsError: supportedVersions is present but empty.
    InvalidServerInfoError: serverInfo is missing name or version string.
  """
  if not isinstance(raw, dict):
    raise TypeError(
      f"DiscoverResult must be a JSON object; got {type(raw).__name__}"
    )

  # resultType — REQUIRED (R-5.3.2-a)
  result_type = raw.get("resultType")
  if not isinstance(result_type, str):
    raise TypeError(
      f"DiscoverResult.resultType must be a string; got {type(result_type).__name__}"
    )

  # supportedVersions — REQUIRED, non-empty list of strings (R-5.3.2-b/c)
  supported_versions = raw.get("supportedVersions")
  if supported_versions is None:
    raise ValueError("DiscoverResult is missing required field 'supportedVersions' (R-5.3.2-b)")
  if not isinstance(supported_versions, list):
    raise TypeError(
      f"DiscoverResult.supportedVersions must be an array; got {type(supported_versions).__name__}"
    )
  if len(supported_versions) == 0:
    raise EmptySupportedVersionsError()
  for i, v in enumerate(supported_versions):
    if not isinstance(v, str):
      raise TypeError(
        f"DiscoverResult.supportedVersions[{i}] must be a string; got {type(v).__name__}"
      )

  # capabilities — REQUIRED dict (empty {} is valid) (R-5.3.2-e)
  capabilities = raw.get("capabilities")
  if capabilities is None:
    raise ValueError("DiscoverResult is missing required field 'capabilities' (R-5.3.2-e)")
  if not isinstance(capabilities, dict):
    raise TypeError(
      f"DiscoverResult.capabilities must be a JSON object; got {type(capabilities).__name__}"
    )

  # serverInfo — REQUIRED; must have string name and string version (R-5.3.2-f)
  server_info = raw.get("serverInfo")
  if server_info is None:
    raise ValueError("DiscoverResult is missing required field 'serverInfo' (R-5.3.2-f)")
  if not isinstance(server_info, dict):
    raise TypeError(
      f"DiscoverResult.serverInfo must be a JSON object; got {type(server_info).__name__}"
    )
  for required_field in ("name", "version"):
    if not isinstance(server_info.get(required_field), str):
      raise InvalidServerInfoError(required_field)

  # instructions — OPTIONAL string (R-5.3.2-g)
  instructions = raw.get("instructions")
  if instructions is not None and not isinstance(instructions, str):
    raise TypeError(
      f"DiscoverResult.instructions must be a string; got {type(instructions).__name__}"
    )

  # _meta — OPTIONAL dict (R-5.3.2-k)
  meta = raw.get("_meta")
  if meta is not None and not isinstance(meta, dict):
    raise TypeError(
      f"DiscoverResult._meta must be a JSON object; got {type(meta).__name__}"
    )

  return DiscoverResult(
    result_type=result_type,
    supported_versions=list(supported_versions),
    capabilities=capabilities,
    server_info=server_info,
    instructions=instructions,
    meta=meta,
  )


# ---------------------------------------------------------------------------
# §5.3.1  Unsupported-revision error data (R-5.3.1-f/g)
# ---------------------------------------------------------------------------

def build_unsupported_version_error_data(
  supported: list[str] | frozenset[str],
  requested: str,
) -> dict[str, Any]:
  """Build the data payload for an UnsupportedProtocolVersion (-32004) error (R-5.3.1-g).

  The server MUST include this data so the client learns which revisions the
  server accepts even though the discover exchange itself failed.

  Args:
    supported: the revisions this server accepts.
    requested: the revision the client requested (the one that was rejected).

  Returns:
    ``{"supported": [...], "requested": "..."}`` for embedding in the error object.
  """
  return {"supported": sorted(supported), "requested": requested}


def check_discover_revision(
  meta: dict[str, Any],
  supported_versions: list[str] | frozenset[str],
) -> str:
  """Extract and validate the requested revision in a discover request (R-5.3.1-f/g).

  A server MUST tolerate a revision it does not support (it should not crash);
  instead it raises UnsupportedRevisionError so the caller can build the error
  response whose data.supported still advertises the server's revisions.

  Args:
    meta: validated request _meta dict (must already contain KEY_PROTOCOL_VERSION).
    supported_versions: the set of revisions this server accepts.

  Returns:
    The requested revision string if it is in supported_versions.

  Raises:
    ValueError: KEY_PROTOCOL_VERSION is absent or not a string.
    UnsupportedRevisionError: the requested revision is not in supported_versions
      (json_rpc_code=-32004; caller should build error response with
      build_unsupported_version_error_data).
  """
  requested = meta.get(KEY_PROTOCOL_VERSION)
  if not isinstance(requested, str):
    raise ValueError(
      f"server/discover request _meta must contain a string "
      f"{KEY_PROTOCOL_VERSION!r}; got {type(requested).__name__}"
    )
  supported_set = (
    supported_versions
    if isinstance(supported_versions, frozenset)
    else frozenset(supported_versions)
  )
  if requested not in supported_set:
    raise UnsupportedRevisionError(requested, supported_set)
  return requested
