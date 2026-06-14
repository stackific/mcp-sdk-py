"""Common Data Types II: ContentBlock, ResourceContents, Annotations & Role — S21.

Delivers the ContentBlock discriminated union and its five members
(TextContent, ImageContent, AudioContent, ResourceLink, EmbeddedResource),
the ResourceContents family (TextResourceContents / BlobResourceContents),
Annotations hints, and the ParticipantRole enumeration ("user"/"assistant").

Note: ParticipantRole ("user"/"assistant") is distinct from
mcp_sdk_py.foundations.Role (HOST/CLIENT/SERVER).

Spec: §14.4–§14.9
Depends on: S05 (_meta pass-through), S20 (Icon, BaseMetadata)
"""

from __future__ import annotations

import base64
import enum
from dataclasses import dataclass, field
from typing import Any, Literal, Union

from mcp_sdk_py.common_types import Icon


# ---------------------------------------------------------------------------
# §14.7  ParticipantRole  [R-14.7-a]
# ---------------------------------------------------------------------------

class ParticipantRole(enum.Enum):
  """Conversation participant role for Annotations.audience and prompt messages (§14.7).

  Wire values are "user" and "assistant".  Any other value MUST be treated as
  invalid (R-14.7-a).  This is a CLOSED enumeration.
  """

  USER = "user"
  ASSISTANT = "assistant"


# ---------------------------------------------------------------------------
# §14.6  Annotations  [R-14.6-a–g]
# ---------------------------------------------------------------------------

@dataclass
class Annotations:
  """Optional, untrusted hints about a piece of content or a resource (§14.6).

  Consumers MUST NOT use these values for security or correctness decisions
  (R-14.6-f); they MAY use them for presentation or ordering (R-14.6-g).
  """

  audience: list[ParticipantRole] | None = None  # R-14.6-b: intended audience
  priority: float | None = None                  # R-14.6-c/d: 0..1 inclusive
  last_modified: str | None = None               # R-14.6-e: ISO 8601; JSON: lastModified

  def __post_init__(self) -> None:
    if self.audience is not None:
      if not isinstance(self.audience, list):
        raise TypeError(
          "Annotations.audience must be a list when present (R-14.6-b)"
        )
      for entry in self.audience:
        if not isinstance(entry, ParticipantRole):
          raise TypeError(
            f"Annotations.audience entries must be ParticipantRole; got {entry!r}"
          )
    if self.priority is not None:
      if isinstance(self.priority, bool) or not isinstance(self.priority, (int, float)):
        raise TypeError("Annotations.priority must be a number (R-14.6-c)")
      if not (0.0 <= self.priority <= 1.0):
        raise ValueError(
          f"Annotations.priority must be in inclusive range 0..1; "
          f"got {self.priority!r} (R-14.6-d)"
        )
    if self.last_modified is not None and not isinstance(self.last_modified, str):
      raise TypeError(
        "Annotations.lastModified must be a string when present (R-14.6-e)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "Annotations":
    """Deserialise from a JSON-decoded dict; unknown keys are silently ignored."""
    raw_audience = data.get("audience")
    audience: list[ParticipantRole] | None = None
    if raw_audience is not None:
      audience = [ParticipantRole(v) for v in raw_audience]
    return cls(
      audience=audience,
      priority=data.get("priority"),
      last_modified=data.get("lastModified"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {}
    if self.audience is not None:
      result["audience"] = [r.value for r in self.audience]
    if self.priority is not None:
      result["priority"] = self.priority
    if self.last_modified is not None:
      result["lastModified"] = self.last_modified
    return result


# ---------------------------------------------------------------------------
# §14.5  ResourceContents family  [R-14.5-a–h]
# ---------------------------------------------------------------------------

def _validate_base64(value: str, field_name: str) -> None:
  """Raise if value is not a valid Base64 string (R-14.4.2-b, R-14.4.3-b, R-14.5-f)."""
  try:
    base64.b64decode(value, validate=True)
  except Exception as exc:
    raise ValueError(
      f"{field_name}: must be a valid Base64 string; decode failed: {exc}"
    ) from exc


@dataclass
class TextResourceContents:
  """Text variant of resource contents; use only for text-representable resources (§14.5).

  Variant selection: 'text' field present → this type (R-14.5-g).
  """

  uri: str              # R-14.5-a: REQUIRED
  text: str             # R-14.5-d: REQUIRED
  mime_type: str | None = None          # R-14.5-b: JSON: mimeType
  meta: dict[str, Any] | None = None   # R-14.5-c: JSON: _meta

  def __post_init__(self) -> None:
    if not isinstance(self.uri, str) or not self.uri:
      raise ValueError(
        "TextResourceContents.uri is REQUIRED and must be a non-empty string (R-14.5-a)"
      )
    if not isinstance(self.text, str):
      raise TypeError("TextResourceContents.text must be a string (R-14.5-d)")

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "TextResourceContents":
    """Deserialise from a JSON-decoded dict."""
    return cls(
      uri=data["uri"],
      text=data["text"],
      mime_type=data.get("mimeType"),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {"uri": self.uri, "text": self.text}
    if self.mime_type is not None:
      result["mimeType"] = self.mime_type
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


@dataclass
class BlobResourceContents:
  """Binary variant of resource contents; blob is a Base64-encoded string (§14.5).

  Variant selection: 'blob' field present → this type (R-14.5-g).
  """

  uri: str              # R-14.5-a: REQUIRED
  blob: str             # R-14.5-f: REQUIRED; valid Base64
  mime_type: str | None = None          # R-14.5-b: JSON: mimeType
  meta: dict[str, Any] | None = None   # R-14.5-c: JSON: _meta

  def __post_init__(self) -> None:
    if not isinstance(self.uri, str) or not self.uri:
      raise ValueError(
        "BlobResourceContents.uri is REQUIRED and must be a non-empty string (R-14.5-a)"
      )
    if not isinstance(self.blob, str):
      raise TypeError("BlobResourceContents.blob must be a string (R-14.5-f)")
    _validate_base64(self.blob, "BlobResourceContents.blob")

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "BlobResourceContents":
    """Deserialise from a JSON-decoded dict."""
    return cls(
      uri=data["uri"],
      blob=data["blob"],
      mime_type=data.get("mimeType"),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {"uri": self.uri, "blob": self.blob}
    if self.mime_type is not None:
      result["mimeType"] = self.mime_type
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


#: Union of the two ResourceContents variants.
ResourceContents = Union[TextResourceContents, BlobResourceContents]


def parse_resource_contents(data: dict[str, Any]) -> ResourceContents:
  """Select and parse the correct ResourceContents variant (R-14.5-g/h).

  Selection is based solely on which of 'text' or 'blob' is present.
  Raises ValueError if both or neither are present.
  """
  has_text = "text" in data
  has_blob = "blob" in data
  if has_text and has_blob:
    raise ValueError(
      "ResourceContents MUST NOT carry both 'text' and 'blob' (R-14.5-h)"
    )
  if has_text:
    return TextResourceContents.from_dict(data)
  if has_blob:
    return BlobResourceContents.from_dict(data)
  raise ValueError(
    "ResourceContents must carry exactly one of 'text' or 'blob' (R-14.5-g)"
  )


# ---------------------------------------------------------------------------
# §14.4  ContentBlock members
# ---------------------------------------------------------------------------

@dataclass
class TextContent:
  """Text content block (§14.4.1); type discriminator is 'text'."""

  text: str                                      # R-14.4.1-b: REQUIRED
  annotations: Annotations | None = None        # R-14.4.1-c: OPTIONAL
  meta: dict[str, Any] | None = None            # R-14.4.1-d: OPTIONAL; JSON: _meta
  type: Literal["text"] = field(default="text", init=False)

  def __post_init__(self) -> None:
    if not isinstance(self.text, str):
      raise TypeError("TextContent.text must be a string (R-14.4.1-b)")

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "TextContent":
    """Deserialise from a JSON-decoded dict."""
    raw_ann = data.get("annotations")
    return cls(
      text=data["text"],
      annotations=Annotations.from_dict(raw_ann) if raw_ann is not None else None,
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {"type": self.type, "text": self.text}
    if self.annotations is not None:
      result["annotations"] = self.annotations.to_dict()
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


@dataclass
class ImageContent:
  """Image content block (§14.4.2); type discriminator is 'image'.

  data must be a valid Base64 string decoding to the raw image bytes (R-14.4.2-b).
  """

  data: str                                      # R-14.4.2-b: REQUIRED; valid Base64
  mime_type: str                                 # R-14.4.2-c: REQUIRED; JSON: mimeType
  annotations: Annotations | None = None        # R-14.4.2-e: OPTIONAL
  meta: dict[str, Any] | None = None            # R-14.4.2-f: OPTIONAL; JSON: _meta
  type: Literal["image"] = field(default="image", init=False)

  def __post_init__(self) -> None:
    if not isinstance(self.data, str):
      raise TypeError("ImageContent.data must be a string (R-14.4.2-b)")
    _validate_base64(self.data, "ImageContent.data")
    if not isinstance(self.mime_type, str):
      raise TypeError("ImageContent.mimeType must be a string (R-14.4.2-c)")

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "ImageContent":
    """Deserialise from a JSON-decoded dict."""
    raw_ann = data.get("annotations")
    return cls(
      data=data["data"],
      mime_type=data["mimeType"],
      annotations=Annotations.from_dict(raw_ann) if raw_ann is not None else None,
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {
      "type": self.type,
      "data": self.data,
      "mimeType": self.mime_type,
    }
    if self.annotations is not None:
      result["annotations"] = self.annotations.to_dict()
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


@dataclass
class AudioContent:
  """Audio content block (§14.4.3); type discriminator is 'audio'.

  data must be a valid Base64 string decoding to the raw audio bytes (R-14.4.3-b).
  """

  data: str                                      # R-14.4.3-b: REQUIRED; valid Base64
  mime_type: str                                 # R-14.4.3-c: REQUIRED; JSON: mimeType
  annotations: Annotations | None = None        # R-14.4.3-e: OPTIONAL
  meta: dict[str, Any] | None = None            # R-14.4.3-f: OPTIONAL; JSON: _meta
  type: Literal["audio"] = field(default="audio", init=False)

  def __post_init__(self) -> None:
    if not isinstance(self.data, str):
      raise TypeError("AudioContent.data must be a string (R-14.4.3-b)")
    _validate_base64(self.data, "AudioContent.data")
    if not isinstance(self.mime_type, str):
      raise TypeError("AudioContent.mimeType must be a string (R-14.4.3-c)")

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "AudioContent":
    """Deserialise from a JSON-decoded dict."""
    raw_ann = data.get("annotations")
    return cls(
      data=data["data"],
      mime_type=data["mimeType"],
      annotations=Annotations.from_dict(raw_ann) if raw_ann is not None else None,
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {
      "type": self.type,
      "data": self.data,
      "mimeType": self.mime_type,
    }
    if self.annotations is not None:
      result["annotations"] = self.annotations.to_dict()
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


@dataclass
class ResourceLink:
  """Reference to a resource by URI without embedding its contents (§14.4.4).

  Type discriminator is 'resource_link'.  uri and name are REQUIRED (R-14.4.4-b/c).
  Reuses the resource-descriptor field set (name/title from BaseMetadata, icons).
  """

  uri: str                                       # R-14.4.4-b: REQUIRED
  name: str                                      # R-14.4.4-c: REQUIRED
  title: str | None = None                       # R-14.4.4-d: OPTIONAL
  icons: list[Icon] | None = None               # R-14.4.4-e: OPTIONAL
  description: str | None = None                # R-14.4.4-f: OPTIONAL
  mime_type: str | None = None                  # R-14.4.4-g: OPTIONAL; JSON: mimeType
  annotations: Annotations | None = None        # R-14.4.4-h: OPTIONAL
  size: float | None = None                     # R-14.4.4-i: OPTIONAL; bytes before Base64
  meta: dict[str, Any] | None = None            # R-14.4.4-k: OPTIONAL; JSON: _meta
  type: Literal["resource_link"] = field(default="resource_link", init=False)

  def __post_init__(self) -> None:
    if not isinstance(self.uri, str) or not self.uri:
      raise ValueError(
        "ResourceLink.uri is REQUIRED and must be a non-empty string (R-14.4.4-b)"
      )
    if not isinstance(self.name, str) or not self.name:
      raise ValueError(
        "ResourceLink.name is REQUIRED and must be a non-empty string (R-14.4.4-c)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "ResourceLink":
    """Deserialise from a JSON-decoded dict."""
    raw_ann = data.get("annotations")
    raw_icons = data.get("icons")
    return cls(
      uri=data["uri"],
      name=data["name"],
      title=data.get("title"),
      icons=[Icon.from_dict(i) for i in raw_icons] if raw_icons is not None else None,
      description=data.get("description"),
      mime_type=data.get("mimeType"),
      annotations=Annotations.from_dict(raw_ann) if raw_ann is not None else None,
      size=data.get("size"),
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {
      "type": self.type,
      "uri": self.uri,
      "name": self.name,
    }
    if self.title is not None:
      result["title"] = self.title
    if self.icons is not None:
      result["icons"] = [i.to_dict() for i in self.icons]
    if self.description is not None:
      result["description"] = self.description
    if self.mime_type is not None:
      result["mimeType"] = self.mime_type
    if self.annotations is not None:
      result["annotations"] = self.annotations.to_dict()
    if self.size is not None:
      result["size"] = self.size
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


@dataclass
class EmbeddedResource:
  """Resource contents embedded inline in a tool result or prompt message (§14.4.5).

  Type discriminator is 'resource'.  resource is REQUIRED (R-14.4.5-b).
  """

  resource: Union[TextResourceContents, BlobResourceContents]  # R-14.4.5-b: REQUIRED
  annotations: Annotations | None = None                       # R-14.4.5-c: OPTIONAL
  meta: dict[str, Any] | None = None                           # R-14.4.5-d: OPTIONAL; JSON: _meta
  type: Literal["resource"] = field(default="resource", init=False)

  def __post_init__(self) -> None:
    if not isinstance(self.resource, (TextResourceContents, BlobResourceContents)):
      raise TypeError(
        "EmbeddedResource.resource must be TextResourceContents or "
        "BlobResourceContents (R-14.4.5-b)"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "EmbeddedResource":
    """Deserialise from a JSON-decoded dict."""
    raw_resource = data.get("resource")
    if not isinstance(raw_resource, dict):
      raise ValueError(
        "EmbeddedResource.resource is REQUIRED and must be an object (R-14.4.5-b)"
      )
    raw_ann = data.get("annotations")
    return cls(
      resource=parse_resource_contents(raw_resource),
      annotations=Annotations.from_dict(raw_ann) if raw_ann is not None else None,
      meta=data.get("_meta"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict; omits absent optional fields."""
    result: dict[str, Any] = {
      "type": self.type,
      "resource": self.resource.to_dict(),
    }
    if self.annotations is not None:
      result["annotations"] = self.annotations.to_dict()
    if self.meta is not None:
      result["_meta"] = self.meta
    return result


# ---------------------------------------------------------------------------
# §14.4  ContentBlock union and dispatch  [R-14.4-a, R-14.4-b, R-14.8-a, R-14.8-b]
# ---------------------------------------------------------------------------

#: Sampling-only content types that MUST NOT appear in ContentBlock positions (R-14.8-a/b).
_FORBIDDEN_CONTENT_TYPES: frozenset[str] = frozenset({"tool_use", "tool_result"})

#: The ContentBlock union: one of five typed members.
ContentBlock = Union[TextContent, ImageContent, AudioContent, ResourceLink, EmbeddedResource]


class UnsupportedContentBlock:
  """Sentinel for content blocks with an unrecognized type value.

  When a receiver encounters an unknown type, it SHOULD treat the block as
  unsupported rather than failing the enclosing message (R-14.4-b).
  """

  def __init__(self, type_value: str, raw: dict[str, Any]) -> None:
    self.type = type_value
    self.raw = raw

  def __repr__(self) -> str:
    return f"UnsupportedContentBlock(type={self.type!r})"


def parse_content_block(
  data: dict[str, Any],
) -> Union[ContentBlock, UnsupportedContentBlock]:
  """Dispatch a raw dict to the correct ContentBlock member by type (R-14.4-a/b).

  Dispatches on the exact, case-sensitive 'type' value (R-14.4-a).
  Unknown types return UnsupportedContentBlock (R-14.4-b).
  Forbidden sampling types ('tool_use', 'tool_result') raise ValueError (R-14.8-a/b).

  Raises:
    ValueError: for missing/non-string type, or forbidden sampling content types.
  """
  type_val = data.get("type")
  if not isinstance(type_val, str):
    raise ValueError(
      f"ContentBlock.type is REQUIRED and must be a string; "
      f"got {type(type_val).__name__}"
    )

  if type_val in _FORBIDDEN_CONTENT_TYPES:
    raise ValueError(
      f"ContentBlock type {type_val!r} is a sampling-only type and MUST NOT "
      f"appear in tool-call results or prompt messages (R-14.8-a/b)"
    )

  # Exact case-sensitive dispatch (R-14.4-a)
  if type_val == "text":
    return TextContent.from_dict(data)
  if type_val == "image":
    return ImageContent.from_dict(data)
  if type_val == "audio":
    return AudioContent.from_dict(data)
  if type_val == "resource_link":
    return ResourceLink.from_dict(data)
  if type_val == "resource":
    return EmbeddedResource.from_dict(data)

  # Unknown type: unsupported but not an error (R-14.4-b)
  return UnsupportedContentBlock(type_val, data)
