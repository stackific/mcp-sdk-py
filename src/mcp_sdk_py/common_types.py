"""Common Data Types I: BaseMetadata, Icons & Implementation — S20.

Delivers BaseMetadata (name/title identity pair), the Icon/Icons types with
their rendering and security rules, and the full Implementation descriptor
that composes all three.  These are the building blocks for Tools, Resources,
Prompts, and the discovery/negotiation handshake defined in later stories.

Spec: §14.1-§14.3
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# §14.2  MIME-type support constants  [R-14.2-l, R-14.2-m]
# ---------------------------------------------------------------------------

#: MIME types every icon-rendering consumer MUST support (R-14.2-l).
SUPPORTED_MIME_TYPES_REQUIRED: frozenset[str] = frozenset({
  "image/png",
  "image/jpeg",
  "image/jpg",   # alias for image/jpeg per the spec note
})

#: MIME types an icon-rendering consumer SHOULD additionally support (R-14.2-m).
SUPPORTED_MIME_TYPES_RECOMMENDED: frozenset[str] = frozenset({
  "image/svg+xml",
  "image/webp",
})

#: Full set of MIME types a conforming icon consumer supports.
SUPPORTED_MIME_TYPES: frozenset[str] = (
  SUPPORTED_MIME_TYPES_REQUIRED | SUPPORTED_MIME_TYPES_RECOMMENDED
)

# ---------------------------------------------------------------------------
# §14.2  Icon URI scheme security  [R-14.2-n, R-14.2-o]
# ---------------------------------------------------------------------------

#: URI schemes a consumer MUST accept for icon src (R-14.2-o).
ALLOWED_ICON_SCHEMES: frozenset[str] = frozenset({"https", "data"})

#: URI schemes a consumer MUST reject as unsafe (R-14.2-n).
UNSAFE_ICON_SCHEMES: frozenset[str] = frozenset({
  "javascript",
  "file",
  "ftp",
  "ws",
})

# Valid size-specifier pattern: integer 'x' integer, e.g. "48x48"
_SIZE_SPEC_RE = re.compile(r'^\d+x\d+$')


def validate_icon_src(src: str) -> None:
  """Check that src uses a consumer-acceptable URI scheme (R-14.2-n, R-14.2-o).

  Raises ValueError for unsafe or non-allowed schemes.  Only ``https:`` URLs
  and ``data:`` URIs are accepted; any other scheme (including plain ``http:``)
  is rejected by the stricter R-14.2-o rule.
  """
  parsed = urlparse(src)
  scheme = parsed.scheme.lower()
  if scheme in UNSAFE_ICON_SCHEMES:
    raise ValueError(
      f"Unsafe icon URI scheme {scheme!r} rejected (R-14.2-n)"
    )
  if scheme not in ALLOWED_ICON_SCHEMES:
    raise ValueError(
      f"Icon src must be an https: URL or data: URI; got scheme {scheme!r} (R-14.2-o)"
    )


def is_valid_size_entry(entry: str) -> bool:
  """Return True for a valid size specifier: 'any' or 'WxH' (R-14.2-h)."""
  return entry == "any" or bool(_SIZE_SPEC_RE.match(entry))


# ---------------------------------------------------------------------------
# §14.2  IconTheme enum  [R-14.2-j]
# ---------------------------------------------------------------------------

class IconTheme(enum.Enum):
  """Background theme an icon is designed for (§14.2, R-14.2-j).

  When absent, the consumer SHOULD assume the icon is usable with any theme
  (R-14.2-k).
  """

  LIGHT = "light"
  DARK = "dark"


# ---------------------------------------------------------------------------
# §14.1  BaseMetadata  [R-14.1-a–f]
# ---------------------------------------------------------------------------

@dataclass
class BaseMetadata:
  """Common name + title identity pair shared by most §14 structures (§14.1).

  ``name`` is a REQUIRED programmatic identifier (R-14.1-a).
  ``title`` is an OPTIONAL human display name (R-14.1-b).

  When a consumer must display a name it MUST prefer ``title`` when present
  (R-14.1-c) and fall back to ``name`` when ``title`` is absent (R-14.1-d).
  """

  name: str
  title: str | None = None

  def __post_init__(self) -> None:
    if not isinstance(self.name, str) or not self.name:
      raise ValueError(
        "name is REQUIRED and must be a non-empty string (R-14.1-a)"
      )
    if self.title is not None and not isinstance(self.title, str):
      raise TypeError("title must be a string when present (R-14.1-b)")

  def display_name(self) -> str:
    """Resolve the display name: title → name (R-14.1-c, R-14.1-d)."""
    return self.title if self.title is not None else self.name


# ---------------------------------------------------------------------------
# §14.2  Icon  [R-14.2-a–u]
# ---------------------------------------------------------------------------

@dataclass
class Icon:
  """A single renderable icon image (§14.2).

  ``src`` is REQUIRED (R-14.2-c) and must be an ``https:`` URL or a
  ``data:`` URI (R-14.2-o); unsafe schemes are rejected at construction
  time (R-14.2-n).
  """

  src: str
  mime_type: str | None = None    # JSON key: mimeType  (R-14.2-g)
  sizes: list[str] | None = None  # R-14.2-h
  theme: IconTheme | None = None  # R-14.2-j

  def __post_init__(self) -> None:
    if not isinstance(self.src, str) or not self.src:
      raise ValueError("Icon.src is REQUIRED and must be a non-empty string (R-14.2-c)")
    validate_icon_src(self.src)  # R-14.2-n, R-14.2-o
    if self.mime_type is not None and not isinstance(self.mime_type, str):
      raise TypeError("Icon.mime_type must be a string when present (R-14.2-g)")
    if self.sizes is not None:
      if not isinstance(self.sizes, list):
        raise TypeError("Icon.sizes must be a list when present (R-14.2-h)")
      for entry in self.sizes:
        if not is_valid_size_entry(entry):
          raise ValueError(
            f"Invalid size entry {entry!r}: must be 'any' or 'WxH' (R-14.2-h)"
          )
    if self.theme is not None and not isinstance(self.theme, IconTheme):
      raise TypeError(
        f"Icon.theme must be an IconTheme enum value when present, got {self.theme!r}"
      )

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "Icon":
    """Deserialise from a JSON-decoded dict; unknown keys are silently ignored."""
    raw_theme = data.get("theme")
    return cls(
      src=data["src"],
      mime_type=data.get("mimeType"),
      sizes=data.get("sizes"),
      theme=IconTheme(raw_theme) if raw_theme is not None else None,
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict, omitting absent optional fields."""
    result: dict[str, Any] = {"src": self.src}
    if self.mime_type is not None:
      result["mimeType"] = self.mime_type
    if self.sizes is not None:
      result["sizes"] = self.sizes
    if self.theme is not None:
      result["theme"] = self.theme.value
    return result


# ---------------------------------------------------------------------------
# §14.3  Implementation  [R-14.3-a–f]
# ---------------------------------------------------------------------------

@dataclass
class Implementation:
  """Identity object each client/server provides to describe itself (§14.3).

  Composes BaseMetadata (name, title) + Icons (icons) and adds version,
  description, and websiteUrl.  name and version are REQUIRED; all others
  are OPTIONAL.

  Additional implementation-defined properties that arrive during
  deserialisation MUST be silently ignored (§2.3.4).
  """

  name: str                        # R-14.3-a  REQUIRED
  version: str                     # R-14.3-d  REQUIRED
  title: str | None = None         # R-14.3-b  OPTIONAL
  icons: list[Icon] | None = None  # R-14.3-c  OPTIONAL
  description: str | None = None   # R-14.3-e  OPTIONAL
  website_url: str | None = None   # R-14.3-f  OPTIONAL  (JSON: websiteUrl)

  def __post_init__(self) -> None:
    if not isinstance(self.name, str) or not self.name:
      raise ValueError(
        "Implementation.name is REQUIRED and must be a non-empty string (R-14.3-a)"
      )
    if not isinstance(self.version, str) or not self.version:
      raise ValueError(
        "Implementation.version is REQUIRED and must be a non-empty string (R-14.3-d)"
      )
    if self.title is not None and not isinstance(self.title, str):
      raise TypeError("Implementation.title must be a string when present (R-14.3-b)")
    if self.icons is not None and not isinstance(self.icons, list):
      raise TypeError("Implementation.icons must be a list when present (R-14.3-c)")
    if self.description is not None and not isinstance(self.description, str):
      raise TypeError(
        "Implementation.description must be a string when present (R-14.3-e)"
      )
    if self.website_url is not None and not isinstance(self.website_url, str):
      raise TypeError(
        "Implementation.website_url must be a string when present (R-14.3-f)"
      )

  def display_name(self) -> str:
    """Resolve display name per BaseMetadata precedence: title → name (R-14.1-c, d)."""
    return self.title if self.title is not None else self.name

  @classmethod
  def from_dict(cls, data: dict[str, Any]) -> "Implementation":
    """Deserialise from a JSON-decoded dict; unknown keys are silently ignored.

    Icons nested inside the dict are converted to Icon objects; the
    websiteUrl JSON key is mapped to the snake-case website_url field.
    """
    raw_icons = data.get("icons")
    icons: list[Icon] | None = (
      [Icon.from_dict(i) for i in raw_icons] if raw_icons is not None else None
    )
    return cls(
      name=data["name"],
      version=data["version"],
      title=data.get("title"),
      icons=icons,
      description=data.get("description"),
      website_url=data.get("websiteUrl"),
    )

  def to_dict(self) -> dict[str, Any]:
    """Serialise to a JSON-compatible dict, omitting absent optional fields."""
    result: dict[str, Any] = {"name": self.name, "version": self.version}
    if self.title is not None:
      result["title"] = self.title
    if self.icons is not None:
      result["icons"] = [i.to_dict() for i in self.icons]
    if self.description is not None:
      result["description"] = self.description
    if self.website_url is not None:
      result["websiteUrl"] = self.website_url
    return result
