"""Common Data Types I: BaseMetadata, Icons & Implementation — S20.

Delivers BaseMetadata (name/title identity pair), the Icon/Icons types with
their rendering and security rules, and the full Implementation descriptor
that composes all three.  These are the building blocks for Tools, Resources,
Prompts, and the discovery/negotiation handshake defined in later stories.

Spec: §14.1-§14.3
"""

from __future__ import annotations

import base64
import enum
import re
import urllib.error
import urllib.request
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
# §14.1  Display-name resolution  [R-14.1-c, R-14.1-d, R-14.1-e]
# ---------------------------------------------------------------------------

def resolve_tool_display_name(
  name: str,
  title: str | None = None,
  annotations_title: str | None = None,
) -> str:
  """Resolve the display name for a tool using the §14.1 / §16 precedence.

  Precedence order (R-14.1-c, R-14.1-d, R-14.1-e):
    1. title            — MUST be preferred when present (R-14.1-c)
    2. annotations.title — tool-specific fallback from §16 (R-14.1-e)
    3. name             — MUST be used when both are absent (R-14.1-d)
  """
  if title is not None:
    return title
  if annotations_title is not None:
    return annotations_title
  return name


# ---------------------------------------------------------------------------
# §14.2  Icon security: fetch and content-type validation
#        [R-14.2-p, R-14.2-q, R-14.2-r, R-14.2-s, R-14.2-t, R-14.2-u]
# ---------------------------------------------------------------------------

class IconFetchError(ValueError):
  """Raised when icon fetching or validation fails a security check (§14.2)."""


def detect_image_mime_type(data: bytes) -> str | None:
  """Detect an image MIME type from the file's magic bytes (R-14.2-s).

  Returns the MIME type string for recognized image formats, or None when the
  content is not a recognized image format.  The declared mimeType field is
  explicitly NOT consulted here — the caller must treat it as advisory only.
  """
  if len(data) >= 8 and data[:8] == b'\x89PNG\r\n\x1a\n':
    return "image/png"
  if len(data) >= 3 and data[:3] == b'\xff\xd8\xff':
    return "image/jpeg"
  if len(data) >= 12 and data[:4] == b'RIFF' and data[8:12] == b'WEBP':
    return "image/webp"
  # SVG: UTF-8 XML; strip BOM (EF BB BF) and leading whitespace
  head = data[:512].lstrip(b'\xef\xbb\xbf \t\r\n')
  if head.startswith((b'<?xml', b'<svg', b'<SVG')):
    return "image/svg+xml"
  return None


def validate_icon_data(data: bytes, declared_mime_type: str | None = None) -> str:
  """Validate icon content and return the detected MIME type (R-14.2-r–u).

  Applies the strict allowlist (R-14.2-u), detects content type from magic
  bytes (R-14.2-s), and rejects mismatches between the detected and declared
  types (R-14.2-t).

  Raises IconFetchError for unrecognized format, type outside allowlist, or
  declared-vs-detected mismatch.
  """
  detected = detect_image_mime_type(data)
  if detected is None:
    raise IconFetchError(
      "Icon content is not a recognized image format; "
      "content type could not be determined from magic bytes (R-14.2-t, R-14.2-u)"
    )
  if detected not in SUPPORTED_MIME_TYPES:
    raise IconFetchError(
      f"Detected image type {detected!r} is not in the strict allowlist "
      f"{sorted(SUPPORTED_MIME_TYPES)} (R-14.2-u)"
    )
  if declared_mime_type is not None:
    # Normalize image/jpg → image/jpeg for the equality check
    norm_decl = "image/jpeg" if declared_mime_type == "image/jpg" else declared_mime_type
    norm_det = "image/jpeg" if detected == "image/jpg" else detected
    if norm_decl != norm_det:
      raise IconFetchError(
        f"MIME type mismatch: declared {declared_mime_type!r} but "
        f"magic bytes indicate {detected!r} (R-14.2-t)"
      )
  return detected


def _parse_data_uri(src: str) -> tuple[str | None, bytes]:
  """Extract (mime_type_or_None, raw_bytes) from a data: URI."""
  rest = src[5:]  # strip "data:"
  if ',' not in rest:
    raise IconFetchError("Malformed data: URI (missing comma) (R-14.2-d)")
  header, encoded = rest.split(',', 1)
  is_base64 = header.endswith(';base64')
  mime_part = header[:-7] if is_base64 else header
  mime_type = mime_part.strip() or None
  if is_base64:
    try:
      raw = base64.b64decode(encoded)
    except Exception as exc:
      raise IconFetchError(
        f"data: URI base64 payload could not be decoded: {exc}"
      ) from exc
  else:
    raw = encoded.encode("latin-1")
  return mime_type, raw


class _SafeIconRedirectHandler(urllib.request.HTTPRedirectHandler):
  """Redirect handler that blocks cross-origin and scheme-change redirects (R-14.2-p)."""

  def __init__(self, original_url: str) -> None:
    super().__init__()
    self._original = urlparse(original_url)

  def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
    dest = urlparse(newurl)
    if dest.netloc != self._original.netloc or dest.scheme != self._original.scheme:
      raise IconFetchError(
        f"Cross-origin or scheme-change redirect blocked: "
        f"{req.full_url!r} → {newurl!r} (R-14.2-p)"
      )
    return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_icon(src: str, declared_mime_type: str | None = None) -> bytes:
  """Fetch and validate an icon enforcing all §14.2 security constraints.

  For data: URIs, decodes the base64 payload locally with no network I/O.
  For https: URLs, issues a credential-free request (R-14.2-q) — no cookies,
  Authorization header, or client credentials are sent — and does not follow
  cross-origin redirects or scheme changes (R-14.2-p).  Validates the content
  type via magic bytes (R-14.2-r, R-14.2-s, R-14.2-t, R-14.2-u).
  """
  validate_icon_src(src)  # scheme allow/deny (R-14.2-n, R-14.2-o)

  if src.startswith("data:"):
    mime_from_uri, raw = _parse_data_uri(src)
    validate_icon_data(raw, declared_mime_type or mime_from_uri)
    return raw

  # https: URL — credential-free fetch; build_opener without HTTPCookieProcessor
  # or auth handlers means no cookies or credentials are sent (R-14.2-q).
  req = urllib.request.Request(src)
  opener = urllib.request.build_opener(_SafeIconRedirectHandler(src))

  try:
    with opener.open(req, timeout=10) as resp:
      raw = resp.read()
  except IconFetchError:
    raise
  except urllib.error.URLError as exc:
    raise IconFetchError(f"Failed to fetch icon {src!r}: {exc}") from exc

  validate_icon_data(raw, declared_mime_type)
  return raw


# ---------------------------------------------------------------------------
# §14.2  Same-/trusted-domain icon check  [R-14.2-e]
# ---------------------------------------------------------------------------

def icon_src_origin(src: str) -> tuple[str, str] | None:
  """Return ``(scheme, host)`` for an icon ``src``, or None for a ``data:`` URI.

  A ``data:`` URI carries its bytes inline — no network origin — so domain
  checks do not apply to it and None is returned.
  """
  parsed = urlparse(src)
  if parsed.scheme.lower() == "data":
    return None
  return (parsed.scheme.lower(), parsed.hostname or "")


def is_same_or_trusted_domain(
  src: str,
  peer_host: str,
  *,
  trusted_hosts: frozenset[str] = frozenset(),
) -> bool:
  """Return True if an icon ``src`` is same-domain as the peer or in ``trusted_hosts`` (R-14.2-e).

  Consumers SHOULD ensure icon-serving URLs are from the same domain as the
  peer (client or server) that advertised the icon, or from an explicitly
  trusted domain.  A ``data:`` URI has no remote host and is always accepted.

  Args:
    src: the icon ``src`` — an ``https:`` URL or ``data:`` URI.
    peer_host: the host of the peer that advertised the icon.
    trusted_hosts: additional hosts the consumer's policy trusts.
  """
  origin = icon_src_origin(src)
  if origin is None:
    return True  # data: URI — no remote host to compare
  host = origin[1]
  return host == peer_host or host in trusted_hosts


def assert_icon_domain_allowed(
  src: str,
  peer_host: str,
  *,
  trusted_hosts: frozenset[str] = frozenset(),
) -> None:
  """Raise if an icon's host is neither the peer's domain nor a trusted one (R-14.2-e).

  The policy-enforcing variant of :func:`is_same_or_trusted_domain`.

  Raises:
    IconFetchError: ``src`` host is neither ``peer_host`` nor in ``trusted_hosts``.
  """
  if not is_same_or_trusted_domain(src, peer_host, trusted_hosts=trusted_hosts):
    host = (icon_src_origin(src) or ("", ""))[1]
    raise IconFetchError(
      f"Icon host {host!r} is neither the peer domain {peer_host!r} nor a "
      f"trusted domain; declining per same-/trusted-domain policy (R-14.2-e)"
    )


# ---------------------------------------------------------------------------
# §14.2  SVG precautions against embedded script  [R-14.2-f]
# ---------------------------------------------------------------------------

#: Element names that can execute script or pull in external/active content.
_SVG_DANGEROUS_ELEMENTS: tuple[bytes, ...] = (b"script", b"foreignObject", b"iframe")
_SVG_ACTIVE_HINTS_RE = re.compile(
  rb"<\s*(script|foreignObject|iframe)\b|javascript:|\son[a-zA-Z]+\s*=",
  re.IGNORECASE,
)
_SVG_EVENT_HANDLER_RE = re.compile(
  rb"\son[a-zA-Z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE
)
_SVG_JS_URI_RE = re.compile(rb"javascript:", re.IGNORECASE)


def _strip_svg_element(data: bytes, name: bytes) -> bytes:
  """Remove every ``<name>…</name>`` and self-closing ``<name/>`` occurrence."""
  paired = re.compile(
    rb"<\s*" + name + rb"\b[^>]*>.*?<\s*/\s*" + name + rb"\s*>",
    re.IGNORECASE | re.DOTALL,
  )
  self_close = re.compile(rb"<\s*" + name + rb"\b[^>]*/\s*>", re.IGNORECASE)
  return self_close.sub(b"", paired.sub(b"", data))


def svg_contains_active_content(data: bytes) -> bool:
  """Return True if an SVG payload may execute script (R-14.2-f).

  Flags ``<script>`` elements, ``on*=`` event-handler attributes, ``javascript:``
  URIs, and elements that can embed external/active content (``foreignObject``,
  ``iframe``).  A consumer SHOULD sanitize such SVG with :func:`sanitize_svg`
  or decline to render it.
  """
  return bool(_SVG_ACTIVE_HINTS_RE.search(data))


def sanitize_svg(data: bytes) -> bytes:
  """Strip executable content from an SVG so it is safer to render (R-14.2-f).

  Removes ``<script>``, ``<foreignObject>``, and ``<iframe>`` elements, ``on*=``
  event-handler attributes, and ``javascript:`` URI occurrences.  After
  sanitizing, :func:`svg_contains_active_content` returns False for the result.
  A consumer with stricter policy MAY instead decline any SVG for which
  :func:`svg_contains_active_content` returns True.
  """
  cleaned = data
  for element in _SVG_DANGEROUS_ELEMENTS:
    cleaned = _strip_svg_element(cleaned, element)
  cleaned = _SVG_EVENT_HANDLER_RE.sub(b" ", cleaned)
  cleaned = _SVG_JS_URI_RE.sub(b"", cleaned)
  return cleaned


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
