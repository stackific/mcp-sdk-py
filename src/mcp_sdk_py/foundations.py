"""Protocol Foundations & Conformance Model — S01.

Establishes the role topology (Host, Client, Server), message vocabulary
(Request, Response, Notification), RFC 2119 requirement-keyword semantics,
deprecation status, the mandatory conformance baseline, and the
MissingCapabilityError that servers raise when a request requires an undeclared
capability.

The Implementation descriptor's full shape is defined in S20
(mcp_sdk_py.common_types); it is re-exported here for backwards compatibility.

Every other module in this SDK depends on the definitions made here.
"""

from __future__ import annotations

import enum


# ---------------------------------------------------------------------------
# §1.1 Roles  [R-1.1-a]
# ---------------------------------------------------------------------------

class Role(enum.Enum):
  """The three roles defined by MCP (§1.1).

  The Host is the trust boundary; it creates and coordinates Clients. Each
  Client has a strict one-to-one binding to a single Server. Servers are
  isolated from one another: no Server can observe another, and none sees the
  Host's full conversation.
  """

  HOST = "host"
  CLIENT = "client"
  SERVER = "server"


# ---------------------------------------------------------------------------
# §1.2 / §2.2  Message kinds
# ---------------------------------------------------------------------------

class MessageKind(enum.Enum):
  """The three JSON-RPC 2.0 message kinds used by MCP (§1.2, §2.2).

  REQUEST:
    Carries an ``id``, a ``method``, and optional parameters. The receiver
    MUST return exactly one matching response (R-2.2-c, AC-01.5).

  RESPONSE:
    Echoes the request ``id``. Carries either a result or an error, never
    both (§2.2).

  NOTIFICATION:
    Carries a ``method`` and optional parameters but NO ``id``. The receiver
    MUST NOT send any response (R-2.2-e, AC-01.7).
  """

  REQUEST = "request"
  RESPONSE = "response"
  NOTIFICATION = "notification"

  @property
  def requires_response(self) -> bool:
    """True only for REQUEST, which demands exactly one matching response."""
    return self is MessageKind.REQUEST

  @property
  def has_id(self) -> bool:
    """True for REQUEST and RESPONSE (both carry a correlation id).

    A NOTIFICATION must never carry an ``id`` field (R-2.2-e).
    """
    return self in (MessageKind.REQUEST, MessageKind.RESPONSE)

  @property
  def must_not_respond(self) -> bool:
    """True for NOTIFICATION: the receiver MUST NOT reply (R-2.2-e)."""
    return self is MessageKind.NOTIFICATION


# ---------------------------------------------------------------------------
# §2.1  RFC 2119 / RFC 8174 requirement keywords  [R-1.4-c]
# ---------------------------------------------------------------------------

class RequirementLevel(enum.Enum):
  """RFC 2119 / RFC 8174 requirement keywords (§2.1).

  These carry normative force **only** when they appear in ALL CAPS inside
  the specification text; identical words in lowercase or mixed case impose
  no conformance obligation [R-1.4-c].
  """

  MUST = "MUST"
  MUST_NOT = "MUST_NOT"
  REQUIRED = "REQUIRED"
  SHALL = "SHALL"
  SHALL_NOT = "SHALL_NOT"
  SHOULD = "SHOULD"
  SHOULD_NOT = "SHOULD_NOT"
  RECOMMENDED = "RECOMMENDED"
  MAY = "MAY"
  OPTIONAL = "OPTIONAL"

  @property
  def is_absolute_requirement(self) -> bool:
    """True for MUST / REQUIRED / SHALL: no-exception obligations (R-2.1-a)."""
    return self in (
      RequirementLevel.MUST,
      RequirementLevel.REQUIRED,
      RequirementLevel.SHALL,
    )

  @property
  def is_absolute_prohibition(self) -> bool:
    """True for MUST NOT / SHALL NOT: never-do-this rules (R-2.1-b)."""
    return self in (RequirementLevel.MUST_NOT, RequirementLevel.SHALL_NOT)

  @property
  def is_conditional(self) -> bool:
    """True for SHOULD / RECOMMENDED: deviation allowed with valid reason (R-2.1-c)."""
    return self in (RequirementLevel.SHOULD, RequirementLevel.RECOMMENDED)

  @property
  def is_conditional_prohibition(self) -> bool:
    """True for SHOULD NOT / NOT RECOMMENDED (R-2.1-d)."""
    return self is RequirementLevel.SHOULD_NOT

  @property
  def is_discretionary(self) -> bool:
    """True for MAY / OPTIONAL: both presence and absence are conforming (R-2.1-e).

    An implementation that includes a MAY feature and one that omits it are
    both conforming, and each MUST interoperate with the other (possibly with
    reduced functionality) without treating the other's choice as an error.
    """
    return self in (RequirementLevel.MAY, RequirementLevel.OPTIONAL)


# ---------------------------------------------------------------------------
# §1.3 / §2.2  Deprecation status  [R-1.3-b, R-2.2-f–h]
# ---------------------------------------------------------------------------

class DeprecationStatus(enum.Enum):
  """Lifecycle label applied to protocol features (§1.3, §2.2, §27).

  ACTIVE:
    Current feature; new implementations MAY freely rely on it.

  DEPRECATED:
    Still defined. Conforming implementations MUST continue to accept and
    process it per its definition while it bears this status (R-2.2-f, -h).
    New implementations SHOULD NOT rely on it (R-1.3-b, R-2.2-g).
  """

  ACTIVE = "active"
  DEPRECATED = "deprecated"

  @property
  def should_not_rely_on(self) -> bool:
    """True for DEPRECATED: new implementations should avoid this feature."""
    return self is DeprecationStatus.DEPRECATED

  @property
  def must_still_accept(self) -> bool:
    """True for DEPRECATED: receivers MUST still process the feature (R-2.2-f)."""
    return self is DeprecationStatus.DEPRECATED


# ---------------------------------------------------------------------------
# §2.2.1  The Implementation descriptor  [R-2.2.1-a – R-2.2.1-g]
# ---------------------------------------------------------------------------
# Full shape (name, version, title, icons, description, websiteUrl) defined
# in S20 / common_types.  Re-exported here so callers can continue to import
# from mcp_sdk_py.foundations without breaking.
from mcp_sdk_py.common_types import Implementation  # noqa: E402  re-export


# ---------------------------------------------------------------------------
# §1.4 / §2.1  Conformance baseline  [R-1.4-a, R-2.1-g]
# ---------------------------------------------------------------------------

#: Features that every conforming MCP party MUST implement, regardless of
#: which optional features they choose to support (R-1.4-a, R-2.1-g).
CONFORMANCE_BASELINE: tuple[str, ...] = (
  "base-message-format",
  "protocol-revision-handling",
  "core-message-patterns",
)


# ---------------------------------------------------------------------------
# §2.2.2 / §22  Missing-capability error  [R-2.2.2-c, AC-01.15]
# ---------------------------------------------------------------------------

class ConformanceError(Exception):
  """Base class for errors that indicate a protocol conformance violation."""


class MissingCapabilityError(ConformanceError):
  """Raised when a server rejects a request for an undeclared capability.

  If processing a request requires a capability the client did not declare in
  the request's ``_meta`` field, the server MUST reject the request with the
  dedicated missing-capability error (R-2.2.2-c). The numeric JSON-RPC error
  code for this error is defined in S09.
  """
