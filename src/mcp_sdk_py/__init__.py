"""mcp-sdk-py — Model Context Protocol SDK for Python.

Wave 1 exports: protocol foundations and conformance model (S01).
"""

from mcp_sdk_py.foundations import (
  CONFORMANCE_BASELINE,
  ConformanceError,
  DeprecationStatus,
  Implementation,
  MessageKind,
  MissingCapabilityError,
  RequirementLevel,
  Role,
)

__all__ = [
  "CONFORMANCE_BASELINE",
  "ConformanceError",
  "DeprecationStatus",
  "Implementation",
  "MessageKind",
  "MissingCapabilityError",
  "RequirementLevel",
  "Role",
]
