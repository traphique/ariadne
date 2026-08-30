"""Re-export the shared C-header emitter for plugin-local imports."""

from ariadne_protocol.c_types import c_type, types_to_c_header

__all__ = ["c_type", "types_to_c_header"]
