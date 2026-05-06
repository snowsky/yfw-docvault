"""Standalone auth shim.

Plugin mode uses the host app's auth and MFA libraries. Standalone mode runs a
local single-user vault suitable for development and self-hosted use.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class StandaloneUser:
    id: int = 1
    email: str = "standalone@docvault.local"


def get_current_user() -> StandaloneUser:
    return StandaloneUser()
