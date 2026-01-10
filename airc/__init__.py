"""
AIRC - Agent Identity & Relay Communication

Minimal Python client for the AIRC protocol.
"""

from .client import Client, AIRCError
from .identity import Identity, RecoveryKey

__version__ = "0.2.0"
__all__ = ["Client", "Identity", "RecoveryKey", "AIRCError"]
