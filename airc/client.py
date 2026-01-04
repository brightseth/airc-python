"""
AIRC Client

Minimal client for AIRC protocol. Four operations, nothing else.
"""

import time
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import json

from .identity import Identity


DEFAULT_REGISTRY = "https://slashvibe.dev"


class Client:
    """
    AIRC protocol client.

    Usage:
        client = Client("my_agent")
        client.register()
        client.heartbeat()
        client.send("@recipient", "hello")
        messages = client.poll()

    That's the entire API.
    """

    def __init__(
        self,
        name: str,
        registry: str = DEFAULT_REGISTRY,
        sign_requests: bool = False,  # Safe Mode: signing optional
    ):
        self.name = name
        self.registry = registry.rstrip("/")
        self.sign_requests = sign_requests
        self.identity = Identity(name)
        self._registered = False

    def register(self) -> Dict[str, Any]:
        """
        Register identity with the registry.

        POST /identity
        """
        self.identity.ensure_keypair()

        payload = {
            "name": self.name,
            "publicKey": self.identity.public_key_base64,
        }

        result = self._post("/api/identity", payload)
        self._registered = True
        return result

    def heartbeat(self, status: str = "available") -> Dict[str, Any]:
        """
        Send presence heartbeat.

        POST /presence
        """
        payload = {
            "action": "heartbeat",
            "username": self.name,
            "status": status,
        }
        return self._post("/api/presence", payload)

    def send(self, to: str, text: str, payload_type: str = "text") -> Dict[str, Any]:
        """
        Send a message to another agent.

        POST /messages

        Args:
            to: Recipient name (with or without @)
            text: Message content
            payload_type: Message type (default: "text")
        """
        to = to.lstrip("@")

        payload = {
            "from": self.name,
            "to": to,
            "type": payload_type,
            "text": text,
        }
        return self._post("/api/messages", payload)

    def poll(self, since: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Poll for new messages.

        GET /messages?to={name}

        Args:
            since: Unix timestamp to filter messages after

        Returns:
            List of message objects
        """
        url = f"{self.registry}/api/messages?to={self.name}"
        if since:
            url += f"&since={since}"

        result = self._get(url)
        return result.get("messages", [])

    def _post(self, endpoint: str, payload: dict) -> Dict[str, Any]:
        """Make a signed POST request."""
        url = f"{self.registry}{endpoint}"
        body = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
        }

        if self.sign_requests:
            signature = self.identity.sign(payload)
            headers["X-AIRC-Signature"] = signature
            headers["X-AIRC-Identity"] = self.name

        req = Request(url, data=body, headers=headers, method="POST")

        try:
            with urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as e:
            error_body = e.read().decode("utf-8") if e.fp else ""
            raise AIRCError(f"HTTP {e.code}: {error_body}") from e

    def _get(self, url: str) -> Dict[str, Any]:
        """Make a GET request."""
        req = Request(url, method="GET")

        try:
            with urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as e:
            error_body = e.read().decode("utf-8") if e.fp else ""
            raise AIRCError(f"HTTP {e.code}: {error_body}") from e


class AIRCError(Exception):
    """AIRC protocol error."""
    pass
