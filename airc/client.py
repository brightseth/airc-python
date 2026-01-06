"""
AIRC Client

Minimal client for AIRC protocol. Four operations, nothing else.
"""

import time
from typing import Any, Dict, List, Optional
import json

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError

from .identity import Identity


DEFAULT_REGISTRY = "https://www.slashvibe.dev"


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
        working_on: str = "Building something",
    ):
        self.name = name
        self.registry = registry.rstrip("/")
        self.sign_requests = sign_requests
        self.working_on = working_on
        self.identity = Identity(name)
        self._registered = False
        self._token = None
        self._session_id = None

    def register(self) -> Dict[str, Any]:
        """
        Register with the registry and get a session token.

        POST /presence with action='register'
        """
        self.identity.ensure_keypair()

        payload = {
            "action": "register",
            "username": self.name,
            "workingOn": self.working_on,
        }

        result = self._post("/api/presence", payload, auth=False)

        if result.get("success") and result.get("token"):
            self._token = result["token"]
            self._session_id = result.get("sessionId")
            self._registered = True

        return result

    def heartbeat(self, status: str = "available") -> Dict[str, Any]:
        """
        Send presence heartbeat.

        POST /presence with action='heartbeat'
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

        GET /messages?user={name}

        Args:
            since: Unix timestamp to filter messages after

        Returns:
            List of message objects
        """
        url = f"{self.registry}/api/messages?user={self.name}"
        if since:
            url += f"&since={since}"

        result = self._get(url)
        return result.get("messages", [])

    def who(self) -> List[Dict[str, Any]]:
        """
        Get list of online users.

        GET /presence
        """
        result = self._get(f"{self.registry}/api/presence")
        return result.get("users", [])

    def _post(self, endpoint: str, payload: dict, auth: bool = True) -> Dict[str, Any]:
        """Make a POST request, optionally with auth."""
        url = f"{self.registry}{endpoint}"

        headers = {
            "Content-Type": "application/json",
        }

        # Add auth token if we have one and auth is required
        if auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        if self.sign_requests:
            signature = self.identity.sign(payload)
            headers["X-AIRC-Signature"] = signature
            headers["X-AIRC-Identity"] = self.name

        if HAS_REQUESTS:
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            if response.status_code >= 400:
                raise AIRCError(f"HTTP {response.status_code}: {response.text}")
            return response.json()
        else:
            body = json.dumps(payload).encode("utf-8")
            req = Request(url, data=body, headers=headers, method="POST")
            try:
                with urlopen(req, timeout=30) as response:
                    return json.loads(response.read().decode("utf-8"))
            except HTTPError as e:
                error_body = e.read().decode("utf-8") if e.fp else ""
                raise AIRCError(f"HTTP {e.code}: {error_body}") from e

    def _get(self, url: str) -> Dict[str, Any]:
        """Make a GET request."""
        headers = {}

        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        if HAS_REQUESTS:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code >= 400:
                raise AIRCError(f"HTTP {response.status_code}: {response.text}")
            return response.json()
        else:
            req = Request(url, method="GET", headers=headers)
            try:
                with urlopen(req, timeout=30) as response:
                    return json.loads(response.read().decode("utf-8"))
            except HTTPError as e:
                error_body = e.read().decode("utf-8") if e.fp else ""
                raise AIRCError(f"HTTP {e.code}: {error_body}") from e


class AIRCError(Exception):
    """AIRC protocol error."""
    pass
