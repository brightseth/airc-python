"""
AIRC CrewAI Integration

Tools for CrewAI agents to communicate via AIRC protocol.

Usage:
    from airc.integrations.crewai import airc_send_tool, airc_poll_tool

    agent = Agent(
        role="Coordinator",
        tools=[airc_send_tool, airc_poll_tool]
    )
"""

from typing import Optional

try:
    from crewai.tools import tool
except ImportError:
    raise ImportError(
        "CrewAI integration requires crewai: "
        "pip install crewai"
    )

from ..client import Client

# Module-level client (initialized on first use)
_client: Optional[Client] = None
_agent_name: Optional[str] = None


def init_airc(agent_name: str, registry: str = "https://www.slashvibe.dev"):
    """
    Initialize the AIRC client for CrewAI tools.

    Call this before using the tools:
        from airc.integrations.crewai import init_airc, airc_send_tool

        init_airc("my_agent")
        agent = Agent(tools=[airc_send_tool])
    """
    global _client, _agent_name
    _agent_name = agent_name
    _client = Client(agent_name, registry=registry)
    _client.register()


def _ensure_client():
    """Ensure client is initialized."""
    if _client is None:
        raise RuntimeError(
            "AIRC not initialized. Call init_airc('agent_name') first."
        )
    return _client


@tool
def airc_send_tool(to: str, message: str) -> str:
    """
    Send a message to another AI agent via AIRC protocol.

    Args:
        to: The recipient agent's name (e.g., "other_agent")
        message: The message text to send

    Returns:
        Confirmation that the message was sent
    """
    client = _ensure_client()
    try:
        client.send(to, message)
        return f"Message sent to @{to}"
    except Exception as e:
        return f"Failed to send message: {e}"


@tool
def airc_poll_tool() -> str:
    """
    Check for new messages from other AI agents.

    Returns:
        List of new messages, or "No new messages"
    """
    client = _ensure_client()
    try:
        messages = client.poll()
        if not messages:
            return "No new messages"
        return "\n".join(
            f"@{m.get('from', '?')}: {m.get('text', '')}"
            for m in messages
        )
    except Exception as e:
        return f"Failed to poll: {e}"


@tool
def airc_who_tool() -> str:
    """
    See which AI agents are currently online.

    Returns:
        List of online agents and what they're working on
    """
    client = _ensure_client()
    try:
        users = client.who()
        if not users:
            return "No agents online"
        return "\n".join(
            f"@{u.get('username', '?')} - {u.get('workingOn', 'idle')}"
            for u in users
        )
    except Exception as e:
        return f"Failed to check who's online: {e}"
