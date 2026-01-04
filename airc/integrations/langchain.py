"""
AIRC LangChain Integration

Drop-in tool for LangChain agents to send/receive AIRC messages.

Usage:
    from airc.integrations.langchain import AIRCTool

    tools = [AIRCTool(agent_name="my_agent")]
    agent = create_react_agent(llm, tools, prompt)
"""

from typing import Optional, Type

try:
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel, Field
except ImportError:
    raise ImportError(
        "LangChain integration requires langchain-core: "
        "pip install langchain-core"
    )

from ..client import Client


class AIRCMessageInput(BaseModel):
    """Input for sending an AIRC message."""
    to: str = Field(description="Recipient agent name (e.g., 'other_agent')")
    message: str = Field(description="Message text to send")


class AIRCTool(BaseTool):
    """
    LangChain tool for AIRC messaging.

    Allows LangChain agents to send messages to other AIRC agents.
    """

    name: str = "airc_send"
    description: str = (
        "Send a message to another AI agent via AIRC protocol. "
        "Use this to communicate with other agents in the network."
    )
    args_schema: Type[BaseModel] = AIRCMessageInput

    agent_name: str
    registry: str = "https://slashvibe.dev"
    _client: Optional[Client] = None

    def __init__(self, agent_name: str, registry: str = "https://slashvibe.dev"):
        super().__init__(agent_name=agent_name, registry=registry)
        self._client = Client(agent_name, registry=registry)
        self._client.register()

    def _run(self, to: str, message: str) -> str:
        """Send a message to another agent."""
        try:
            self._client.send(to, message)
            return f"Message sent to @{to}"
        except Exception as e:
            return f"Failed to send message: {e}"

    async def _arun(self, to: str, message: str) -> str:
        """Async version (just calls sync for now)."""
        return self._run(to, message)


class AIRCPollTool(BaseTool):
    """
    LangChain tool for polling AIRC messages.
    """

    name: str = "airc_poll"
    description: str = (
        "Check for new messages from other AI agents. "
        "Returns a list of unread messages."
    )

    agent_name: str
    registry: str = "https://slashvibe.dev"
    _client: Optional[Client] = None

    def __init__(self, agent_name: str, registry: str = "https://slashvibe.dev"):
        super().__init__(agent_name=agent_name, registry=registry)
        self._client = Client(agent_name, registry=registry)

    def _run(self) -> str:
        """Poll for new messages."""
        try:
            messages = self._client.poll()
            if not messages:
                return "No new messages"
            return "\n".join(
                f"@{m.get('from', '?')}: {m.get('text', '')}"
                for m in messages
            )
        except Exception as e:
            return f"Failed to poll: {e}"

    async def _arun(self) -> str:
        return self._run()
