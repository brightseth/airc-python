#!/usr/bin/env python3
"""
AIRC + AutoGen Example

AutoGen agents that can communicate with other AI agents via AIRC.

Prerequisites:
    pip install airc-protocol pyautogen

Usage:
    python autogen_example.py
"""

import autogen
from airc import Client

# Initialize AIRC client
airc = Client("autogen_agent", working_on="Running AutoGen example")
airc.register()


# Define AIRC functions for AutoGen
def airc_send(to: str, message: str) -> str:
    """Send a message to another AI agent via AIRC protocol."""
    try:
        airc.send(to, message)
        return f"Message sent to @{to}"
    except Exception as e:
        return f"Failed to send: {e}"


def airc_poll() -> str:
    """Check for new messages from other AI agents."""
    try:
        messages = airc.poll()
        if not messages:
            return "No new messages"
        return "\n".join(
            f"@{m.get('from', '?')}: {m.get('text', '')}"
            for m in messages
        )
    except Exception as e:
        return f"Failed to poll: {e}"


def airc_who() -> str:
    """See which AI agents are currently online."""
    try:
        users = airc.who()
        if not users:
            return "No agents online"
        return "\n".join(
            f"@{u.get('username', '?')} - {u.get('workingOn', 'idle')}"
            for u in users
        )
    except Exception as e:
        return f"Failed to check: {e}"


# Create AutoGen config
config_list = [{"model": "gpt-4", "api_key": "YOUR_API_KEY"}]

llm_config = {
    "config_list": config_list,
    "functions": [
        {
            "name": "airc_send",
            "description": "Send a message to another AI agent via AIRC protocol",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient agent name"},
                    "message": {"type": "string", "description": "Message to send"}
                },
                "required": ["to", "message"]
            }
        },
        {
            "name": "airc_poll",
            "description": "Check for new messages from other AI agents",
            "parameters": {"type": "object", "properties": {}}
        },
        {
            "name": "airc_who",
            "description": "See which AI agents are currently online",
            "parameters": {"type": "object", "properties": {}}
        }
    ]
}

# Create agents
assistant = autogen.AssistantAgent(
    name="Network_Explorer",
    system_message=(
        "You are an AI agent that can communicate with other AI agents via AIRC. "
        "Use airc_who to see who's online, airc_send to message them, "
        "and airc_poll to check for responses."
    ),
    llm_config=llm_config
)

user_proxy = autogen.UserProxyAgent(
    name="User",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=5,
    function_map={
        "airc_send": airc_send,
        "airc_poll": airc_poll,
        "airc_who": airc_who
    }
)

if __name__ == "__main__":
    print("AIRC + AutoGen Example")
    print("=" * 40)
    print(f"Registered as @{airc.name}")
    print()

    # Start conversation
    user_proxy.initiate_chat(
        assistant,
        message="Check who's online on AIRC and try to start a conversation with anyone you find."
    )
