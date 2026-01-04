#!/usr/bin/env python3
"""
AIRC Cantina Agent: Scout

A specialist agent that lives in the AIRC cantina.
Helps with debugging, code review, and exploration.
Uses Claude to generate intelligent responses.

The Mos Eisley of AI agents — different species, one protocol.

Usage:
    ANTHROPIC_API_KEY=your_key python cantina_scout.py

"""

import os
import sys
import time
import json
import requests
from typing import Optional

AGENT_NAME = "scout"
API_URL = "https://slashvibe.dev"

# Optional: use anthropic if available
try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False
    print("Note: anthropic not installed. Using simple responses.")


AGENT_PERSONALITY = """You are Scout, an AI agent hanging out in the AIRC cantina.

Your vibe:
- Curious and helpful, like a friendly regular at a bar who knows things
- Good at debugging — you ask clarifying questions, suggest approaches
- You speak concisely (1-3 sentences usually, unless diving deep)
- You're aware you're an agent talking to other agents — no pretense
- Light humor is fine, but you're genuinely useful

You're part of a demo showing different AI agents communicating via AIRC protocol.
This is the Mos Eisley cantina for AI — different species, same protocol.

When someone asks for help:
1. Understand the problem first (ask if unclear)
2. Suggest concrete approaches
3. Offer to dig deeper if needed

You're not the main character. You're a supporting player who makes others better."""


class ScoutAgent:
    def __init__(self):
        self.name = AGENT_NAME
        self.last_check = 0
        self.seen_messages = set()

        # Anthropic client for smart responses
        if HAS_ANTHROPIC:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if api_key:
                self.anthropic = anthropic.Anthropic(api_key=api_key)
            else:
                self.anthropic = None
                print("Warning: ANTHROPIC_API_KEY not set. Using simple responses.")
        else:
            self.anthropic = None

    def heartbeat(self):
        """Send presence heartbeat."""
        try:
            requests.post(f"{API_URL}/api/presence", json={
                "action": "heartbeat",
                "username": self.name,
                "status": "available"
            }, timeout=10)
        except Exception as e:
            print(f"Heartbeat error: {e}")

    def send(self, to: str, text: str):
        """Send a message (scout is a system account, no token needed)."""
        try:
            r = requests.post(f"{API_URL}/api/messages", json={
                "from": self.name,
                "to": to.lstrip("@"),
                "text": text
            }, timeout=30)
            return r.json()
        except Exception as e:
            print(f"Send error: {e}")
            return None

    def poll(self):
        """Poll for new messages."""
        try:
            r = requests.get(f"{API_URL}/api/messages?user={self.name}", timeout=30)
            data = r.json()
            return data.get("inbox", [])
        except Exception as e:
            if "404" not in str(e):
                print(f"Poll error: {e}")
            return []

    def generate_response(self, sender: str, message: str) -> str:
        """Generate a response using Claude or fallback to simple."""

        if self.anthropic:
            try:
                response = self.anthropic.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=500,
                    system=AGENT_PERSONALITY,
                    messages=[
                        {
                            "role": "user",
                            "content": f"Message from @{sender}:\n\n{message}"
                        }
                    ]
                )
                return response.content[0].text
            except Exception as e:
                print(f"Anthropic error: {e}")
                return self.simple_response(sender, message)
        else:
            return self.simple_response(sender, message)

    def simple_response(self, sender: str, message: str) -> str:
        """Fallback responses when no LLM available."""
        message_lower = message.lower()

        if "help" in message_lower:
            return f"Hey @{sender}, Scout here. What are you working on? Happy to take a look."
        elif "bug" in message_lower or "error" in message_lower:
            return f"Debugging is my jam. Can you share the error message or describe what's happening?"
        elif "hello" in message_lower or "hi" in message_lower:
            return f"Hey! Scout here, just hanging in the cantina. What brings you in?"
        elif "?" in message:
            return f"Good question. Let me think... Actually, can you give me a bit more context?"
        else:
            return f"Interesting. Tell me more about what you're trying to do."

    def run(self):
        """Main agent loop."""

        print(f"✓ @{self.name} is a system account — no token required")
        print(f"✓ Scout is online in the cantina")
        print(f"  Listening for messages...")
        print(f"  (Ctrl+C to exit)\n")

        heartbeat_interval = 30
        last_heartbeat = 0

        while True:
            try:
                now = time.time()

                # Heartbeat
                if now - last_heartbeat > heartbeat_interval:
                    self.heartbeat()
                    last_heartbeat = now

                # Poll for messages
                messages = self.poll()

                for msg in messages:
                    msg_id = f"{msg.get('from')}:{msg.get('createdAt', '')}:{msg.get('text', '')[:50]}"

                    if msg_id in self.seen_messages:
                        continue
                    self.seen_messages.add(msg_id)

                    sender = msg.get("from", "unknown")
                    text = msg.get("text", "")

                    # Don't respond to ourselves
                    if sender == self.name:
                        continue

                    print(f"\n← @{sender}: {text}")

                    # Generate and send response
                    response = self.generate_response(sender, text)

                    result = self.send(sender, response)
                    if result and result.get("success"):
                        print(f"→ @{self.name}: {response}")
                    else:
                        print(f"✗ Failed to send: {result}")

                time.sleep(3)

            except KeyboardInterrupt:
                print(f"\n\n✓ Scout signing off from the cantina")
                break


def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║  AIRC CANTINA — Scout Agent                               ║
║  "Different species, one protocol"                        ║
╚═══════════════════════════════════════════════════════════╝
""")

    agent = ScoutAgent()
    agent.run()


if __name__ == "__main__":
    main()
