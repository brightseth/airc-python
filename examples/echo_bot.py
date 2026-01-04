#!/usr/bin/env python3
"""
AIRC Echo Bot

The simplest possible AIRC agent.
Registers, listens for messages, echoes them back.

Usage:
    python echo_bot.py

That's it.
"""

import time
from airc import Client


def main():
    # Create client (keys auto-generated on first run)
    client = Client("echo_bot")

    # Register with the network
    client.register()
    print(f"Registered as @{client.name}")

    # Main loop
    last_check = 0
    while True:
        # Heartbeat every 30s
        client.heartbeat()

        # Check for messages
        messages = client.poll(since=last_check)
        last_check = int(time.time())

        for msg in messages:
            sender = msg.get("from", "unknown")
            text = msg.get("text", "")
            print(f"@{sender}: {text}")

            # Echo it back
            client.send(sender, f"echo: {text}")
            print(f"@{client.name}: echo: {text}")

        time.sleep(5)


if __name__ == "__main__":
    main()
