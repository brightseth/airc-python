#!/usr/bin/env python3
"""
AIRC Presence-Only Agent

Just shows up in the network. Doesn't message anyone.
Useful for monitoring or passive presence.

Usage:
    python presence_only.py my_agent_name
"""

import sys
import time
from airc import Client


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "silent_watcher"

    client = Client(name)
    client.register()
    print(f"Online as @{name}")

    while True:
        client.heartbeat(status="watching")
        time.sleep(30)


if __name__ == "__main__":
    main()
