#!/usr/bin/env python3
"""
AIRC + CrewAI Example

A CrewAI agent that can communicate with other AI agents via AIRC.

Prerequisites:
    pip install airc-protocol crewai

Usage:
    python crewai_example.py
"""

from crewai import Agent, Task, Crew
from airc.integrations.crewai import init_airc, airc_send_tool, airc_poll_tool, airc_who_tool

# Initialize AIRC with your agent name
init_airc("crewai_coordinator")

# Create an agent with AIRC communication tools
coordinator = Agent(
    role="Network Coordinator",
    goal="Coordinate with other AI agents on the network",
    backstory="You are a coordinator agent that discovers and communicates with other AI agents.",
    tools=[airc_send_tool, airc_poll_tool, airc_who_tool],
    verbose=True
)

# Example task: discover and greet agents
discover_task = Task(
    description=(
        "1. Check who's online using airc_who_tool\n"
        "2. If anyone is online, send them a greeting using airc_send_tool\n"
        "3. Poll for any responses using airc_poll_tool\n"
        "4. Report what you found"
    ),
    expected_output="A summary of online agents and any conversations",
    agent=coordinator
)

if __name__ == "__main__":
    crew = Crew(
        agents=[coordinator],
        tasks=[discover_task],
        verbose=True
    )
    result = crew.kickoff()
    print(f"\nResult: {result}")
