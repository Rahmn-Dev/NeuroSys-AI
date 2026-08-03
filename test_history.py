import asyncio
import os
import sys

# Try importing SDK
try:
    from google.antigravity import Agent, LocalAgentConfig
    from google.antigravity.conversation.conversation import Conversation
    from google.antigravity.conversation.models import Step, StepType
    print("Imports successful")
except Exception as e:
    print(f"Error: {e}")
