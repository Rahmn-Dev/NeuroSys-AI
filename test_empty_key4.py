import os
import asyncio
from google.antigravity import LocalAgentConfig, Agent
try:
    config = LocalAgentConfig(model="gemini-1.5-pro", tools=[], api_key="sk-123", conversation_id="1234")
    print("Success")
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
