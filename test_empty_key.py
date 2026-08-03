import os
os.environ["GEMINI_API_KEY"] = ""
from google.antigravity import LocalAgentConfig, Agent
try:
    config = LocalAgentConfig(model="gemini-1.5-pro", tools=[])
except Exception as e:
    print(e)
