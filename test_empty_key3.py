import os
import asyncio
os.environ["GEMINI_API_KEY"] = ""
os.environ["OPENAI_API_KEY"] = "sk-12345"
from google.antigravity import LocalAgentConfig, Agent
async def main():
    try:
        config = LocalAgentConfig(model="gemini-1.5-pro", tools=[])
        agent = Agent(config)
        async with agent:
            await agent.conversation.send("hello")
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}")
asyncio.run(main())
