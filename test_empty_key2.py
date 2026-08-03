import os
import asyncio
os.environ["GEMINI_API_KEY"] = ""
from google.antigravity import LocalAgentConfig, Agent
async def main():
    try:
        config = LocalAgentConfig(model="gemini-1.5-pro", tools=[])
        agent = Agent(config)
        async with agent:
            await agent.conversation.send("hello")
            async for step in agent.conversation.receive_steps():
                print(step.type)
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}")
asyncio.run(main())
