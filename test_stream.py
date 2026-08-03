import asyncio
import os
from google_antigravity import Agent, LocalAgentConfig

async def main():
    api_key = os.environ.get("GEMINI_KEY", os.environ.get("GEMINI_API_KEY"))
    config = LocalAgentConfig(model="gemini-3.6-flash", api_key=api_key)
    agent = Agent(config)
    async with agent as a:
        await a.conversation.send("Tell me a 3 word story")
        async for step in a.conversation.receive_steps():
            if step.type == "TEXT_RESPONSE":
                print(f"CHUNK: '{step.content}'")

asyncio.run(main())
