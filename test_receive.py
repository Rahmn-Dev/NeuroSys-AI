import asyncio
from google.antigravity import LocalAgentConfig, Agent

async def test():
    config = LocalAgentConfig(model='gemini-1.5-pro', tools=[])
    agent = Agent(config)
    async with agent:
        print(help(agent.conversation.receive_steps))

asyncio.run(test())
