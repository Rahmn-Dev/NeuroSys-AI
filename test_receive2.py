import asyncio
from google.antigravity import LocalAgentConfig, Agent

async def test():
    config = LocalAgentConfig(model='gemini-1.5-pro', tools=[])
    agent = Agent(config)
    async with agent:
        agent.conversation.send("hello")
        async for step in agent.conversation.receive_steps():
            print(step.type)
            if step.type == "TEXT_RESPONSE":
                print(step.content)

asyncio.run(test())
