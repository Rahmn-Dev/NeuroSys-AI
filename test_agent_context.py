import asyncio
from google.antigravity import LocalAgentConfig, Agent

async def main():
    config = LocalAgentConfig(model="gemini-1.5-pro", tools=[])
    try:
        agent = Agent(config)
        async for step in agent.conversation.receive_steps("hello"):
            print(step)
    except Exception as e:
        print("Error without async with:", e)
        
    try:
        agent = Agent(config)
        async with agent:
            async for step in agent.conversation.receive_steps("hello"):
                print(step.type)
                if step.type == "TEXT_RESPONSE":
                    print(step.content)
    except Exception as e:
        print("Error with async with:", e)

asyncio.run(main())
