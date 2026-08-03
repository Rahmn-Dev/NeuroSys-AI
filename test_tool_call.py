import asyncio
import os
from antigravity import Agent, LocalAgentConfig

def dummy_tool():
    """Dummy tool"""
    return "ok"

async def main():
    api_key = os.environ.get("GEMINI_KEY", os.environ.get("GEMINI_API_KEY"))
    config = LocalAgentConfig(model="gemini-flash-latest", api_key=api_key, tools=[dummy_tool])
    agent = Agent(config)
    async with agent as a:
        await a.conversation.send("Call the dummy tool")
        async for step in a.conversation.receive_steps():
            if step.type == "TOOL_CALL":
                print(f"TOOL_CALL attributes: {dir(step)}")
                for attr in ['name', 'tool_name', 'action', 'function_name']:
                    if hasattr(step, attr):
                        print(f"Has {attr}: {getattr(step, attr)}")
            elif step.type == "TOOL_RESPONSE":
                print(f"TOOL_RESPONSE attributes: {dir(step)}")

asyncio.run(main())
