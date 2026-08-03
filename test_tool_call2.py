import asyncio
import os
from antigravity import Agent, LocalAgentConfig

def run_ls(dir_path: str):
    """Run ls command"""
    return os.listdir(dir_path)

async def main():
    api_key = os.environ.get("GEMINI_KEY", os.environ.get("GEMINI_API_KEY"))
    config = LocalAgentConfig(model="gemini-flash-latest", api_key=api_key, tools=[run_ls])
    agent = Agent(config)
    async with agent as a:
        await a.conversation.send("List files in the current directory using run_ls")
        async for step in a.conversation.receive_steps():
            if step.type == "TOOL_CALL":
                print(f"TOOL_CALL attributes: {dir(step)}")
                if hasattr(step, 'action'):
                    print(f"Action: {step.action}")
                if hasattr(step, 'tool'):
                    print(f"Tool: {step.tool}")
                if hasattr(step, 'function_name'):
                    print(f"Func: {step.function_name}")
                if hasattr(step, 'name'):
                    print(f"Name: {step.name}")

asyncio.run(main())
