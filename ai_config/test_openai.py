import asyncio
from google.antigravity import Agent, LocalAgentConfig
from google.antigravity.models import ModelTarget, GeminiAPIEndpoint, ModelType

async def main():
    config = LocalAgentConfig(
        model=ModelTarget(
            name="llama3.1",
            endpoint=GeminiAPIEndpoint(base_url="http://localhost:11434/v1", api_key="ollama")
        ),
        system_prompt="You are a helpful assistant."
    )
    async with Agent(config) as agent:
        try:
            res = await agent.chat("Hello")
            print("Success:", res.text())
        except Exception as e:
            print("Error:", e)

asyncio.run(main())
