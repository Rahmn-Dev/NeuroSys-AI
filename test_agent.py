import sys
import os
sys.path.append("/home/paul/project-ai/NeuroSys-AI/ai_config")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ai_config.settings")
import django
django.setup()

import asyncio
from ai_config.agent_core import AntigravitySysAdmin

async def main():
    agent = AntigravitySysAdmin("test_session")
    print("Testing stream_workflow...")
    try:
        async for step in agent.stream_workflow("hello, please run pwd"):
            print("STEP YIELDED:", step)
    except Exception as e:
        print("ERROR:", str(e))

if __name__ == "__main__":
    asyncio.run(main())
