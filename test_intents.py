import asyncio
import os
import sys

# Set up Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ai_config.settings")
import django
django.setup()

from ai_config.agent_core import AntigravitySysAdmin

async def main():
    agent = AntigravitySysAdmin("test_session_intent")
    
    print("\n\n" + "="*50)
    print("TEST 1: SIMPLE_INFORMATION")
    print("="*50)
    async for step in agent.stream_workflow("what is requirements.txt?"):
        pass # The backend logs will show what happens
    
    print("\n\n" + "="*50)
    print("TEST 2: COMPLEX_DEBUG")
    print("="*50)
    # Re-initialize to reset state
    agent2 = AntigravitySysAdmin("test_session_complex")
    async for step in agent2.stream_workflow("why is nginx not working?"):
        pass

if __name__ == "__main__":
    asyncio.run(main())
