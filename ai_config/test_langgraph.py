import asyncio
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
import os

os.environ["GEMINI_API_KEY"] = "dummy"

@tool
def execute_shell(command: str) -> str:
    """Executes a bash command and returns the output."""
    return "executed"

async def main():
    llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash")
    agent_executor = create_react_agent(llm, [execute_shell])
    
    # We will just print the stream events
    print("Agent created.")
    # async for event in agent_executor.astream_events({"messages": [("user", "Run ls -la")]}, version="v2"):
    #    print(event["event"], event.get("name"))

asyncio.run(main())
