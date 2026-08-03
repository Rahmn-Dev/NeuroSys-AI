# from langchain.agents import initialize_agent
# from langchain.agents.agent import AgentExecutor
from langchain_ollama import ChatOllama
from .tools import run_shell, list_directory, read_file, write_file, restart_service, tail_log
from langgraph.prebuilt import create_react_agent

llm = ChatOllama(model="qwen2.5-coder:latest")
tools = [
    run_shell, list_directory, read_file, write_file, restart_service, tail_log
]
agent = create_react_agent(llm, tools=tools)