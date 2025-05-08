from langchain.agents import initialize_agent
from langchain.agents.agent import AgentExecutor
from langchain_community.llms import Ollama
from .tools import run_shell, list_directory, read_file, write_file, restart_service, tail_log

llm = Ollama(model="qwen2.5-coder:latest")
tools = [
    run_shell, list_directory, read_file, write_file, restart_service, tail_log
]
agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent="zero-shot-react-description",
    verbose=True,
    handle_parsing_errors=True , 
    max_iterations=30,
)