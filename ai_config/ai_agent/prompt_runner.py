from .agent import agent

def run_prompt(prompt: str) -> str:
    return agent.run(prompt)
