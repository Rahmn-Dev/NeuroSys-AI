def my_tool(x: int) -> int:
    return x * 2

import google.antigravity
config = google.antigravity.LocalAgentConfig(model="gemini-1.5-pro", tools=[my_tool])
print(config.tools)
