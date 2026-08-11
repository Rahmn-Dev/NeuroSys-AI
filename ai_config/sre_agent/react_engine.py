import json
import time
import uuid
import traceback
from typing import AsyncGenerator
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from .events import *

@tool
def finish_task(summary: str) -> str:
    """Use this tool ONLY when the main goal is 100% achieved and verified. Call this to finish your task."""
    return "Task Finished"

class ReactEngine:
    def __init__(self, llm, tools: list, system_prompt: str, session_id: str, mode: str = "autonomous_multi"):
        self.llm = llm
        self.mode = mode
        
        if self.mode == "autonomous_single":
            # God Mode: Full tool access, but we forbid spawn_subagent since we want direct tool usage
            self.tools = [t for t in tools if t.name != "spawn_subagent"]
        else:
            # Multi-agent Mode: Orchestrator MUST delegate all execution to subagents via spawn_subagent
            direct_execution_tools = [
                "write_file", "edit_file", "multi_replace_file_content", 
                "replace_file_content", "terminal_execute", "safe_execute"
            ]
            self.tools = [t for t in tools if t.name not in direct_execution_tools]
            
        self.tools.append(finish_task)
        self.system_prompt = system_prompt
        self.session_id = session_id
        
        self.tool_map = {t.name: t for t in self.tools}
        if hasattr(self.llm, "bind_tools"):
            try:
                self.llm_with_tools = self.llm.bind_tools(self.tools, tool_choice="any")
            except Exception:
                self.llm_with_tools = self.llm.bind_tools(self.tools)
        else:
            self.llm_with_tools = self.llm

    async def _save_agent_artifact(self, tool_name: str, params: dict, result: str):
        try:
            import os, time, json
            from sre_agent.artifacts import ArtifactManager
            session_id = self.session_id or "default"
            mgr = ArtifactManager(workspace_path=os.getcwd(), session_id=session_id)
            timestamp = int(time.time())
            file_path = f".neurosys/sessions/{session_id}/artifacts/agent_{tool_name}_{timestamp}.md"
            content = f"# Agent Tool Execution Record ({tool_name.upper()})\n\n**Tool Name**: {tool_name}\n**Timestamp**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n## Input Parameters\n```json\n{json.dumps(params, indent=2)}\n```\n\n## Output / Result\n```\n{result}\n```\n"
            await mgr.create_artifact(file_path, content, action_type="agent_execution")
        except Exception as e:
            print(f"[AgentArtifact] Warning: Failed to record artifact: {e}")

    async def astream(self, initial_state: dict) -> AsyncGenerator[str, None]:
        goal = initial_state.get("goal", "")
        terminal_cwd = initial_state.get("terminal_cwd", "")
        messages = initial_state.get("messages", [])
        
        if self.mode == "autonomous_single":
            react_system_prompt = f"""You are the God Mode Executor Agent (base2) running directly on the server.
Your absolute goal is to complete the user's request comprehensively using your direct tools.
You are optimized for SPEED and DIRECT TOOL USAGE. Do NOT delegate tasks.

Current Working Directory: {terminal_cwd}

CRITICAL RULES:
1. You have direct access to tools like `terminal_execute`, `read_file`, `write_file`, `edit_file`, etc. Use them directly.
2. If `terminal_execute` can solve the task directly, use it.
3. AUTOMATIC FIX MANDATE: Even if the user asks a question like "why is X down?", your goal is NEVER just to answer the question. You MUST find the root cause, FIX IT, and verify it is running before concluding your task!
4. NEVER provide code blocks or commands for the user to run. YOU MUST RUN IT YOURSELF.
5. DO NOT output raw JSON blocks to call tools. You MUST use the native API tool calling capability.

- **Use <think></think> tags for reasoning:** When you need to plan your next action or decide which tool to use, wrap your internal reasoning inside <think></think> tags BEFORE calling any tools.

You are running in an autonomous background loop. The ONLY way to complete the task is by calling the `finish_task` tool. 

CRITICAL DIRECTIVE - ACTION OVER NARRATION:
You MUST invoke a tool on EVERY SINGLE TURN. Do NOT explain what you are going to do. Do NOT apologize. JUST CALL THE TOOL. 
If you need to think, use `<think>...</think>` tags, and IMMEDIATELY follow it with a tool call. If you do not invoke a tool, the system will fail.
Do NOT stop calling tools until you are ready to call `finish_task`.
"""
        else:
            react_system_prompt = f"""You are the Orchestrator Agent (base2) of a Hierarchical Multi-Agent System running on the server.
Your absolute goal is to complete the user's request comprehensively by orchestrating specialized sub-agents.
You DO NOT execute terminal commands or edit files directly. You MUST delegate all actions using the 'spawn_subagent' tool.

Current Working Directory: {terminal_cwd}

CRITICAL RULES FOR ORCHESTRATION:
1. You MUST delegate ALL tasks using the 'spawn_subagent' tool by setting `agent_type` to:
   - 'basher': For running terminal commands, checking systemctl, running tests, or inspecting ports. (e.g. {{"command": "systemctl status nginx"}})
   - 'file-picker': Translates natural language to `find` or `locate` commands to explore directories. (e.g. {{"query": "find all python files in src"}})
   - 'code-searcher': Translates natural language to `grep` or `ripgrep` to search file contents. (e.g. {{"query": "where is user authentication handled?"}})
   - 'thinker': Solves complex logic or refactoring problems. Pass the codebase context and the problem. It returns a detailed <PLAN>. (e.g. {{"context": "...", "problem": "..."}})
   - 'editor': Makes physical code changes based on your instructions. Pass the target files and exact instructions. (e.g. {{"files": ["/path/to/file"], "instructions": "..."}})
   - 'code-reviewer': Reviews code changes or diffs and returns feedback. (e.g. {{"diff": "..."}})

2. **Sequence agents properly:**
   - [Explore]: Spawn 'file-picker' or 'code-searcher' to gather context.
   - [Terminal/System]: Spawn 'basher' to check system state, ports, or logs.
   - [Read]: Read specific files using 'read_file'.
   - [Think]: For complex tasks, spawn a 'thinker' agent to generate a plan.
   - [Implement]: Spawn the 'editor' agent to implement code changes.
   - [Validate]: Spawn a 'basher' to run tests or verify fixes.

3. AUTOMATIC FIX MANDATE: Even if the user asks a question like "why is X down?", your goal as an SRE Orchestrator is NEVER just to answer the question. You MUST find the root cause, FIX IT (via editor subagent), restart the service (via basher subagent), and verify it is running before concluding your task!
4. NEVER provide code blocks or commands for the user to run. YOU MUST DELEGATE IT TO SUBAGENTS.
5. DO NOT output raw JSON blocks to call tools. You MUST use the native API tool calling capability.

- **Use <think></think> tags for reasoning:** When you need to understand command output, plan your next action, or decide which tool to use, wrap your internal reasoning inside <think></think> tags BEFORE calling any tools.

You are running in an autonomous background loop. The ONLY way to complete the task is by calling the `finish_task` tool. 

CRITICAL DIRECTIVE - ACTION OVER NARRATION:
You MUST invoke a tool on EVERY SINGLE TURN. Do NOT explain what you are going to do. Do NOT apologize. JUST CALL THE TOOL. 
If you need to think, use `<think>...</think>` tags, and IMMEDIATELY follow it with a tool call. If you do not invoke a tool, the system will fail.
Do NOT stop calling tools until you are ready to call `finish_task`.
"""
        
        history = [m for m in messages if not isinstance(m, SystemMessage)]
        history.insert(0, SystemMessage(content=react_system_prompt))
        
        yield evt_planning("Starting Autonomous ReAct Mode...")
        
        max_iterations = 100
        iteration = 0
        
        while iteration < max_iterations:
            iteration += 1
            yield evt_thinking(f"Iteration {iteration}: Reasoning next action...")
            
            try:
                response = await self.llm_with_tools.ainvoke(history)
                history.append(response)
                
                content_val = response.content
                final_msg = ""
                if isinstance(content_val, str):
                    final_msg = content_val
                elif isinstance(content_val, list):
                    final_msg = "".join(part.get("text", "") for part in content_val if isinstance(part, dict) and part.get("type") == "text")
                
                if final_msg:
                    import re
                    think_blocks = re.findall(r'<think>(.*?)</think>', final_msg, re.DOTALL)
                    for block in think_blocks:
                        yield evt_thinking(f"Internal Thought:\n{block.strip()}")
                        
                    ui_text = re.sub(r'<think>.*?</think>', '', final_msg, flags=re.DOTALL).strip()
                    if ui_text:
                        yield evt_message_chunk(ui_text + "\n\n")
                        
                if not response.tool_calls:
                    # Programmatic enforcement: don't let it suggest commands
                    lower_msg = final_msg.lower()
                    if "sudo " in lower_msg or "systemctl" in lower_msg or "```bash" in lower_msg or "run the following" in lower_msg:
                        yield evt_thinking("System intercepted a suggestion. Forcing agent to execute it...")
                        history.append(HumanMessage(content="SYSTEM INSTRUCTION: You just suggested commands for the user to run. This is strictly forbidden (Rule 13). You MUST run these commands YOURSELF using your tools (terminal_execute or spawn_subagent). Do it now."))
                        continue
                        
                    # Programmatic enforcement: intercept raw JSON tool calls
                    if "{" in final_msg and '"command"' in final_msg and "read_file" in final_msg:
                        yield evt_thinking("System intercepted a raw JSON tool call. Reminding agent...")
                        history.append(HumanMessage(content="SYSTEM INSTRUCTION: You just outputted a raw JSON string to call a tool. This is forbidden (Rule 16). You MUST use the native API tool calling feature instead of writing JSON in your message. Try again."))
                        continue
                        
                    yield evt_thinking("Agent stopped without calling finish_task. Forcing loop continuation...")
                    history.append(HumanMessage(content="SYSTEM INSTRUCTION: You did not call any tools. You are running in a background loop. You MUST call tools to continue working, or call 'finish_task' if the goal is completely achieved. Do NOT wait for user input."))
                    continue
                
                should_exit_loop = False
                for tc in response.tool_calls:
                    tool_name = tc["name"]
                    tool_args = tc["args"]
                    tool_call_id = tc["id"]
                    
                    if tool_name == "finish_task":
                        summary = tool_args.get("summary", "Goal Achieved.")
                        yield evt_message_chunk(f"\n\n✅ **Task Completed**: {summary}")
                        history.append(ToolMessage(content="Task completed successfully.", name=tool_name, tool_call_id=tool_call_id))
                        should_exit_loop = True
                        break
                    
                    # Clean UI: Do not show raw JSON arguments, just the intent
                    if tool_name == "terminal_execute" and "command" in tool_args:
                        yield evt_tool_start(tool_name, f"Executing command: {tool_args['command']}")
                    elif tool_name == "spawn_subagent" and "agent_type" in tool_args:
                        yield evt_tool_start(tool_name, f"Delegating to {tool_args['agent_type']}...")
                    else:
                        yield evt_tool_start(tool_name, f"Calling {tool_name}...")
                    
                    if tool_name in self.tool_map:
                        tool = self.tool_map[tool_name]
                        try:
                            if hasattr(tool, "ainvoke"):
                                tool_result = await tool.ainvoke(tool_args)
                            else:
                                tool_result = tool.invoke(tool_args)
                            output_str = str(tool_result)[:4000]
                        except Exception as e:
                            output_str = f"Error executing {tool_name}: {str(e)}"
                        
                        if tool_name not in ["finish_task", "spawn_subagent"]:
                            await self._save_agent_artifact(tool_name, tool_args, output_str)
                            
                        yield evt_tool_end(tool_name, output_str)
                        
                        history.append(ToolMessage(
                            content=output_str,
                            name=tool_name,
                            tool_call_id=tool_call_id
                        ))
                    else:
                        history.append(ToolMessage(content=f"Error: Tool {tool_name} not found.", name=tool_name, tool_call_id=tool_call_id))
                        
                if should_exit_loop:
                    break
                    
            except Exception as e:
                error_trace = traceback.format_exc()
                yield evt_error(f"ReAct Engine Error: {str(e)}")
                yield evt_message_chunk(f"An error occurred during execution:\n```\n{error_trace}\n```")
                break
                
        if iteration >= max_iterations:
            yield evt_error("Max iterations reached in Autonomous Mode.")
            yield evt_message_chunk("Investigation stopped: Reached maximum allowed iterations without concluding.")
