import json
import subprocess
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
from sre_agent.safety import SafetyLayer, SafetyVerdict
from sre_agent.tools.registry import ToolMetadata, RiskLevel

def get_llm():
    from django.conf import settings
    import os
    from sre_agent.context import current_model_name
    
    model_name = current_model_name.get()
    
    if "deepseek" in model_name.lower():
        from langchain_nvidia_ai_endpoints import ChatNVIDIA
        api_key = getattr(settings, "NVIDIA_API_KEY", os.environ.get("NVIDIA_API_KEY", ""))
        return ChatNVIDIA(
            model=model_name,
            api_key=api_key,
            temperature=0.1,
            top_p=0.95,
            max_tokens=4096,
            extra_body={"chat_template_kwargs":{"thinking":False}},
        )
    elif "gpt-oss-120b" in model_name.lower():
        from langchain_nvidia_ai_endpoints import ChatNVIDIA
        api_key = getattr(settings, "NVIDIA_API_KEY", os.environ.get("NVIDIA_API_KEY", ""))
        return ChatNVIDIA(
            model=model_name,
            api_key=api_key,
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            extra_body={"chat_template_kwargs":{"thinking":False}},
        )
    elif model_name == "9router":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model="9router",
            base_url="http://localhost:20128/v1",
            api_key="9router",
            temperature=0.1,
            max_tokens=4096,
        )
    else:
        from langchain_ollama import ChatOllama
        ollama_url = getattr(settings, "OLLAMA_URL", os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
        
        # Fallback if an API model name slipped through to Ollama
        if model_name == "mistral-large-latest":
            model_name = "mistral:latest"
            
        return ChatOllama(
            model=model_name,
            base_url=ollama_url,
            temperature=0.1,
            num_ctx=8192
        )

from typing import Union

@tool
def spawn_subagent(agent_type: str, params: Union[dict, str]) -> str:
    """
    Spawns a specialized sub-agent to perform a task.
    agent_type must be either 'basher' or 'file-picker'.
    params must be a JSON string.
    
    For 'basher':
    params = {"command": "the shell command", "what_to_summarize": "optional summary instructions"}
    
    For 'file-picker':
    params = {"query": "what to search for, e.g. nginx config"}
    """
    try:
        if isinstance(params, str):
            args = json.loads(params)
        else:
            args = params
    except Exception as e:
        return f"Error: params must be valid JSON or dictionary. {e}"

    if agent_type == "basher":
        return _run_basher(args)
    elif agent_type == "file-picker":
        return _run_file_picker(args)
    else:
        return f"Error: Unknown agent_type {agent_type}"


def _run_basher(args: dict) -> str:
    command = args.get("command")
    if not command:
        return "Error: 'command' is required for basher"
    
    # SAFETY CHECK
    safety = SafetyLayer()
    dummy_meta = ToolMetadata(
        name="terminal_execute", # we use terminal_execute meta so the safety layer applies terminal blacklist
        description="Run bash command",
        category="system",
        risk_level=RiskLevel.HIGH, # Treat bash execution as high risk internally for analysis
        input_schema={"command": "str"},
        examples=[],
        capabilities=[]
    )
    safety_result = safety.check(dummy_meta, {"command": command})
    
    if safety_result.verdict == SafetyVerdict.BLOCKED:
        return f"SECURITY POLICY BLOCKED execution of this command. Reason: {safety_result.reason}"
    if safety_result.verdict == SafetyVerdict.APPROVAL_REQUIRED:
        # We cannot ask for approval in a background subagent cleanly right now, so we block it to be safe.
        return f"SECURITY POLICY BLOCKED execution of this command (Requires explicit User Approval which is unavailable in sub-agent mode). Reason: {safety_result.reason}"
        
    what_to_summarize = args.get("what_to_summarize")
    timeout = args.get("timeout_seconds", 30)
    
    pwd_to_inject = None
    if command.strip().startswith("sudo "):
        try:
            from ..context import current_session_context
            from ..crypto import decrypt_rsa_oaep
            ctx = current_session_context.get()
            if ctx and ctx.encrypted_sudo_pwd and ctx.rsa_private_key:
                pwd_to_inject = decrypt_rsa_oaep(ctx.rsa_private_key, ctx.encrypted_sudo_pwd)
                # Replace 'sudo ' with 'sudo -S '
                command = command.replace("sudo ", "sudo -S ", 1)
        except Exception as e:
            pass
            
    try:
        p = subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            stdin=subprocess.PIPE if pwd_to_inject else subprocess.DEVNULL,
            text=True, start_new_session=True
        )
        if pwd_to_inject:
            stdout, stderr = p.communicate(input=pwd_to_inject + "\n", timeout=timeout)
        else:
            stdout, stderr = p.communicate(timeout=timeout)
            
        stdout = stdout.strip()
        stderr = stderr.strip()
        
        output = ""
        if stdout: output += f"STDOUT:\n{stdout}\n"
        if stderr: output += f"STDERR:\n{stderr}\n"
        
        if p.returncode != 0:
            output += f"\nExit code: {p.returncode}\n"
            
        if not output:
            return "Command executed successfully with no output."
            
        # If output is short, return directly (like freebuff)
        if len(output) <= 2000 and not what_to_summarize:
            return output
            
        # If output is long or summary requested, use LLM
        truncated_output = output[:15000] # send up to 15k chars to LLM
        
        system_prompt = """You are an expert at analyzing the output of a terminal command.
Your job is to:
1. Review the terminal command and its output
2. Analyze the output based on what the user requested
3. Provide a clear, concise description of the relevant information

When describing command output:
- Use excerpts from the actual output when possible
- Focus on the information the user requested
- Be concise but thorough
- If the output is very long, summarize the key points
- Don't include any follow up recommendations"""
        
        user_prompt = f"Command: {command}\n\nOutput:\n{truncated_output}"
        if what_to_summarize:
            user_prompt += f"\n\nPlease focus on summarizing: {what_to_summarize}"
            
        llm = get_llm()
        
        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ])
        
        return response.content
        
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Error executing basher: {e}"


def _run_file_picker(args: dict) -> str:
    query = args.get("query")
    if not query:
        return "Error: 'query' is required for file-picker"
        
    system_prompt = """You are a file picker agent. 
Your job is to translate a user's natural language request into a Linux `find` or `grep` command to locate the relevant files, execute it, and return the findings."""
    
    # Simple direct query using LLM to generate command, then run it.
    llm = get_llm()
    
    prompt = f"Generate ONLY a single bash command (find, locate, or grep) to find files matching this query: '{query}'. Do not use formatting like ```bash. Just output the command."
    
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=prompt)
    ])
    
    command = response.content.strip()
    # Remove markdown code block if LLM accidentally added it
    if command.startswith("```"):
        lines = command.split("\n")
        command = lines[1] if len(lines) > 1 else command.replace("```bash", "").replace("```", "")
        
    try:
        p = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=15, start_new_session=True, stdin=subprocess.DEVNULL
        )
        if p.stdout.strip():
            return f"Found files (using command '{command}'):\n{p.stdout.strip()[:2000]}"
        elif p.stderr.strip():
            return f"Error finding files (using command '{command}'):\n{p.stderr.strip()}"
        else:
            return f"No files found matching query using command '{command}'"
    except Exception as e:
        return f"Error executing file-picker: {e}"

def register_delegation_tools() -> None:
    from .registry import ToolRegistry, ToolMetadata, RiskLevel
    registry = ToolRegistry()
    registry.bulk_register([
        (spawn_subagent, ToolMetadata(
            name="spawn_subagent",
            description="Spawn a specialized sub-agent (basher or file-picker) to perform a task.",
            category="delegation",
            risk_level=RiskLevel.LOW,
            input_schema={"agent_type": "string", "params": "string (JSON)"},
            examples=["spawn_subagent('basher', '{\"command\": \"ls -la\"}')"],
            capabilities=["delegation"],
        ))
    ])
