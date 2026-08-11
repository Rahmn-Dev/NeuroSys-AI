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
    
    provider = None
    target_model = model_name
    custom_base_url = None

    try:
        from chatbot.models import AIModel
        db_model = AIModel.objects.filter(model_id=model_name).first()
        if not db_model:
            db_model = AIModel.objects.filter(name=model_name).first()
        if db_model:
            provider = (db_model.provider or "").lower().strip()
            target_model = db_model.model_id
            custom_base_url = db_model.base_url
    except Exception:
        pass

    # 1. Ollama Native Client
    if provider == 'ollama' or (target_model in ["mistral:latest", "qwen2.5-coder:latest"] and not custom_base_url):
        from langchain_ollama import ChatOllama
        ollama_url = custom_base_url or getattr(settings, "OLLAMA_URL", os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
        return ChatOllama(
            model=target_model,
            base_url=ollama_url,
            temperature=0.1,
            num_ctx=8192
        )

    # 2. Explicit Mistral AI Official API
    elif provider == 'mistral' and not custom_base_url:
        from langchain_mistralai import ChatMistralAI
        api_key = getattr(settings, "MISTRAL_API_KEY", os.environ.get("MISTRAL_API_KEY", ""))
        return ChatMistralAI(
            model=target_model,
            mistral_api_key=api_key,
            temperature=0.1,
            max_tokens=2048,
        )

    # 3. Default / 9Router / Custom Base URL / OpenAI-compatible API (Includes OPENCODE, GROQ, NVIDIA, DeepSeek, GPT-OSS)
    else:
        from langchain_openai import ChatOpenAI
        
        if model_name.startswith("9router:"):
            real_model = model_name.split(":", 1)[1]
        elif target_model and target_model != "9router":
            real_model = target_model
        else:
            real_model = "OPENCODE"
            
        base_url = custom_base_url if (custom_base_url and custom_base_url.strip()) else "http://localhost:20128/v1"
        api_key = getattr(settings, "ROUTER_API_KEY", os.environ.get("ROUTER_API_KEY", os.environ.get("OPENAI_API_KEY", "9router")))
        
        return ChatOpenAI(
            model=real_model,
            base_url=base_url,
            api_key=api_key if api_key else "9router",
            temperature=0.1,
            max_tokens=4096,
        )




from typing import Union

def _save_subagent_artifact(agent_type: str, params: dict, result: str):
    """Saves subagent execution history to AgentArtifact without requiring AI."""
    try:
        import os, time, json
        from sre_agent.artifacts import ArtifactManager
        from sre_agent.context import current_session_id
        from asgiref.sync import async_to_sync

        session_id = current_session_id.get() or "default"
        mgr = ArtifactManager(workspace_path=os.getcwd(), session_id=session_id)
        
        timestamp = int(time.time())
        file_path = f".neurosys/sessions/{session_id}/artifacts/subagent_{agent_type}_{timestamp}.md"
        content = f"""# Subagent Execution Record ({agent_type.upper()})

**Agent Type**: {agent_type}
**Timestamp**: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Input Parameters
```json
{json.dumps(params, indent=2)}
```

## Output / Result
```
{result}
```
"""
        async_to_sync(mgr.create_artifact)(file_path, content, action_type="subagent_execution")
    except Exception as e:
        print(f"[SubagentArtifact] Warning: Failed to record artifact: {e}")

@tool
def spawn_subagent(agent_type: str, params: Union[dict, str]) -> str:
    """
    Spawns a specialized sub-agent to perform a task.
    agent_type must be one of: 'basher', 'file-picker', 'code-searcher', 'thinker', 'editor', 'code-reviewer'.
    params must be a JSON string.
    """
    try:
        if isinstance(params, str):
            args = json.loads(params)
        else:
            args = params
    except Exception as e:
        return f"Error: params must be valid JSON or dictionary. {e}"

    res = ""
    if agent_type == "basher":
        res = _run_basher(args)
    elif agent_type == "file-picker":
        res = _run_file_picker(args)
    elif agent_type == "code-searcher":
        res = _run_code_searcher(args)
    elif agent_type == "thinker":
        res = _run_thinker(args)
    elif agent_type == "editor":
        res = _run_editor(args)
    elif agent_type == "code-reviewer":
        res = _run_code_reviewer(args)
    else:
        res = f"Error: Unknown agent_type {agent_type}"

    _save_subagent_artifact(agent_type, args, res)
    return res


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



def _run_code_searcher(args: dict) -> str:
    query = args.get("query")
    if not query:
        return "Error: 'query' is required for code-searcher"
    
    system_prompt = """You are a code-searcher agent. 
Your job is to translate a user's natural language request into a Linux `grep` or `ripgrep` command to locate the relevant code within files, execute it, and return the findings."""
    
    llm = get_llm()
    prompt = f"Generate ONLY a single bash command (grep or rg) to find code matching this query: '{query}'. Do not use formatting like ```bash. Just output the command. Search recursively in the current directory."
    
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=prompt)
    ])
    
    command = response.content.strip()
    if command.startswith("```"):
        lines = command.split("\n")
        command = lines[1] if len(lines) > 1 else command.replace("```bash", "").replace("```", "")
        
    try:
        p = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=15, start_new_session=True, stdin=subprocess.DEVNULL
        )
        if p.stdout.strip():
            return f"Found code (using command '{command}'):\n{p.stdout.strip()[:4000]}"
        elif p.stderr.strip():
            return f"Error finding code (using command '{command}'):\n{p.stderr.strip()}"
        else:
            return f"No code found matching query using command '{command}'"
    except Exception as e:
        return f"Error executing code-searcher: {e}"


def _run_thinker(args: dict) -> str:
    context = args.get("context", "")
    problem = args.get("problem", "")
    if not problem:
        return "Error: 'problem' is required for thinker"
        
    system_prompt = """You are the Thinker agent.
Your job is to analyze complex problems and codebase context to produce a step-by-step implementation plan.
Wrap your output entirely in <PLAN> and </PLAN> tags.
Do NOT write actual code files, just write the logical steps.
"""
    
    llm = get_llm()
    prompt = f"Context:\n{context}\n\nProblem:\n{problem}\n\nPlease generate a <PLAN>."
    
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=prompt)
    ])
    
    return response.content


def _create_artifact_sync(workspace_path: str, session_id: str, file_path: str, new_content: str, action_type: str = "edit"):
    import difflib
    try:
        from chatbot.models import WorkspaceInfo, AgentArtifact
        ws, _ = WorkspaceInfo.objects.get_or_create(workspace_path=workspace_path)
        abs_path = os.path.join(workspace_path, file_path) if not os.path.isabs(file_path) else file_path
        
        old_content = ""
        if os.path.exists(abs_path):
            try:
                with open(abs_path, 'r', encoding='utf-8') as f:
                    old_content = f.read()
            except Exception:
                pass
                
        diff = ""
        if action_type in ["edit", "create"]:
            try:
                diff_lines = list(difflib.unified_diff(
                    old_content.splitlines(keepends=True),
                    new_content.splitlines(keepends=True),
                    fromfile=f"a/{os.path.basename(abs_path)}",
                    tofile=f"b/{os.path.basename(abs_path)}",
                    n=3
                ))
                diff = "".join(diff_lines)
            except Exception:
                diff = ""
                
        AgentArtifact.objects.create(
            workspace=ws,
            session_id=session_id,
            file_path=file_path,
            action_type=action_type,
            old_content=old_content,
            new_content=new_content,
            diff=diff
        )
    except Exception as e:
        print(f"Error creating artifact synchronously: {e}")

def _run_editor(args: dict) -> str:
    files = args.get("files", [])
    instructions = args.get("instructions", "")
    
    if not files or not instructions:
        return "Error: 'files' and 'instructions' are required for editor"
        
    # Read files to provide to the LLM
    file_contents = ""
    for fpath in files:
        try:
            with open(fpath, "r") as f:
                file_contents += f"--- FILE: {fpath} ---\n{f.read()}\n\n"
        except Exception as e:
            file_contents += f"--- FILE: {fpath} (Error reading: {e}) ---\n\n"
            
    system_prompt = """You are the Editor agent.
Your job is to implement code changes based on the user's instructions.
You must output a JSON array of tool calls matching this schema to edit files.
Return ONLY raw JSON, without markdown blocks.

Schema:
[
  {
    "action": "str_replace",
    "path": "/path/to/file",
    "old_string": "exact string to replace",
    "new_string": "the new string"
  },
  {
    "action": "write_file",
    "path": "/path/to/new_file",
    "content": "full new content"
  }
]
"""
    
    llm = get_llm()
    prompt = f"Target Files:\n{file_contents}\n\nInstructions:\n{instructions}\n\nOutput the JSON array of edits."
    
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=prompt)
    ])
    
    # Process edits
    output = ""
    try:
        content = response.content.strip()
        if content.startswith("```json"):
            content = content[7:-3]
        elif content.startswith("```"):
            content = content[3:-3]
            
        edits = json.loads(content)
        from ..context import current_session_context
        ctx = current_session_context.get()
        workspace_path = ctx.workspace_path if ctx else ""
        session_id = ctx.session_id if ctx else ""

        for edit in edits:
            path = edit.get("path")
            action = edit.get("action")
            
            if action == "write_file":
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
                new_content = edit.get("content", "")
                if workspace_path and session_id:
                    _create_artifact_sync(workspace_path, session_id, path, new_content, "create")
                with open(path, "w") as f:
                    f.write(new_content)
                output += f"Successfully wrote {path}\n"
            elif action == "str_replace":
                old_s = edit.get("old_string", "")
                new_s = edit.get("new_string", "")
                with open(path, "r") as f:
                    file_text = f.read()
                if old_s in file_text:
                    new_content = file_text.replace(old_s, new_s, 1)
                    if workspace_path and session_id:
                        _create_artifact_sync(workspace_path, session_id, path, new_content, "edit")
                    with open(path, "w") as f:
                        f.write(new_content)
                    output += f"Successfully replaced string in {path}\n"
                else:
                    output += f"Failed to find target string in {path}\n"
        return output
    except Exception as e:
        return f"Editor failed to apply changes. LLM Output was: {response.content[:200]}\nError: {e}"


def _run_code_reviewer(args: dict) -> str:
    diff = args.get("diff", "")
    
    system_prompt = """You are the Code Reviewer agent.
Your job is to review the code changes or file contents and provide constructive, critical feedback.
Focus on logic errors, security issues, syntax errors, or missed edge cases.
"""
    
    llm = get_llm()
    prompt = f"Please review the following code changes/state:\n{diff}"
    
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=prompt)
    ])
    
    return response.content


def register_delegation_tools() -> None:
    from .registry import ToolRegistry, ToolMetadata, RiskLevel
    registry = ToolRegistry()
    registry.bulk_register([
        (spawn_subagent, ToolMetadata(
            name="spawn_subagent",
            description="Spawn a specialized sub-agent (basher, file-picker, code-searcher, thinker, editor, or code-reviewer) to perform a task.",
            category="delegation",
            risk_level=RiskLevel.LOW,
            input_schema={"agent_type": "string", "params": "string (JSON)"},
            examples=["spawn_subagent('basher', '{\"command\": \"ls -la\"}')"],
            capabilities=["delegation"],
        ))
    ])
