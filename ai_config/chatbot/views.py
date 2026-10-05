import logging
import requests
import subprocess
import json
import psutil
import os
from datetime import datetime
from rest_framework.decorators import api_view
from rest_framework.decorators import permission_classes
from rest_framework import permissions
from rest_framework.response import Response
from datasets import load_dataset
import ansible_runner
import re
from django.http import JsonResponse
from django.shortcuts import render
from django.conf import settings
@api_view(['GET'])
def system_status(request):
    status = {
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "uptime": psutil.boot_time()
    }
    return Response(status)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@api_view(['GET'])
def agent_runs_active(request):
    """Every still-running agent run of this user, for the live history sidebar.

    Lets any chat see that another chat is executing right now, without having
    witnessed its events. Terminal states are excluded; a finished run is
    announced by its own events instead.
    """
    from .models import AgentRun
    terminal = ['completed', 'failed', 'cancelled', 'denied', 'denied_timeout',
                'security_blocked', 'blocked', 'error', 'finalized']
    try:
        user_id = str(request.user.pk)
    except Exception:
        user_id = 'anonymous'
    runs = (AgentRun.objects.filter(user_id=user_id).exclude(status__in=terminal)
            .order_by('-updated_at')[:20])
    return Response({'runs': [{
        'session_id': str(r.session_id),
        'status': r.status,
        'goal': (r.goal or '')[:120],
        'current_node': r.current_node or '',
        'updated_at': r.updated_at.isoformat(),
    } for r in runs]})


def agent_run_snapshot(request):
    """Return only the authenticated user's durable run state for rehydration."""
    from .models import AgentRun, AgentApproval, ChatMessage
    from django.utils import timezone
    session_id = request.GET.get('session_id')
    if not session_id:
        return Response({'run': None, 'messages': [], 'reason': 'session_id required'}, status=400)
    from sre_agent.canonical_lifecycle import expire_abandoned_runs
    expire_abandoned_runs(session_id, request.user.pk)
    run = AgentRun.objects.filter(session_id=session_id).order_by('-updated_at').first()
    if not run:
        return Response({'run': None, 'messages': [], 'server_time': timezone.now().isoformat()})
    if str(run.user_id) != str(request.user.pk):
        return Response({'error': 'run ownership mismatch'}, status=403)
    now = timezone.now()
    messages = [{'id': str(m.id), 'role': m.role, 'sender': m.sender, 'content': m.message,
                 'created_at': m.created_at.isoformat()}
                for m in reversed(list(ChatMessage.objects.filter(session_id=session_id).order_by('-created_at')[:100]))]
    pending = AgentApproval.objects.filter(session_id=str(session_id), user_id=str(request.user.pk), status='pending').order_by('-created_at').first()
    approval = None
    if pending and pending.expires_at <= now:
        from sre_agent.approvals import expire
        from sre_agent.canonical_lifecycle import DurableAgentLifecycle
        try:
            pending = expire(pending.pk, session_id=str(session_id), user_id=str(request.user.pk))
        except PermissionError:
            pending.refresh_from_db()
        if pending.status == 'denied_timeout' and run.status == 'awaiting_approval':
            lifecycle = DurableAgentLifecycle(session_id=str(session_id), user_id=str(request.user.pk))
            lifecycle.run = run
            run = lifecycle.transition('approval', 'blocked', 'denied_timeout', {'approval_status': 'denied_timeout'})
        if pending.status != 'pending':
            pending = None
    if pending:
        approval = {'id': pending.pk, 'request_id': pending.request_id, 'tool': pending.tool_name,
                    'args': pending.arguments_preview, 'risk': pending.risk, 'reason': pending.reason,
                    'status': pending.status, 'expires_at': pending.expires_at.isoformat(),
                    'expires_in': max(0, int((pending.expires_at - now).total_seconds()))}
    events = list(run.transitions.order_by('-sequence').values(
        'sequence', 'node', 'from_status', 'to_status', 'event_type', 'payload', 'correlation_id', 'created_at')[:50])
    for event in events:
        event['created_at'] = event['created_at'].isoformat()
    return Response({'run': {'id': run.pk, 'session_id': str(run.session_id), 'status': run.status,
                             'goal': run.goal, 'summary': run.summary, 'provider': run.provider,
                             'model': run.model, 'mode': run.mode, 'current_node': run.current_node,
                             'checkpoint_version': run.checkpoint_version, 'state': run.state,
                             'budget': run.budget, 'updated_at': run.updated_at.isoformat(),
                             'tasks': list(run.tasks.order_by('created_at').values(
                                 'task_key', 'title', 'description', 'status', 'dependencies',
                                 'required_capability', 'selected_tool', 'attempts', 'evidence', 'findings')),
                             'events': events, 'pending_approval': approval},
                    'messages': messages, 'server_time': now.isoformat()})


# Setup logging folder
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "app.log")
SUBPROCESS_LOG_FILE = os.path.join(LOG_DIR, "subprocess.log")
AI_RESPONSE_LOG_FILE = os.path.join(LOG_DIR, "ai_response.log")
ANSIBLE_CONFIG_DIR = os.path.join(LOG_DIR, "ansible_config")

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

OLLAMA_URL = getattr(settings, "OLLAMA_URL")


# ds = load_dataset("mrheinen/linux-commands")
DATASET_PATH = os.path.join(os.path.dirname(__file__), "../dataset/ds.json")
with open(DATASET_PATH, "r") as f:
    data = json.load(f)

# command_dict = {entry["input"]: entry["output"] for entry in ds["train"]}
# command_dict = {entry["input"]: entry["output"] for entry in data}


def log_to_file(filename, message):
    with open(filename, "a") as f:
        f.write(f"{datetime.now()} - {message}\n")

def extract_commands_from_ai(prompt):
    ollama_payload = {
        "model": "qwen2.5-coder:latest",
        "prompt": f"""
            You are an expert Linux automation AI specializing in generating valid Linux commands. 
            Extract and return ONLY a valid JSON array of Linux commands that fulfill the user's request.
            - Return only a JSON array with no Markdown formatting.
            - Do NOT include explanations, descriptions, or any additional text.
            - Ensure the output is a valid JSON array without wrapping it inside a Markdown block.
            
            User request: '{prompt}'
            
            Example Output:
            ["ls", "pwd", "whoami"]
        """,
        "stream": False  # ✅ Streaming mode enabled
    }

    response = requests.post(OLLAMA_URL, json=ollama_payload, stream=False)
    try:
        response_json = response.json()
        raw_response = response_json.get("response", "")

        # ✅ Remove Markdown code block if present
        match = re.search(r"```json\n(.*?)\n```", raw_response, re.DOTALL)
        if match:
            raw_response = match.group(1)

        log_to_file(AI_RESPONSE_LOG_FILE, f"AI Raw Response: {raw_response}")

        # ✅ Attempt to parse as JSON
        try:
            command_list = json.loads(raw_response)
            if isinstance(command_list, list):
                return command_list
            else:
                raise ValueError("Response is not a JSON array")
        except json.JSONDecodeError:
            # Fallback: Try parsing as plain text (e.g., commands separated by newlines)
            command_list = [cmd.strip() for cmd in raw_response.split("\n") if cmd.strip()]
            return command_list

    except Exception as e:
        logging.error(f"Error processing AI response: {e}")
        logging.error(f"Raw AI Response: {raw_response}")

    return []


# def extract_commands_from_ai(prompt):
#     ollama_payload = {
#         "model": "codellama:7b",
#         "prompt": f"""
#         You are an expert Linux automation AI commands. 
#         Extract and return ONLY a JSON array of valid Linux commands to fulfill the user's request.
#         Do NOT include explanations, descriptions. just return the JSON array base on user's request.
#         User request: '{prompt}'
        
#         """,
#         "stream": True  # ✅ Streaming mode enabled
#     }

#     response = requests.post(OLLAMA_URL, json=ollama_payload, stream=True)

#     raw_response = ""
    
#     # ✅ Read streaming response line by line
#     for line in response.iter_lines():
#         if line:
#             try:
#                 json_line = json.loads(line.decode("utf-8"))  # ✅ Decode JSON chunk
#                 raw_response += json_line.get("response", "")
#             except json.JSONDecodeError:
#                 logger.error("Received invalid JSON chunk from AI")
#                 continue

#     log_to_file(AI_RESPONSE_LOG_FILE, f"AI Raw Response: {raw_response}")

#     # ✅ Ensure raw_response contains valid JSON before parsing
#     try:
#         command_list = json.loads(raw_response.strip())
#         if isinstance(command_list, list):
#             return command_list
#     except json.JSONDecodeError:
#         logger.error("AI response is not valid JSON")

#     return []

FORBIDDEN_COMMANDS = ["rm", "rmdir", "unlink", "truncate", "shred", "wipe", "dd if=/dev", "mkfs", "chmod 000"]

def is_dangerous_command(command):
    """ Check if a command contains a forbidden deletion operation """
    return any(forbidden in command for forbidden in FORBIDDEN_COMMANDS)

def generate_ansible_playbook(prompt):
    ollama_payload = {
        "model": "qwen2.5-coder:latest",
        "prompt": f"""
        You are an expert Ansible AI.
        Generate a valid Ansible playbook in YAML format for the following request:
        {prompt}
        Ensure the playbook is well-structured and follows Ansible best practices.
        Example Output:
        ---
        - name: Configure firewall and SSH rules
          hosts: all
          tasks:
            - name: Block port 80 in firewall
              ufw:
                rule: deny
                port: 80
                proto: tcp
        """,
        "stream": False
    }
    response = requests.post(OLLAMA_URL, json=ollama_payload)
    if response.status_code == 200:
        raw_response = response.json().get("response", "")
        # Validate YAML structure
        try:
            import yaml
            playbook_content = yaml.safe_load(raw_response)
            if not isinstance(playbook_content, list):  # Playbook must be a list of plays
                raise ValueError("Generated playbook is not a valid YAML list")
            return raw_response
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML generated by AI: {e}")
            return ""
    return ""

def save_ansible_playbook(playbook_content, filename):
    playbook_path = os.path.join(ANSIBLE_CONFIG_DIR, filename)
    try:
        with open(playbook_path, "w") as f:
            f.write(playbook_content)
        logger.info(f"Ansible playbook saved to {playbook_path}")
        return playbook_path
    except Exception as e:
        logger.error(f"Failed to save Ansible playbook: {str(e)}")
        return None

def execute_ansible_playbook(playbook_path):
    try:
        result = ansible_runner.run(
            private_data_dir=".",  # Direktori kerja Ansible
            playbook=playbook_path
        )
        if result.rc == 0:
            logger.info(f"Ansible playbook executed successfully: {result.stdout}")
            return result.stdout
        else:
            logger.error(f"Ansible playbook failed: {result.stderr}")
            return result.stderr
    except Exception as e:
        logger.error(f"Error executing Ansible playbook: {str(e)}")
        return f"Error executing Ansible playbook: {str(e)}"

def execute_linux_command(command):
    if is_dangerous_command(command):
        logger.warning(f"Blocked dangerous command: {command}")
        log_to_file(SUBPROCESS_LOG_FILE, f"Blocked Command Attempt: {command}")
        return f"Permission required for command: {command}", "blocked"
    
    try:
        process = subprocess.run(command, shell=False, text=True, capture_output=True)
        output = process.stdout if process.stdout else process.stderr
        log_to_file(SUBPROCESS_LOG_FILE, f"Command: {command}\nOutput: {output}")
        return output, "subprocess"
    except Exception as e:
        return f"Error executing command: {str(e)}", "error"
    

def execute_linux_command_with_ansible(command):
    """ Menggunakan Ansible untuk mengeksekusi perintah """
    if is_dangerous_command(command):
        logger.warning(f"Blocked dangerous command: {command}")
        return f"Blocked Command: {command}", "blocked"

    try:
        # Jalankan command dengan Ansible Runner
        result = ansible_runner.run(
            private_data_dir=".",
            host_pattern="localhost",
            module="command",
            module_args=command  # ✅ Correct way to pass the command
        ) 
        # Parsing hasil eksekusi
        if result.rc == 0:
            output = result.stdout
        else:
            output = result.stderr
        
        return output, "ansible"
    except Exception as e:
        return f"Error executing command with Ansible: {str(e)}", "error"

# @api_view(['POST'])
# def chat_with_ai(request):
#     """ Endpoint untuk mengelola chat dan eksekusi perintah """
#     if request.method == 'POST':
#         try:
#             data = request.data
#             user_prompt = data.get("prompt", "").strip()
#             if not user_prompt:
#                 return Response({"error": "Prompt tidak boleh kosong"}, status=400)

#             logger.info(f"User prompt: {user_prompt}")
#             extracted_commands = extract_commands_from_ai(user_prompt)

#             responses = []
#             executed_commands = []
#             blocked_commands = []

#             if extracted_commands:
#                 for cmd in extracted_commands:
#                     if is_dangerous_command(cmd):
#                         blocked_commands.append(cmd)
#                         responses.append({"command": cmd, "output": "Permission required", "status": "blocked"})
#                     else:
#                         logger.info(f"Executing command : {cmd}")
#                         output, source = execute_linux_command(cmd)
#                         executed_commands.append(cmd)
#                         responses.append({"command": cmd, "output": output, "status": source})

#             # **Tambahkan hasil eksekusi command ke dalam prompt AI**
#             command_output_text = "\n".join(
#                 [f"Command: {r['command']}\nOutput: {r['output']}" for r in responses]
#             )

#             ai_response_prompt = f"""
#             You are an expert Linux automation AI. 
#             User requested: '{user_prompt}'
#             Commands executed and outputs:
#             {command_output_text}
#             Provide a clear response based on the outputs.
#             """

#             ai_summary = requests.post(OLLAMA_URL, json={
#                 "model": "qwen2.5-coder:latest",
#                 "prompt": ai_response_prompt,
#                 "stream": False
#             }).json().get("response", "")

#             return Response({
#                 "response": responses,
#                 "executed_commands": executed_commands,
#                 "blocked_commands": blocked_commands,
#                 "ai_response": ai_summary
#             })

#         except Exception as e:
#             logger.error(f"Error saat memproses permintaan: {e}")
#             return Response({"error": f"Gagal memproses permintaan: {str(e)}"}, status=500)
        
# @api_view(['POST'])
# def chat_with_ai(request):
#     if request.method == 'POST':
#         try:
#             data = request.data
#             user_prompt = data.get("prompt", "").strip()
#             if not user_prompt:
#                 return Response({"error": "Prompt tidak boleh kosong"}, status=400)

#             logger.info(f"User prompt: {user_prompt}")

#             if "install" in user_prompt.lower() or "configure" in user_prompt.lower():
#                 playbook_content = generate_ansible_playbook(user_prompt)
#                 if not playbook_content.strip():
#                     return Response({"error": "Failed to generate Ansible playbook"}, status=500)
                
#                 filename = f"playbook_{datetime.now().strftime('%Y%m%d%H%M%S')}.yml"
#                 playbook_path = save_ansible_playbook(playbook_content, filename)
#                 execution_output = execute_ansible_playbook(playbook_path)
                
#                 return Response({
#                     "message": "Ansible playbook executed successfully",
#                     "playbook_path": playbook_path,
#                     "execution_output": execution_output
#                 })
            
#             return Response({"error": "No valid operation detected in the prompt"})
        
#         except Exception as e:
#             logger.error(f"Error processing request: {e}")
#             return Response({"error": f"Gagal memproses permintaan: {str(e)}"}, status=500)

def parse_user_input(prompt):
    # Escape special characters in the prompt
    safe_prompt = json.dumps(prompt)[1:-1]  # Remove surrounding quotes added by json.dumps

    ollama_payload = {
        "model": "qwen2.5-coder:latest",
        "prompt": f"""
            You are an expert Linux administrator AI.
            Analyze the following user request and break it into a series of steps:
            '{safe_prompt}'
            Return the steps as a JSON array of objects, where each object contains:
            - "description": A brief description of the step.
            - "command": The Linux command to execute.
            Example Output:
            [
                {{"description": "Check disk usage", "command": "df -h"}},
                {{"description": "Identify partitions over 80% full", "command": "df -h | awk '$5 > 80'"}},
                {{"description": "Notify user of high usage", "command": "echo 'High disk usage detected'"}}
            ]
        """,
        "stream": False
    }
    response = requests.post(OLLAMA_URL, json=ollama_payload)
    if response.status_code == 200:
        try:
            raw_response = response.json().get("response", "")
            
            # Remove Markdown formatting if present
            match = re.search(r"```json(.*?)```", raw_response, re.DOTALL)
            if match:
                raw_response = match.group(1).strip()
            
            # Attempt to parse as JSON
            try:
                steps = json.loads(raw_response)
                if isinstance(steps, list) and all(isinstance(step, dict) and "description" in step and "command" in step for step in steps):
                    return steps
                else:
                    raise ValueError("Parsed JSON is not a list of valid step objects")
            except json.JSONDecodeError:
                logger.error(f"AI response is not valid JSON: {raw_response}")
                return []
        except Exception as e:
            logger.error(f"Error processing AI response: {e}")
    return []
def verify_with_ai(command, output):
    """Verify the success of a command using AI."""
    # Escape special characters in command and output
    safe_command = json.dumps(command)[1:-1]
    safe_output = json.dumps(output)[1:-1]

    if "inactive (dead)" in output.lower():
        return True
    logger.info(command)
    ollama_payload = {
        "model": "qwen2.5-coder:latest",
        "prompt": f"""
            You are an expert Linux automation AI.
            Analyze the following command and its output to determine if the task was successful:
            Command: {safe_command}
            Output: {safe_output}
            If the output indicates that the service is 'inactive (dead)' but was stopped successfully,Return only one word: "True".
            Otherwise,Return only one word: "True" if the task was successful, and "False" if it failed. No explanation.
        """,
        "stream": False
    }
    response = requests.post(OLLAMA_URL, json=ollama_payload)
    if response.status_code == 200:
        ai_response = response.json().get("response", "").strip()
        logger.info(f"dia status 200 dengan response {ai_response}")
        return ai_response.lower() == "true"
    else :
        return False

def execute_step(step):
    description = step.get("description", "")
    command = step.get("command", "").strip()
    
    if not command:
        return {"status": "error", "message": "Empty command"}
    
    try:
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = process.stdout if process.stdout else process.stderr
        success = process.returncode in [0, 3]
        
        
        # Log the result
        log_to_file(SUBPROCESS_LOG_FILE, f"Step: {description}\nCommand: {command}\nOutput: {output}")
        
        # Check if the output indicates a password prompt
        # if "[sudo] password for" in output or "password is required" in output.lower():
        if any(keyword in output.lower() for keyword in ["[sudo] password for", "password is required", "authentication required"]):
            return {
                "status": "pending",
                "message": "Password is required to proceed. Please enter your password.",
                "requires_input": True,  # Set requires_input to True
                "input_type": "password"
            }
        if "Do you want to continue?" in output:
            return {
                "status": "pending",
                "message": "User confirmation (Y/N) is required.",
                "requires_input": True,
                "input_type": "confirmation"
            }

        # Verify the result using AI
        verification_result_ai = verify_with_ai(command, output)
        logger.info(f"hasil verifikasi AI: {verification_result_ai} dengan command {command} dan output {output}")
        return {
            "status": "success" if success and verification_result_ai else "error",
            "message": output,
            "verification": verification_result_ai
        }
    except Exception as e:
        log_to_file(SUBPROCESS_LOG_FILE, f"Error executing step: {description}\nError: {str(e)}")
        return {"status": "error", "message": str(e)}

import pexpect
import subprocess
import pexpect
import subprocess

def execute_step_with_input(step, additional_input):
    description = step.get("description", "")
    command = step.get("command", "").strip()
    logger.info(f"Executing step : {additional_input}")

    if not command:
        logger.info("Empty command")
        return {"status": "error", "message": "Empty command"}

    try:
        # Use `sudo -S` to accept password from stdin
        full_command = f"echo '{additional_input}' | sudo -S {command}"
        logger.info(f"Running command: {full_command}")

        # Execute the command using subprocess
        process = subprocess.run(
            full_command,
            shell=True,
            capture_output=True,
            text=True
        )

        output = process.stdout if process.stdout else process.stderr
        success = process.returncode in [0, 3]
        
        logger.info(f"Command output: {output}")

        return {
            "status": "success" if success else "error",
            "message": output
        }
    except Exception as e:
        logger.error(f"Error executing step: {description}\nError: {str(e)}")
        return {"status": "error", "message": str(e)}

@api_view(['POST'])
def chat_with_ai(request):
    if request.method == 'POST':
        try:
            data = request.data
            user_prompt = data.get("prompt", "").strip()
            additional_input = data.get("additional_input", None)
            step_id = data.get("step_id")
            if not user_prompt:
                return Response({"error": "Prompt tidak boleh kosong"}, status=400)
            
            logger.info(f"User prompt: {user_prompt}")
            # If additional input is provided, append it to the prompt
            # if additional_input:
                # user_prompt += f"\nAdditional Input: {additional_input}"
            
            if not additional_input:
                logger.info("Additional input is required but not provided.")
            # Parse the user input into steps
            steps = parse_user_input(user_prompt)
            logger.info(f"Parsed steps: {steps}")
            if not steps:
                return Response({"error": "Failed to parse user input"}, status=500)
            
            responses = []
            print(additional_input)
            for step in steps:
                if additional_input:
                    logger.info("Executing step with additional input")
                    result = execute_step_with_input(step, additional_input)
                    step["requires_input"] = False  # Reset requires_input after processing
                else:
                    logger.info("Executing step without additional input")
                    result = execute_step(step)
                    
                responses.append({
                    "step": step.get("description"),
                    "command": step.get("command"),
                    # "verification": result["verification"],
                    "status": result["status"],
                    "message": result["message"],
                    "requires_input": result.get("requires_input", False),  # Tambahkan ini
                    "input_type": result.get("input_type", None)
                })
                if result.get("requires_input"):
                    return Response({
                        "message": "Task requires additional input",
                        "responses": responses
                    }, status=200)
                
                # Stop execution if any step fails
                if result["status"] != "success":
                    return Response({
                        "message": "Task failed at a step",
                        "responses": responses
                    }, status=200)
            
            # All steps completed successfully
            print(responses)
            return Response({
                "message": "Task completed successfully",
                "responses": responses
            })
        
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return Response({"error": f"Gagal memproses permintaan: {str(e)}"}, status=500)

# --- Workspace & Artifacts APIs ---

@api_view(['GET'])
def workspace_tree_api(request):
    """Returns a basic file tree. If path is provided, loads that directory's children (depth=1)."""
    import os
    base_dir = os.path.dirname(os.path.abspath(__file__)) 
    project_dir = os.path.dirname(base_dir)
    
    target_path = request.GET.get('path')
    if not target_path or not os.path.isdir(target_path):
        target_path = project_dir

    def get_tree_depth1(path):
        tree = []
        try:
            for item in os.listdir(path):
                if item in ['.git', '__pycache__', 'logs', 'db.sqlite3', '.env']:
                    continue
                item_path = os.path.join(path, item)
                is_dir = os.path.isdir(item_path)
                
                # Check if directory has children for lazy loading indicator
                has_children = False
                if is_dir:
                    try:
                        has_children = len(os.listdir(item_path)) > 0
                    except:
                        pass
                        
                tree.append({
                    "name": item,
                    "path": item_path,
                    "type": "directory" if is_dir else "file",
                    "has_children": has_children,
                    "children": [] # Lazy loaded by UI
                })
        except Exception:
            pass
        return sorted(tree, key=lambda x: (x['type'] != 'directory', x['name']))
        
    return Response(get_tree_depth1(target_path))

@api_view(['GET'])
def workspace_file_api(request):
    """Returns the content of a file."""
    import os
    file_path = request.GET.get('path', '')
    if not file_path:
        return Response({"error": "Path required"}, status=400)
        
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    full_path = os.path.abspath(os.path.join(base_dir, file_path))
    
    if not full_path.startswith(base_dir):
        return Response({"error": "Invalid path"}, status=403)
        
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return Response({"content": content})
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(['GET'])
def artifact_list_api(request):
    """Returns a list of artifacts."""
    from chatbot.models import AgentArtifact
    from django.db.models import Q
    
    session_id = request.GET.get('session_id')
    if not session_id:
        return Response([])
        
    artifacts = AgentArtifact.objects.filter(
        Q(session_id=session_id) | Q(file_path__icontains=session_id)
    ).exclude(action_type="active_state").order_by('-created_at')[:200]

    # Titles let the UI label each group with the case that produced it.
    from chatbot.models import Investigation
    case_ids = {a.case_id for a in artifacts if a.case_id}
    titles = dict(
        Investigation.objects.filter(id__in=case_ids).values_list('id', 'title')
    ) if case_ids else {}

    data = []
    for a in artifacts:
        diff_text = a.diff or ""
        added = sum(1 for line in diff_text.splitlines() if line.startswith('+') and not line.startswith('+++'))
        removed = sum(1 for line in diff_text.splitlines() if line.startswith('-') and not line.startswith('---'))
        data.append({
            "id": a.id,
            "file_path": a.file_path,
            "action_type": a.action_type,
            "case_id": a.case_id or "",
            "case_title": titles.get(a.case_id, "") if a.case_id else "",
            "diff": diff_text,
            "has_diff": bool(diff_text.strip()),
            "added": added,
            "removed": removed,
            "old_content": a.old_content,
            "new_content": a.new_content,
            "created_at": a.created_at.isoformat()
        })
    return Response(data)

@api_view(['POST'])
def artifact_rollback_api(request, artifact_id):
    """Rollbacks an artifact."""
    from sre_agent.artifacts import ArtifactManager
    from chatbot.models import WorkspaceInfo
    
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Needs to be async compatible or use async_to_sync
        from asgiref.sync import async_to_sync
        manager = ArtifactManager(workspace_path=base_dir)
        success = async_to_sync(manager.rollback)(artifact_id)
        if success:
            return Response({"status": "success"})
        return Response({"error": "Rollback failed"}, status=500)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

from django.views.decorators.csrf import csrf_exempt
from chatbot.models import AIModel

DEFAULT_AI_MODELS = [
    {"name": "OpenCode Provider (9Router)", "model_id": "OPENCODE", "provider": "9router", "order": 1},
    {"name": "Groq Provider (9Router)", "model_id": "GROQ", "provider": "9router", "order": 2},
    {"name": "Mistral Large", "model_id": "mistral-large-latest", "provider": "mistral", "order": 3},
    {"name": "Local Mistral (Ollama)", "model_id": "mistral:latest", "provider": "ollama", "order": 4},
    {"name": "Local Qwen2.5 Coder (Ollama)", "model_id": "qwen2.5-coder:latest", "provider": "ollama", "order": 5},

]


def seed_default_ai_models():
    if AIModel.objects.count() == 0:
        for item in DEFAULT_AI_MODELS:
            AIModel.objects.create(**item)

@csrf_exempt
def ai_models_api(request):
    if request.method == 'GET':
        seed_default_ai_models()
        models = AIModel.objects.all().order_by('order', 'id')
        def rotation_group(model):
            provider = (model.provider or '').lower().strip()
            base_url = (model.base_url or '').strip().rstrip('/')
            endpoint_type = (getattr(model, 'endpoint_type', None) or 'openai').lower().strip()
            if endpoint_type == 'anthropic' and not base_url:
                return 'anthropic:official'
            if provider == 'ollama':
                return f"ollama:{base_url or 'default'}"
            if provider == 'mistral' and not base_url:
                return 'mistral:official'
            if provider == 'openai' and not base_url:
                return 'openai:official'
            if provider == 'groq' and model.api_key and not base_url:
                return 'groq:official'
            return f"openai_compatible:{base_url or 'http://localhost:20128/v1'}"

        data = [
            {
                'id': m.id,
                'name': m.name,
                'model_id': m.model_id,
                'provider': m.provider,
                'endpoint_type': getattr(m, 'endpoint_type', 'openai') or 'openai',
                'base_url': m.base_url or '',
                'api_key': m.api_key or '',
                # Never the secret itself, just enough for the composer to warn
                # before a run fails with an opaque provider error.
                'has_key': bool(m.api_key),
                'tool_choice': getattr(m, 'tool_choice', 'any') or 'any',
                'is_active': m.is_active,
                'order': m.order,
                'rotation_group': rotation_group(m),
            }
            for m in models
        ]
        return JsonResponse({'status': 'success', 'models': data})
    
    elif request.method == 'POST':
        try:
            payload = json.loads(request.body)
            name = payload.get('name', '').strip()
            model_id = payload.get('model_id', '').strip()
            provider = payload.get('provider', '9router').strip()
            endpoint_type = (payload.get('endpoint_type', 'openai') or 'openai').strip().lower()
            if endpoint_type not in ('openai', 'anthropic'):
                endpoint_type = 'openai'
            base_url = payload.get('base_url', '').strip() or None
            api_key = payload.get('api_key', '').strip() or None
            is_active = payload.get('is_active', True)
            tool_choice = (payload.get('tool_choice') or 'any').strip().lower()
            if tool_choice not in ('any', 'required', 'auto'):
                tool_choice = 'any'
            order = int(payload.get('order', 0))

            if not name or not model_id:
                return JsonResponse({'status': 'error', 'message': 'Name and model_id are required.'}, status=400)

            model_obj = AIModel.objects.create(
                name=name,
                model_id=model_id,
                provider=provider,
                endpoint_type=endpoint_type,
                base_url=base_url,
                api_key=api_key,
                tool_choice=tool_choice,
                is_active=is_active,
                order=order
            )
            return JsonResponse({
                'status': 'success',
                'model': {
                    'id': model_obj.id,
                    'name': model_obj.name,
                    'model_id': model_obj.model_id,
                    'provider': model_obj.provider,
                'endpoint_type': getattr(model_obj, 'endpoint_type', 'openai') or 'openai',
                    'endpoint_type': getattr(model_obj, 'endpoint_type', 'openai') or 'openai',
                    'base_url': model_obj.base_url or '',
                    'api_key': model_obj.api_key or '',
                    'is_active': model_obj.is_active,
                    'order': model_obj.order
                }
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)


@csrf_exempt
def ai_model_detail_api(request, pk):
    try:
        model_obj = AIModel.objects.get(pk=pk)
    except AIModel.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Model not found.'}, status=404)

    if request.method == 'GET':
        return JsonResponse({
            'status': 'success',
            'model': {
                'id': model_obj.id,
                'name': model_obj.name,
                'model_id': model_obj.model_id,
                'provider': model_obj.provider,
                'endpoint_type': getattr(model_obj, 'endpoint_type', 'openai') or 'openai',
                'base_url': model_obj.base_url or '',
                'api_key': model_obj.api_key or '',
                'is_active': model_obj.is_active,
                'order': model_obj.order
            }
        })
    elif request.method == 'PUT':
        try:
            payload = json.loads(request.body)
            model_obj.name = payload.get('name', model_obj.name).strip()
            model_obj.model_id = payload.get('model_id', model_obj.model_id).strip()
            model_obj.provider = payload.get('provider', model_obj.provider).strip()
            if 'endpoint_type' in payload:
                et = (payload.get('endpoint_type') or 'openai').strip().lower()
                model_obj.endpoint_type = et if et in ('openai', 'anthropic') else 'openai'
            model_obj.base_url = payload.get('base_url', model_obj.base_url or '').strip() or None
            if 'api_key' in payload:
                model_obj.api_key = payload['api_key'].strip() or None
            if 'is_active' in payload:
                model_obj.is_active = bool(payload['is_active'])
            if 'tool_choice' in payload:
                tc = (payload.get('tool_choice') or 'any').strip().lower()
                model_obj.tool_choice = tc if tc in ('any', 'required', 'auto') else 'any'
            if 'order' in payload:
                model_obj.order = int(payload['order'])
            model_obj.save()

            return JsonResponse({
                'status': 'success',
                'model': {
                    'id': model_obj.id,
                    'name': model_obj.name,
                    'model_id': model_obj.model_id,
                    'provider': model_obj.provider,
                'endpoint_type': getattr(model_obj, 'endpoint_type', 'openai') or 'openai',
                    'endpoint_type': getattr(model_obj, 'endpoint_type', 'openai') or 'openai',
                    'base_url': model_obj.base_url or '',
                    'api_key': model_obj.api_key or '',
                    'is_active': model_obj.is_active,
                    'order': model_obj.order
                }
            })
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    elif request.method == 'DELETE':
        model_obj.delete()
        return JsonResponse({'status': 'success', 'message': 'Model deleted successfully.'})

    return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)


@csrf_exempt
def ai_model_test_api(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Method not allowed.'}, status=405)

    fetched_models = []
    try:
        payload = json.loads(request.body)
        model_id = payload.get('model_id', '').strip()
        provider = payload.get('provider', '9router').strip().lower()
        base_url = payload.get('base_url', '').strip() or None
        api_key = payload.get('api_key', '').strip() or None

        if not model_id:
            return JsonResponse({'status': 'error', 'message': 'Model ID is required for testing.'}, status=400)

        # Try listing models from GET {base_url}/models if base_url is specified
        target_endpoint = base_url.rstrip('/') if base_url else "http://localhost:20128/v1"
        try:
            headers = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
           
            resp = requests.get(f"{target_endpoint}/models", headers=headers, timeout=4)
            if resp.status_code == 200:
                resp_json = resp.json()
                if isinstance(resp_json, dict) and "data" in resp_json and isinstance(resp_json["data"], list):
                    fetched_models = [m.get("id") for m in resp_json["data"] if isinstance(m, dict) and m.get("id")]
        except Exception:
            pass

        # Try a quick invocation test with LangChain LLM
        from langchain_core.messages import HumanMessage
        from langchain_openai import ChatOpenAI
        from langchain_ollama import ChatOllama
        from langchain_mistralai import ChatMistralAI

        if provider == 'ollama':
            url = base_url or getattr(settings, "OLLAMA_URL", os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
            llm = ChatOllama(model=model_id, base_url=url, temperature=0.1)
        elif provider == 'mistral' and not base_url:
            key = api_key or getattr(settings, "MISTRAL_API_KEY", os.environ.get("MISTRAL_API_KEY", ""))
            llm = ChatMistralAI(model=model_id, mistral_api_key=key, temperature=0.1)
        elif (payload.get('endpoint_type', 'openai') or 'openai').strip().lower() == 'anthropic' and not base_url:
            from langchain_anthropic import ChatAnthropic
            key = api_key or getattr(settings, "ANTHROPIC_API_KEY", os.environ.get("ANTHROPIC_API_KEY", ""))
            if not key:
                return JsonResponse({'status': 'error', 'message': 'Anthropic API key is required.'}, status=400)
            llm = ChatAnthropic(model=model_id, api_key=key, temperature=0.1, max_tokens=10)
        else:
            url = base_url if base_url else "http://localhost:20128/v1"
            key = api_key or os.environ.get("MIMO_API_KEY") or getattr(settings, "ROUTER_API_KEY", os.environ.get("ROUTER_API_KEY", os.environ.get("OPENAI_API_KEY", "9router")))
            llm = ChatOpenAI(model=model_id, base_url=url, api_key=key, temperature=0.1, max_tokens=10)

        res = llm.invoke([HumanMessage(content="hi")])
        reply = res.content if hasattr(res, 'content') else str(res)

        return JsonResponse({
            'status': 'success',
            'message': 'Connection & Model test successful!',
            'reply': str(reply)[:100],
            'available_models': fetched_models
        })
    except Exception as e:
        err_msg = str(e)
        return JsonResponse({
            'status': 'error',
            'message': err_msg,
            'available_models': fetched_models
        }, status=400)
