import logging
import requests
import subprocess
import json
import psutil
import os
from datetime import datetime
from rest_framework.decorators import api_view
from rest_framework.response import Response
from datasets import load_dataset
import ansible_runner
import re

# Setup logging folder
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "app.log")
SUBPROCESS_LOG_FILE = os.path.join(LOG_DIR, "subprocess.log")
AI_RESPONSE_LOG_FILE = os.path.join(LOG_DIR, "ai_response.log")
ANSIBLE_CONFIG_DIR = os.path.join(LOG_DIR, "ansible_config")

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"

ds = load_dataset("mrheinen/linux-commands")
DATASET_PATH = os.path.join(os.path.dirname(__file__), "../dataset/ds.json")
with open(DATASET_PATH, "r") as f:
    data = json.load(f)

command_dict = {entry["input"]: entry["output"] for entry in ds["train"]}
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
        Generate an Ansible playbook YAML file for the following request:
        {prompt}
        """,
        "stream": False
    }
    response = requests.post(OLLAMA_URL, json=ollama_payload)
    if response.status_code == 200:
        return response.json().get("response", "")
    return ""

def save_ansible_playbook(playbook_content, filename):
    playbook_path = os.path.join(ANSIBLE_CONFIG_DIR, filename)
    with open(playbook_path, "w") as f:
        f.write(playbook_content)
    return playbook_path

def execute_ansible_playbook(playbook_path):
    try:
        result = ansible_runner.run(private_data_dir=".", playbook=playbook_path)
        return result.stdout if result.rc == 0 else result.stderr
    except Exception as e:
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

@api_view(['POST'])
def chat_with_ai(request):
    """ Endpoint untuk mengelola chat dan eksekusi perintah """
    if request.method == 'POST':
        try:
            data = request.data
            user_prompt = data.get("prompt", "").strip()
            if not user_prompt:
                return Response({"error": "Prompt tidak boleh kosong"}, status=400)

            logger.info(f"User prompt: {user_prompt}")
            extracted_commands = extract_commands_from_ai(user_prompt)

            responses = []
            executed_commands = []
            blocked_commands = []

            if extracted_commands:
                for cmd in extracted_commands:
                    if is_dangerous_command(cmd):
                        blocked_commands.append(cmd)
                        responses.append({"command": cmd, "output": "Permission required", "status": "blocked"})
                    else:
                        logger.info(f"Executing command : {cmd}")
                        output, source = execute_linux_command(cmd)
                        executed_commands.append(cmd)
                        responses.append({"command": cmd, "output": output, "status": source})

            # **Tambahkan hasil eksekusi command ke dalam prompt AI**
            command_output_text = "\n".join(
                [f"Command: {r['command']}\nOutput: {r['output']}" for r in responses]
            )

            ai_response_prompt = f"""
            You are an expert Linux automation AI. 
            User requested: '{user_prompt}'
            Commands executed and outputs:
            {command_output_text}
            Provide a clear response based on the outputs.
            """

            ai_summary = requests.post(OLLAMA_URL, json={
                "model": "qwen2.5-coder:latest",
                "prompt": ai_response_prompt,
                "stream": False
            }).json().get("response", "")

            return Response({
                "response": responses,
                "executed_commands": executed_commands,
                "blocked_commands": blocked_commands,
                "ai_response": ai_summary
            })

        except Exception as e:
            logger.error(f"Error saat memproses permintaan: {e}")
            return Response({"error": f"Gagal memproses permintaan: {str(e)}"}, status=500)
        
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


@api_view(['GET'])
def system_status(request):
    status = {
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "uptime": psutil.boot_time()
    }
    return Response(status)
