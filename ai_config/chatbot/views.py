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
from django.http import JsonResponse
from django.shortcuts import render

@api_view(['GET'])
def system_status(request):
    status = {
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "uptime": psutil.boot_time()
    }
    return Response(status)


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

