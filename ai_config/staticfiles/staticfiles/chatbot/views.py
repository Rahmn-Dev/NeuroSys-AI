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

# Setup logging folder
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "app.log")
SUBPROCESS_LOG_FILE = os.path.join(LOG_DIR, "subprocess.log")
AI_RESPONSE_LOG_FILE = os.path.join(LOG_DIR, "ai_response.log")

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
        "model": "codellama:7b",
        "prompt": f"""
        You are an expert Linux automation AI. 
        Extract and return ONLY a JSON array of the necessary Linux commands 
        to fulfill the user's request. Do NOT include explanations, just return the JSON array.
        
        User request: '{prompt}'
        """,
        "stream": False
    }

    response = requests.post(OLLAMA_URL, json=ollama_payload)
    log_to_file(AI_RESPONSE_LOG_FILE, f"AI Raw Response: {response.text}")
    
    if response.status_code == 200:
        raw_response = response.json().get("response", "[]").strip()
        try:
            command_list = json.loads(raw_response)
            if isinstance(command_list, list):
                return command_list
        except json.JSONDecodeError:
            logger.error("AI response is not valid JSON")
    return []

def execute_linux_command(command):
    try:
        process = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = process.stdout if process.stdout else process.stderr
        log_to_file(SUBPROCESS_LOG_FILE, f"Command: {command}\nOutput: {output}")
        return output, "subprocess"
    except Exception as e:
        return f"Error executing command: {str(e)}", "error"

@api_view(['POST'])
def chat_with_ai(request):
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
            
            if extracted_commands:
                for cmd in extracted_commands:
                    logger.info(f"Executing command: {cmd}")
                    output, source = execute_linux_command(cmd)
                    executed_commands.append(cmd)
                    responses.append({"command": cmd, "output": output})
            
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
                "model": "codellama:7b",
                "prompt": ai_response_prompt,
                "stream": False
            }).json().get("response", "")

            return Response({
                "response": responses,
                "executed_commands": executed_commands,
                "ai_response": ai_summary
            })
        
        except Exception as e:
            logger.error(f"Error saat memproses permintaan: {e}")
            return Response({"error": f"Gagal memproses permintaan: {str(e)}"}, status=500)

@api_view(['GET'])
def system_status(request):
    status = {
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "uptime": psutil.boot_time()
    }
    return Response(status)
