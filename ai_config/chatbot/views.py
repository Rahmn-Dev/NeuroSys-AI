import logging
import requests
import subprocess
from rest_framework.decorators import api_view
from rest_framework.response import Response
import json
import psutil
from datasets import load_dataset

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"

# Load dataset dari Hugging Face
ds = load_dataset("mrheinen/linux-commands")
command_dict = {entry["input"]: entry["output"] for entry in ds["train"]}

def extract_command_from_ai(prompt):
    """
    Menggunakan Ollama untuk memahami apakah prompt mengandung perintah Linux.
    """
    ollama_payload = {
        # "model": "deepseek-r1:7b",
        "model": "llama3.2:latest",
        "prompt": f"Extract the Linux command from this prompt: '{prompt}'. Only return the command, nothing else.",
        "stream": False
    }

    response = requests.post(OLLAMA_URL, json=ollama_payload)
    
    if response.status_code == 200:
        extracted_command = response.json().get("response", "").strip()
        return extracted_command
    return None

def execute_linux_command(command):
    """
    Mengeksekusi perintah Linux menggunakan subprocess.
    """
    try:
        process = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = process.stdout if process.stdout else process.stderr
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

            # Minta Ollama untuk mengekstrak command dari prompt user
            extracted_command = extract_command_from_ai(user_prompt)

            if extracted_command:
                logger.info(f"Extracted command: {extracted_command}")

                # Jalankan command jika valid
                output, source = execute_linux_command(extracted_command)

                return Response({
                    "response": output,
                    "source": source,
                    "executed_command": extracted_command
                })
            
            # Jika tidak ada command, tetap kirim prompt ke AI seperti biasa
            response = requests.post(OLLAMA_URL, json={
                "model": "deepseek-r1:7b",
                "prompt": user_prompt,
                "stream": False
            })

            if response.status_code == 200:
                data = response.json()
                return Response({"response": data.get("response", "Error: No response from AI")})
            else:
                return Response({"error": "Gagal mendapatkan respons dari AI"}, status=500)

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