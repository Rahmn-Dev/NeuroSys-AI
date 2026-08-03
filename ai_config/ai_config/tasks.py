from chatbot.models import AIRecommendation
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
import subprocess
import os
from langchain.llms.base import LLM
from django.conf import settings
from typing import Dict, List, Optional, Any, Mapping
import requests

# Inisialisasi model AI
# llm = OllamaLLM(model="qwen2.5-coder:latest")

OLLAMA_URL = getattr(settings, "OLLAMA_URL")
OLLAMA_MODEL = getattr(settings, "OLLAMA_MODEL")
OLLAMA_API_KEY = getattr(settings, "OLLAMA_API_KEY")
class KantorOllamaLLM(LLM):
    """
    Wrapper khusus untuk connect ke FastAPI Kantor.
    Menggunakan requests biasa agar Header Authorization terjamin terkirim.
    """
    api_url: str
    api_key: str
    model_name: str
    
    @property
    def _llm_type(self) -> str:
        return "kantor_ollama_custom"

    def _call(self, prompt: str, stop: Optional[List[str]] = None, **kwargs: Any) -> str:
        # Header ini PASTI terkirim
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "prompt": prompt,
            "model": self.model_name
        }

        try:
            # Kita paksa URL-nya bersih di sini
            # Hapus trailing slash jika ada
            base = self.api_url.rstrip("/")
            # Pastikan endpointnya benar (sesuai main.py kamu: /api/generate)
            if not base.endswith("/api/generate"):
                endpoint = f"{base}/api/generate"
            else:
                endpoint = base

            print(f"DEBUG: Sending to {endpoint} with Key prefix: {self.api_key[:2]}***") # Debug Log di Terminal Django

            response = requests.post(
                endpoint, 
                json=payload, 
                headers=headers, 
                timeout=120
            )
            
            if response.status_code == 401:
                return "Error 401: Unauthorized. Cek API Key di Django settings."
            
            response.raise_for_status()
            
            # Ambil jawaban dari JSON response FastAPI
            data = response.json()
            return data.get("response", "")
            
        except requests.exceptions.RequestException as e:
            return f"Error connecting to AI Server: {str(e)}"

    @property
    def _identifying_params(self) -> Mapping[str, Any]:
        return {"api_url": self.api_url, "model": self.model_name}
    
llm = KantorOllamaLLM(
    api_url=OLLAMA_URL, 
    api_key=OLLAMA_API_KEY,
    model_name=OLLAMA_MODEL
)


# Template general security analyzer
security_prompt = PromptTemplate.from_template("""
You are a Linux system security assistant.
Analyze the following system log or event and determine if there is any suspicious activity:

{input_data}

If yes, explain what it might be (e.g., brute-force attack, unauthorized access), and recommend one action to mitigate the threat.
""")

# Template general maintenance analyzer
maintenance_prompt = PromptTemplate.from_template("""
You are a Linux system maintenance assistant.
The following information shows the current state of the system:

{input_data}

Identify potential issues that could lead to system instability or performance degradation.
Recommend one specific action to prevent or resolve the issue.
""")


# Buat chains
security_chain = security_prompt | llm | StrOutputParser()
maintenance_chain = maintenance_prompt | llm | StrOutputParser()


# Fungsi baca file log dengan aman
def get_system_info(command):
    try:
        return subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return "[No relevant data found or command failed]"


# Fungsi baca semua log penting di /var/log/
def read_all_logs():
    log_dir = "/var/log"
    log_files = [
        "auth.log", "syslog", "messages", "secure", "faillog",
        "kern.log", "daemon.log", "dmesg", "journal"
    ]

    collected_logs = {}

    for log_file in log_files:
        path = os.path.join(log_dir, log_file)
        if os.path.exists(path):
            try:
                # Baca 20 baris terakhir saja untuk efisiensi
                output = subprocess.check_output(
                    f"tail -n 20 {path}", shell=True, text=True, stderr=subprocess.DEVNULL
                )
                collected_logs[log_file] = output
            except subprocess.CalledProcessError:
                collected_logs[log_file] = "[Empty or unreadable]"
        else:
            collected_logs[log_file] = "[Not found]"

    return collected_logs


# Jalankan analisis keamanan dan pemeliharaan
def analyze_general_and_save():
    print("🔍 Membaca log sistem...\n")
    logs = read_all_logs()

    print("\n--- Security Analysis ---")
    for filename, content in logs.items():
        if content and "[not found]" not in content.lower() and "[empty]" not in content.lower():
            print(f"\n📄 Analisis log: {filename}")
            result = security_chain.invoke({"log_data": content})
            print(result)

            # Simpan ke database
            AIRecommendation.objects.create(
                category="security",
                title=f"Security Alert: {filename}",
                description=content[:200],
                recommendation=result
            )

    print("\n--- Maintenance Analysis ---")
    print("\n📊 Memeriksa penggunaan disk...")
    disk_usage = get_system_info("df -h")
    result = maintenance_chain.invoke({"input_data": disk_usage})
    print(result)
    AIRecommendation.objects.create(
        category="maintenance",
        title="Disk Usage Status",
        description=disk_usage[:200],
        recommendation=result
    )

    print("\n📊 Memeriksa status service yang gagal...")
    failed_services = get_system_info("systemctl list-units --failed")
    result = maintenance_chain.invoke({"input_data": failed_services})
    print(result)
    AIRecommendation.objects.create(
        category="maintenance",
        title="Failed Services Check",
        description=failed_services[:200],
        recommendation=result
    )

    print("\n📊 Memeriksa penggunaan CPU & RAM...")
    cpu_mem = get_system_info("top -n 1 -b")
    result = maintenance_chain.invoke({"input_data": cpu_mem})
    print(result)
    AIRecommendation.objects.create(
        category="maintenance",
        title="CPU & Memory Status",
        description=cpu_mem[:200],
        recommendation=result
    )