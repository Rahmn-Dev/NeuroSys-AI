from chatbot.models import AIRecommendation
from langchain_ollama import OllamaLLM
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
import subprocess
import os


# Inisialisasi model AI
llm = OllamaLLM(model="qwen2.5-coder:latest")


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
security_chain = LLMChain(llm=llm, prompt=security_prompt)
maintenance_chain = LLMChain(llm=llm, prompt=maintenance_prompt)


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
            result = security_chain.run(content)
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
    result = maintenance_chain.run(disk_usage)
    print(result)
    AIRecommendation.objects.create(
        category="maintenance",
        title="Disk Usage Status",
        description=disk_usage[:200],
        recommendation=result
    )

    print("\n📊 Memeriksa status service yang gagal...")
    failed_services = get_system_info("systemctl list-units --failed")
    result = maintenance_chain.run(failed_services)
    print(result)
    AIRecommendation.objects.create(
        category="maintenance",
        title="Failed Services Check",
        description=failed_services[:200],
        recommendation=result
    )

    print("\n📊 Memeriksa penggunaan CPU & RAM...")
    cpu_mem = get_system_info("top -n 1 -b")
    result = maintenance_chain.run(cpu_mem)
    print(result)
    AIRecommendation.objects.create(
        category="maintenance",
        title="CPU & Memory Status",
        description=cpu_mem[:200],
        recommendation=result
    )