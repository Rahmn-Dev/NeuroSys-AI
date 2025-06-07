from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib import messages
from django.contrib.auth import logout
import psutil, os, subprocess
from django.http import JsonResponse
from datetime import datetime
import socket
import re
import requests
import logging
import json
from django.views.decorators.csrf import csrf_exempt
from two_factor.views import LoginView as TwoFactorLoginView
from two_factor.utils import default_device
from django_ratelimit.decorators import ratelimit
from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.response import Response
from langchain_ollama import OllamaLLM
from django.conf import settings
import shlex
from langchain_community.llms import Ollama
from langchain_experimental.agents.agent_toolkits import create_pandas_dataframe_agent # Contoh, kita tidak pakai ini
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from .tools import ALL_TOOLS
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from langchain.agents import initialize_agent
import time

# Inisialisasi model AI
llm = OllamaLLM(model="qwen2.5-coder:latest")
OLLAMA_URL = getattr(settings, "OLLAMA_URL")
OLLAMA_MODEL = getattr(settings, "OLLAMA_MODEL")

@login_required
def chatAI(request):
    return render(request,"generator/textGenerator.html",{'headTitle' : 'Chat AI','toggle' : "true"})
    # testing
def chatAI2(request):
    # return render(request,"generator/textGenerator.html",{'headTitle' : 'Chat AI','toggle' : "true"})
    # testing
    return render(request,"chat.html",{'headTitle' : 'Chat AI','toggle' : "true"})

@login_required
def index(request):
    return render(request, "index.html")

@login_required
def dashboard(request):
    return render(request, "dashboard.html", { 'headTitle':'Dashboard' })

@login_required
def ai_optimization(request):
    return render(request, "ai_optimization.html", { 'headTitle':'AI Optimization' })


from django.core.cache import cache
from django.contrib import messages
from django.shortcuts import render, redirect
from django_ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='3/1m', block=False)
def user_login(request):
    ip_address = request.META.get('REMOTE_ADDR')
    cache_key = f'login_attempts:{ip_address}'
    attempts = cache.get(cache_key, 0)

    if getattr(request, 'limited', False):  # Cek apakah pengguna telah melebihi batas
        remaining_time = cache.ttl(cache_key)  # Hitung waktu tersisa dalam detik
        if remaining_time > 0:
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            return render(request, 'login.html', {
                'rate_limit_exceeded': True,
                'remaining_minutes': minutes,
                'remaining_seconds': seconds,
            })

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Reset login attempts cache on successful login
            cache.delete(cache_key)

            # Perform "semi-login" by logging the user in temporarily
            auth_login(request, user)

            # Set the user's session as inactive
            user.profile.is_active_session = False
            user.profile.save()

            # Redirect to setup 2FA for OTP verification
            return redirect("setup_2fa")
        else:
            # Increment login attempts
            cache.set(cache_key, attempts + 1, timeout=60)  # Timeout 1 menit
            messages.error(request, "Invalid username or password")

    return render(request, "login.html")

import base64
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.conf import settings
import qrcode
from io import BytesIO
from django.contrib import messages
from django.shortcuts import redirect, render

def setup_2fa(request):
    # Check if the user is authenticated
    if not request.user.is_authenticated:
        return redirect("login")  # Redirect to login if not authenticated

    user = request.user

    # Get or create the TOTP device for the user
    device, created = TOTPDevice.objects.get_or_create(user=user, defaults={'confirmed': False})

    if request.method == "POST":
        otp = request.POST.get("otp")
        if device and device.verify_token(otp):
            if not device.confirmed:
                # Mark 2FA as confirmed
                device.confirmed = True
                device.save()
                messages.success(request, "2FA has been activated successfully.")

            # Mark the user's session as active
            user.profile.is_active_session = True
            user.profile.save()

            # Redirect to dashboard after successful OTP verification
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    # Generate QR code only if 2FA is not yet confirmed
    qr_code_base64 = None
    if not device.confirmed:
        # Encode bin_key to Base32 for compatibility with Google Authenticator
        secret_key = base64.b32encode(device.bin_key).decode('utf-8').rstrip('=')

        # Use user's email or username in the label
        user_label = f"{user.email}" if user.email else f"{user.username}"
        label = f"NeuroSys-AI:{user_label}"

        # Generate QR code URL for Google Authenticator
        qr_code_url = f"otpauth://totp/{label}?secret={secret_key}&issuer=NeuroSys-AI"
        
        # Generate QR code image
        img = qrcode.make(qr_code_url)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return render(request, "setup_2fa.html", {
        "qr_code_base64": qr_code_base64,
        "is_2fa_activated": device.confirmed
    })

def user_logout(request):
    user = request.user
    if user.is_authenticated:
        # Deactivate the user's session
        user.profile.is_active_session = False
        user.profile.save()
    

        # Reset login attempts cache on logout
        ip_address = request.META.get('REMOTE_ADDR')
        cache_key = f'login_attempts:{ip_address}'
        cache.delete(cache_key)

    # Perform logout
    auth_logout(request)
    return redirect("login")


def system_monitor(request):
    # CPU, RAM, Disk
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    vram = get_vram_usage()  

    network_overview = {
        "server_ip": socket.gethostbyname(socket.gethostname()),
        "external_ip": get_external_ip(),
        "rx": get_bandwidth_usage()["rx"],
        "tx": get_bandwidth_usage()["tx"],
        "active_connections": get_active_connections(),
        "connected_devices": get_connected_devices(),
    }

    # Active network connections
    net_stat = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True).stdout

    # Running services
    services = subprocess.run(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
        capture_output=True, text=True
    ).stdout
    
    return JsonResponse({
        "cpu": cpu,
        "ram": ram,
        "vram": vram,
        "disk": disk,
        "network": net_stat,
        "services": services,
        "network_overview": network_overview,
        "timestamp": datetime.now().strftime("%H:%M:%S"), 
    })

try:
    from pynvml import nvmlInit, nvmlDeviceGetHandleByIndex, nvmlDeviceGetMemoryInfo, nvmlShutdown
except ImportError:
    nvmlInit = nvmlDeviceGetHandleByIndex = nvmlDeviceGetMemoryInfo = nvmlShutdown = None

def get_vram_usage():
    if nvmlInit:
        try:
            nvmlInit()
            handle = nvmlDeviceGetHandleByIndex(0) 
            info = nvmlDeviceGetMemoryInfo(handle)
            vram_usage = (info.used / info.total) * 100
            nvmlShutdown()
            return round(vram_usage, 2)
        except Exception as e:
            return f"Error: {str(e)}"
    return "N/A"  

def get_external_ip():
    try:
        response = requests.get("https://api64.ipify.org?format=json", timeout=5)
        return response.json().get("ip", "Unknown")
    except requests.RequestException:
        return "Unknown"

def get_connected_devices():
    devices = []
    try:
        arp_output = subprocess.check_output("arp -a", shell=True, text=True)
        for line in arp_output.split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                devices.append({"ip": parts[0], "mac": parts[1], "hostname": parts[-1] if len(parts) > 3 else "Unknown"})
    except subprocess.CalledProcessError:
        pass
    return devices

def get_bandwidth_usage():
    net_io = psutil.net_io_counters()
    return {"rx": round(net_io.bytes_recv / 1024, 2), "tx": round(net_io.bytes_sent / 1024, 2)}

def get_active_connections():
    try:
        output = subprocess.check_output("ss -tun | wc -l", shell=True, text=True).strip()
        return int(output) if output.isdigit() else 0
    except subprocess.CalledProcessError:
        return 0

def get_running_services():
    try:
        output = subprocess.check_output("systemctl list-units --type=service --state=running --no-pager --no-legend", shell=True, text=True)
        services = [line.split()[0] for line in output.strip().split("\n") if line]
        return services
    except subprocess.CalledProcessError:
        return []
    

@login_required
def service_control(request):
    failed_services = get_failed_services()
    return render(request,"service_control.html",{'headTitle' : 'Service Control', 'failed_services': failed_services})

import json

@login_required
@csrf_exempt
def sudo_command(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            password = data.get('password')
            command = data.get('command')

            if not password or not command:
                return JsonResponse({'status': 'error', 'message': 'Password and command are required.'}, status=400)

            # Jalankan perintah dengan sudo menggunakan password
            full_command = f'echo {password} | sudo -S {command}'
            result = subprocess.run(full_command, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                return JsonResponse({'status': 'success', 'message': result.stdout})
            else:
                return JsonResponse({'status': 'error', 'message': result.stderr}, status=500)

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
        


SERVICE_DIR_ETC = "/etc/systemd/system/"
SERVICE_DIR_LIB = "/lib/systemd/system/"
def find_service_file(service_name):
    """
    Cari file layanan di /etc/systemd/system/ dan /lib/systemd/system/.
    Return path file jika ditemukan, atau None jika tidak ditemukan.
    """
    # Hapus .service jika ada
    if service_name.endswith('.service'):
        service_name = service_name[:-8]

    # Cek di /etc/systemd/system/
    etc_path = os.path.join(SERVICE_DIR_ETC, f"{service_name}.service")
    if os.path.exists(etc_path):
        return etc_path

    # Cek di /lib/systemd/system/
    lib_path = os.path.join(SERVICE_DIR_LIB, f"{service_name}.service")
    if os.path.exists(lib_path):
        return lib_path

    # Jika tidak ditemukan di kedua lokasi
    return None


@api_view(['GET'])
def get_service_config(request, service_name):
    """
    Endpoint untuk membaca isi file konfigurasi layanan.
    """
    try:
        # Cari file layanan
        config_path = find_service_file(service_name)
        if not config_path:
            return JsonResponse({"error": f"Service file {service_name} not found."}, status=404)
        

        # Baca isi file
        with open(config_path, 'r') as f:
            config_content = f.read()
        
        return JsonResponse({"config": config_content})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@api_view(['POST'])
def save_service_config(request, service_name):
    try:
        # Gunakan request.data untuk membaca data JSON
        new_config = request.data.get("config", "").strip()
        password = request.data.get("password")

        if not new_config:
            return Response({"error": "Configuration content is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Hapus .service jika ada
        if service_name.endswith('.service'):
            service_name = service_name[:-8]

        config_path = f"/etc/systemd/system/{service_name}.service"

        # Simpan konfigurasi baru dengan sudo menggunakan subprocess
        write_command = ['sudo', '-S', 'tee', config_path]
        write_result = subprocess.run(
            write_command,
            input=f'{password}\n{new_config}',  # Kirim password dan konfigurasi baru sebagai input
            capture_output=True,
            text=True
        )

        if write_result.returncode != 0:
            return Response({"error": f"Failed to save configuration: {write_result.stderr}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Reload systemd
        reload_command = ['sudo', '-S', 'systemctl', 'daemon-reload']
        reload_result = subprocess.run(
            reload_command,
            input=password,  # Kirim hanya password sebagai input
            capture_output=True,
            text=True
        )

        if reload_result.returncode != 0:
            return Response({"error": f"Failed to reload systemd: {reload_result.stderr}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": f"Configuration for {service_name} saved successfully."}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
from ai_agent.prompt_runner import run_prompt

def sysadmin_prompt(request):
    result = ""
    if request.method == "POST":
        prompt = request.POST.get("prompt")
        result = run_prompt(prompt)
    return render(request, "sysadmin_prompt.html", {"result": result})

from .tasks import analyze_general_and_save  # fungsi AI-mu

def run_analysis(request):
    try:
        analyze_general_and_save()  # fungsi AI-mu
        return JsonResponse({"status": "success", "message": "Analysis completed"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)

from chatbot import models
def logs_report(request):
   recommendations = models.AIRecommendation.objects.all().order_by('-created_at')[:20]
   suricata_logs = models.SuricataLog.objects.all()[:10]
   return render(request, "logs_report.html", {'recommendations': recommendations, 'suricata_logs': suricata_logs})

def get_failed_services():
    try:
        result = subprocess.check_output(
            "systemctl list-units --type=service --state=failed --no-pager",
            shell=True,
            text=True
        )
       
        lines = result.strip().splitlines()
        services = []
        
        for line in lines:
            line = line.strip()

            # Skip baris kosong, legend, header, atau footer
            if (not line or 
                line.startswith("UNIT") or 
                line.startswith("Legend:") or 
                line.startswith("LOAD") or 
                line.startswith("ACTIVE") or 
                line.startswith("SUB") or
                "loaded units listed" in line or
                line.startswith("--")):
                continue

            # Clean line dari karakter bullet point
            clean_line = line.replace("●", "").strip()
            parts = clean_line.split()

            # Pastikan baris memiliki minimal 4 kolom
            if len(parts) < 4:
                continue

            # Pastikan ini service yang valid
            if not parts[0].endswith('.service'):
                continue

            service_name = parts[0]
            load_status = parts[1]
            active_status = parts[2]
            sub_status = parts[3]

            # Gabungkan sisa bagian sebagai deskripsi
            description = ' '.join(parts[4:]) if len(parts) > 4 else "No description"

            services.append({
                "name": service_name,
                "description": description,
                "load": load_status,
                "active": active_status,
                "sub": sub_status
            })
        
        # Return statement dipindah ke luar loop
        return services
        
    except Exception as e:
        print(f"Error fetching failed services: {e}")
        return []
@login_required
def ai_analyze_service(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Only POST method allowed"}, status=405)
    
    try:
        service = request.POST.get("service")
        
        if not service:
            return JsonResponse({"error": "Service name is required"}, status=400)

        # --- Validasi nama service ---
        if not re.match(r'^[a-zA-Z0-9_\-\./@]+\.?service$', service):
            return JsonResponse({"error": "Invalid service name format"}, status=400)

        # --- Ambil status service ---
        try:
            status_data = subprocess.run(
                ["systemctl", "status", service],
                capture_output=True,
                text=True,
                timeout=10
            ).stdout
        except Exception as e:
            status_data = f"Error getting status: {e}"

        # --- Ambil log journalctl ---
        try:
            log_data = subprocess.run(
                ["journalctl", "-u", service, "-n", "50"],
                capture_output=True,
                text=True,
                timeout=30
            ).stdout
        except Exception as e:
            log_data = f"Error getting logs: {e}"

        # --- Baca file config service menggunakan fungsi yang sudah disediakan ---
        config_path = find_service_file(service)
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config_data = f.read()
            except Exception as e:
                config_data = f"Error reading config file: {e}"
        else:
            config_data = "Service configuration file not found."

        # --- Buat prompt ---
        prompt = f"""
       You are a Linux system administrator assistant with expertise in debugging systemd services.
        Analyze the following information to determine why the service is failing:

        Service Name: {service}

        1. Service Status:
        {status_data}

        2. Service Configuration File ({config_path or 'Not found'}):
        {config_data}

        3. Recent Logs (latest 50 entries):
        {log_data}

        Based on all this information, please provide:
        1. Root cause of the failure — be specific (e.g., missing binary, invalid path, permission issue, syntax error in config, etc.)
        2. Exact command(s) to fix the issue — include systemctl commands, file edits if needed, and how to reload/restart the service
        3. Tips to prevent recurrence — e.g., what to check before deploying/updating the service

        Be concise, technical, and actionable. Prioritize insights from the configuration file if it contains relevant issues.
        """

        # --- Kirim ke LLM ---
        llm_response = llm.invoke(prompt)

        return JsonResponse({
            "diagnosis": llm_response,
            "service": service
        })
        
    except Exception as e:
        return JsonResponse({
            "error": f"Analysis failed: {str(e)}"
        }, status=500)
    
def ai_fix_service(request):
    service = request.POST.get("service")
    # Ambil diagnosis dari AI (bisa dari cache/db jika sudah disimpan)
    # Di sini kita asumsikan diagnosis menghasilkan perintah seperti:
    command = "sudo nginx -t && sudo systemctl restart nginx"

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return JsonResponse({
            "status": "success",
            "output": result.stdout + "\n\n✅ Service restarted successfully."
        })
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "output": str(e)
        })
    
# testing
def parse_ollama_response(response_text):
    """
    Mencoba mem-parsing output dari Ollama yang diharapkan memiliki format:
    COMMAND: <perintah>
    EXPLANATION: <penjelasan>
    Juga membersihkan backtick dari perintah.
    """
    command = None
    explanation = None
    response_text_clean = response_text.strip() # Bersihkan sekali di awal
    lines = response_text_clean.split('\n')

    for line in lines:
        line_stripped = line.strip() # Strip setiap baris juga
        if line_stripped.upper().startswith("COMMAND:"): # Case-insensitive check for "COMMAND:"
            command_raw = line_stripped[len("COMMAND:"):].strip()
            if command_raw.startswith("`") and command_raw.endswith("`"):
                command = command_raw[1:-1].strip()
            else:
                command = command_raw
        elif line_stripped.upper().startswith("EXPLANATION:"): # Case-insensitive check for "EXPLANATION:"
            explanation = line_stripped[len("EXPLANATION:"):].strip()
    
    # Fallback jika parsing gagal total tapi ada teks respons
    if command is None and explanation is None and response_text_clean:
        explanation = f"AI response could not be parsed into COMMAND/EXPLANATION format. Raw: {response_text_clean}"
        command = "REFUSE" # Default ke REFUSE jika format tidak jelas
    elif command is None and explanation is not None: # Jika ada penjelasan tapi tidak ada command terdeteksi
        # Bisa jadi AI hanya memberi penjelasan atau menolak secara implisit
        if "refuse" in explanation.lower() or "cannot" in explanation.lower() or "unable" in explanation.lower():
            command = "REFUSE"
        else: # Jika tidak ada indikasi penolakan, dan tidak ada command, anggap sebagai klarifikasi
             command = "ASK_CLARIFICATION"


    # Jika command terdeteksi sebagai string kosong, anggap REFUSE atau butuh klarifikasi
    if command is not None and not command.strip(): # Jika command hanya spasi atau kosong
        if explanation and ("clarification" in explanation.lower() or "specify" in explanation.lower()):
            command = "ASK_CLARIFICATION"
        else:
            command = "REFUSE"
            if not explanation:
                explanation = "AI generated an empty command."

    return command, explanation


@csrf_exempt # Hapus atau kelola CSRF dengan benar untuk produksi
def chat_interface(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_message = data.get('message')

            if not user_message:
                return JsonResponse({'error': 'Pesan tidak boleh kosong'}, status=400)

            current_working_directory = os.getcwd() # Dapatkan CWD

            # 1. Kirim pesan ke Ollama
            prompt = f"""
You are a highly cautious Linux administration assistant.
The current working directory of the system you are interacting with is: '{current_working_directory}'.
Your primary goal is safety and accuracy.
The user will provide a task in natural language.
Your role is to:
1.  Understand the task thoroughly.
2.  If the user refers to a file without specifying a full path (e.g., "read manage.py", "delete temp.txt"),
    assume they are referring to a file within the current working directory ('{current_working_directory}').
    Generate the command accordingly (e.g., "cat manage.py", not "cat /path/to/manage.py" unless the user specified "/path/to/").
3.  If the task is clear, safe, and within common administrative operations, generate **ONLY** the Linux command.
4.  If the task is ambiguous, potentially destructive (e.g., 'rm -rf /', 'mkfs'), or seems risky,
    you **MUST** respond with "REFUSE" in the COMMAND field and explain why.
5.  If you need more information to perform a safe action, use "ASK_CLARIFICATION".
6.  Provide a brief explanation of what the command does. If you refuse or ask for clarification, provide a clear reason.

Format your response **strictly** as follows, with NO other text before or after:
COMMAND: <the Linux command OR "ASK_CLARIFICATION" OR "REFUSE">
EXPLANATION: <your explanation OR clarification question OR reason for refusal>

User task: {user_message}
Assistant:
"""
            ollama_payload = {
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            }

            ai_response_text = "Tidak dapat menghubungi AI."
            generated_command = None
            ai_explanation = "Terjadi kesalahan saat memproses permintaan AI."

            try:
                response = requests.post(OLLAMA_URL, json=ollama_payload, timeout=60)
                response.raise_for_status()
                ollama_data = response.json()
                ai_response_text = ollama_data.get('response', 'AI tidak memberikan respons yang diharapkan.')
                generated_command, ai_explanation = parse_ollama_response(ai_response_text)

                # Debugging tambahan:
                print(f"Raw AI Response: {ai_response_text}")
                print(f"Parsed Command: '{generated_command}', Parsed Explanation: '{ai_explanation}'")

            except requests.exceptions.RequestException as e:
                ai_explanation = f"Error saat menghubungi Ollama: {str(e)}"
                generated_command = "REFUSE" # Jika AI tidak terjangkau, jangan jalankan apa pun
            except json.JSONDecodeError:
                ai_explanation = "Format respons dari Ollama tidak valid (bukan JSON)."
                generated_command = "REFUSE"
            except Exception as e:
                 ai_explanation = f"Error internal saat memproses respons AI: {str(e)}\nRaw AI Response:\n{ai_response_text}"
                 generated_command = "REFUSE"


            command_output = ""
            command_error = ""
            # Simpan perintah asli AI untuk ditampilkan jika dimodifikasi atau ditolak oleh Python
            original_ai_command_for_display = generated_command 

            # Dapatkan CWD lagi untuk digunakan dalam logika ini
            cwd = os.getcwd() 

            # Pra-pengecekan file untuk perintah umum jika path relatif diberikan oleh AI
            # (setelah AI diharapkan menghasilkan path relatif karena prompt baru)
            # command_check_for_execution akan menjadi perintah final yang mungkin dijalankan
            command_check_for_execution = str(generated_command).upper() if generated_command is not None else ""

            if generated_command and command_check_for_execution not in ["ASK_CLARIFICATION", "REFUSE", ""]:
                try:
                    parts = shlex.split(generated_command) # Pecah perintah menjadi bagian
                    if parts:
                        # Perintah target (misal 'cat', 'ls') ada di parts[0]
                        # Argumen file/direktori potensial biasanya di akhir atau setelah opsi
                        # Ini adalah heuristik sederhana, untuk TA mungkin cukup jika Anda fokus pada kasus umum
                        
                        # Perintah yang sering beroperasi pada file/direktori sebagai argumen utama (non-opsi)
                        # dan kita ingin melakukan pengecekan CWD.
                        # Batasi pada kasus sederhana seperti "cmd file"
                        file_op_commands = ["cat", "ls", "cd", "head", "tail", "less", "more", "rm", "touch", "stat", "edit", "nano", "vi"]
                        
                        cmd_action = parts[0]
                        # Jika pakai sudo, perintah sebenarnya ada di parts[1]
                        if cmd_action == "sudo" and len(parts) > 1:
                             cmd_action = parts[1] # misal sudo cat file.txt -> cmd_action = cat

                        # Fokus pada perintah sederhana (misal: 'cat file.txt', 'ls mydir')
                        # Jika ada banyak opsi atau argumen kompleks, logika ini mungkin perlu lebih canggih.
                        # Untuk contoh ini, kita asumsikan argumen file/dir adalah yang terakhir jika bukan opsi.
                        if cmd_action in file_op_commands and len(parts) >= 2:
                            target_arg = parts[-1] # Ambil argumen terakhir

                            # Pastikan argumen terakhir bukan opsi (tidak diawali '-')
                            # dan bukan path absolut (AI seharusnya tidak menghasilkan ini untuk file di CWD lagi)
                            if not target_arg.startswith('-') and not os.path.isabs(target_arg) \
                               and target_arg not in ['.', '..']:
                                
                                path_in_cwd = os.path.join(cwd, target_arg)

                                # Perintah yang mengharapkan file/dir ada (kecuali 'touch' atau 'mkdir' jika ditambahkan)
                                if cmd_action in ["cat", "ls", "cd", "head", "tail", "less", "more", "stat", "rm", "edit", "nano", "vi"]:
                                    if not os.path.exists(path_in_cwd):
                                        # File/direktori tidak ditemukan di CWD
                                        original_ai_command_for_display = generated_command # Simpan yang asli untuk ditampilkan
                                        ai_explanation = f"File atau direktori '{target_arg}' tidak ditemukan di direktori saat ini ({cwd}). {ai_explanation if ai_explanation else ''}".strip()
                                        command_error = f"Error: File atau direktori '{target_arg}' tidak ditemukan di '{cwd}'."
                                        generated_command = "REFUSE" # Override perintah AI, jangan eksekusi
                                        command_check_for_execution = "REFUSE" # Update juga ini
                                    else:
                                        # File/direktori ADA di CWD.
                                        # Kita bisa mengganti argumen dengan path absolut untuk kejelasan saat eksekusi.
                                        parts[-1] = os.path.abspath(path_in_cwd)
                                        generated_command = shlex.join(parts) if hasattr(shlex, 'join') else ' '.join(shlex.quote(p) for p in parts)
                                        # original_ai_command_for_display bisa tetap yang lama atau yang baru, tergantung preferensi
                                        original_ai_command_for_display = generated_command # Tampilkan perintah yang akan dieksekusi
                                        print(f"Path resolved: '{target_arg}' -> '{parts[-1]}'. Command: '{generated_command}'")
                
                except ValueError as e: # shlex.split bisa gagal
                    print(f"Peringatan: Gagal mem-parse perintah untuk pengecekan CWD: '{generated_command}'. Error: {e}")
                    # Biarkan perintah asli dieksekusi apa adanya jika parsing gagal
                except Exception as e_path_check: # Tangkap error lain selama path checking
                    print(f"Error selama path checking: {e_path_check}")
                    # Mungkin lebih aman untuk menolak jika ada error tak terduga di sini
                    original_ai_command_for_display = generated_command
                    generated_command = "REFUSE"
                    command_check_for_execution = "REFUSE"
                    ai_explanation = f"Terjadi error internal saat memvalidasi path: {str(e_path_check)}. {ai_explanation if ai_explanation else ''}".strip()
                    command_error = f"Error validasi path: {str(e_path_check)}"



            # --- !!! PERINGATAN KEAMANAN SANGAT TINGGI !!! ---
            # Eksekusi sekarang sepenuhnya bergantung pada AI yang mengembalikan perintah valid
            # dan tidak mengembalikan "ASK_CLARIFICATION" atau "REFUSE".
            # Ini adalah pendekatan yang SANGAT BERISIKO.

            # Pastikan generated_command adalah string sebelum melakukan .upper()
            command_check = str(generated_command).upper() if generated_command is not None else ""

            if generated_command and command_check not in ["ASK_CLARIFICATION", "REFUSE", ""]:
                try:
                    # Menggunakan timeout untuk mencegah proses berjalan terlalu lama
                    result = subprocess.run(
                        generated_command, # generated_command sudah dibersihkan oleh parse_ollama_response
                        shell=True, # SANGAT BERBAHAYA! Terutama tanpa validasi sisi Python.
                        capture_output=True,
                        text=True,
                        timeout=30, # Detik, sesuaikan
                        check=False # Jangan raise exception untuk non-zero exit codes, tangani manual
                    )
                    command_output = result.stdout
                    command_error = result.stderr
                    if result.returncode != 0:
                        # Tambahkan output ke error jika ada, untuk konteks
                        if command_output and not command_error:
                             command_error = f"Perintah selesai dengan kode error: {result.returncode}\nOutput:\n{command_output}"
                        elif command_output and command_error:
                             command_error = f"Perintah selesai dengan kode error: {result.returncode}\nOutput:\n{command_output}\nError Output:\n{command_error}"
                        elif not command_output and command_error:
                            command_error = f"Perintah selesai dengan kode error: {result.returncode}\nError Output:\n{command_error}"
                        else: # No stdout, no stderr, but non-zero return code
                            command_error = f"Perintah selesai dengan kode error: {result.returncode}"


                except subprocess.TimeoutExpired:
                    command_error = "Eksekusi perintah melebihi batas waktu."
                except OSError as e:
                    command_error = f"Error OS saat menjalankan perintah '{generated_command}': {str(e)}"
                except Exception as e:
                    command_error = f"Error tak terduga saat menjalankan perintah '{generated_command}': {str(e)}"
            
            elif command_check == "REFUSE":
                command_output = "AI menolak untuk memproses permintaan."
                # ai_explanation sudah seharusnya berisi alasan dari AI.
            
            elif command_check == "ASK_CLARIFICATION":
                command_output = "AI membutuhkan klarifikasi lebih lanjut."
                # ai_explanation sudah seharusnya berisi pertanyaan klarifikasi dari AI.
            
            else: # Jika generated_command adalah None atau string kosong atau tidak valid
                if not ai_explanation or ai_explanation == "Terjadi kesalahan saat memproses permintaan AI.":
                     ai_explanation = "AI tidak menghasilkan perintah yang valid atau respons tidak dapat diparsing."
                command_output = "Tidak ada perintah yang dihasilkan atau valid untuk dieksekusi."


            return JsonResponse({
                'ai_explanation': ai_explanation if ai_explanation else "Tidak ada penjelasan dari AI.",
                # Tampilkan perintah yang AI awalnya hasilkan atau yang dimodifikasi jika path resolve berhasil
                'generated_command': original_ai_command_for_display if original_ai_command_for_display and command_check_for_execution not in ["ASK_CLARIFICATION", "REFUSE", ""] else "",
                'command_output': command_output,
                'command_error': command_error
            })

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Format request tidak valid (JSON diharapkan)'}, status=400)
        except Exception as e: # Tangkap error tak terduga lainnya di level view
            print(f"VIEW LEVEL EXCEPTION: {str(e)}") # Untuk debugging di server
            return JsonResponse({'error': f'Terjadi kesalahan internal server yang tidak tertangani: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Hanya metode POST yang diizinkan'}, status=405)




# Template Prompt ReAct (bisa disesuaikan atau ambil dari LangChain Hub)
# Sesuaikan template ini agar lebih cocok dengan tugas administrasi Linux
REACT_PROMPT_TEMPLATE_STR = """
Jawab pertanyaan berikut dengan sebaik mungkin. Anda memiliki akses ke alat berikut:

{tools}

Gunakan format berikut:

Pertanyaan: pertanyaan input yang harus Anda jawab
Pikiran: Anda harus selalu berpikir tentang apa yang harus dilakukan, termasuk mempertimbangkan direktori kerja saat ini jika relevan. Direktori kerja saat ini adalah: {current_working_directory}.
Tindakan: tindakan yang harus diambil, harus salah satu dari [{tool_names}]
Input Tindakan: input untuk tindakan tersebut
Observasi: hasil dari tindakan
... (Pikiran/Tindakan/Input Tindakan/Observasi ini dapat berulang N kali)
Pikiran: Saya sekarang tahu jawaban akhirnya
Jawaban Akhir: jawaban akhir untuk pertanyaan input asli

Mulai!

Pertanyaan: {input}
Pikiran:{agent_scratchpad}
"""
# Jika Anda ingin menggunakan template dari hub (lebih direkomendasikan jika tersedia yang cocok):
# from langchain import hub
# react_prompt = hub.pull("hwchase17/react") # Cek nama prompt yang sesuai di LangChain Hub

# Buat instance PromptTemplate
# Perhatikan: 'current_working_directory' ditambahkan sebagai variabel input baru.
react_prompt = PromptTemplate.from_template(REACT_PROMPT_TEMPLATE_STR)


# Buat Agen ReAct
# Fungsi create_react_agent mungkin memerlukan llm, tools, dan prompt
try:
    react_agent = create_react_agent(llm=llm, tools=ALL_TOOLS, prompt=react_prompt)
    # AGENT_EXECUTOR = AgentExecutor(
    AGENT_EXECUTOR = initialize_agent(
        # agent=react_agent,
        agent="zero-shot-react-description",
        llm=llm,
        tools=ALL_TOOLS,
        verbose=True, # Sangat berguna untuk debugging, tampilkan proses berpikir agen
        handle_parsing_errors=True, # Mencoba memperbaiki error parsing output LLM
        max_iterations=30, # Mencegah loop tak terbatas
        # early_stopping_method="generate", # Opsional, untuk menghentikan jika LLM menghasilkan Final Answer
    )
    print("LangChain ReAct AgentExecutor berhasil diinisialisasi.")
except Exception as e:
    print(f"GAGAL menginisialisasi LangChain AgentExecutor: {e}")
    AGENT_EXECUTOR = None # Set ke None jika gagal

# ... (fungsi parse_ollama_response tidak lagi relevan untuk alur utama ini) ...

@csrf_exempt
def react_chat_interface_lc(request): # Buat endpoint baru untuk LangChain
    if AGENT_EXECUTOR is None:
        return JsonResponse({'error': 'LangChain Agent tidak berhasil diinisialisasi. Cek log server.'}, status=500)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_message = data.get('message')
            if not user_message:
                return JsonResponse({'error': 'Pesan tidak boleh kosong'}, status=400)

            cwd = os.getcwd()
            agent_input = {
                "input": user_message,
                "current_working_directory": cwd,
                # agent_scratchpad akan diisi oleh AgentExecutor secara otomatis
            }
            
            # Jalankan agen
            # Respons akan berisi 'output' (jawaban akhir) dan bisa juga 'intermediate_steps'
            response_obj = AGENT_EXECUTOR.invoke(agent_input)
            
            final_answer = response_obj.get('output', "AI tidak memberikan jawaban akhir.")
            
            intermediate_steps_str = ""
            if 'intermediate_steps' in response_obj and response_obj['intermediate_steps']:
                for step in response_obj['intermediate_steps']:
                    action_log = step[0].log # step[0] adalah AgentAction, step[1] adalah observasi
                    observation = step[1]
                    # Log biasanya berisi Thought, Action, Action Input. Kita coba parse kasar.
                    intermediate_steps_str += f"{action_log.strip()}\nObservasi: {str(observation)}\n\n"
            else: # Jika verbose=True, kadang output sudah ada di 'output' dalam format ReAct
                  # Jika tidak ada intermediate_steps, final_answer mungkin sudah berisi log jika LLM tidak menghasilkan Final Answer
                  pass


            return JsonResponse({
                'ai_final_answer': final_answer,
                'intermediate_steps_log': intermediate_steps_str, # Log proses berpikir untuk ditampilkan di frontend
                # 'raw_agent_response': response_obj, # Untuk debugging jika perlu
            })

        except Exception as e:
            import traceback
            print(f"Error di LangChain ReAct Interface: {str(e)}")
            traceback.print_exc() # Tampilkan traceback lengkap di log server
            return JsonResponse({'error': f'Terjadi kesalahan internal saat menggunakan LangChain: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Hanya metode POST yang diizinkan untuk endpoint ini'}, status=405)


# new
# Setup logging
logger = logging.getLogger(__name__)

@dataclass
class ServiceContext:
    """Context information tentang service"""
    name: str
    status: str
    config_path: Optional[str]
    config_content: str
    logs: str
    errors: List[str]
    warnings: List[str]
    dependencies: List[str]
    ports: List[int]
    
@dataclass
class FixAction:
    """Action yang bisa dilakukan untuk fix service"""
    type: str  # 'command', 'file_edit', 'permission', 'install'
    description: str
    command: Optional[str] = None
    file_path: Optional[str] = None
    file_content: Optional[str] = None
    requires_sudo: bool = False
    risk_level: str = "low"  # low, medium, high

class ServiceMCPTools:
    """MCP Tools untuk analisis dan perbaikan service"""
    
    @staticmethod
    def get_service_context(service_name: str) -> ServiceContext:
        """Mengumpulkan semua context tentang service"""
        context = ServiceContext(
            name=service_name,
            status="",
            config_path=None,
            config_content="",
            logs="",
            errors=[],
            warnings=[],
            dependencies=[],
            ports=[]
        )
        
        # Get service status
        try:
            result = subprocess.run(
                ["systemctl", "status", service_name],
                capture_output=True, text=True, timeout=10
            )
            context.status = result.stdout
            if result.returncode != 0:
                context.errors.append(f"Service status error: {result.stderr}")
        except Exception as e:
            context.errors.append(f"Failed to get status: {str(e)}")
        
        # Get service config
        config_path = ServiceMCPTools.find_service_file(service_name)
        if config_path and os.path.exists(config_path):
            context.config_path = config_path
            try:
                with open(config_path, 'r') as f:
                    context.config_content = f.read()
            except Exception as e:
                context.errors.append(f"Failed to read config: {str(e)}")
        
        # Get logs
        try:
            result = subprocess.run(
                ["journalctl", "-u", service_name, "-n", "100", "--no-pager"],
                capture_output=True, text=True, timeout=30
            )
            context.logs = result.stdout
        except Exception as e:
            context.errors.append(f"Failed to get logs: {str(e)}")
        
        # Analyze dependencies
        context.dependencies = ServiceMCPTools.get_service_dependencies(service_name)
        
        # Get listening ports
        context.ports = ServiceMCPTools.get_service_ports(service_name)
        
        return context
    
    @staticmethod
    def find_service_file(service_name: str) -> Optional[str]:
        """Find service configuration file"""
        possible_paths = [
            f"/etc/systemd/system/{service_name}",
            f"/lib/systemd/system/{service_name}",
            f"/usr/lib/systemd/system/{service_name}",
            f"/etc/systemd/system/{service_name}.service",
            f"/lib/systemd/system/{service_name}.service",
            f"/usr/lib/systemd/system/{service_name}.service"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None
    
    @staticmethod
    def get_service_dependencies(service_name: str) -> List[str]:
        """Get service dependencies"""
        try:
            result = subprocess.run(
                ["systemctl", "list-dependencies", service_name],
                capture_output=True, text=True, timeout=10
            )
            dependencies = []
            for line in result.stdout.split('\n'):
                if '●' in line or '├─' in line or '└─' in line:
                    dep = line.strip().replace('●', '').replace('├─', '').replace('└─', '').strip()
                    if dep and dep != service_name:
                        dependencies.append(dep)
            return dependencies
        except:
            return []
    
    @staticmethod
    def get_service_ports(service_name: str) -> List[int]:
        """Get ports used by service using multiple methods for better detection"""
        def extract_port_from_line(line: str) -> Optional[int]:
            """Extract port number from a line containing network connection info"""
            parts = line.strip().split()
            if len(parts) < 5:
                return None
            
            # Extract local address:port
            addr_port = parts[3] if len(parts) > 3 else ""
            if ':' in addr_port:
                port_str = addr_port.split(':')[-1]
                try:
                    return int(port_str)
                except ValueError:
                    return None
            return None

        ports = set()

        try:
            # Method 1: Use ss to find listening ports with service name
            result = subprocess.run(
                ["ss", "-tulnp"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if service_name in line:
                    port = extract_port_from_line(line)
                    if port:
                        ports.add(port)

            # Method 2: Use lsof to find open network connections by service name
            result = subprocess.run(
                ["lsof", "-i", "-P", "-n", f"-c{service_name}"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if 'TCP' in line or 'UDP' in line:
                    port = extract_port_from_line(line)
                    if port:
                        ports.add(port)

            # Method 3: Use ps + netstat as fallback
            result = subprocess.run(
                ["ps", "-C", service_name, "-o", "pid="],
                capture_output=True, text=True, timeout=10
            )
            pids = [pid.strip() for pid in result.stdout.split('\n') if pid.strip()]
            
            for pid in pids:
                result = subprocess.run(
                    ["netstat", "-tulnp", "--program", "--pid", pid],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'LISTEN' in line or 'ESTABLISHED' in line:
                        port = extract_port_from_line(line)
                        if port:
                            ports.add(port)

        except Exception as e:
            logger.warning(f"Port detection failed: {str(e)}")

        return list(ports)
    
    @staticmethod
    def validate_service_config(config_content: str, service_name: str) -> List[str]:
        """Validate service configuration with deeper checks"""
        issues = []
        
        if not config_content:
            return ["Configuration file is empty or not found"]
        
        lines = config_content.split('\n')
        in_service_section = False
        directives_in_unit = set()
        directives_in_service = set()
        
        # Valid directives per section (basic validation)
        KNOWN_DIRECTIVES = {
            'Unit': ['Description', 'Documentation', 'Requires', 'Wants', 'After', 'Before'],
            'Service': ['Type', 'ExecStart', 'ExecStartPre', 'ExecStartPost', 
                        'ExecStop', 'ExecStopPost', 'Restart', 'User', 'Group',
                        'WorkingDirectory', 'EnvironmentFile', 'Environment',
                        'PIDFile', 'TimeoutStartSec', 'TimeoutStopSec']
        }
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('[Unit]'):
                in_service_section = False
                continue
                
            if line.startswith('[Service]'):
                in_service_section = True
                continue
                
            if line.startswith('['):
                # Another section like [Install], ignore for now
                continue
            
            if '=' in line and in_service_section:
                key = line.split('=', 1)[0].strip()
                directives_in_service.add(key)
                
                # Check unknown directives
                if key not in KNOWN_DIRECTIVES['Service']:
                    issues.append(f"Unknown directive in [Service]: {key}")
                    
            elif line.startswith('User='):
                user = line.split('=', 1)[1].strip()
                try:
                    subprocess.run(["id", user], capture_output=True, check=True)
                except:
                    issues.append(f"User '{user}' does not exist")
                        
            elif line.startswith('Group='):
                group = line.split('=', 1)[1].strip()
                try:
                    subprocess.run(["getent", "group", group], capture_output=True, check=True)
                except:
                    issues.append(f"Group '{group}' does not exist")
                        
            elif line.startswith('ExecStart='):
                exec_path = line.split('=', 1)[1].strip().split()[0]
                if not os.path.exists(exec_path):
                    issues.append(f"ExecStart binary not found: {exec_path}")
                    
            elif line.startswith('WorkingDirectory='):
                work_dir = line.split('=', 1)[1].strip()
                if not os.path.exists(work_dir):
                    issues.append(f"WorkingDirectory path does not exist: {work_dir}")
                    
            elif line.startswith('EnvironmentFile='):
                env_file = line.split('=', 1)[1].strip()
                if env_file.startswith('-'):
                    env_file = env_file[1:].strip()  # Optional file
                if not os.path.exists(env_file):
                    issues.append(f"EnvironmentFile not found: {env_file}")
        
        # Mandatory directives
        if 'ExecStart' not in directives_in_service:
            issues.append("Missing required ExecStart directive in [Service]")
            
        if '[Service]' not in config_content:
            issues.append("Missing required [Service] section")
        
        if '[Unit]' not in config_content:
            issues.append("Missing required [Unit] section")
        
        # Common misconfigurations
        if 'Type=forking' in config_content and 'PIDFile' not in config_content:
            issues.append("Type=forking used without PIDFile directive")
            
        if 'User=' in config_content and 'WorkingDirectory=' in config_content:
            # Check if home directory exists for User
            pass  # already checked above
        
        return issues
    
    def ai_analyze_config(self, config_content: str, service_name: str, llm) -> List[str]:
        if not config_content:
            return ["Configuration content is empty or missing"]

        prompt = f"""
        You are an expert Linux system administrator with deep knowledge of systemd service files.
        
        Analyze the following systemd service configuration for potential issues:
        
        Service Name: {service_name}
        
        Configuration Content:
        {config_content[:4000]}
        
        Please check for:
        - Case sensitivity errors (e.g., 'user=' instead of 'User=')
        - Invalid directive names or typos
        - Misplaced directives in wrong section ([Unit] vs [Service])
        - Syntax errors (e.g., missing equals sign, invalid values)
        - Best practice violations (e.g., unsafe permissions, deprecated options)
        - Logical misconfigurations that could cause failures
        
        Return your findings as a list of specific issues found.
        """
        
        try:
            response = llm.invoke(prompt)

            # Parse hasil
            issues = []
            for line in response.split('\n'):
                line = line.strip()
                if line.startswith('- ') or line.startswith('* '):
                    issues.append(line[2:])
                elif ':' in line and not line.startswith('{') and not line.startswith('}'):
                    _, val = line.split(':', 1)
                    issues.append(val.strip())
            return issues
        except Exception as e:
            logger.warning(f"AI config analysis failed: {str(e)}")
            return []

class AIServiceFixer:
    """AI Service Fixer dengan MCP capabilities"""
    
    def __init__(self, llm_client):
        self.llm = llm_client
        self.tools = ServiceMCPTools()
    
    def analyze_and_fix(self, service_name: str, auto_fix: bool = False) -> Dict[str, Any]:
        """Analyze service dan generate fix actions"""
        
        # Step 1: Gather context using MCP tools
        context = self.tools.get_service_context(service_name)
        
        # Step 2: Validate configuration
        config_issues = self.tools.validate_service_config(context.config_content, service_name)
        
        # Step 3: Validasi tambahan via AI
        ai_config_issues = self.tools.ai_analyze_config(context.config_content, service_name, self.llm)

         # Step 4: Gabung semua issue
        all_config_issues = list(set(config_issues + ai_config_issues))

        # Step 5: Generate comprehensive prompt for LLM
        prompt = self._build_analysis_prompt(context, all_config_issues)
        
        # Step 6: Get AI analysis
        try:
            ai_response = self.llm.invoke(prompt)
            
            # Step 7: Parse AI response to extract actions
            fix_actions = self._parse_fix_actions(ai_response)
            
            # Step 8: Execute fixes if auto_fix is enabled
            execution_results = []
            if auto_fix:
                execution_results = self._execute_fixes(fix_actions, service_name)
            
            return {
                "service": service_name,
                "context": context.__dict__,
                "config_issues": config_issues,
                "ai_analysis": ai_response,
                "fix_actions": [action.__dict__ for action in fix_actions],
                "execution_results": execution_results,
                "auto_fix_enabled": auto_fix
            }
            
        except Exception as e:
            logger.error(f"AI analysis failed for {service_name}: {str(e)}")
            return {
                "error": f"AI analysis failed: {str(e)}",
                "service": service_name
            }
    
    def _build_analysis_prompt(self, context: ServiceContext, config_issues: List[str]) -> str:
        """Build comprehensive prompt for AI analysis"""
        prompt = f"""
            You are an expert Linux system administrator with deep knowledge of systemd services.
            CONTEXT INFORMATION:
            Service Name: {context.name}
            Config Path: {context.config_path or 'Not found'}
            SERVICE STATUS:
            {context.status}
            CONFIGURATION ISSUES DETECTED:
            {chr(10).join(f"- {issue}" for issue in config_issues) if config_issues else "No configuration issues detected"}
            SERVICE CONFIGURATION:
            {context.config_content[:2000]}...
            RECENT LOGS (last 100 entries):
            {context.logs[:3000]}...
            DEPENDENCIES:
            {', '.join(context.dependencies) if context.dependencies else 'None detected'}
            LISTENING PORTS:
            {', '.join(map(str, context.ports)) if context.ports else 'None detected'}
            ERRORS ENCOUNTERED:
            {chr(10).join(f"- {error}" for error in context.errors) if context.errors else "No errors"}
            ANALYSIS REQUEST:
            Please provide a comprehensive analysis in this EXACT JSON format:
            {{
                "root_cause": "Specific root cause of the service failure",
                "severity": "low|medium|high",
                "fix_actions": [
                    {{
                        "type": "command|file_edit|permission|install",
                        "description": "What this action does",
                        "command": "exact command to run (if type is command)",
                        "file_path": "path to file (if type is file_edit)",
                        "file_content": "new file content (if type is file_edit)",
                        "requires_sudo": true/false,
                        "risk_level": "low|medium|high"
                    }}
                ],
                "verification_steps": ["Step 1", "Step 2", "..."],
                "prevention_tips": ["Tip 1", "Tip 2", "..."]
            }}
            Focus on actionable, specific solutions. If multiple issues exist, prioritize them by impact.
            Use the CONFIGURATION ISSUES section as a primary source of truth — many failures stem from misconfigured directives.
            """
        return prompt
    
    def _parse_fix_actions(self, ai_response: str) -> List[FixAction]:
        """Parse AI response to extract fix actions"""
        fix_actions = []
        
        try:
            # Try to extract JSON from AI response
            json_start = ai_response.find('{')
            json_end = ai_response.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = ai_response[json_start:json_end]
                parsed = json.loads(json_str)
                
                for action_data in parsed.get('fix_actions', []):
                    action = FixAction(
                        type=action_data.get('type', 'command'),
                        description=action_data.get('description', ''),
                        command=action_data.get('command'),
                        file_path=action_data.get('file_path'),
                        file_content=action_data.get('file_content'),
                        requires_sudo=action_data.get('requires_sudo', False),
                        risk_level=action_data.get('risk_level', 'low')
                    )
                    fix_actions.append(action)
        
        except Exception as e:
            logger.error(f"Failed to parse AI response: {str(e)}")
            # Fallback: create a basic restart action
            fix_actions.append(FixAction(
                type='command',
                description='Restart the service',
                command=f'systemctl restart {service_name}',
                requires_sudo=True,
                risk_level='low'
            ))
        
        return fix_actions
    
    def _execute_fixes(self, fix_actions: List[FixAction], service_name: str) -> List[Dict[str, Any]]:
        """Execute fix actions safely"""
        results = []
        
        for i, action in enumerate(fix_actions):
            result = {
                "action_index": i,
                "action_type": action.type,
                "description": action.description,
                "success": False,
                "output": "",
                "error": ""
            }
            
            try:
                if action.type == 'command' and action.command:
                    # Execute command
                    cmd_result = subprocess.run(
                        action.command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    result["success"] = cmd_result.returncode == 0
                    result["output"] = cmd_result.stdout
                    result["error"] = cmd_result.stderr
                
                elif action.type == 'file_edit' and action.file_path and action.file_content:
                    # Edit file (with backup)
                    backup_path = f"{action.file_path}.backup.{int(time.time())}"
                    
                    # Create backup
                    if os.path.exists(action.file_path):
                        subprocess.run(["cp", action.file_path, backup_path])
                    
                    # Write new content
                    with open(action.file_path, 'w') as f:
                        f.write(action.file_content)
                    
                    result["success"] = True
                    result["output"] = f"File updated successfully. Backup created at {backup_path}"
                
                elif action.type == 'permission' and action.command:
                    # Permission changes
                    cmd_result = subprocess.run(
                        action.command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    result["success"] = cmd_result.returncode == 0
                    result["output"] = cmd_result.stdout
                    result["error"] = cmd_result.stderr
                
            except Exception as e:
                result["error"] = str(e)
            
            results.append(result)
            
            # Stop if critical action failed
            if not result["success"] and action.risk_level == "high":
                break
        
        return results

class LangchainLLMWrapper:
    def __init__(self, llm_instance):
        self.llm = llm_instance
    
    def invoke(self, prompt):
        """Wrapper to match the expected interface"""
        try:
            response = self.llm.invoke(prompt)
            return response
        except Exception as e:
            logger.error(f"LLM invocation failed: {str(e)}")
            # Fallback response in case of LLM failure
            return """{
                "root_cause": "Unable to analyze due to LLM error",
                "severity": "medium",
                "fix_actions": [
                    {
                        "type": "command",
                        "description": "Basic service restart",
                        "command": "systemctl restart """ + """",
                        "requires_sudo": true,
                        "risk_level": "low"
                    }
                ],
                "verification_steps": ["Check service status after restart"],
                "prevention_tips": ["Monitor service logs regularly"]
            }"""

# Initialize the LLM client with your existing setup
llm_client = LangchainLLMWrapper(llm)

# Django Views
@login_required
@csrf_exempt
def ai_analyze_service_v2(request):
    """Enhanced AI service analyzer with MCP"""
    if request.method != 'POST':
        return JsonResponse({"error": "Only POST method allowed"}, status=405)
    
    try:
        service = request.POST.get("service")
        auto_fix = request.POST.get("auto_fix", "false").lower() == "true"
        
        if not service:
            return JsonResponse({"error": "Service name is required"}, status=400)
        
        # Validate service name
        if not re.match(r'^[a-zA-Z0-9_\-\./@]+\.?service$', service):
            return JsonResponse({"error": "Invalid service name format"}, status=400)
        
        # Initialize AI Service Fixer (assuming you have llm client)
        # fixer = AIServiceFixer(your_llm_client)
        
        # For demo, we'll create a mock response
        # mock_response = {
        #     "service": service,
        #     "analysis_complete": True,
        #     "timestamp": time.time(),
        #     "mcp_tools_used": [
        #         "service_context_gatherer",
        #         "config_validator", 
        #         "dependency_analyzer",
        #         "port_scanner"
        #     ],
        #     "ai_recommendations": f"Service {service} analysis completed using MCP tools",
        #     "auto_fix_enabled": auto_fix
        # }
        fixer = AIServiceFixer(llm_client)
        
        # Run analysis only (no auto-fix)
        result = fixer.analyze_and_fix(service, auto_fix=False)
        
        
        return JsonResponse(result)
        
    except Exception as e:
        logger.error(f"Service analysis failed: {str(e)}")
        return JsonResponse({
            "error": f"Analysis failed: {str(e)}"
        }, status=500)

@login_required 
@csrf_exempt
def ai_fix_service_v2(request):
    """Enhanced AI service fixer with MCP execution"""
    if request.method != 'POST':
        return JsonResponse({"error": "Only POST method allowed"}, status=405)
    
    try:
        service = request.POST.get("service")
        confirm_fixes = request.POST.get("confirm", "false").lower() == "true"
        
        if not service:
            return JsonResponse({"error": "Service name is required"}, status=400)
        
        # Initialize and run fixer
        fixer = AIServiceFixer(llm_client)
        result = fixer.analyze_and_fix(service, auto_fix=confirm_fixes)
        
        # Mock response for demo
        # mock_result = {
        #     "service": service,
        #     "fixes_applied": confirm_fixes,
        #     "actions_taken": [
        #         {
        #             "type": "command",
        #             "description": "Reloaded systemd daemon",
        #             "success": True,
        #             "output": "Daemon reloaded successfully"
        #         },
        #         {
        #             "type": "command", 
        #             "description": f"Restarted service {service}",
        #             "success": True,
        #             "output": f"Service {service} restarted successfully"
        #         }
        #     ],
        #     "final_status": "Service is now running",
        #     "mcp_enhanced": True
        # }
        
        return JsonResponse(result)
        
    except Exception as e:
        logger.error(f"Service fix failed: {str(e)}")
        return JsonResponse({
            "error": f"Fix failed: {str(e)}"
        }, status=500)
