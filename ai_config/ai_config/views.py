from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib import messages
from django.contrib.auth import logout
import psutil, os, subprocess
from django.http import JsonResponse
from datetime import datetime
import socket
import requests
from two_factor.views import LoginView as TwoFactorLoginView
from two_factor.utils import default_device
from django_ratelimit.decorators import ratelimit
from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.response import Response
from langchain_ollama import OllamaLLM
# Inisialisasi model AI
llm = OllamaLLM(model="qwen2.5-coder:latest")

@login_required
def chatAI(request):
    return render(request,"generator/textGenerator.html",{'headTitle' : 'Chat AI','toggle' : "true"})

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
    
from django.views.decorators.csrf import csrf_exempt

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
            "systemctl list-units --type=service --state=failed",
            shell=True,
            text=True
        )
        lines = result.strip().splitlines()
        services = []
        for line in lines[1:-7]:  # skip header & footer
            if line.strip() and not line.startswith(" "):
                parts = line.split()
                service_name = parts[0]
                description = " ".join(parts[1:-1])
                services.append({
                    "name": service_name,
                    "description": description
                })
        return services
    except Exception as e:
        return []
    
def ai_analyze_service(request):
    service = request.POST.get("service")
    log_data = subprocess.check_output(
        f"journalctl -u {service} --since '5 minutes ago'",
        shell=True,
        text=True
    )

    prompt = f"""
    You are a Linux system assistant.
    The following service is in failed state: {service}
    Here are the logs from the last 5 minutes:

    {log_data}

    Identify the cause of the failure and recommend one action to fix it.
    If possible, generate the exact bash command to fix the issue.
    """

    llm_response = llm.run(prompt)

    return JsonResponse({
        "diagnosis": llm_response
    })

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