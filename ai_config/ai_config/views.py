from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib import messages
from django.contrib.auth import logout
# from django.contrib.auth.models import User
import psutil, os, subprocess
from django.http import JsonResponse
from datetime import datetime
import socket
import re
import requests
import logging
import json
from django.core.paginator import Paginator
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
from chatbot.models import SystemScan, ConfigurationIssue
from .system_analyzer import LinuxConfigAnalyzer
import asyncio
from django.utils import timezone
# Inisialisasi model AI
# llm = OllamaLLM(model="qwen2.5-coder:latest")
llm = OllamaLLM(model="mistral:latest")
OLLAMA_URL = getattr(settings, "OLLAMA_URL")
OLLAMA_MODEL = getattr(settings, "OLLAMA_MODEL")
OPENAI_API_KEY = getattr(settings, "OPENAI_KEY")
GEMINI_API_KEY = getattr(settings, "GEMINI_KEY")
MISTRAL_API_KEY = getattr(settings, "MISTRAL_API_KEY")

@login_required
def chatAI(request):
    return render(request,"generator/textGenerator.html",{'headTitle' : 'Chat AI','toggle' : "true"})
    # testing
@login_required
def chatAI2(request):
    # return render(request,"generator/textGenerator.html",{'headTitle' : 'Chat AI','toggle' : "true"})
    # testing
    return render(request,"chat.html",{'headTitle' : 'Chat AI','toggle' : "true"})
# config detector
@login_required
def config_detector(request):
    recent_scans = SystemScan.objects.filter(scanned_by=request.user).order_by('-scanned_at')[:5]
    return render(request, 'config_detector.html', {
        'recent_scans': recent_scans
    })

@login_required
def run_scan(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        scan_type = data.get('scan_type', 'full')
        use_ai = data.get('use_ai_enhancement', False)
        # Initialize analyzer
        print(use_ai)
        analyzer = LinuxConfigAnalyzer(use_ai_enhancement=use_ai)
        results = analyzer.analyze_system(scan_type)
        
        # Save scan to database
        system_scan = SystemScan.objects.create(
            hostname=results['system_info']['hostname'],
            ip_address='127.0.0.1',  # Local scan
            os_info=json.dumps(results['system_info']),
            scan_type=scan_type,
            scanned_by=request.user
        )
        
        # Save issues
        for issue in results['issues']:
            ConfigurationIssue.objects.create(
                system_scan=system_scan,
                category=issue['category'],
                severity=issue['severity'],
                title=issue['title'],
                description=issue['description'],
                config_file=issue.get('config_file'),
                current_value=issue.get('current_value'),
                recommended_value=issue.get('recommended_value'),
                fix_command=issue.get('fix_command'),
                is_auto_fixable=issue.get('is_auto_fixable', False),
                ai_risk=issue.get('ai_risk'),
                ai_recommendation=issue.get('ai_recommendation'),
                ai_impact=issue.get('ai_impact')
            )
        
        return JsonResponse({
            'success': True,
            'scan_id': system_scan.id,
            'results': results
        })
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
def scan_results(request, scan_id):
    system_scan = SystemScan.objects.get(id=scan_id, scanned_by=request.user)
    issues = ConfigurationIssue.objects.filter(system_scan=system_scan).order_by('-severity', 'category')
    
    system_info = json.loads(system_scan.os_info)
    
    context = {
        'system_scan': system_scan,
        'system_info': system_info,
        'issues': issues,
        'total_issues': issues.count(),
        'critical_count': issues.filter(severity='critical').count(),
        'high_count': issues.filter(severity='high').count(),
        'auto_fixable_count': issues.filter(is_auto_fixable=True).count(),
    }
    
    return render(request, 'scan_results.html', context)

@login_required
def api_scan_results(request, scan_id):
    """Return scan results as JSON for AJAX requests"""
    try:
        system_scan = SystemScan.objects.get(id=scan_id, scanned_by=request.user)
        issues = ConfigurationIssue.objects.filter(system_scan=system_scan).order_by('-severity', 'category')
        
        system_info = json.loads(system_scan.os_info)
        
        # Serialize issues to JSON
        issues_data = []
        for issue in issues:
            issues_data.append({
                'id': issue.id,
                'category': issue.category,
                'severity': issue.severity,
                'title': issue.title,
                'description': issue.description,
                'config_file': issue.config_file,
                'current_value': issue.current_value,
                'recommended_value': issue.recommended_value,
                'is_auto_fixable': issue.is_auto_fixable,
                'is_fixed': issue.is_fixed,
                'ai_risk': issue.ai_risk,
                'ai_recommendation': issue.ai_recommendation, 
                'ai_impact' : issue.ai_impact,
            })
        
        # Calculate statistics
        issues_by_severity = {
            'critical': issues.filter(severity='critical').count(),
            'high': issues.filter(severity='high').count(),
            'medium': issues.filter(severity='medium').count(),
            'low': issues.filter(severity='low').count()
        }
        
        return JsonResponse({
            'success': True,
            'scan_id': system_scan.id,
            'results': {
                
                'system_info': system_info,
                'issues': issues_data,
                'scanned_at': system_scan.scanned_at.strftime("%d %b %Y, %H:%M"),
                'total_issues': issues.count(),
                'issues_by_severity': issues_by_severity,
                'auto_fixable': issues.filter(is_auto_fixable=True, is_fixed=False).count()
            }
        })
        
    except SystemScan.DoesNotExist:
        return JsonResponse({'error': 'Scan not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
@login_required
def auto_fix_issue(request, issue_id):
    if request.method == 'POST':
        try:
            issue = ConfigurationIssue.objects.get(id=issue_id)
            
            if not issue.is_auto_fixable or not issue.fix_command:
                return JsonResponse({'error': 'Issue is not auto-fixable'}, status=400)
            
            # Execute fix command (BE VERY CAREFUL HERE!)
            result = subprocess.run(
                issue.fix_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                issue.is_fixed = True
                issue.save()
                return JsonResponse({
                    'success': True,
                    'message': 'Issue fixed successfully',
                    'output': result.stdout
                })
            else:
                return JsonResponse({
                    'error': 'Fix command failed',
                    'output': result.stderr
                }, status=500)
                
        except subprocess.TimeoutExpired:
            return JsonResponse({'error': 'Fix command timeout'}, status=500)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)
# end config detector
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
   suricata_logs = models.SuricataLog.objects.all().order_by('-timestamp')[:10]
   # Ambil semua ExecutionLog dan paginate
   ai_chat_log_list = models.ExecutionLog.objects.all().order_by('-created_at')
   paginator = Paginator(ai_chat_log_list, 20)  # Tampilkan 20 per halaman
   page_number = request.GET.get('page')
   ai_chat_logs = paginator.get_page(page_number)
   return render(request, "logs_report.html", {
        'recommendations': recommendations,
        'suricata_logs': suricata_logs,
        'ai_chat_logs': ai_chat_logs
    })

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
        
        
        return JsonResponse(result)
        
    except Exception as e:
        logger.error(f"Service fix failed: {str(e)}")
        return JsonResponse({
            "error": f"Fix failed: {str(e)}"
        }, status=500)


# from chatbot.smart_agent import SmartAgent
import openai
import google.generativeai as genai
from mistralai import Mistral

# ## terbaru ==================================
class AITools:
    """Collection of tools that AI can use for system administration"""
    
    def __init__(self):
        self.tool_registry = {
            "file_read": self.file_read,
            "file_write": self.file_write,
            "file_edit": self.file_edit,
            "execute_command": self.execute_command,
            "service_control": self.service_control,
            "config_validate": self.config_validate,
            "backup_create": self.backup_create,
            "backup_restore": self.backup_restore,
            "security_scan": self.security_scan,
            "network_scan": self.network_scan,
            "log_analyze": self.log_analyze,
            # "package_manage": self.package_manage,
            # "user_manage": self.user_manage,
            # "permission_check": self.permission_check,
            # "process_monitor": self.process_monitor
        }
    
    def get_available_tools(self):
        """Return list of available tools for AI"""
        return [
            {
                "type": "function",
                "function": {
                    "name": "file_read",
                    "description": "Read contents of a file",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "Path to the file to read"},
                            "lines": {"type": "integer", "description": "Number of lines to read (optional)"}
                        },
                        "required": ["file_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "network_scan",
                    "description": "Scan network and connectivity",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "scan_type": {"type": "string", "description": "Type: ping, port_scan, interface_check"},
                            "target": {"type": "string", "description": "Target IP or hostname"}
                        },
                        "required": ["scan_type"]
                    }
                }
            },
            {
                "type": "function", 
                "function": {
                    "name": "file_write",
                    "description": "Write content to a file",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "Path to the file to write"},
                            "content": {"type": "string", "description": "Content to write"},
                            "mode": {"type": "string", "description": "Write mode: 'w' (overwrite) or 'a' (append)", "default": "w"}
                        },
                        "required": ["file_path", "content"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "file_edit",
                    "description": "Edit specific lines in a file or replace text patterns",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "Path to the file to edit"},
                            "operation": {"type": "string", "description": "Edit operation: 'replace_line', 'insert_line', 'delete_line', 'replace_pattern'"},
                            "line_number": {"type": "integer", "description": "Line number for line operations"},
                            "content": {"type": "string", "description": "New content or pattern"},
                            "replacement": {"type": "string", "description": "Replacement text for pattern operations"}
                        },
                        "required": ["file_path", "operation"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "execute_command",
                    "description": "Execute a shell command",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string", "description": "Command to execute"},
                            "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30},
                            "working_dir": {"type": "string", "description": "Working directory"}
                        },
                        "required": ["command"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "service_control",
                    "description": "Control systemd services",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "service_name": {"type": "string", "description": "Name of the service"},
                            "action": {"type": "string", "description": "Action: start, stop, restart, reload, enable, disable, status"}
                        },
                        "required": ["service_name", "action"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "config_validate",
                    "description": "Validate configuration files",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "service_type": {"type": "string", "description": "Type of service: nginx, apache, ssh, mysql, etc."},
                            "config_path": {"type": "string", "description": "Path to config file"}
                        },
                        "required": ["service_type"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "security_scan",
                    "description": "Perform security scans and audits",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "scan_type": {"type": "string", "description": "Type of scan: ports, users, permissions, logs, firewall"},
                            "target": {"type": "string", "description": "Target for scan (optional)"}
                        },
                        "required": ["scan_type"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "log_analyze",
                    "description": "Analyze system logs",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "log_file": {"type": "string", "description": "Path to log file"},
                            "pattern": {"type": "string", "description": "Pattern to search for"},
                            "lines": {"type": "integer", "description": "Number of lines to analyze", "default": 100}
                        },
                        "required": ["log_file"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "backup_create",
                    "description": "Create backup of files or directories",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "source_path": {"type": "string", "description": "Path to backup"},
                            "backup_dir": {"type": "string", "description": "Backup destination directory", "default": "/var/backups"},
                            "compression": {"type": "boolean", "description": "Compress backup", "default": True}
                        },
                        "required": ["source_path"]
                    }
                }
            },{
                "type": "function",
                "function": {
                    "name": "backup_restore",
                    "description": "Restore from backup",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "backup_path": {"type": "string", "description": "Path to backup file"},
                            "restore_path": {"type": "string", "description": "Where to restore"},
                            "force": {"type": "boolean", "description": "Force overwrite", "default": False}
                        },
                        "required": ["backup_path", "restore_path"]
                    }
                }
            },

        ]
    
    def network_scan(self, scan_type, target=None):
        """Scan network and connectivity"""
        try:
            if scan_type == "ping":
                if not target:
                    return {"success": False, "error": "Target required for ping scan"}
                
                result = subprocess.run(['ping', '-c', '4', target], 
                                      capture_output=True, text=True)
                return {
                    "success": True,
                    "scan_type": scan_type,
                    "target": target,
                    "reachable": result.returncode == 0,
                    "output": result.stdout
                }
            
            elif scan_type == "interface_check":
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
                return {
                    "success": True,
                    "scan_type": scan_type,
                    "interfaces": result.stdout
                }
            
            elif scan_type == "port_scan":
                if not target:
                    return {"success": False, "error": "Target required for port scan"}
                
                # Basic port scan using netcat
                common_ports = [22, 80, 443, 21, 25, 53, 110, 993, 995]
                open_ports = []
                
                for port in common_ports:
                    result = subprocess.run(['nc', '-z', '-w', '1', target, str(port)], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        open_ports.append(port)
                
                return {
                    "success": True,
                    "scan_type": scan_type,
                    "target": target,
                    "open_ports": open_ports
                }
            
            else:
                return {"success": False, "error": f"Unknown scan type: {scan_type}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def backup_create(self, source_path, backup_dir="/var/backups", compression=True):
        """Create backup of files or directories"""
        try:
            if not os.path.exists(source_path):
                return {"success": False, "error": f"Source path does not exist: {source_path}"}
            
            # Create backup directory if it doesn't exist
            os.makedirs(backup_dir, exist_ok=True)
            
            # Generate backup filename with timestamp
            timestamp = int(time.time())
            source_name = os.path.basename(source_path.rstrip('/'))
            
            if compression:
                backup_filename = f"{source_name}_backup_{timestamp}.tar.gz"
                backup_path = os.path.join(backup_dir, backup_filename)
                
                # Create compressed backup
                if os.path.isdir(source_path):
                    result = subprocess.run(['tar', '-czf', backup_path, '-C', 
                                           os.path.dirname(source_path), source_name], 
                                         capture_output=True, text=True)
                else:
                    result = subprocess.run(['tar', '-czf', backup_path, source_path], 
                                         capture_output=True, text=True)
            else:
                backup_filename = f"{source_name}_backup_{timestamp}"
                backup_path = os.path.join(backup_dir, backup_filename)
                
                # Create uncompressed backup
                if os.path.isdir(source_path):
                    result = subprocess.run(['cp', '-r', source_path, backup_path], 
                                         capture_output=True, text=True)
                else:
                    result = subprocess.run(['cp', source_path, backup_path], 
                                         capture_output=True, text=True)
            
            if result.returncode == 0:
                backup_size = os.path.getsize(backup_path) if os.path.isfile(backup_path) else 0
                return {
                    "success": True,
                    "source_path": source_path,
                    "backup_path": backup_path,
                    "backup_size": backup_size,
                    "compressed": compression,
                    "timestamp": timestamp
                }
            else:
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def backup_restore(self, backup_path, restore_path, force=False):
        """Restore from backup"""
        try:
            if not os.path.exists(backup_path):
                return {"success": False, "error": f"Backup file does not exist: {backup_path}"}
            
            # Check if restore path exists and force flag
            if os.path.exists(restore_path) and not force:
                return {"success": False, "error": f"Restore path exists. Use force=True to overwrite: {restore_path}"}
            
            # Create restore directory if needed
            restore_dir = os.path.dirname(restore_path)
            if restore_dir:
                os.makedirs(restore_dir, exist_ok=True)
            
            # Determine if backup is compressed
            is_compressed = backup_path.endswith('.tar.gz') or backup_path.endswith('.tgz')
            
            if is_compressed:
                # Extract compressed backup
                result = subprocess.run(['tar', '-xzf', backup_path, '-C', restore_dir], 
                                      capture_output=True, text=True)
            else:
                # Copy uncompressed backup
                if os.path.isdir(backup_path):
                    result = subprocess.run(['cp', '-r', backup_path, restore_path], 
                                         capture_output=True, text=True)
                else:
                    result = subprocess.run(['cp', backup_path, restore_path], 
                                         capture_output=True, text=True)
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "backup_path": backup_path,
                    "restore_path": restore_path,
                    "compressed": is_compressed
                }
            else:
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def file_read(self, file_path, lines=None):
        """Read file contents"""
        try:
            with open(file_path, 'r') as f:
                if lines:
                    content = ''.join(f.readlines()[:lines])
                else:
                    content = f.read()
            
            return {
                "success": True,
                "content": content,
                "file_path": file_path,
                "size": len(content)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def file_write(self, file_path, content, mode="w"):
        """Write to file"""
        try:
            # Create backup if file exists
            backup_path = None
            if os.path.exists(file_path):
                backup_path = f"{file_path}.backup.{int(time.time())}"
                subprocess.run(['cp', file_path, backup_path], check=True)
            
            with open(file_path, mode) as f:
                f.write(content)
            
            return {
                "success": True,
                "file_path": file_path,
                "backup_path": backup_path,
                "bytes_written": len(content)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def file_edit(self, file_path, operation, line_number=None, content=None, replacement=None):
        """Edit file with specific operations"""
        try:
            # Create backup
            backup_path = f"{file_path}.backup.{int(time.time())}"
            subprocess.run(['cp', file_path, backup_path], check=True)
            
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            if operation == "replace_line":
                if line_number and 1 <= line_number <= len(lines):
                    lines[line_number - 1] = content + '\n' if not content.endswith('\n') else content
                
            elif operation == "insert_line":
                if line_number and 1 <= line_number <= len(lines) + 1:
                    lines.insert(line_number - 1, content + '\n' if not content.endswith('\n') else content)
                
            elif operation == "delete_line":
                if line_number and 1 <= line_number <= len(lines):
                    del lines[line_number - 1]
                    
            elif operation == "replace_pattern":
                file_content = ''.join(lines)
                file_content = re.sub(content, replacement, file_content)
                lines = file_content.splitlines(keepends=True)
            
            with open(file_path, 'w') as f:
                f.writelines(lines)
            
            return {
                "success": True,
                "operation": operation,
                "file_path": file_path,
                "backup_path": backup_path
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def execute_command(self, command, timeout=30, working_dir=None):
        """Execute shell command safely"""
        # Security check - block dangerous commands
        dangerous_patterns = [
            'rm -rf /', 'dd if=', 'mkfs', 'fdisk', 'format', 
            'del /f', 'deltree', '> /dev/', 'chmod 777 /',
            'chown root /', 'sudo su', 'passwd'
        ]
        
        if any(pattern in command.lower() for pattern in dangerous_patterns):
            return {"success": False, "error": "Dangerous command blocked"}
        
        try:
            kwargs = {
                'capture_output': True,
                'text': True,
                'timeout': timeout
            }
            
            if working_dir:
                kwargs['cwd'] = working_dir
            
            result = subprocess.run(['bash', '-c', command], **kwargs)
            
            return {
                "success": True,
                "command": command,
                "output": result.stdout,
                "error": result.stderr,
                "return_code": result.returncode,
                "working_dir": working_dir
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Command timeout ({timeout}s)"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def service_control(self, service_name, action):
        """Control systemd services"""
        valid_actions = ['start', 'stop', 'restart', 'reload', 'enable', 'disable', 'status']
        
        if action not in valid_actions:
            return {"success": False, "error": f"Invalid action. Valid actions: {valid_actions}"}
        
        try:
            result = subprocess.run(['systemctl', action, service_name], 
                                  capture_output=True, text=True)
            
            return {
                "success": True,
                "service": service_name,
                "action": action,
                "output": result.stdout,
                "error": result.stderr,
                "return_code": result.returncode
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def config_validate(self, service_type, config_path=None):
        """Validate configuration files"""
        validation_commands = {
            'nginx': ['nginx', '-t'],
            'apache': ['apache2ctl', 'configtest'],
            'apache2': ['apache2ctl', 'configtest'], 
            'sshd': ['sshd', '-t'],
            'ssh': ['sshd', '-t'],
            'mysql': ['mysqld', '--help', '--verbose', '--dry-run'],
            'postgresql': ['postgres', '--check-config']
        }
        
        if service_type not in validation_commands:
            return {"success": False, "error": f"Validation not supported for {service_type}"}
        
        try:
            result = subprocess.run(validation_commands[service_type], 
                                  capture_output=True, text=True)
            
            return {
                "success": True,
                "service_type": service_type,
                "valid": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def security_scan(self, scan_type, target=None):
        """Perform security scans"""
        try:
            if scan_type == "ports":
                result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
                open_ports = []
                for line in result.stdout.split('\n'):
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            open_ports.append(parts[3])
                
                return {
                    "success": True,
                    "scan_type": scan_type,
                    "open_ports": open_ports,
                    "raw_output": result.stdout
                }
            
            elif scan_type == "users":
                # Check for suspicious users
                result = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True)
                users_with_shell = []
                
                for line in result.stdout.split('\n'):
                    if line and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 7 and parts[6] in ['/bin/bash', '/bin/sh', '/bin/zsh']:
                            users_with_shell.append({
                                'username': parts[0],
                                'uid': parts[2],
                                'shell': parts[6]
                            })
                
                return {
                    "success": True,
                    "scan_type": scan_type,
                    "users_with_shell": users_with_shell
                }
            
            elif scan_type == "permissions":
                # Check critical file permissions
                critical_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
                permissions = {}
                
                for file_path in critical_files:
                    if os.path.exists(file_path):
                        stat_result = subprocess.run(['stat', '-c', '%a', file_path], 
                                                   capture_output=True, text=True)
                        permissions[file_path] = stat_result.stdout.strip()
                
                return {
                    "success": True,
                    "scan_type": scan_type,
                    "file_permissions": permissions
                }
            
            elif scan_type == "firewall":
                # Check firewall status
                ufw_result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                iptables_result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                
                return {
                    "success": True,
                    "scan_type": scan_type,
                    "ufw_status": ufw_result.stdout,
                    "iptables_rules": iptables_result.stdout
                }
            
            else:
                return {"success": False, "error": f"Unknown scan type: {scan_type}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def log_analyze(self, log_file, pattern=None, lines=100):
        """Analyze log files"""
        try:
            if not os.path.exists(log_file):
                return {"success": False, "error": f"Log file not found: {log_file}"}
            
            if pattern:
                result = subprocess.run(['grep', pattern, log_file], capture_output=True, text=True)
                matches = result.stdout.strip().split('\n') if result.stdout.strip() else []
                
                return {
                    "success": True,
                    "log_file": log_file,
                    "pattern": pattern,
                    "matches": matches[-lines:],  # Last N matches
                    "total_matches": len(matches)
                }
            else:
                result = subprocess.run(['tail', '-n', str(lines), log_file], capture_output=True, text=True)
                
                return {
                    "success": True,
                    "log_file": log_file,
                    "content": result.stdout,
                    "lines_read": lines
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}
        
class MCPClient:
    def __init__(self):
        # openai.api_key = OPENAI_API_KEY
        # genai.configure(api_key=GEMINI_API_KEY)
        # Mistral.api_key = MISTRAL_API_KEY
        self.api_key = MISTRAL_API_KEY
        self.client = Mistral(api_key=self.api_key)
        self.model = "open-mistral-nemo"
        # self.model = "mistral-small-latest"
        
    def process_complex_task(self, user_input):
        system_prompt = """
        You are an advanced Linux system administrator that can handle complex multi-step tasks.
        Break down complex requests into sequential steps with validation.
        
        For complex tasks, return JSON with:
        - "workflow": array of steps
        - "description": overall task description
        - "validation_points": checks to perform between steps
        
        Examples:
        
        1. "backup data ini lalu cek apakah ada data yang hilang":
        {
            "workflow": [
                {"step": 1, "command": "rsync -av /source/path/ /backup/path/", "description": "Backup data"},
                {"step": 2, "command": "diff -r /source/path/ /backup/path/", "description": "Compare source and backup"},
                {"step": 3, "command": "find /backup/path -type f | wc -l", "description": "Count backup files"},
                {"step": 4, "command": "find /source/path -type f | wc -l", "description": "Count source files"}
            ],
            "validation_points": ["Check file count match", "Verify no diff output"],
            "description": "Backup data and verify integrity"
        }
        
        2. "duplicate file ini sebanyak 10 data lalu pindahkan ke folder ini":
        {
            "workflow": [
                {"step": 1, "command": "ls -la /source/file.txt", "description": "Check source file exists"},
                {"step": 2, "command": "mkdir -p /target/folder", "description": "Create target folder"},
                {"step": 3, "command": "for i in {1..10}; do cp /source/file.txt /target/folder/file_$i.txt; done", "description": "Duplicate file 10 times"},
                {"step": 4, "command": "ls -la /target/folder/ | grep file_", "description": "Verify duplicated files"}
            ],
            "validation_points": ["Source file exists", "Target folder created", "10 files created"],
            "description": "Duplicate file 10 times and move to target folder"
        }
        """
        
        try:
            response = self.client.chat.complete(
                model= self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_input}
                ],
                temperature=0.1
            )
            
            return response.choices[0].message.content
        except Exception as e:
            return f"Error processing request: {str(e)}"


class SafeCommandExecutor:
    def __init__(self):
        # Whitelist of allowed commands
        self.allowed_commands = [
            'ls', 'cat', 'grep', 'find', 'wc', 'head', 'tail', 
            'ps', 'top', 'free', 'df', 'du', 'uptime', 'whoami',
            'pwd', 'which', 'file', 'stat', 'chmod', 'chown',
            'mkdir', 'rmdir', 'cp', 'mv', 'rsync', 'diff',
            'tar', 'gzip', 'gunzip', 'zip', 'unzip'
        ]
    
    def execute(self, command_json):
        """Execute simple command from JSON format"""
        try:
            if isinstance(command_json, str):
                try:
                    command_data = json.loads(command_json)
                    command = command_data.get('command', '').strip()
                except json.JSONDecodeError:
                    # If not JSON, treat as plain command
                    command = command_json.strip()
            else:
                command = command_json.get('command', '').strip()
            
            return self.execute_bash_command(command)
            
        except Exception as e:
            return {"error": str(e)}
    
    def execute_bash_command(self, command, context_memory=None):
        """Execute complex bash commands with safety checks"""
        current_dir = context_memory.get("current_directory") if context_memory else os.getcwd()
        # Blacklist dangerous commands
        dangerous_patterns = [
            'rm -rf /', 'dd if=', 'mkfs', 'fdisk', 'parted',
            'format', 'del /f', 'deltree', '> /dev/', 'chmod 777 /',
            'chown root /', 'sudo su', 'su -', 'passwd'
        ]
        
        if any(pattern in command.lower() for pattern in dangerous_patterns):
            return {"error": "Dangerous command detected and blocked"}
        
        # Check if base command is allowed (for simple commands)
        cmd_base = command.split()[0] if command.split() else ""
        
        # Allow complex commands with pipes, loops, etc.
        complex_indicators = ['|', '&&', '||', ';', 'for', 'while', 'if']
        is_complex = any(indicator in command for indicator in complex_indicators)
        
        # if not is_complex and cmd_base not in self.allowed_commands:
        #     return {"error": f"Command '{cmd_base}' not in allowed list"}
        
        try:
            result = subprocess.run(
                ['bash', '-c', command],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=current_dir  # Execute in current directory
            )
            
            return {
                "output": result.stdout,
                "error": result.stderr,
                "return_code": result.returncode,
                "command": command
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Command timeout (30s)"}
        except Exception as e:
            return {"error": str(e)}


class SmartAgent:
    def __init__(self):
        self.mcp_client = MCPClient()
        self.executor = SafeCommandExecutor()
        self.ai_tools = AITools()
        self.conversation_history = []
        self.current_goal = None
        self.context_memory = {}
        
        # Set OpenAI API key
        
    # komen smart workflow sementara
    # def process_smart_workflow(self, user_query):
    #     """Main method to process user query with smart workflow"""
    #     self.current_goal = user_query
    #     self.conversation_history = [{"role": "user", "content": user_query}]
    #     workflow_result = {
    #         "steps": [],
    #         "final_status": "in_progress",
    #         "goal": user_query,
    #         "start_time": time.time()
    #     }
    #     print(f"🧠 Starting smart workflow for: {user_query}")
    #     step_count = 0
    #     max_steps = 10  # Mencegah infinite loop
    #     while step_count < max_steps:
    #         print(f"\n--- Step {step_count + 1} ---")
    #         next_action = self.get_next_action()
    #         print(f"AI Decision: {next_action}")
    #         if next_action.get("action") == "complete":
    #             workflow_result["final_status"] = "completed"
    #             workflow_result["summary"] = next_action.get("summary")
    #             print("✅ Workflow completed!")
    #             break
    #         elif next_action.get("action") == "execute":
    #             command = next_action.get("command")
    #             reasoning = next_action.get("reasoning")
    #             print(f"Reasoning: {reasoning}")
    #             print(f"Executing: {command}")
    #             execution_result = self.execute_with_context(command)
    #             workflow_result["steps"].append({
    #                 "step": step_count + 1,
    #                 "reasoning": reasoning,
    #                 "command": command,
    #                 "result": execution_result,
    #                 "timestamp": time.time()
    #             })
    #             self.add_execution_result_to_conversation(command, execution_result)
    #             print(f"Result: {execution_result.get('output', 'No output')[:100]}...")
    #             step_count += 1
    #         elif next_action.get("action") == "tool_call":
    #             tool_name = next_action.get("tool_name")
    #             parameters = next_action.get("parameters")
    #             reasoning = next_action.get("reasoning")
    #             print(f"Reasoning: {reasoning}")
    #             print(f"Calling Tool: {tool_name} with parameters: {parameters}")
    #             if hasattr(self.ai_tools, tool_name):
    #                 tool_func = getattr(self.ai_tools, tool_name)
    #                 try:
    #                     tool_result = tool_func(**parameters)
    #                     workflow_result["steps"].append({
    #                         "step": step_count + 1,
    #                         "reasoning": reasoning,
    #                         "tool_call": tool_name,
    #                         "parameters": parameters,
    #                         "result": tool_result,
    #                         "timestamp": time.time()
    #                     })
    #                     self.add_tool_result_to_conversation(tool_name, tool_result)
    #                     print(f"Tool Result: {tool_result}")
    #                 except Exception as e:
    #                     print(f"Error calling tool: {str(e)}")
    #                     workflow_result["steps"].append({
    #                         "step": step_count + 1,
    #                         "reasoning": reasoning,
    #                         "tool_call": tool_name,
    #                         "parameters": parameters,
    #                         "result": {"success": False, "error": str(e)},
    #                         "timestamp": time.time()
    #                     })
    #             else:
    #                 print(f"Unknown tool: {tool_name}")
    #                 workflow_result["steps"].append({
    #                     "step": step_count + 1,
    #                     "reasoning": reasoning,
    #                     "tool_call": tool_name,
    #                     "parameters": parameters,
    #                     "result": {"success": False, "error": f"Unknown tool: {tool_name}"},
    #                     "timestamp": time.time()
    #                 })
    #             step_count += 1
    #         else:
    #             workflow_result["final_status"] = "failed"
    #             workflow_result["error"] = next_action.get("error", "Unknown error")
    #             print(f"⚠️ Workflow failed: {workflow_result['error']}")
    #             break
    #     workflow_result["end_time"] = time.time()
    #     workflow_result["duration"] = workflow_result["end_time"] - workflow_result["start_time"]
    #     return workflow_result
    def process_smart_workflow(self, user_query):
        """Main method to process user query with smart workflow"""
        self.current_goal = user_query
        self.conversation_history = [{"role": "user", "content": user_query}]
        
        workflow_result = {
            "steps": [],
            "final_status": "in_progress",
            "goal": user_query,
            "start_time": time.time()
        }
        
        print(f"🧠 Starting smart workflow for: {user_query}")
        step_count = 0
        max_steps = 10
        
        while step_count < max_steps:
            print(f"\n--- Step {step_count + 1} ---")
            next_action = self.get_next_action()
            print(f"AI Decision: {next_action}")
            
            if next_action.get("action") == "complete":
                workflow_result["final_status"] = "completed"
                workflow_result["summary"] = next_action.get("summary")
                print("✅ Workflow completed!")
                break
                
            elif next_action.get("action") == "execute":
                command = next_action.get("command")
                reasoning = next_action.get("reasoning")
                print(f"Reasoning: {reasoning}")
                print(f"Executing bash command: {command}")
                
                execution_result = self.execute_with_context(command)
                
                workflow_result["steps"].append({
                    "step": step_count + 1,
                    "type": "bash_command",
                    "reasoning": reasoning,
                    "command": command,
                    "result": execution_result,
                    "timestamp": time.time()
                })
                
                self.add_execution_result_to_conversation(command, execution_result)
                print(f"Result: {execution_result.get('output', 'No output')[:100]}...")
                step_count += 1
                
            elif next_action.get("action") == "tool_call":
                tool_name = next_action.get("tool_name")
                parameters = next_action.get("parameters", {})
                reasoning = next_action.get("reasoning")
                
                print(f"Reasoning: {reasoning}")
                print(f"Calling AITool: {tool_name} with parameters: {parameters}")
                
                # Call the AITools function
                if hasattr(self.ai_tools, tool_name):
                    tool_func = getattr(self.ai_tools, tool_name)
                    try:
                        tool_result = tool_func(**parameters)
                        
                        workflow_result["steps"].append({
                            "step": step_count + 1,
                            "type": "tool_call",
                            "reasoning": reasoning,
                            "tool_name": tool_name,
                            "parameters": parameters,
                            "result": tool_result,
                            "timestamp": time.time()
                        })
                        
                        self.add_tool_result_to_conversation(tool_name, parameters, tool_result)
                        print(f"Tool Result: {tool_result}")
                        
                    except Exception as e:
                        error_result = {"success": False, "error": str(e)}
                        print(f"Error calling tool: {str(e)}")
                        
                        workflow_result["steps"].append({
                            "step": step_count + 1,
                            "type": "tool_call",
                            "reasoning": reasoning,
                            "tool_name": tool_name,
                            "parameters": parameters,
                            "result": error_result,
                            "timestamp": time.time()
                        })
                        
                        self.add_tool_result_to_conversation(tool_name, parameters, error_result)
                else:
                    error_result = {"success": False, "error": f"Unknown tool: {tool_name}"}
                    print(f"Unknown tool: {tool_name}")
                    
                    workflow_result["steps"].append({
                        "step": step_count + 1,
                        "type": "tool_call",
                        "reasoning": reasoning,
                        "tool_name": tool_name,
                        "parameters": parameters,
                        "result": error_result,
                        "timestamp": time.time()
                    })
                    
                    self.add_tool_result_to_conversation(tool_name, parameters, error_result)
                
                step_count += 1
                
            else:
                workflow_result["final_status"] = "failed"
                workflow_result["error"] = next_action.get("error", "Unknown error")
                print(f"⚠️ Workflow failed: {workflow_result['error']}")
                break
        
        workflow_result["end_time"] = time.time()
        workflow_result["duration"] = workflow_result["end_time"] - workflow_result["start_time"]
        return workflow_result
    
    def add_tool_result_to_conversation(self, tool_name, parameters, result):
        """Add tool call result to conversation history"""
        self.conversation_history.append({
            "role": "assistant",
            "content": f"Called AITool: {tool_name}({parameters})"
        })
        
        # Limit output length to prevent token overflow
        output = str(result)[:1000]
        self.conversation_history.append({
            "role": "user",
            "content": f"Tool result:\n{output}"
        })
        
        # Update context memory if needed
        self.update_context_memory_from_tool(tool_name, result)
        
        # Keep conversation history manageable
        if len(self.conversation_history) > 20:
            self.conversation_history = [self.conversation_history[0]] + self.conversation_history[-18:]

    def update_context_memory_from_tool(self, tool_name, result):
        """Update context memory based on tool results"""
        if tool_name == "service_control":
            if result.get("success"):
                service_name = result.get("service")
                action = result.get("action")
                self.context_memory[f"{service_name}_status"] = {
                    "action": action,
                    "output": result.get("output", ""),
                    "timestamp": time.time()
                }
        
        elif tool_name == "file_read":
            if result.get("success"):
                file_path = result.get("file_path")
                self.context_memory[f"file_content_{file_path}"] = {
                    "size": result.get("size"),
                    "content_preview": result.get("content", "")[:200],
                    "timestamp": time.time()
                }
        
        elif tool_name == "security_scan":
            if result.get("success"):
                scan_type = result.get("scan_type")
                self.context_memory[f"security_scan_{scan_type}"] = {
                    "result": result,
                    "timestamp": time.time()
                }
    
    # def stream_process_smart_workflow(self, user_query):
    #     """Main method to process user query with smart workflow - streams results"""
    #     self.current_goal = user_query
    #     self.conversation_history = [{"role": "user", "content": user_query}]
        
    #     workflow_result = {
    #         "steps": [],
    #         "final_status": "in_progress",
    #         "goal": user_query,
    #         "start_time": time.time()
    #     }

    #     yield {"type": "status", "content": f"🤖 Starting smart workflow for: {user_query}"}

    #     step_count = 0
    #     max_steps = 10
    #     while step_count < max_steps:
    #         next_action = self.get_next_action()
    #         if next_action.get("action") == "complete":
    #             workflow_result["final_status"] = "completed"
    #             workflow_result["summary"] = next_action.get("summary")
    #             yield {"type": "complete", "content": workflow_result}
    #             break
    #         elif next_action.get("action") == "execute":
    #             command = next_action.get("command")
    #             reasoning = next_action.get("reasoning")
    #             execution_result = self.execute_with_context(command)

    #             step_data = {
    #                 "step": step_count + 1,
    #                 "reasoning": reasoning,
    #                 "command": command,
    #                 "result": execution_result
    #             }
    #             workflow_result["steps"].append(step_data)
    #             yield {"type": "step", "content": step_data}
    #             self.add_execution_result_to_conversation(command, execution_result)
    #         else:
    #             workflow_result["final_status"] = "failed"
    #             workflow_result["error"] = next_action.get("error", "Unknown error")
    #             yield {"type": "error", "content": workflow_result["error"]}
    #             break
    def stream_process_smart_workflow(self, user_query):
        """Main method to process user query with smart workflow - streams results"""
        self.current_goal = user_query
        self.conversation_history = [{"role": "user", "content": user_query}]
        
        workflow_result = {
            "steps": [],
            "final_status": "in_progress",
            "goal": user_query,
            "start_time": time.time()
        }
        
        yield {"type": "status", "content": f"🧠 Starting smart workflow for: {user_query}"}
        
        step_count = 0
        max_steps = 10
        
        while step_count < max_steps:
            yield {"type": "step_info", "content": f"--- Step {step_count + 1} ---"}
            
            next_action = self.get_next_action()
            yield {"type": "decision", "content": f"AI Decision: {next_action}"}
            
            if next_action.get("action") == "complete":
                workflow_result["final_status"] = "completed"
                workflow_result["summary"] = next_action.get("summary")
                workflow_result["end_time"] = time.time()
                workflow_result["duration"] = workflow_result["end_time"] - workflow_result["start_time"]
                yield {"type": "complete", "content": workflow_result}
                break
                
            elif next_action.get("action") == "execute":
                command = next_action.get("command")
                reasoning = next_action.get("reasoning")
                
                yield {"type": "reasoning", "content": reasoning}
                yield {"type": "command", "content": f"Executing bash command: {command}"}
                
                execution_result = self.execute_with_context(command)
                
                step_data = {
                    "step": step_count + 1,
                    "type": "bash_command",
                    "reasoning": reasoning,
                    "command": command,
                    "result": execution_result,
                    "timestamp": time.time()
                }
                
                workflow_result["steps"].append(step_data)
                yield {"type": "step", "content": step_data}
                yield {"type": "result", "content": f"Result: {execution_result.get('output', 'No output')[:100]}..."}
                
                self.add_execution_result_to_conversation(command, execution_result)
                step_count += 1
                
            elif next_action.get("action") == "tool_call":
                tool_name = next_action.get("tool_name")
                parameters = next_action.get("parameters", {})
                reasoning = next_action.get("reasoning")
                
                yield {"type": "reasoning", "content": reasoning}
                yield {"type": "tool_call", "content": f"Calling AITool: {tool_name} with parameters: {parameters}"}
                
                # Call the AITools function
                if hasattr(self.ai_tools, tool_name):
                    tool_func = getattr(self.ai_tools, tool_name)
                    try:
                        tool_result = tool_func(**parameters)
                        
                        step_data = {
                            "step": step_count + 1,
                            "type": "tool_call",
                            "reasoning": reasoning,
                            "tool_name": tool_name,
                            "parameters": parameters,
                            "result": tool_result,
                            "timestamp": time.time()
                        }
                        
                        workflow_result["steps"].append(step_data)
                        yield {"type": "step", "content": step_data}
                        yield {"type": "tool_result", "content": f"Tool Result: {tool_result}"}
                        
                        self.add_tool_result_to_conversation(tool_name, parameters, tool_result)
                        
                    except Exception as e:
                        error_result = {"success": False, "error": str(e)}
                        
                        step_data = {
                            "step": step_count + 1,
                            "type": "tool_call",
                            "reasoning": reasoning,
                            "tool_name": tool_name,
                            "parameters": parameters,
                            "result": error_result,
                            "timestamp": time.time()
                        }
                        
                        workflow_result["steps"].append(step_data)
                        yield {"type": "step", "content": step_data}
                        yield {"type": "error", "content": f"Error calling tool: {str(e)}"}
                        
                        self.add_tool_result_to_conversation(tool_name, parameters, error_result)
                else:
                    error_result = {"success": False, "error": f"Unknown tool: {tool_name}"}
                    
                    step_data = {
                        "step": step_count + 1,
                        "type": "tool_call",
                        "reasoning": reasoning,
                        "tool_name": tool_name,
                        "parameters": parameters,
                        "result": error_result,
                        "timestamp": time.time()
                    }
                    
                    workflow_result["steps"].append(step_data)
                    yield {"type": "step", "content": step_data}
                    yield {"type": "error", "content": f"Unknown tool: {tool_name}"}
                    
                    self.add_tool_result_to_conversation(tool_name, parameters, error_result)
                
                step_count += 1
                
            else:
                workflow_result["final_status"] = "failed"
                workflow_result["error"] = next_action.get("error", "Unknown error")
                workflow_result["end_time"] = time.time()
                workflow_result["duration"] = workflow_result["end_time"] - workflow_result["start_time"]
                yield {"type": "error", "content": workflow_result["error"]}
                break
        
        # Handle max steps reached
        if step_count >= max_steps:
            workflow_result["final_status"] = "max_steps_reached"
            workflow_result["end_time"] = time.time()
            workflow_result["duration"] = workflow_result["end_time"] - workflow_result["start_time"]
            yield {"type": "warning", "content": f"Workflow reached maximum steps ({max_steps})"}
            yield {"type": "complete", "content": workflow_result}
            
    def get_next_action(self):
        """Ask AI what to do next based on conversation history"""
        system_prompt = f"""
        You are a smart Linux system administrator AI agent. 
        Your goal: {self.current_goal}
        
        Based on the conversation history, decide the next action:
        
        1. If goal is achieved → return {{"action": "complete", "summary": "description"}}
        2. If need to execute command → return {{"action": "execute", "command": "command", "reasoning": "why"}}
        3. If failed → return {{"action": "fail", "error": "reason"}}
        
         Available AITools functions:
        - file_read: file_read(file_path, lines=None)
        - file_write: file_write(file_path, content, mode="w")
        - file_edit: file_edit(file_path, operation, line_number=None, content=None, replacement=None)
        - execute_command: execute_command(command, timeout=30, working_dir=None)
        - service_control: service_control(service_name, action)
        - config_validate: config_validate(service_type, config_path=None)
        - security_scan: security_scan(scan_type, target=None)
        - log_analyze: log_analyze(log_file, pattern=None, lines=100)
        
        
         Examples:
        - To check Apache status: {{"action": "tool_call", "tool_name": "service_control", "parameters": {{"service_name": "apache2", "action": "status"}}, "reasoning": "Check Apache service status"}}
        - To read a file: {{"action": "tool_call", "tool_name": "file_read", "parameters": {{"file_path": "/etc/apache2/apache2.conf"}}, "reasoning": "Read Apache config file"}}
        - To run bash command: {{"action": "execute", "command": "ls -la /var/log", "reasoning": "List log files"}}

        Be specific with parameters and paths. 
        Context memory: {json.dumps(self.context_memory)}
        
        IMPORTANT: Return only valid JSON format. No additional text.
        """
        
        messages = [
            {"role": "system", "content": system_prompt}
        ] + self.conversation_history
        
        try:
            response = self.mcp_client.client.chat.complete(
                model=self.mcp_client.model,  # Use GPT-3.5 for cost efficiency
                messages=messages,
                temperature=0.1,
                max_tokens=200
            )
            
            ai_response = response.choices[0].message.content.strip()
            
            # Try to extract JSON if response has extra text
            if not ai_response.startswith('{'):
                # Look for JSON in the response
                start = ai_response.find('{')
                end = ai_response.rfind('}') + 1
                if start >= 0 and end > start:
                    ai_response = ai_response[start:end]
            
            return json.loads(ai_response)
            
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            print(f"AI Response: {ai_response}")
            return {"action": "fail", "error": f"Invalid JSON response: {str(e)}"}
        except Exception as e:
            return {"action": "fail", "error": str(e)}
    
    def execute_with_context(self, command):
        """Execute command with current context"""
        if command.startswith("cd"):
            # Execute 'cd' and update current directory
            result = self.executor.execute_bash_command(command, context_memory=self.context_memory)
            self.update_context_memory(command, result)
            return result
        else:
            return self.executor.execute_bash_command(command, context_memory=self.context_memory)
        
    # def add_execution_result_to_conversation(self, command, result):
    #     """Add command execution result to conversation history"""
        
    #     # Update context memory with important info
    #     self.update_context_memory(command, result)
        
    #     # Add to conversation
    #     self.conversation_history.append({
    #         "role": "assistant", 
    #         "content": f"Executed: {command}"
    #     })
        
    #     # Limit output length to prevent token overflow
    #     output = result.get('output', '')[:1000]
    #     error = result.get('error', '')[:500]
        
    #     self.conversation_history.append({
    #         "role": "user", 
    #         "content": f"Command result:\nOutput: {output}\nError: {error}\nReturn code: {result.get('return_code', 0)}"
    #     })
        
    #     # Keep conversation history manageable
    #     if len(self.conversation_history) > 20:
    #         # Keep first message (original goal) and last 18 messages
    #         self.conversation_history = [self.conversation_history[0]] + self.conversation_history[-18:]
    def add_execution_result_to_conversation(self, command, result):
        """Add command execution result to conversation history"""
        self.update_context_memory(command, result)
        
        self.conversation_history.append({
            "role": "assistant", 
            "content": f"Executed bash: {command}"
        })
        
        output = result.get('output', '')[:1000]
        error = result.get('error', '')[:500]
        
        self.conversation_history.append({
            "role": "user", 
            "content": f"Command result:\nOutput: {output}\nError: {error}\nReturn code: {result.get('return_code', 0)}"
        })
        
        if len(self.conversation_history) > 20:
            self.conversation_history = [self.conversation_history[0]] + self.conversation_history[-18:]
    
    # def update_context_memory(self, command, result):
    #     """Extract and store important information from command results"""
        
    #     # Store file counts
    #     if "find" in command and "wc -l" in command:
    #         self.context_memory["file_count"] = result.get("output", "").strip()
        
    #     # Store disk usage
    #     if command.startswith("df"):
    #         self.context_memory["disk_usage"] = result.get("output", "")
        
    #     # Store process info
    #     if command.startswith("ps"):
    #         self.context_memory["processes"] = result.get("output", "")
        
    #     # Store backup status
    #     if "rsync" in command:
    #         if result.get("return_code") == 0:
    #             self.context_memory["backup_status"] = "success"
    #         else:
    #             self.context_memory["backup_status"] = "failed"
                
    #     # Store directory listings
    #     if command.startswith("ls"):
    #         self.context_memory["last_listing"] = result.get("output", "")
            
    #     # Store current working directory
    #     if command.startswith("pwd"):
    #         self.context_memory["current_directory"] = result.get("output", "").strip()
        
    #     if command.startswith("cd"):
    #         self.conversation_history.append({
    #             "role": "assistant",
    #             "content": f"Updating directory context after cd command"
    #         })
    #         output = self.executor.execute_bash_command("pwd")
    #         self.context_memory["current_directory"] = output.get("output", "").strip()
    def update_context_memory(self, command, result):
        """Extract and store important information from command results"""
        if "find" in command and "wc -l" in command:
            self.context_memory["file_count"] = result.get("output", "").strip()
        
        if command.startswith("df"):
            self.context_memory["disk_usage"] = result.get("output", "")
        
        if command.startswith("ps"):
            self.context_memory["processes"] = result.get("output", "")
        
        if "rsync" in command:
            if result.get("return_code") == 0:
                self.context_memory["backup_status"] = "success"
            else:
                self.context_memory["backup_status"] = "failed"
                
        if command.startswith("ls"):
            self.context_memory["last_listing"] = result.get("output", "")
            
        if command.startswith("pwd"):
            self.context_memory["current_directory"] = result.get("output", "").strip()
        
        if command.startswith("cd"):
            self.conversation_history.append({
                "role": "assistant",
                "content": f"Updating directory context after cd command"
            })
            output = self.executor.execute_bash_command("pwd")
            self.context_memory["current_directory"] = output.get("output", "").strip()


# @csrf_exempt
# def process_smart_chat(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         user_message = data.get('message', '')
        
#         # Initialize smart agent
#         agent = SmartAgent()
        
#         # Process with smart workflow
#         workflow_result = agent.process_smart_workflow(user_message)
        
#         # Format response
#         response = f"🤖 **Smart Agent Result**\n\n"
#         response += f"**Goal:** {workflow_result['goal']}\n"
#         response += f"**Status:** {workflow_result['final_status']}\n\n"
        
#         if workflow_result['final_status'] == 'completed':
#             response += f"**Summary:** {workflow_result.get('summary', '')}\n\n"
        
#         response += "**Execution Steps:**\n"
#         for step in workflow_result['steps']:
#             response += f"\n**Step {step['step']}**\n"
#             response += f"*Reasoning:* {step['reasoning']}\n"
#             response += f"*Command:* `{step['command']}`\n"
#             response += f"*Output:*\n```\n{step['result'].get('output', 'No output')}\n```\n"
            
#             if step['result'].get('error'):
#                 response += f"*Error:* {step['result']['error']}\n"
        
#         # Add WebSocket support for real-time updates
#         return JsonResponse({
#             'response': response,
#             'workflow_result': workflow_result,
#             'user_message': user_message
#         })
@csrf_exempt
def process_smart_chat(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    if request.method == 'POST':
        # data = json.loads(request.body)
        # user_message = data.get('message', '')
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)

        user_message = data.get('message')
        if not user_message:
            return JsonResponse({'error': 'Message is required'}, status=400)
        # Initialize smart agent
        agent = SmartAgent()
        print(agent)
        # Process with smart workflow
        workflow_result = agent.process_smart_workflow(user_message)
        
        # Format response
        response = f"🤖 **Smart Agent Result**\n\n"
        response += f"**Goal:** {workflow_result['goal']}\n"
        response += f"**Status:** {workflow_result['final_status']}\n\n"
        
        if workflow_result['final_status'] == 'completed':
            response += f"**Summary:** {workflow_result.get('summary', '')}\n\n"
        
        response += "**Execution Steps:**\n"
        for step in workflow_result['steps']:
            response += f"\n**Step {step['step']}** ({step['type']})\n"
            response += f"*Reasoning:* {step['reasoning']}\n"
            
            if step['type'] == 'bash_command':
                response += f"*Command:* `{step['command']}`\n"
                response += f"*Output:*\n```\n{step['result'].get('output', 'No output')}\n```\n"
                if step['result'].get('error'):
                    response += f"*Error:* {step['result']['error']}\n"
            
            elif step['type'] == 'tool_call':
                response += f"*Tool:* {step['tool_name']}({step['parameters']})\n"
                result = step['result']
                if result.get('success'):
                    response += f"*Success:* {result.get('output', result)}\n"
                else:
                    response += f"*Error:* {result.get('error', 'Unknown error')}\n"
        
        return JsonResponse({
            'response': response,
            'workflow_result': workflow_result,
            'user_message': user_message
        })

class AIReasoningAgent:
    """AI Agent that can reason and use tools for Linux administration"""
    
    def __init__(self, MISTRAL_API_KEY):
        self.client = Mistral(api_key=MISTRAL_API_KEY)
        self.model = "open-mistral-nemo"
        self.tools = AITools()
        self.conversation_history = []
        self.context_memory = {}
        
    def process_admin_request(self, user_request):
        """Process user request with AI reasoning and tool usage"""
        
        # System prompt that defines the AI's role and capabilities
        system_prompt = f"""
        You are an advanced AI Linux System Administrator with access to powerful tools. You can:

        1. REASON through complex problems step by step
        2. USE TOOLS to interact with the system (read files, execute commands, etc.)
        3. LEARN from command outputs and adapt your approach
        4. HANDLE security, configuration, and maintenance tasks

        Available Tools: {[tool for tool in self.tools.tool_registry.keys()]}

        Your approach should be:
        1. Understand the user's request
        2. Plan your approach (what tools you need to use)
        3. Execute step by step using appropriate tools
        4. Validate results and make corrections if needed
        5. Provide clear summary of what was accomplished

        IMPORTANT RULES:
        - Always backup config files before making changes
        - Validate configurations before applying them
        - Check service status after making changes
        - Be security-conscious (never expose sensitive data)
        - Explain your reasoning for each action

        Current system context: {json.dumps(self.context_memory)}

        User Request: {user_request}

        Think step by step and use the appropriate tools to complete this task.
        """

        try:
            # Start conversation with system prompt
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_request}
            ]
            
            # Initialize workflow tracking
            workflow = {
                "request": user_request,
                "steps": [],
                "start_time": time.time(),
                "status": "in_progress"
            }
            
            max_iterations = 10
            iteration = 0
            
            while iteration < max_iterations:
                # Get AI response with tool calling
                response = self.client.chat.complete(
                    model=self.model,
                    messages=messages,
                    tools=self.tools.get_available_tools(),
                    temperature=0.1
                )
                
                choice = response.choices[0]
                
                # Add AI response to conversation
                messages.append({
                    "role": "assistant",
                    "content": choice.message.content,
                    "tool_calls": choice.message.tool_calls if hasattr(choice.message, 'tool_calls') else None
                })
                
                # Check if AI wants to use tools
                if hasattr(choice.message, 'tool_calls') and choice.message.tool_calls:
                    tool_results = []
                    
                    for tool_call in choice.message.tool_calls:
                        function_name = tool_call.function.name
                        function_args = json.loads(tool_call.function.arguments)
                        
                        print(f"🔧 Using tool: {function_name} with args: {function_args}")
                        
                        # Execute the tool
                        if function_name in self.tools.tool_registry:
                            result = self.tools.tool_registry[function_name](**function_args)
                            tool_results.append({
                                "tool": function_name,
                                "args": function_args,
                                "result": result
                            })
                            
                            # Add tool result to conversation
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": json.dumps(result)
                            })
                            
                            # Update context memory
                            self.update_context_memory(function_name, function_args, result)
                        
                    # Add step to workflow
                    workflow["steps"].append({
                        "iteration": iteration + 1,
                        "ai_reasoning": choice.message.content,
                        "tools_used": tool_results,
                        "timestamp": time.time()
                    })
                    
                else:
                    # AI has finished the task
                    workflow["status"] = "completed"
                    workflow["final_response"] = choice.message.content
                    break
                
                iteration += 1
            
            workflow["end_time"] = time.time()
            workflow["duration"] = workflow["end_time"] - workflow["start_time"]
            
            if iteration >= max_iterations:
                workflow["status"] = "max_iterations_reached"
            
            return workflow
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "request": user_request
            }
    
    def update_context_memory(self, tool_name, args, result):
        """Update context memory with important information from tool usage"""
        if tool_name == "service_control":
            service_name = args.get("service_name")
            action = args.get("action")
            if result.get("success"):
                self.context_memory[f"service_{service_name}_status"] = action
        
        elif tool_name == "file_read":
            file_path = args.get("file_path")
            if result.get("success"):
                self.context_memory[f"file_content_{file_path}"] = {
                    "size": result.get("size"),
                    "last_read": time.time()
                }
        
        elif tool_name == "security_scan":
            scan_type = args.get("scan_type")
            if result.get("success"):
                self.context_memory[f"security_scan_{scan_type}"] = {
                    "last_scan": time.time(),
                    "result": result
                }
    
    def stream_process_admin_request(self, user_request):
        """Stream the processing of admin request for real-time updates"""
        for step in self.process_admin_request(user_request):
            yield step

class SmartLinuxAdmin:
    """Main class that integrates everything"""
    
    def __init__(self, MISTRAL_API_KEY):
        self.ai_agent = AIReasoningAgent(MISTRAL_API_KEY)
        self.tools = AITools()
    
    def handle_request(self, user_request):
        """Handle user request with full AI reasoning"""
        print(f"🤖 Processing request: {user_request}")
        
        workflow = self.ai_agent.process_admin_request(user_request)
        
        # Format and return response
        return self.format_workflow_response(workflow)
    
    def format_workflow_response(self, workflow):
        """Format workflow response for display"""
        response = f"## AI Linux Admin - Task Results\n\n"
        response += f"**Request:** {workflow['request']}\n"
        response += f"**Status:** {workflow['status']}\n"
        response += f"**Duration:** {workflow.get('duration', 0):.2f} seconds\n\n"
        
        if workflow.get('steps'):
            response += "### Execution Steps:\n\n"
            for i, step in enumerate(workflow['steps'], 1):
                response += f"**Step {i}:**\n"
                response += f"*AI Reasoning:* {step['ai_reasoning']}\n\n"
                
                if step.get('tools_used'):
                    response += "*Tools Used:*\n"
                    for tool_usage in step['tools_used']:
                        response += f"- **{tool_usage['tool']}** with {tool_usage['args']}\n"
                        response += f"  Result: {tool_usage['result']['success']}\n"
                        if not tool_usage['result']['success']:
                            response += f"  Error: {tool_usage['result'].get('error', 'Unknown error')}\n"
                    response += "\n"
        
        if workflow.get('final_response'):
            response += f"### Final Summary:\n{workflow['final_response']}\n"
        
        return response
@csrf_exempt
def ai_admin_chat(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user_message = data.get('message', '')
        
        # Initialize AI admin
        admin = SmartLinuxAdmin(MISTRAL_API_KEY)
        
        # Process with AI reasoning
        result = admin.handle_request(user_message)
        
        return JsonResponse({
            'response': result,
            'user_message': user_message,
            'timestamp': datetime.now().isoformat()
        })
    
## test2
class MCPClient2:
    """MCP (Model Context Protocol) Client for communicating with MCP servers via existing WebSocket consumer"""
    
    def __init__(self, websocket_consumer=None):
        self.websocket_consumer = websocket_consumer
        self.request_id = 0
        self.pending_requests = {}  # Store pending MCP requests
        
    def setup_consumer(self, websocket_consumer):
        """Setup WebSocket consumer for MCP communication"""
        self.websocket_consumer = websocket_consumer
        
    async def send_to_mcp_server(self, message: dict):
        """Send message to MCP server via WebSocket consumer"""
        if not self.websocket_consumer:
            raise Exception("WebSocket consumer not configured")
        
        # Send via existing WebSocket consumer
        await self.websocket_consumer.send(text_data=json.dumps({
            "type": "mcp_request",
            "data": message
        }))
        
    async def handle_mcp_response(self, response: dict):
        """Handle MCP response from WebSocket consumer"""
        request_id = response.get("id")
        if request_id in self.pending_requests:
            # Resolve pending request
            future = self.pending_requests.pop(request_id)
            future.set_result(response)
        
    async def wait_for_response(self, request_id: int, timeout: int = 30):
        """Wait for MCP response"""
        future = asyncio.Future()
        self.pending_requests[request_id] = future
        
        try:
            response = await asyncio.wait_for(future, timeout=timeout)
            return response
        except asyncio.TimeoutError:
            self.pending_requests.pop(request_id, None)
            raise Exception(f"MCP request {request_id} timed out")
    
    async def send_initialize(self):
        """Send initialize request to MCP server"""
        request_id = self._next_request_id()
        init_request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "sampling": {}
                },
                "clientInfo": {
                    "name": "smart-agent",
                    "version": "1.0.0"
                }
            }
        }
        
        await self.send_to_mcp_server(init_request)
        response = await self.wait_for_response(request_id)
        return response
    
    async def list_tools(self) -> List[Dict]:
        """List available tools from MCP server"""
        request_id = self._next_request_id()
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/list"
        }
        
        await self.send_to_mcp_server(request)
        response = await self.wait_for_response(request_id)
        result = response.get("result", {})
        
        return result.get("tools", [])
    
    async def call_tool(self, tool_name: str, arguments: Dict = None) -> Dict:
        """Call a tool on the MCP server"""
        request_id = self._next_request_id()
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {}
            }
        }
        
        await self.send_to_mcp_server(request)
        response = await self.wait_for_response(request_id)
        
        if "error" in response:
            raise Exception(f"Tool call failed: {response['error']}")
            
        return response.get("result", {})
    
    async def send_prompt(self, messages: List[Dict], model: str = "open-mistral-nemo") -> str:
        """Send prompt to AI model through MCP server"""
        request_id = self._next_request_id()
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "completion/complete",
            "params": {
                "ref": {
                    "type": "ref/prompt",
                    "name": "system-admin"
                },
                "arguments": {
                    "messages": messages,
                    "model": model,
                    "temperature": 0.1,
                    "max_tokens": 1000
                }
            }
        }
        
        await self.send_to_mcp_server(request)
        response = await self.wait_for_response(request_id)
        
        if "error" in response:
            raise Exception(f"Completion failed: {response['error']}")
            
        return response.get("result", {}).get("content", [{}])[0].get("text", "")
    
    def _next_request_id(self) -> int:
        """Generate next request ID"""
        self.request_id += 1
        return self.request_id


class SafeCommandExecutor2:
    """Safe command executor with MCP integration"""
    
    def __init__(self, mcp_client: MCPClient2):
        self.mcp_client = mcp_client
        self.allowed_commands = [
            'ls', 'cat', 'grep', 'find', 'wc', 'head', 'tail', 
            'ps', 'top', 'free', 'df', 'du', 'uptime', 'whoami',
            'pwd', 'which', 'file', 'stat', 'chmod', 'chown',
            'mkdir', 'rmdir', 'cp', 'mv', 'rsync', 'diff',
            'tar', 'gzip', 'gunzip', 'zip', 'unzip'
        ]
    
    async def execute_via_mcp(self, command: str) -> Dict:
        """Execute command through MCP server tools"""
        try:
            # Use MCP shell tool if available
            result = await self.mcp_client.call_tool("shell", {
                "command": command,
                "timeout": 30
            })
            return result
        except Exception as e:
            # Fallback to local execution
            return self.execute_local(command)
    
    def execute_local(self, command: str) -> Dict:
        """Local command execution as fallback"""
        dangerous_patterns = [
            'rm -rf /', 'dd if=', 'mkfs', 'fdisk', 'parted',
            'format', 'del /f', 'deltree', '> /dev/', 'chmod 777 /',
            'chown root /', 'sudo su', 'su -', 'passwd'
        ]
        
        if any(pattern in command.lower() for pattern in dangerous_patterns):
            return {"error": "Dangerous command detected and blocked"}
        
        try:
            result = subprocess.run(
                ['bash', '-c', command],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.getcwd()
            )
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Command: {command}\nOutput: {result.stdout}\nError: {result.stderr}\nReturn code: {result.returncode}"
                    }
                ],
                "isError": result.returncode != 0
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Command timeout (30s)"}
        except Exception as e:
            return {"error": str(e)}


class SmartMCPAgent:
    """Smart Agent using MCP for AI and tool interactions via WebSocket consumer"""
    
    def __init__(self, websocket_consumer=None):
        self.mcp_client = MCPClient2(websocket_consumer)
        self.executor = SafeCommandExecutor2(self.mcp_client)
        self.conversation_history = []
        self.current_goal = None
        self.context_memory = {}
        self.available_tools = []
        
    def setup_consumer(self, websocket_consumer):
        """Setup WebSocket consumer for MCP communication"""
        self.mcp_client.setup_consumer(websocket_consumer)
        
    async def initialize(self):
        """Initialize MCP session and discover tools"""
        if not self.mcp_client.websocket_consumer:
            raise Exception("WebSocket consumer not configured")
        
        # Initialize MCP session
        await self.mcp_client.send_initialize()
        
        # Discover available tools
        self.available_tools = await self.mcp_client.list_tools()
        print(f"Available MCP tools: {[tool['name'] for tool in self.available_tools]}")
        
        return True
    
    async def handle_mcp_response(self, response: dict):
        """Handle MCP response from WebSocket consumer"""
        await self.mcp_client.handle_mcp_response(response)
    
    async def process_smart_workflow(self, user_query: str) -> Dict:
        """Main method to process user query with MCP-based smart workflow"""
        self.current_goal = user_query
        self.conversation_history = [
            {"role": "user", "content": user_query}
        ]
        
        workflow_result = {
            "steps": [],
            "final_status": "in_progress",
            "goal": user_query,
            "start_time": time.time(),
            "mcp_enabled": True
        }
        
        print(f"🤖 Starting MCP smart workflow for: {user_query}")
        
        step_count = 0
        max_steps = 10
        
        while step_count < max_steps:
            print(f"\n--- Step {step_count + 1} ---")
            
            try:
                # Get next action from AI via MCP
                next_action = await self.get_next_action_via_mcp()
                print(f"AI Decision: {next_action}")
                
                if next_action.get("action") == "complete":
                    workflow_result["final_status"] = "completed"
                    workflow_result["summary"] = next_action.get("summary")
                    print("✅ Workflow completed!")
                    break
                    
                elif next_action.get("action") == "execute":
                    command = next_action.get("command")
                    reasoning = next_action.get("reasoning")
                    
                    print(f"Reasoning: {reasoning}")
                    print(f"Executing: {command}")
                    
                    # Execute via MCP
                    execution_result = await self.executor.execute_via_mcp(command)
                    
                    workflow_result["steps"].append({
                        "step": step_count + 1,
                        "reasoning": reasoning,
                        "command": command,
                        "result": execution_result,
                        "timestamp": time.time(),
                        "via_mcp": True
                    })
                    
                    # Feed result back to conversation
                    await self.add_execution_result_to_conversation(command, execution_result)
                    
                    step_count += 1
                    
                elif next_action.get("action") == "use_tool":
                    # Use specific MCP tool
                    tool_name = next_action.get("tool")
                    tool_args = next_action.get("arguments", {})
                    reasoning = next_action.get("reasoning")
                    
                    print(f"Reasoning: {reasoning}")
                    print(f"Using MCP tool: {tool_name}")
                    
                    tool_result = await self.mcp_client.call_tool(tool_name, tool_args)
                    
                    workflow_result["steps"].append({
                        "step": step_count + 1,
                        "reasoning": reasoning,
                        "tool": tool_name,
                        "arguments": tool_args,
                        "result": tool_result,
                        "timestamp": time.time(),
                        "via_mcp": True
                    })
                    
                    await self.add_tool_result_to_conversation(tool_name, tool_result)
                    step_count += 1
                    
                else:
                    workflow_result["final_status"] = "failed"
                    workflow_result["error"] = next_action.get("error", "Unknown error")
                    print(f"❌ Workflow failed: {workflow_result['error']}")
                    break
                    
            except Exception as e:
                workflow_result["final_status"] = "failed"
                workflow_result["error"] = str(e)
                print(f"❌ MCP workflow error: {e}")
                break
        
        workflow_result["end_time"] = time.time()
        workflow_result["duration"] = workflow_result["end_time"] - workflow_result["start_time"]
        
        return workflow_result
    
    async def get_next_action_via_mcp(self) -> Dict:
        """Get next action from AI via MCP"""
        system_prompt = f"""
        You are a smart Linux system administrator AI agent with MCP capabilities.
        Your goal: {self.current_goal}
        
        Available MCP tools: {[tool['name'] for tool in self.available_tools]}
        
        Based on the conversation history, decide the next action:
        
        1. If goal is achieved → {{"action": "complete", "summary": "description"}}
        2. If need to execute shell command → {{"action": "execute", "command": "command", "reasoning": "why"}}  
        3. If need to use specific MCP tool → {{"action": "use_tool", "tool": "tool_name", "arguments": {{}}, "reasoning": "why"}}
        4. If failed → {{"action": "fail", "error": "reason"}}
        
        Be smart and use MCP tools when appropriate:
        - Use 'filesystem' tool for file operations
        - Use 'browser' tool for web research  
        - Use 'database' tool for data queries
        - Use 'shell' tool for system commands
        
        Context memory: {json.dumps(self.context_memory)}
        
        IMPORTANT: Return only valid JSON format.
        """
        
        messages = [
            {"role": "system", "content": system_prompt}
        ] + self.conversation_history
        
        try:
            ai_response = await self.mcp_client.send_prompt(messages)
            
            # Clean and parse JSON response
            if not ai_response.startswith('{'):
                start = ai_response.find('{')
                end = ai_response.rfind('}') + 1
                if start >= 0 and end > start:
                    ai_response = ai_response[start:end]
            
            return json.loads(ai_response)
            
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            print(f"AI Response: {ai_response}")
            return {"action": "fail", "error": f"Invalid JSON response: {str(e)}"}
        except Exception as e:
            return {"action": "fail", "error": str(e)}
    
    async def add_execution_result_to_conversation(self, command: str, result: Dict):
        """Add command execution result to conversation history"""
        self.update_context_memory(command, result)
        
        self.conversation_history.append({
            "role": "assistant", 
            "content": f"Executed command via MCP: {command}"
        })
        
        # Extract result text from MCP response
        if isinstance(result.get("content"), list):
            result_text = ""
            for content in result["content"]:
                if content.get("type") == "text":
                    result_text += content.get("text", "")
        else:
            result_text = str(result)
        
        self.conversation_history.append({
            "role": "user", 
            "content": f"MCP Command result:\n{result_text[:1000]}"
        })
        
        # Keep conversation manageable
        if len(self.conversation_history) > 20:
            self.conversation_history = [self.conversation_history[0]] + self.conversation_history[-18:]
    
    async def add_tool_result_to_conversation(self, tool_name: str, result: Dict):
        """Add MCP tool result to conversation history"""
        self.conversation_history.append({
            "role": "assistant", 
            "content": f"Used MCP tool: {tool_name}"
        })
        
        result_text = json.dumps(result, indent=2)[:1000]
        
        self.conversation_history.append({
            "role": "user", 
            "content": f"MCP Tool result:\n{result_text}"
        })
    
    def update_context_memory(self, command: str, result: Dict):
        """Extract and store important information from results"""
        if isinstance(result.get("content"), list):
            for content in result["content"]:
                if content.get("type") == "text":
                    text = content.get("text", "")
                    
                    # Store various context info
                    if "find" in command and "wc -l" in command:
                        self.context_memory["file_count"] = text.strip()
                    elif command.startswith("df"):
                        self.context_memory["disk_usage"] = text
                    elif command.startswith("ps"):
                        self.context_memory["processes"] = text
                    elif "rsync" in command:
                        self.context_memory["backup_status"] = "success" if not result.get("isError") else "failed"
                    elif command.startswith("ls"):
                        self.context_memory["last_listing"] = text
                    elif command == "pwd":
                        self.context_memory["current_directory"] = text.strip()


# Django views with MCP integration via WebSocket
@csrf_exempt
def process_mcp_smart_chat_view(request):
    """Django view for MCP-based smart chat (WebSocket-based)"""
    if request.method == 'POST':
        data = json.loads(request.body)
        user_message = data.get('message', '')
        
        # Return WebSocket connection info instead of processing directly
        return JsonResponse({
            'message': 'Use WebSocket connection for MCP Smart Agent',
            'websocket_url': 'ws://localhost:8000/ws/mcp-agent/',
            'user_message': user_message,
            'instructions': {
                'connect': 'Connect to WebSocket URL',
                'send': {
                    'type': 'smart_workflow',
                    'message': user_message
                }
            }
        })
    
    return JsonResponse({'error': 'Method not allowed'})


# Traditional HTTP endpoint for backward compatibility
@csrf_exempt
def process_mcp_smart_chat_http(request):
    """HTTP endpoint that creates temporary WebSocket connection"""
    if request.method == 'POST':
        data = json.loads(request.body)
        user_message = data.get('message', '')
        
        # This would need to be implemented with temporary WebSocket connection
        # For now, return instructions to use WebSocket
        return JsonResponse({
            'response': 'MCP Smart Agent requires WebSocket connection for real-time communication',
            'user_message': user_message,
            'websocket_url': 'ws://localhost:8000/ws/mcp-agent/',
            'mcp_enabled': True,
            'instructions': 'Please use WebSocket connection for full MCP functionality'
        })
    
    return JsonResponse({'error': 'Method not allowed'})



from django.db.models import Q

def network_Security(request):
    """Main logs report view with real-time data"""
    recommendations = models.AIRecommendation.objects.all().order_by('-created_at')[:20]
    suricata_logs = models.SuricataLog.objects.all().order_by('-timestamp')[:10]
    blocked_ips = models.BlockedIP.objects.all().order_by('-blocked_at')[:10]
    whitelisted_ips = models.WhitelistedIP.objects.all().order_by('-added_at')[:10]
    
    # Statistics
    total_blocked = models.BlockedIP.objects.count()
    active_blocks = models.BlockedIP.objects.filter(
        Q(blocked_until__gt=timezone.now()) | Q(is_permanent=True)
    ).count()
    
    # AI chat logs with pagination
    ai_chat_log_list = models.ExecutionLog.objects.all().order_by('-created_at')
    paginator = Paginator(ai_chat_log_list, 20)
    page_number = request.GET.get('page')
    ai_chat_logs = paginator.get_page(page_number)
    
    context = {
        'recommendations': recommendations,
        'suricata_logs': suricata_logs,
        'ai_chat_logs': ai_chat_logs,
        'blocked_ips': blocked_ips,
        'whitelisted_ips': whitelisted_ips,
        'total_blocked': total_blocked,
        'active_blocks': active_blocks,
    }
    
    return render(request, "network_security.html", context)

def security_stats_api(request):
    """API endpoint for real-time statistics"""
    stats = {
        'total_blocked': models.BlockedIP.objects.count(),
        'active_blocks': models.BlockedIP.objects.filter(
            Q(blocked_until__gt=timezone.now()) | Q(is_permanent=True)
        ).count(),
        'total_logs': models.SuricataLog.objects.count(),
        'recent_alerts': models.SuricataLog.objects.filter(
            timestamp__gte=timezone.now() - timezone.timedelta(hours=24)
        ).count(),
    }
    
    return JsonResponse(stats)