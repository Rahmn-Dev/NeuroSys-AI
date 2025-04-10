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


@login_required
def chatAI(request):
    return render(request,"generator/textGenerator.html",{'headTitle' : 'Chat AI','toggle' : "true"})

@login_required
def index(request):
    return render(request, "index.html")

@login_required
def dashboard(request):
    return render(request, "dashboard.html", { 'headTitle':'Dashboard' })


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