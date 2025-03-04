import psutil
import socket
import requests
import subprocess
import asyncio
from datetime import datetime
from fastapi import FastAPI, WebSocket
from typing import List

# Coba import pynvml untuk VRAM usage
try:
    from pynvml import nvmlInit, nvmlDeviceGetHandleByIndex, nvmlDeviceGetMemoryInfo, nvmlShutdown
    NVML_AVAILABLE = True
except ImportError:
    NVML_AVAILABLE = False

app = FastAPI()
connections: List[WebSocket] = []  # Menyimpan koneksi WebSocket yang aktif

def get_vram_usage():
    if NVML_AVAILABLE:
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

def get_bandwidth_usage():
    net_io = psutil.net_io_counters()
    return {"rx": round(net_io.bytes_recv / 1024, 2), "tx": round(net_io.bytes_sent / 1024, 2)}

def get_active_connections():
    try:
        output = subprocess.check_output("ss -tun | wc -l", shell=True, text=True).strip()
        return int(output) if output.isdigit() else 0
    except subprocess.CalledProcessError:
        return 0

# def get_running_services():
#     try:
#         output = subprocess.check_output("systemctl list-units --type=service --state=running --no-pager --no-legend", shell=True, text=True)
#         services = [line.split()[0] for line in output.strip().split("\n") if line]
#         return services
#     except subprocess.CalledProcessError:
#         return []
    
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


def get_system_monitor_data():
    
    # Active network connections
    net_stat = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True).stdout

        # Running services
    services = subprocess.run(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
        capture_output=True, text=True
    ).stdout

    return {
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent,
        "vram": get_vram_usage(),
        "network": net_stat,
        "network_overview": {
            "server_ip": socket.gethostbyname(socket.gethostname()),
            "external_ip": get_external_ip(),
            "rx": get_bandwidth_usage()["rx"],
            "tx": get_bandwidth_usage()["tx"],
            "active_connections": get_active_connections(),
            "connected_devices": get_connected_devices(),
        },
        # "services": get_running_services(),
        "services": services,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }

@app.websocket("/ws/system_monitor/")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            if websocket.client_state.name != "CONNECTED":
                break  # Stop sending if WebSocket is no longer connected

            data = get_system_monitor_data()
            await websocket.send_json(data)  # Send data to client
            await asyncio.sleep(1)  # Wait before sending the next update

    except Exception as e:
        print(f"WebSocket error: {e}")
    
    finally:
        if websocket.client_state.name != "CLOSED":
            await websocket.close()  # Ensure WebSocket is properly closed
        print("WebSocket connection closed")