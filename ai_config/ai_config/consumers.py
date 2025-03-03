import json
import psutil
import socket
import requests
import subprocess
from datetime import datetime
from channels.generic.websocket import AsyncWebsocketConsumer

class SystemMonitorConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        await self.send_system_data()

    async def disconnect(self, close_code):
        pass

    async def send_system_data(self):
        while True:
            data = {
                "cpu": psutil.cpu_percent(),
                "ram": psutil.virtual_memory().percent,
                "vram": get_vram_usage(),
                "disk": psutil.disk_usage('/').percent,
                "network_overview": {
                    "server_ip": socket.gethostbyname(socket.gethostname()),
                    "external_ip": get_external_ip(),
                    "rx": get_bandwidth_usage()["rx"],
                    "tx": get_bandwidth_usage()["tx"],
                    "active_connections": get_active_connections(),
                    "connected_devices": get_connected_devices(),
                },
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }
            await self.send(text_data=json.dumps(data))
            await asyncio.sleep(5)  # Update setiap 5 detik

def get_vram_usage():
    try:
        from pynvml import nvmlInit, nvmlDeviceGetHandleByIndex, nvmlDeviceGetMemoryInfo, nvmlShutdown
        nvmlInit()
        handle = nvmlDeviceGetHandleByIndex(0)
        info = nvmlDeviceGetMemoryInfo(handle)
        vram_usage = (info.used / info.total) * 100
        nvmlShutdown()
        return round(vram_usage, 2)
    except:
        return "N/A"

def get_external_ip():
    try:
        response = requests.get("https://api64.ipify.org?format=json", timeout=5)
        return response.json().get("ip", "Unknown")
    except:
        return "Unknown"

def get_bandwidth_usage():
    net_io = psutil.net_io_counters()
    return {"rx": round(net_io.bytes_recv / 1024, 2), "tx": round(net_io.bytes_sent / 1024, 2)}

def get_active_connections():
    try:
        output = subprocess.check_output("ss -tun | wc -l", shell=True, text=True).strip()
        return int(output) if output.isdigit() else 0
    except:
        return 0

def get_connected_devices():
    devices = []
    try:
        arp_output = subprocess.check_output("arp -a", shell=True, text=True)
        for line in arp_output.split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                devices.append({"ip": parts[0], "mac": parts[1], "hostname": parts[-1] if len(parts) > 3 else "Unknown"})
    except:
        pass
    return devices