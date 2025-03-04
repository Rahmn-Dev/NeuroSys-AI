import json
import psutil
import socket
import requests
import subprocess
import asyncio  # Import asyncio for async sleep
from datetime import datetime
from channels.generic.websocket import AsyncWebsocketConsumer

# Try importing pynvml for VRAM usage
try:
    from pynvml import nvmlInit, nvmlDeviceGetHandleByIndex, nvmlDeviceGetMemoryInfo, nvmlShutdown
    NVML_AVAILABLE = True
except ImportError:
    NVML_AVAILABLE = False

class SystemMonitorConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        await self.send_system_data()

    async def disconnect(self, close_code):
        pass

    async def send_system_data(self):
        while True:
            data = self.get_system_monitor_data()
            await self.send(text_data=json.dumps(data))
            await asyncio.sleep(1)  # Update every 5 seconds

    def get_system_monitor_data(self):
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
            "vram": self.get_vram_usage(),
            "network": net_stat,
            "network_overview": {
                "server_ip": socket.gethostbyname(socket.gethostname()),
                "external_ip": self.get_external_ip(),
                "rx": self.get_bandwidth_usage()["rx"],
                "tx": self.get_bandwidth_usage()["tx"],
                "active_connections": self.get_active_connections(),
                "connected_devices": self.get_connected_devices(),
            },
            "services": services,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }

    def get_vram_usage(self):
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

    def get_external_ip(self):
        try:
            response = requests.get("https://api64.ipify.org?format=json", timeout=5)
            return response.json().get("ip", "Unknown")
        except requests.RequestException:
            return "Unknown"

    def get_bandwidth_usage(self):
        net_io = psutil.net_io_counters()
        return {"rx": round(net_io.bytes_recv / 1024, 2), "tx": round(net_io.bytes_sent / 1024, 2)}

    def get_active_connections(self):
        try:
            output = subprocess.check_output("ss -tun | wc -l", shell=True, text=True).strip()
            return int(output) if output.isdigit() else 0
        except subprocess.CalledProcessError:
            return 0

    def get_connected_devices(self):
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