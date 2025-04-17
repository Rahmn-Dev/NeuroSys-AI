import json
import psutil
import socket
import requests
import subprocess
import asyncio  # Import asyncio for async sleep
from datetime import datetime
import time
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

        # Get total CPU cores and frequency
        cpu_info = {
            "cores": psutil.cpu_count(logical=True),
            "frequency": round(psutil.cpu_freq().current / 1000, 2) if psutil.cpu_freq() else "N/A",
        }

        # Get total RAM in GB
        ram_info = {
            "total": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        }

        # Get total disk space in GB
        disk_info = {
            "total": round(psutil.disk_usage('/').total / (1024 ** 3), 2),
        }

        # Get total VRAM in GB
        vram_info = {
            "total": self.get_total_vram(),
        }

        return {
            "cpu": psutil.cpu_percent(),
            "cpu_info": cpu_info,
            "ram": psutil.virtual_memory().percent,
            "ram_info": ram_info,
            "disk": psutil.disk_usage('/').percent,
            "disk_info": disk_info,
            "vram": self.get_vram_usage(),
            "vram_info": vram_info,
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
    def get_total_vram(self):
        if NVML_AVAILABLE:
            try:
                nvmlInit()
                handle = nvmlDeviceGetHandleByIndex(0)
                info = nvmlDeviceGetMemoryInfo(handle)
                total_vram = round(info.total / (1024 ** 3), 2)  # Convert bytes to GB
                nvmlShutdown()
                return total_vram
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
    



import re
from datetime import datetime

# Regex pattern untuk parsing log Suricata
LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)'
    r'\s+\[\*\*\]\s+\[(?P<sid>\d+):(?P<gid>\d+):(?P<rev>\d+)\]\s+(?P<message>[^\[]+)'
    r'\[\*\*\]\s+\[Classification:\s+(?P<classification>[^\]]+)\]'
    r'\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}'
    r'\s+(?P<source_ip>\S+):(?P<source_port>\d+)\s+->\s+(?P<destination_ip>\S+):(?P<destination_port>\d+)$'
)

def parse_suricata_log(line):
    match = LOG_PATTERN.match(line)
    if not match:
        return None  # Return None jika log tidak sesuai format

    data = match.groupdict()
    # Convert timestamp to datetime object
    data['timestamp'] = datetime.strptime(data['timestamp'], '%m/%d/%Y-%H:%M:%S.%f')
    # Convert priority to integer
    data['priority'] = int(data['priority'])
    # Convert source and destination ports to integers
    data['source_port'] = int(data['source_port'])
    data['destination_port'] = int(data['destination_port'])

    return data

from asgiref.sync import sync_to_async  # Import sync_to_async

class SuricataLogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        await self.send_suricata_logs()

    async def disconnect(self, close_code):
        pass

    async def send_suricata_logs(self):
        log_file = "/var/log/suricata/fast.log"
        async for new_line in self.tail_log(log_file):  # Gunakan async for
            if new_line is None:  # Skip empty lines
                continue
            parsed_data = parse_suricata_log(new_line.strip())
            if not parsed_data:
                continue 
            if parsed_data['priority'] not in [1, 2]:
                continue
            from chatbot.models import SuricataLog
            # Use sync_to_async to save the log asynchronously
            await sync_to_async(SuricataLog.objects.create)(
                timestamp=parsed_data['timestamp'],
                message=parsed_data['message'],
                severity="High" if parsed_data['priority'] >= 3 else "Low",  # Contoh logika severity
                source_ip=parsed_data['source_ip'],
                source_port=parsed_data['source_port'],
                destination_ip=parsed_data['destination_ip'],
                destination_port=parsed_data['destination_port'],
                protocol=parsed_data['protocol'],
                classification=parsed_data['classification'],
                priority=parsed_data['priority'],
            )
            
            # Send the log message to the WebSocket client
            await self.send(text_data=json.dumps({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": new_line.strip()
            }))
            await asyncio.sleep(0.1)  # Small delay to avoid overload

    async def tail_log(self, file_path):
        with open(file_path, 'r') as file:
            # Move to the end of the file
            file.seek(0, 2)
            while True:
                line = file.readline()
                if not line:
                    await asyncio.sleep(0.1)  # Use asyncio.sleep instead of time.sleep
                    continue
                yield line.strip()