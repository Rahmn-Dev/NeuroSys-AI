import json
import psutil
import socket
import requests
import subprocess
import asyncio  # Import asyncio for async sleep
from datetime import datetime
import time
import requests
from asgiref.sync import async_to_sync
from django.core.cache import cache
from channels.generic.websocket import AsyncWebsocketConsumer

# Try importing pynvml for VRAM usage
try:
    from pynvml import nvmlInit, nvmlDeviceGetHandleByIndex, nvmlDeviceGetMemoryInfo, nvmlShutdown
    NVML_AVAILABLE = True
except ImportError:
    NVML_AVAILABLE = False

class SystemMonitorConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_external_ip = None  # Store the last external IP
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
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
            capture_output=True, text=True
        )
        services = []
        lines = result.stdout.split('\n')

        # Filter baris yang tidak relevan (legenda, footer, dll.)
        filtered_lines = [
            line for line in lines
            if not line.startswith("Legend:")  # Hapus legenda
            and not line.startswith("To show all installed unit files")  # Hapus footer
            and not line.endswith("loaded units listed.")  # Hapus jumlah unit
            and not line.strip().startswith("LOAD")  # Hapus header kolom
            and not line.strip().startswith("ACTIVE")
            and not line.strip().startswith("SUB")
            and line.strip()  # Hapus baris kosong
        ]
        for line in filtered_lines:
            parts = line.split()
            if len(parts) < 4:  # Pastikan baris memiliki cukup kolom
                continue

            # Ekstrak informasi layanan
            name = parts[0]
            status = parts[3]
            description = " ".join(parts[4:]) if len(parts) > 4 else "N/A"

            # Tambahkan ke daftar layanan
            services.append({
                'name': name,
                'status': status,
                'description': description
            })

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
        external_ip = self.get_external_ip()
        geolocation = self.get_geolocation_if_changed(external_ip)
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
                "external_ip": external_ip,
                "geolocation": geolocation,
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
    
    def get_geolocation_if_changed(self, current_ip):
        """Fetch geolocation only if the external IP has changed."""
        if current_ip != self.last_external_ip:
            print(f"IP changed from {self.last_external_ip} to {current_ip}. Fetching new geolocation...")
            self.last_external_ip = current_ip  # Update the last external IP
            return self.fetch_geolocation(current_ip)
        else:
            print("External IP has not changed. Using cached geolocation...")
            cache_key = f'geolocation_{current_ip}'
            cached_data = cache.get(cache_key)
            return cached_data if cached_data else {'error': 'No cached geolocation data'}

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

        # Step 2: Get active users and their details using `w -h`
        try:
            w_output = subprocess.check_output("w -h", shell=True, text=True)
            print(f"w -h Output: {w_output}")  # Debug w -h output
            for line in w_output.split("\n"):
                if not line.strip():
                    continue
                parts = line.split()
                print(f"Parsing w -h Line: {line}")  # Debug each line

                # Ensure the line has enough parts
                if len(parts) >= 8:
                    user = parts[0]
                    ip = parts[1]
                    # from_ip = parts[2]
                    login_time = parts[2]
                    jcpu = parts[4]
                    pcpu = parts[5]
                    what1 = parts[6]
                    what2 = " ".join(parts[7:])

                    # Check if the device is already in the list
                    device_exists = False
                    for device in devices:
                        if device["ip"] == ip:
                            device.update({
                                "user": user,
                                "ip": ip,
                                "login": login_time,
                                "idle": "N/A",
                                "jcpu": jcpu,
                                "pcpu": pcpu,
                                "what": what2
                            })
                            device_exists = True
                            break

                    # If the device is not in the list, add it
                    if not device_exists:
                        devices.append({
                            "user": user,
                            "ip": ip,
                            "mac": "N/A",  # MAC address not available without ARP
                            "hostname": "N/A",  # Hostname not available without ARP
                            "login": login_time,
                            "idle": "N/A",
                            "jcpu": jcpu,
                            "pcpu": pcpu,
                           "what": what2
                        })
            # Step 2: Get ARP table for connected devices
    
        except subprocess.CalledProcessError as e:
            print(f"Error running 'w -h': {e}")

        

        print(f"Final Devices: {devices}")  # Debug final devices list
        return devices
    
    def fetch_geolocation(self, ip):
        cache_key = f'geolocation_{ip}'
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=10)
            if response.status_code != 200:
                return {'error': f'Failed to fetch data: {response.status_code}'}
            
            data = response.json()
            if 'error' in data:
                return {'error': data['error']}
            
            # Cache the data for 1 hour
            cache.set(cache_key, data, timeout=3600)
            return data
        
        except requests.exceptions.RequestException as e:
            print(f"Error fetching geolocation data: {e}")
            return {'error': 'Unable to fetch geolocation data'}


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

class ServiceControlConsumer(AsyncWebsocketConsumer):
    async def connect(self):
            await self.accept()
            # Kirim daftar layanan yang sedang berjalan saat koneksi dibuka
            await self.get_running_services()
            

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            action = data.get('action')  # start, stop, restart, reload
            service_name = data.get('service_name')

            if not service_name or not action:
                await self.send(json.dumps({'error': 'Service name and action are required.'}))
                return

            # Jalankan perintah systemctl
            result = await sync_to_async(self.run_systemctl_command)(action, service_name)

            if result['status'] == 'success':
                await self.send(json.dumps({'status': 'success', 'message': result['message']}))
            else:
                await self.send(json.dumps({'status': 'error', 'message': result['message']}))

        except Exception as e:
            await self.send(json.dumps({'status': 'error', 'message': str(e)}))

    def run_systemctl_command(self, action, service_name):
        try:
            command = ['systemctl', action, service_name]
            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode == 0:
                return {'status': 'success', 'message': result.stdout}
            else:
                return {'status': 'error', 'message': result.stderr}

        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    async def get_running_services(self):
        while True:
            try:
                # Jalankan perintah systemctl untuk mendapatkan daftar layanan
                result = subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--all", "--no-pager"],
                    capture_output=True, text=True
                )
                services = []
                lines = result.stdout.split('\n')

                # Filter baris yang tidak relevan (legenda, footer, dll.)
                filtered_lines = [
                    line for line in lines
                    if not line.startswith("Legend:")  # Hapus legenda
                    and not line.startswith("To show all installed unit files")  # Hapus footer
                    and not line.endswith("loaded units listed.")  # Hapus jumlah unit
                    and not line.strip().startswith("LOAD")  # Hapus header kolom
                    and not line.strip().startswith("ACTIVE")
                    and not line.strip().startswith("SUB")
                    and line.strip()  # Hapus baris kosong
                ]

                 # Hitung statistik layanan
                total_services = 0
                active_services = 0
                inactive_services = 0

                # Proses setiap baris yang relevan
                for line in filtered_lines:
                    parts = line.split()
                    if len(parts) < 4:  # Pastikan baris memiliki cukup kolom
                        continue

                    total_services += 1
                    if parts[2] == "active":
                        active_services += 1
                    elif parts[2] == "inactive":
                        inactive_services += 1
                    # Ekstrak informasi layanan
                    name = parts[0]
                    status = parts[3]
                    description = " ".join(parts[4:]) if len(parts) > 4 else "N/A"

                    # Tambahkan ke daftar layanan
                    services.append({
                        'name': name,
                        'status': status,
                        'description': description
                    })

                # Kirim data layanan ke frontend
                await self.send(json.dumps({'status': 'success', 'services': services, "service_stats": {
                    "total": total_services,
                    "active": active_services,
                    "inactive": inactive_services,
                }
                }
                )
                )

            except Exception as e:
                await self.send(json.dumps({'status': 'error', 'message': str(e)}))
            await asyncio.sleep(1)