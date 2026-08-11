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
from channels.layers import get_channel_layer
from asgiref.sync import sync_to_async
from django.utils import timezone
import base64
import traceback
from asgiref.sync import sync_to_async
from django.conf import settings
from importlib import import_module

import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ai_config.settings")
django.setup()
# Try importing pynvml for VRAM usage
try:
    from pynvml import nvmlInit, nvmlDeviceGetHandleByIndex, nvmlDeviceGetMemoryInfo, nvmlShutdown
    NVML_AVAILABLE = True
except ImportError:
    NVML_AVAILABLE = False

import json
from datetime import datetime

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)
    
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
        print(result)
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
            if parsed_data['priority'] not in [1]:
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

                # Hitung statistik layanan
                total_services = 0
                active_services = 0
                inactive_services = 0
                failed_services = 0

                # Proses setiap baris
                for line in lines:
                    # Skip baris kosong
                    if not line.strip():
                        continue
                    
                    # Skip header dan footer
                    if (line.strip().startswith("UNIT") or 
                        line.strip().startswith("Legend:") or 
                        line.strip().startswith("To show all installed unit files") or 
                        "loaded units listed" in line or
                        line.strip().startswith("LOAD") or
                        line.strip().startswith("ACTIVE") or
                        line.strip().startswith("SUB")):
                        continue

                    # Clean line dari karakter bullet point dan whitespace berlebih
                    clean_line = line.replace("●", "").strip()
                    
                    # Split berdasarkan whitespace
                    parts = clean_line.split()
                    
                    # Pastikan baris memiliki minimal 4 kolom (UNIT, LOAD, ACTIVE, SUB)
                    if len(parts) < 4:
                        continue

                    # Pastikan ini baris service yang valid
                    if not parts[0].endswith('.service'):
                        continue

                    total_services += 1
                    
                    # Ekstrak informasi layanan
                    name = parts[0]
                    load_state = parts[1]
                    active_state = parts[2] 
                    sub_state = parts[3]
                    description = " ".join(parts[4:]) if len(parts) > 4 else "N/A"

                    # Hitung statistik berdasarkan active state
                    if active_state == "active":
                        active_services += 1
                    elif active_state == "inactive":
                        inactive_services += 1
                    elif active_state == "failed":
                        failed_services += 1

                    # Tentukan status overall
                    if active_state == "failed" or sub_state == "failed":
                        status = "failed"
                    elif active_state == "active":
                        status = "running"
                    elif load_state == "not-found":
                        status = "not-found"
                    else:
                        status = "stopped"

                    # Tambahkan ke daftar layanan
                    services.append({
                        'name': name,
                        'status': status,
                        'active_state': active_state,
                        'sub_state': sub_state,
                        'load_state': load_state,
                        'description': description
                    })

                # Kirim data layanan ke frontend
                await self.send(json.dumps({
                    'status': 'success', 
                    'services': services, 
                    'service_stats': {
                        "total": total_services,
                        "active": active_services,
                        "inactive": inactive_services,
                        "failed": failed_services
                    }
                }))

            except Exception as e:
                await self.send(json.dumps({'status': 'error', 'message': str(e)}))
            
            await asyncio.sleep(1)


# baru ==========================

class MCPSmartAgentConsumer(AsyncWebsocketConsumer):
    """WebSocket Consumer for MCP Smart Agent communication"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.smart_agent = None
        self.mcp_server_websocket = None
        self.room_group_name = None
        
    async def connect(self):
        """Handle WebSocket connection"""
        from .views import SmartMCPAgent
        # Accept the WebSocket connection
        await self.accept()
        
        # Create room group for this user
        self.room_group_name = f"mcp_agent_{self.scope['user'].id if self.scope.get('user') else 'anonymous'}"
        
        # Add to room group
        # await self.channel_layer.group_add(
        #     self.room_group_name,
        #     self.channel_name
        # )
        
        # Initialize Smart Agent with this consumer
        self.smart_agent = SmartMCPAgent()
        self.smart_agent.setup_consumer(self)
        
        # Connect to MCP server
        await self.connect_to_mcp_server()
        
        # Send connection success
        await self.send(text_data=json.dumps({
            'type': 'connection_status',
            'status': 'connected',
            'message': 'MCP Smart Agent connected'
        }))
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        # Disconnect from MCP server
        if self.mcp_server_websocket:
            await self.mcp_server_websocket.close()
        
        # Remove from room group
        # if self.room_group_name:
        #     await self.channel_layer.group_discard(
        #         self.room_group_name,
        #         self.channel_name
        #     )
    
    async def connect_to_mcp_server(self):
        """Connect to actual MCP server"""
        try:
            import websockets
            self.mcp_server_websocket = await websockets.connect("ws://localhost:8080/mcp")
            
            # Start listening to MCP server responses
            asyncio.create_task(self.listen_to_mcp_server())
            
            # Initialize MCP session
            await self.smart_agent.initialize()
            
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Failed to connect to MCP server: {str(e)}'
            }))
    
    async def listen_to_mcp_server(self):
        """Listen to responses from MCP server"""
        try:
            async for message in self.mcp_server_websocket:
                mcp_response = json.loads(message)
                
                # Handle MCP response in smart agent
                await self.smart_agent.handle_mcp_response(mcp_response)
                
                # Forward MCP response to client if needed
                await self.send(text_data=json.dumps({
                    'type': 'mcp_response',
                    'data': mcp_response
                }))
                
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'MCP server connection error: {str(e)}'
            }))
    
    async def receive(self, text_data):
        """Handle messages from WebSocket client"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'smart_workflow':
                # Process smart workflow request
                await self.handle_smart_workflow(data)
                
            elif message_type == 'mcp_request':
                # Forward MCP request to server
                await self.handle_mcp_request(data)
                
            elif message_type == 'ping':
                # Handle ping
                await self.send(text_data=json.dumps({
                    'type': 'pong',
                    'timestamp': data.get('timestamp')
                }))
                
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))
    
    async def handle_smart_workflow(self, data):
        """Handle smart workflow request"""
        user_query = data.get('message', '')
        
        if not user_query:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'No message provided'
            }))
            return
        
        # Send workflow started status
        await self.send(text_data=json.dumps({
            'type': 'workflow_status',
            'status': 'started',
            'goal': user_query
        }))
        
        try:
            # Process smart workflow
            workflow_result = await self.smart_agent.process_smart_workflow(user_query)
            
            # Send workflow result
            await self.send(text_data=json.dumps({
                'type': 'workflow_result',
                'result': workflow_result,
                'formatted_response': self.format_workflow_response(workflow_result)
            }))
            
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'workflow_error',
                'error': str(e)
            }))
    
    async def handle_mcp_request(self, data):
        """Handle direct MCP request"""
        mcp_data = data.get('data', {})
        
        if self.mcp_server_websocket:
            try:
                await self.mcp_server_websocket.send(json.dumps(mcp_data))
            except Exception as e:
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': f'Failed to send MCP request: {str(e)}'
                }))
    
    def format_workflow_response(self, workflow_result):
        """Format workflow result for display"""
        response = f"🤖 **MCP Smart Agent Result**\\n\\n"
        response += f"**Goal:** {workflow_result['goal']}\\n"
        response += f"**Status:** {workflow_result['final_status']}\\n"
        response += f"**MCP Enabled:** ✅\\n\\n"
        
        if workflow_result['final_status'] == 'completed':
            response += f"**Summary:** {workflow_result.get('summary', '')}\\n\\n"
        
        response += "**Execution Steps:**\\n"
        for step in workflow_result['steps']:
            response += f"\\n**Step {step['step']}**\\n"
            response += f"*Reasoning:* {step['reasoning']}\\n"
            
            if 'command' in step:
                response += f"*Command:* `{step['command']}`\\n"
            elif 'tool' in step:
                response += f"*MCP Tool:* `{step['tool']}`\\n"
                response += f"*Arguments:* {json.dumps(step['arguments'])}\\n"
            
            # Format result
            result = step['result']
            if isinstance(result.get('content'), list):
                for content in result['content']:
                    if content.get('type') == 'text':
                        response += f"*Output:*\\n```\\n{content['text'][:500]}...\\n```\\n"
            else:
                response += f"*Output:*\\n```\\n{str(result)[:500]}...\\n```\\n"
        
        return response
    
    # Group message handlers
    async def mcp_broadcast(self, event):
        """Handle broadcast messages to MCP group"""
        await self.send(text_data=json.dumps({
            'type': 'broadcast',
            'message': event['message']
        }))


# Additional consumer for MCP server proxy
class MCPServerProxyConsumer(AsyncWebsocketConsumer):
    """WebSocket Consumer that acts as proxy to MCP server"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mcp_server_websocket = None
        
    async def connect(self):
        await self.accept()
        
        # Connect to actual MCP server
        try:
            import websockets
            self.mcp_server_websocket = await websockets.connect("ws://localhost:8080/mcp")
            
            # Start bidirectional proxy
            asyncio.create_task(self.proxy_from_mcp_server())
            
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Failed to connect to MCP server: {str(e)}'
            }))
            await self.close()
    
    async def disconnect(self, close_code):
        if self.mcp_server_websocket:
            await self.mcp_server_websocket.close()
    
    async def receive(self, text_data):
        """Forward messages to MCP server"""
        if self.mcp_server_websocket:
            try:
                await self.mcp_server_websocket.send(text_data)
            except Exception as e:
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': f'Failed to forward to MCP server: {str(e)}'
                }))
    
    async def proxy_from_mcp_server(self):
        """Forward messages from MCP server to client"""
        try:
            async for message in self.mcp_server_websocket:
                await self.send(text_data=message)
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'MCP server proxy error: {str(e)}'
            }))


# Utility functions for MCP integration
async def broadcast_to_mcp_agents(message, user_id=None):
    """Broadcast message to all MCP agents or specific user"""
    channel_layer = get_channel_layer()
    
    if user_id:
        group_name = f"mcp_agent_{user_id}"
    else:
        group_name = "mcp_agents_all"
    
    await channel_layer.group_send(
        group_name,
        {
            'type': 'mcp_broadcast',
            'message': message
        }
    )

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        import json
        await self.send(text_data=json.dumps({
            "type": "status",
            "content": "✅ Connected to Antigravity AI Agent."
        }))

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        import json
        from .agent_core import AntigravitySysAdmin
        
        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            return 

        user_message = data.get("message")
        if not user_message:
            return
            
        session_id = data.get("session_id")
        if not session_id:
            session_id = self.scope["session"].session_key or "default_session"
            
        agent = AntigravitySysAdmin(session_id)
        provider = data.get("provider", "gemini")

        try:
            # Stream dari agent (di mana agent akan me-yield token/progress)
            async for step in agent.stream_workflow(user_message, provider=provider):
                await self.send(text_data=json.dumps(step))
        except Exception as e:
            import traceback
            traceback.print_exc()
            await self.send(text_data=json.dumps({
                "type": "error",
                "content": f"Workflow Error: {str(e)}"
            }))


import threading
class TerminalConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        loop = asyncio.get_event_loop()
        self.polling_task = None
        self.last_cwd = None

        def handle_output(output):
            asyncio.run_coroutine_threadsafe(
                self.send(text_data=json.dumps({"type": "output", "data": output})),
                loop
            )

        from .terminal_utils import start_shell
        self.shell_writer, self.shell_process, self.shell_pid = start_shell(handle_output)
        self.handle_input = lambda data: self.shell_writer(data)

        # Start CWD polling task
        self.polling_task = asyncio.create_task(self.poll_cwd())

    async def poll_cwd(self):
        import os
        while True:
            try:
                # Read CWD of the bash shell process
                cwd = os.readlink(f"/proc/{self.shell_pid}/cwd")
                if cwd != self.last_cwd:
                    self.last_cwd = cwd
                    await self.send(text_data=json.dumps({"type": "cwd", "cwd": cwd}))
            except Exception:
                pass
            await asyncio.sleep(1)

    async def disconnect(self, close_code):
        print("WebSocket disconnected")
        if self.polling_task:
            self.polling_task.cancel()
        try:
            if hasattr(self, 'shell_process'):
                self.shell_process.terminate()
        except Exception as e:
            print(f"Error during termination: {e}")

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            if data.get("type") == "input":
                self.handle_input(data.get("data", ""))
            elif data.get("type") == "resize":
                try:
                    cols = data.get("cols", 80)
                    rows = data.get("rows", 24)
                    if hasattr(self, 'shell_process'):
                        self.shell_process.setwinsize(rows, cols)
                except Exception as e:
                    print(f"Resize error: {e}")
        except json.JSONDecodeError:
            print("Invalid JSON")

from channels.db import database_sync_to_async


class SecurityConsumer(AsyncWebsocketConsumer):
       
    async def connect(self):
        await self.channel_layer.group_add(
            "security_alerts",
            self.channel_name
        )
        await self.accept()
        
        # Send initial data
        await self.send_initial_data()
        
        # Kirim stats saat pertama kali connect
        await self.send_security_stats()

        # Mulai pengiriman periodik
        asyncio.create_task(self.send_periodic_stats())

    async def send_periodic_stats(self):
        while True:
            try:
                await self.send_security_stats()
                await asyncio.sleep(1)  # Kirim setiap 30 detik
            except Exception as e:
                print("Error sending periodic stats:", str(e))
                break
    async def disconnect(self, close_code):
        # Leave security alerts group
        await self.channel_layer.group_discard(
            "security_alerts",
            self.channel_name
        )
    
    async def receive(self, text_data):
        """Handle incoming WebSocket messages"""
        try:
            text_data_json = json.loads(text_data)
            action = text_data_json.get('action')
            
            if action == 'manual_block':
                await self.handle_manual_block(text_data_json)
            elif action == 'unblock_ip':
                await self.handle_unblock_ip(text_data_json)
            elif action == 'add_whitelist':
                await self.handle_add_whitelist(text_data_json)
                
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'error': 'Invalid JSON'
            }))
    
    async def handle_manual_block(self, data):
        """Handle manual IP blocking via WebSocket"""
        ip_address = data.get('ip_address')
        reason = data.get('reason', 'Manual block via WebSocket')
        permanent = data.get('permanent', False)
        
        if ip_address:
            result = await self.manual_block_ip(ip_address, reason, permanent)
            await self.send(text_data=json.dumps({
                'action': 'manual_block_response',
                'success': result['success'],
                'message': result['message']
            }))
    
    async def handle_unblock_ip(self, data):
        """Handle IP unblocking via WebSocket"""
        ip_address = data.get('ip_address')
        
        if ip_address:
            result = await self.unblock_ip(ip_address)
            await self.send(text_data=json.dumps({
                'action': 'unblock_response',
                'success': result['success'],
                'message': result['message']
            }))
    
    async def handle_add_whitelist(self, data):
        """Handle adding IP to whitelist via WebSocket"""
        ip_address = data.get('ip_address')
        description = data.get('description', 'Added via WebSocket')
        
        if ip_address:
            result = await self.add_to_whitelist(ip_address, description)
            await self.send(text_data=json.dumps({
                'action': 'whitelist_response',
                'success': result['success'],
                'message': result['message']
            }))
    
    @database_sync_to_async
    def manual_block_ip(self, ip_address, reason, permanent):
        """Database operation for manual blocking"""
        from .security_service import SecurityService
        from chatbot.models import BlockedIP, WhitelistedIP
        
        try:
            if SecurityService.is_whitelisted(ip_address):
                return {'success': False, 'message': f'IP {ip_address} is whitelisted'}
            
            if SecurityService.is_already_blocked(ip_address):
                return {'success': False, 'message': f'IP {ip_address} is already blocked'}
            
            if SecurityService.block_ip_iptables(ip_address, permanent):
                blocked_until = None if permanent else timezone.now() + timezone.timedelta(hours=24)
                
                BlockedIP.objects.create(
                    ip_address=ip_address,
                    reason=reason,
                    is_permanent=permanent,
                    blocked_until=blocked_until
                )
                
                return {'success': True, 'message': f'IP {ip_address} blocked successfully'}
            else:
                return {'success': False, 'message': f'Failed to block IP {ip_address}'}
                
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    @database_sync_to_async
    def unblock_ip(self, ip_address):
        """Database operation for unblocking"""
        from .security_service import SecurityService
        from chatbot.models import BlockedIP
        
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
            if SecurityService.unblock_ip_iptables(ip_address):
                blocked_ip.delete()
                return {'success': True, 'message': f'IP {ip_address} unblocked successfully'}
            else:
                return {'success': False, 'message': f'Failed to unblock IP {ip_address}'}
        except BlockedIP.DoesNotExist:
            return {'success': False, 'message': f'IP {ip_address} not found in blocked list'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    @database_sync_to_async
    def add_to_whitelist(self, ip_address, description):
        """Database operation for whitelisting"""
        from chatbot.models import WhitelistedIP
        
        try:
            whitelist_ip, created = WhitelistedIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={'description': description}
            )
            
            if created:
                return {'success': True, 'message': f'IP {ip_address} added to whitelist'}
            else:
                return {'success': False, 'message': f'IP {ip_address} already in whitelist'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    @database_sync_to_async
    def get_initial_data(self):
        """Get initial data for WebSocket connection"""
        from chatbot.models import BlockedIP, SuricataLog
        
        blocked_ips = list(BlockedIP.objects.values(
            'ip_address', 'reason', 'blocked_at', 'is_permanent'
        ).order_by('-blocked_at')[:10])
        
        recent_logs = list(SuricataLog.objects
            .values('timestamp', 'message', 'source_ip', 'classification', 'priority')
            .order_by('-timestamp')[:5]
        )

        # Convert datetime to string
        for log in recent_logs:
            if isinstance(log['timestamp'], datetime):
                log['timestamp'] = log['timestamp'].isoformat()
        return {
            'blocked_ips': blocked_ips,
            'recent_logs': recent_logs
        }
    
    async def send_initial_data(self):
        """Send initial data when client connects"""
        data = await self.get_initial_data()
        await self.send(text_data=json.dumps({
            'type': 'initial_data',
            'data': data
        },  cls=CustomJSONEncoder))
    
    # Handle messages from group
    async def security_alert(self, event):
        """Handle security alert messages from group"""
        await self.send(text_data=json.dumps({
            'type': event['message_type'],
            'data': event['data']
        }, cls=CustomJSONEncoder))
    
    async def send_security_stats(self):
        """Ambil statistik terbaru dan kirim via WebSocket"""
        stats = await self.get_security_stats()
        await self.send(text_data=json.dumps({
            'type': 'security_stats',
            'data': stats
        }))

    @database_sync_to_async
    def get_security_stats(self):
        from django.db.models import Q, Count
        from chatbot.models import BlockedIP, SuricataLog
        return {
            'total_blocked': BlockedIP.objects.count(),
            'active_blocks': BlockedIP.objects.filter(
                Q(blocked_until__gt=timezone.now()) | Q(is_permanent=True)
            ).count(),
            'total_logs': SuricataLog.objects.count(),
            'recent_alerts': SuricataLog.objects.filter(
                timestamp__gte=timezone.now() - timezone.timedelta(hours=24)
            ).count(),
                'details': {
                'source_ips': list(
                    SuricataLog.objects.values('source_ip')
                    .annotate(count=Count('id'))
                    .order_by('-count')
                ),
                'destination_ips': list(
                    SuricataLog.objects.values('destination_ip')
                    .annotate(count=Count('id'))
                    .order_by('-count')
                ),
                'source_ports': list(
                    SuricataLog.objects.values('source_port')
                    .annotate(count=Count('id'))
                    .order_by('-count')
                ),
                'destination_ports': list(
                    SuricataLog.objects.values('destination_port')
                    .annotate(count=Count('id'))
                    .order_by('-count')
                ),
                'protocols': list(
                    SuricataLog.objects.values('protocol')
                    .annotate(count=Count('id'))
                    .order_by('-count')
                ),
                'classifications': list(
                    SuricataLog.objects.values('classification')
                    .annotate(count=Count('id'))
                    .order_by('-count')
                ),
                'severities': list(
                    SuricataLog.objects.values('severity')
                    .annotate(count=Count('id'))
                    .order_by('-count')
                ),
                'priorities': list(
                    SuricataLog.objects.values('priority')
                    .annotate(count=Count('id'))
                    .order_by('-count')
                ),
            }
        }
    
from dataset.IntrusionDetection.detector import predict_intrusion

class AiIntrusionLogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Masuk ke group untuk broadcast alert ke dashboard
        await self.channel_layer.group_add("ai_intrusion_logs", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("ai_intrusion_logs", self.channel_name)

    # MENERIMA DATA DARI AGENT (real_time.py)
    # 1. MENERIMA DATA DARI SNIFFER (direct_sniffer.py)
    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            features = data.get('features')
            
            # Ambil Info IP (Biar gak Unknown)
            src_ip = data.get('src_ip', 'Unknown')
            dst_ip = data.get('dst_ip', 'Unknown')
            proto = data.get('proto', 'TCP')

            if features:
                # Debug Print di Terminal Django (Biar kelihatan kalau data masuk)
                print(f"[WS RECEIVE] {src_ip} -> {dst_ip} | Features: {features}")

                # Prediksi
                result = await sync_to_async(predict_intrusion)(features)
                print(f"[WS DEBUG] Prediction Result: {result}")
                # Jika BUKAN Benign, Simpan & Broadcast
                if result.upper() != "BENIGN":
                    from chatbot.models import AIIntrusionLog
                    
                    # Simpan ke Database
                    intrusion = await sync_to_async(AIIntrusionLog.objects.create)(
                        result=result,
                        raw_features=features,
                        # Pastikan models.py kamu punya field ini, kalau tidak hapus baris src_ip/dest_ip
                        src_ip=src_ip,       
                        destination_ip=dst_ip 
                    )

                    # Struktur Pesan untuk Frontend
                    response_payload = {
                        "type": "send_intrusion_log", # <--- PENTING BUAT JS
                        "data": {
                            "id": intrusion.id,
                            "result": intrusion.result,
                            "timestamp": datetime.now().isoformat(),
                            "features": features,
                            "src_ip": src_ip,       # Kirim IP ke Frontend
                            "destination_ip": dst_ip
                        }
                    }
                    
                    # Broadcast ke Group
                    await self.channel_layer.group_send(
                        "ai_intrusion_logs",
                        response_payload
                    )
                    
                    # Balas ke Sniffer (Optional)
                    await self.send(text_data=json.dumps({"status": "ALERT", "label": result}))

        except Exception as e:
            print(f"WS Error: {e}")

    # 2. MENGIRIM DATA KE FRONTEND (Browser)
    async def send_intrusion_log(self, event):
        print(f"[WS DEBUG] Sending to Browser: {event}")
        # PERBAIKAN UTAMA: Kirim seluruh event, JANGAN cuma event["data"]
        await self.send(text_data=json.dumps(event))


# ---------------------------------------------------------------------------
# SRE Agent Consumer — WebSocket for the new agent framework
# ---------------------------------------------------------------------------

class SREAgentConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for the NeuroSysAI SRE Agent.
    Connects to /ws/sre-agent/ and streams structured agent events.
    """

    async def connect(self):
        await self.accept()
        
        # Generate RSA Key Pair for E2E Sudo Auth
        from sre_agent.crypto import generate_rsa_key_pair
        self.rsa_private_key, public_pem = generate_rsa_key_pair()
        self.encrypted_sudo_pwd = ""
        
        await self.send(text_data=json.dumps({
            "type": "sudo_key_exchange",
            "public_key": public_pem
        }))
        
        await self.send(text_data=json.dumps({
            "type": "status",
            "content": "🚀 Connected to NeuroSysAI SRE Agent."
        }))

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                "type": "error",
                "content": "Invalid JSON payload."
            }))
            return

        msg_type = data.get("type", "message")

        if msg_type == "message":
            await self._handle_message(data)
        elif msg_type == "approval":
            await self._handle_approval(data)
        elif msg_type == "set_sudo_pwd":
            self.encrypted_sudo_pwd = data.get("encrypted_password", "")
            await self.send(text_data=json.dumps({
                "type": "status",
                "content": "🔒 Sudo password securely received (End-to-End Encrypted)."
            }))
        else:
            await self.send(text_data=json.dumps({
                "type": "error",
                "content": f"Unknown message type: {msg_type}"
            }))

    async def _handle_message(self, data):
        """Handle a user chat message — run the SRE agent loop."""
        user_message = data.get("message", "").strip()
        if not user_message:
            return

        session_id = data.get("session_id", "")
        terminal_cwd = data.get("terminal_cwd", None)
        active_workspace = data.get("active_workspace", None)
        selected_file = data.get("selected_file", None)
        selected_file_name = data.get("selected_file_name", None)
        model_name = data.get("model", "mistral-large-latest")
        mode = data.get("mode", "guided")

        try:
            from sre_agent.engine import SREAgentEngine

            engine = SREAgentEngine(
                session_id=session_id, 
                model_name=model_name,
                rsa_private_key=self.rsa_private_key,
                encrypted_sudo_pwd=self.encrypted_sudo_pwd
            )

            async for event in engine.run(
                user_message,
                terminal_cwd=terminal_cwd,
                active_workspace=active_workspace,
                selected_file=selected_file,
                selected_file_name=selected_file_name,
                mode=mode
            ):
                await self.send(text_data=json.dumps(event.to_dict()))

        except Exception as e:
            import traceback
            traceback.print_exc()
            await self.send(text_data=json.dumps({
                "type": "error",
                "content": f"Agent Error: {str(e)}"
            }))

    async def _handle_approval(self, data):
        """Handle user approval for HIGH-risk tool execution."""
        # For now, acknowledge the approval — full approval flow can be
        # implemented when the frontend supports it.
        approved = data.get("approved", False)
        tool_name = data.get("tool", "unknown")
        await self.send(text_data=json.dumps({
            "type": "status",
            "content": f"{'✅ Approved' if approved else '❌ Rejected'}: {tool_name}"
        }))
class ArchitectureConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        from sre_agent.crypto import generate_rsa_key_pair
        self.rsa_private_key, public_pem = generate_rsa_key_pair()
        await self.accept()
        await self.send(text_data=json.dumps({
            "type": "arch_sudo_key_exchange",
            "public_key": public_pem
        }))

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
        except json.JSONDecodeError:
            return

        msg_type = data.get("type")

        if msg_type == "load_cache":
            await self._handle_load_cache()
        elif msg_type == "generate":
            import asyncio
            asyncio.create_task(self._handle_generate(data.get("model_id", "mistral:latest"), data.get("encrypted_password", "")))
        elif msg_type == "status_update":
            await self._handle_status_update(data.get("services", []))

    async def _handle_load_cache(self):
        from chatbot.models import SystemArchitectureCache
        from asgiref.sync import sync_to_async
        cache = await sync_to_async(lambda: SystemArchitectureCache.objects.order_by('-updated_at').first())()
        
        if cache and cache.mermaid_diagram:
            elements_data = cache.mermaid_diagram
                
            try:
                services_data = json.loads(cache.services_json) if cache.services_json else {}
                if isinstance(services_data, list):
                    # Migration from old format where services_json was just a list
                    services_data = {"services": services_data}
            except Exception:
                services_data = {}
                
            await self.send(text_data=json.dumps({
                "type": "arch_result",
                "data": {
                    "mermaid_diagram": elements_data,
                    "services": services_data.get("services", []),
                    "network": services_data.get("network", {}),
                    "infrastructure": services_data.get("infrastructure", {}),
                    "dependencies": services_data.get("dependencies", []),
                    "security": services_data.get("security", {}),
                    "insights": json.loads(cache.insights_json) if cache.insights_json else []
                },
                "cached": True
            }))
        else:
            await self.send(text_data=json.dumps({
                "type": "arch_not_found"
            }))

    async def _handle_status_update(self, services):
        import asyncio
        updated_services = []
        for s in services:
            service_name = s.get("name")
            if service_name:
                proc = await asyncio.create_subprocess_shell(
                    f"systemctl is-active {service_name}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                status = stdout.decode().strip()
                # Consider running or active as running
                s["status"] = "running" if status in ["active", "activating"] else "stopped"
            updated_services.append(s)
            
        await self.send(text_data=json.dumps({
            "type": "status_result",
            "services": updated_services
        }))

    async def _scan_system_deterministically(self, sudo_input):
        import platform
        import socket
        import os

        # 1. Infrastructure
        hostname = socket.gethostname()
        os_name = f"{platform.system()} {platform.release()}"
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            os_name = line.split("=")[1].strip().strip('"')
                            break
        except Exception:
            pass

        cpu_cores = os.cpu_count() or 1

        p_ram = await asyncio.create_subprocess_shell("free -h", stdout=asyncio.subprocess.PIPE)
        out_ram, _ = await p_ram.communicate()
        ram_total, ram_used, ram_free = "N/A", "N/A", "N/A"
        for line in out_ram.decode(errors='ignore').splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                if len(parts) >= 4:
                    ram_total, ram_used, ram_free = parts[1], parts[2], parts[3]

        p_disk = await asyncio.create_subprocess_shell("df -h /", stdout=asyncio.subprocess.PIPE)
        out_disk, _ = await p_disk.communicate()
        disk_list = []
        for line in out_disk.decode(errors='ignore').splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                disk_list.append({"mount": parts[5], "total": parts[1], "used": parts[2], "type": parts[0]})

        p_docker = await asyncio.create_subprocess_shell("sudo -S docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}'", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out_docker, _ = await p_docker.communicate(input=sudo_input)
        containers = []
        for line in out_docker.decode(errors='ignore').splitlines():
            if "|" in line:
                parts = line.split("|")
                containers.append({"name": parts[0], "image": parts[1], "status": parts[2]})

        infra_data = {
            "hostname": hostname,
            "os": os_name,
            "kernel": platform.release(),
            "cpu": {"cores": cpu_cores, "model": platform.machine()},
            "ram": {"total": ram_total, "used": ram_used, "free": ram_free},
            "disk": disk_list,
            "containers": containers
        }

        # 2. Network
        p_pub_ip = await asyncio.create_subprocess_shell("curl -s --max-time 3 ifconfig.me || curl -s --max-time 3 api.ipify.org", stdout=asyncio.subprocess.PIPE)
        out_pub_ip, _ = await p_pub_ip.communicate()
        public_ip = out_pub_ip.decode(errors='ignore').strip() or "N/A"

        p_ip = await asyncio.create_subprocess_shell("sudo -S ip -4 addr show", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out_ip, _ = await p_ip.communicate(input=sudo_input)
        interfaces = []
        curr_iface = ""
        for line in out_ip.decode(errors='ignore').splitlines():
            if line and line[0].isdigit():
                curr_iface = line.split(":")[1].strip()
            elif "inet " in line:
                ip = line.strip().split()[1]
                interfaces.append({"name": curr_iface, "ip": ip, "type": "ipv4"})

        if public_ip != "N/A":
            interfaces.insert(0, {"name": "public_internet", "ip": public_ip, "type": "public"})

        p_gw = await asyncio.create_subprocess_shell("ip route show default", stdout=asyncio.subprocess.PIPE)
        out_gw, _ = await p_gw.communicate()
        gateway = "N/A"
        gw_parts = out_gw.decode(errors='ignore').split()
        if "via" in gw_parts:
            gateway = gw_parts[gw_parts.index("via") + 1]

        p_ports = await asyncio.create_subprocess_shell("sudo -S ss -tulnp", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out_ports, _ = await p_ports.communicate(input=sudo_input)
        open_ports = []
        for line in out_ports.decode(errors='ignore').splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0]
                local_addr = parts[4]
                process_name = parts[-1] if len(parts) >= 7 else "unknown"
                port = local_addr.split(":")[-1]
                if port.isdigit():
                    open_ports.append({"port": int(port), "protocol": proto, "service": process_name, "risk": "low"})

        net_data = {
            "interfaces": interfaces,
            "gateway": gateway,
            "dns": ["8.8.8.8"],
            "open_ports": open_ports
        }

        # 3. Dynamic Services & Ports Extraction (NO HARDCODING)
        p_systemd = await asyncio.create_subprocess_shell("sudo -S systemctl list-units --type=service --state=running --no-legend", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out_systemd, _ = await p_systemd.communicate(input=sudo_input)

        raw_services_list = []
        seen_identifiers = set()

        import re
        # Dynamic process & port extraction from ss -tulnp
        for item in open_ports:
            port = item["port"]
            proc_raw = item["service"]
            proc_match = re.search(r'users:\(\("([^"]+)"', proc_raw)
            pname = proc_match.group(1) if proc_match else proc_raw
            
            identifier = f"port_{port}_{pname}"
            if identifier not in seen_identifiers:
                seen_identifiers.add(identifier)
                raw_services_list.append({
                    "raw_name": pname,
                    "port": port,
                    "protocol": item["protocol"],
                    "source": "listening_port"
                })

        # Dynamic Docker containers extraction
        for c in containers:
            identifier = f"docker_{c['name']}"
            if identifier not in seen_identifiers:
                seen_identifiers.add(identifier)
                raw_services_list.append({
                    "raw_name": c["name"],
                    "image": c["image"],
                    "status": c["status"],
                    "source": "docker_container"
                })

        # Dynamic Systemd active services extraction
        for line in out_systemd.decode(errors='ignore').splitlines():
            parts = line.split()
            if parts:
                svc_name = parts[0].replace(".service", "")
                identifier = f"systemd_{svc_name}"
                if identifier not in seen_identifiers:
                    seen_identifiers.add(identifier)
                    raw_services_list.append({
                        "raw_name": svc_name,
                        "description": " ".join(parts[4:]) if len(parts) >= 5 else "",
                        "source": "systemd_service"
                    })

        return infra_data, net_data, raw_services_list

    async def _handle_generate(self, model_id, encrypted_password):
        import asyncio
        import json
        import subprocess
        
        try:
            print(f"[ArchitectureConsumer] Received generate request with model_id='{model_id}'", flush=True)
            
            sudo_pwd = ""
            if encrypted_password:
                from sre_agent.crypto import decrypt_rsa_oaep
                try:
                    sudo_pwd = decrypt_rsa_oaep(self.rsa_private_key, encrypted_password) + "\n"
                except Exception as e:
                    print(f"[ArchitectureConsumer] Decryption failed: {e}", flush=True)
                    await self.send(text_data=json.dumps({"type": "arch_error", "message": f"Sudo decryption failed: {str(e)}"}))
                    return
            else:
                await self.send(text_data=json.dumps({"type": "arch_error", "message": "Sudo password is required for deep scan."}))
                return
            
            sudo_input = sudo_pwd.encode()
            
            # 1. Deterministic Scanning of Raw Ports & Services
            await self.send(text_data=json.dumps({"type": "arch_progress", "step": "Scanning raw ports, containers, and services dynamically..."}))
            infra_data, net_data, raw_services_list = await self._scan_system_deterministically(sudo_input)

            await self.send(text_data=json.dumps({"type": "arch_progress", "step": "Categorizing services and building Mermaid diagram with AI..."}))

            prompt = f"""### TASK: Categorize Services & Generate Architecture Flowchart

System Information:
- Hostname: {infra_data['hostname']}
- OS: {infra_data['os']} ({infra_data['kernel']})
- CPU Cores: {infra_data['cpu']['cores']} ({infra_data['cpu']['model']})
- RAM: {infra_data['ram']['total']} (Used: {infra_data['ram']['used']})

Network Interfaces:
{json.dumps(net_data['interfaces'], indent=2)}

RAW DETECTED PORTS, CONTAINERS & SERVICES:
{json.dumps(raw_services_list, indent=2)}

YOUR TASKS:
1. Categorize all the raw detected items into clean, human-readable service objects inside a "services" array:
   - "name": Clean name (e.g., "PostgreSQL", "Nginx", "Redis", "Ollama AI", "Docker: <container>", "SSH Server")
   - "type": "Database" | "Web Server" | "Cache" | "Web Application" | "Container" | "System Service" | "AI Infrastructure"
   - "status": "running"
   - "ports": list of ports associated with this service (e.g. [5432] or [])

2. Generate a comprehensive Mermaid flowchart (graph TD) connecting User({infra_data['hostname']}) to all the detected services, databases, network interfaces, and containers.
   Use subgraphs for grouping (e.g., subgraph Network Layer, subgraph Services Layer, subgraph Database Layer).

OUTPUT FORMAT:
Respond STRICTLY in the following JSON format (no markdown blocks around the JSON):
{{
  "services": [
    {{"name": "...", "type": "...", "status": "running", "ports": [5432], "pid": 0, "memory": "N/A"}}
  ],
  "mermaid_diagram": "graph TD\\nUser({infra_data['hostname']}) --> Nginx[Nginx Web Server]\\n...",
  "insights": ["<insight_1>", "<insight_2>"]
}}
"""
            from sre_agent.engine import SREAgentEngine
            from langchain_core.messages import HumanMessage
            
            engine = SREAgentEngine(model_name=model_id)
            llm = engine._get_llm()
            
            print(f"[ArchitectureConsumer] Invoking LLM with model: {model_id}", flush=True)
            parsed = None
            for attempt in range(3):
                try:
                    resp = await asyncio.wait_for(
                        llm.ainvoke([HumanMessage(content=prompt)]),
                        timeout=30.0
                    )
                    
                    content = resp.content.strip()
                    if not content:
                        raise ValueError("Empty response")
                    
                    if content.startswith("```json"):
                        content = content[7:-3]
                    elif content.startswith("```"):
                        content = content[3:-3]
                    
                    parsed = json.loads(content)
                    break
                    
                except asyncio.TimeoutError:
                    if attempt < 2:
                        await self.send(text_data=json.dumps({
                            "type": "arch_progress",
                            "step": f"AI timeout (attempt {attempt+1}/3), retrying..."
                        }))
                    else:
                        raise Exception("AI analysis timed out after 3 attempts")
                        
                except json.JSONDecodeError:
                    if attempt < 2:
                        await self.send(text_data=json.dumps({
                            "type": "arch_progress", 
                            "step": f"Invalid JSON (attempt {attempt+1}/3), retrying..."
                        }))
                    else:
                        raise Exception(f"Failed to parse AI response after 3 attempts")
            
            if not parsed or not isinstance(parsed, dict):
                parsed = {}

            # Inject deterministic infra and network data
            parsed["infrastructure"] = infra_data
            parsed["network"] = net_data
            
            # Sanitize services array
            sanitized_services = []
            raw_services = parsed.get("services", [])
            if isinstance(raw_services, list):
                for s in raw_services:
                    if isinstance(s, dict):
                        s_name = s.get("name") or s.get("service_name") or s.get("service") or s.get("raw_name") or "Unknown Service"
                        s_type = s.get("type") or s.get("category") or "System Service"
                        s_status = s.get("status") or "running"
                        s_ports = s.get("ports") if isinstance(s.get("ports"), list) else ([s.get("port")] if s.get("port") else [])
                        sanitized_services.append({
                            "name": str(s_name),
                            "type": str(s_type),
                            "status": str(s_status),
                            "ports": s_ports,
                            "pid": 0,
                            "memory": "N/A"
                        })
            
            if not sanitized_services:
                sanitized_services = [
                    {
                        "name": str(item.get("raw_name", "Unknown Service")),
                        "type": "System Service",
                        "status": "running",
                        "ports": [item["port"]] if "port" in item else [],
                        "pid": 0,
                        "memory": "N/A"
                    }
                    for item in raw_services_list
                ]

            parsed["services"] = sanitized_services
                
            # Save to Cache
            from chatbot.models import SystemArchitectureCache
            from asgiref.sync import sync_to_async
            
            await sync_to_async(lambda: SystemArchitectureCache.objects.create(
                mermaid_diagram=parsed.get("mermaid_diagram", ""),
                services_json=json.dumps({
                    "services": sanitized_services,
                    "network": net_data,
                    "infrastructure": infra_data
                }),
                insights_json=json.dumps(parsed.get("insights", []))
            ))()
            
            await self.send(text_data=json.dumps({
                "type": "arch_result",
                "data": parsed,
                "cached": False
            }))
            print(f"[ArchitectureConsumer] Success!", flush=True)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            await self.send(text_data=json.dumps({
                "type": "arch_error",
                "message": str(e)
            }))
