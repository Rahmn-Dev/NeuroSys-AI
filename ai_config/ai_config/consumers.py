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

import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ai_config.settings")
django.setup()
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
        from ai_config.views import SmartMCPAgent
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

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        user_message = data.get("message")
        from .views import SmartAgent
        # Inisialisasi agent
        agent = SmartAgent()

        # Streaming hasil langkah demi langkah
        for result in agent.stream_process_smart_workflow(user_message):
            await self.send(json.dumps(result))


import threading
class TerminalConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        loop = asyncio.get_event_loop()

        def handle_output(output):
            asyncio.run_coroutine_threadsafe(
                self.send(text_data=output),
                loop
            )

        from .terminal_utils import start_shell
        self.shell_writer, self.shell_process = start_shell(handle_output)
        self.handle_input = lambda data: self.shell_writer(data)

    async def disconnect(self, close_code):
        print("WebSocket disconnected")
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
        except json.JSONDecodeError:
            print("Invalid JSON")