import os
import re
import subprocess
import psutil
import distro
from pathlib import Path
import json
from collections import defaultdict
from django.conf import settings
MISTRAL_API_KEY = getattr(settings, "MISTRAL_API_KEY")
from mistralai import Mistral

class LinuxConfigAnalyzer:
    def __init__(self, use_ai_enhancement=False):
        self.issues = []
        self.system_info = self.get_system_info()
                # --- Tambahan untuk AI ---
        self.api_key = MISTRAL_API_KEY
        self.client = Mistral(api_key=self.api_key)
        self.model = "open-mistral-nemo" # Model yang cepat dan efisien
        self.use_ai_enhancement = use_ai_enhancement
        # ------------------------

        # Define critical config files to check
        self.config_files = {
            '/etc/ssh/sshd_config': 'ssh',
            '/etc/security/limits.conf': 'security',
            '/etc/sysctl.conf': 'kernel',
            '/etc/fstab': 'filesystem',
            '/etc/hosts': 'network',
            '/etc/sudoers': 'sudo',
            '/etc/passwd': 'users',
            '/etc/shadow': 'users',
            '/etc/nginx/nginx.conf': 'nginx',
            '/etc/apache2/apache2.conf': 'apache',
            '/etc/mysql/mysql.conf.d/mysqld.cnf': 'mysql',
            '/etc/systemd/system': 'systemd',
        }

        
        # Security rules database
        self.security_rules = {
            'ssh': {
                'PermitRootLogin': {'recommended': 'no', 'severity': 'high'},
                'PasswordAuthentication': {'recommended': 'no', 'severity': 'medium'},
                'Port': {'recommended': '!22', 'severity': 'medium'},
                'Protocol': {'recommended': '2', 'severity': 'high'},
                'X11Forwarding': {'recommended': 'no', 'severity': 'low'},
                'MaxAuthTries': {'recommended': '<=3', 'severity': 'medium'},
            },
            'kernel': {
                'net.ipv4.ip_forward': {'recommended': '0', 'severity': 'medium'},
                'net.ipv4.conf.all.send_redirects': {'recommended': '0', 'severity': 'medium'},
                'net.ipv4.conf.default.send_redirects': {'recommended': '0', 'severity': 'medium'},
                'kernel.dmesg_restrict': {'recommended': '1', 'severity': 'low'},
                'fs.suid_dumpable': {'recommended': '0', 'severity': 'high'},
            }
        }
    def scan_configuration_with_ai(self, file_path, file_category):
        """
        Menganalisis seluruh file konfigurasi menggunakan AI untuk menemukan masalah keamanan.
        """
        print(f"[{file_category.upper()}] Running AI-driven scan on {file_path}...")
        
        if not os.path.exists(file_path):
            return [] # Kembalikan list kosong jika file tidak ada

        try:
            with open(file_path, 'r') as f:
                content = f.read()
                # Batasi konten untuk menghemat token jika terlalu besar
                if len(content) > 25000: # Batas sekitar 25rb karakter
                    content = content[:25000]

            # Prompt dirancang untuk meminta AI bertindak sebagai auditor
            # dan mengembalikan JSON dalam format yang kita inginkan.
            prompt = f"""
            Anda adalah auditor keamanan siber Linux senior yang sedang meninjau file konfigurasi dari server {self.system_info.get('os')} {self.system_info.get('version')}.

            Berikut adalah isi dari file `{file_path}`:
            ---
            {content}
            ---

            Tugas Anda:
            Analisis konten file di atas berdasarkan standar keamanan industri (seperti CIS Benchmarks). Identifikasi potensi miskonfigurasi keamanan. Abaikan baris yang dikomentari (#).

            Untuk SETIAP masalah yang Anda temukan, berikan detail dalam format OBJEK JSON di dalam sebuah LIST JSON. Setiap objek harus memiliki kunci berikut:
            - "title": Judul singkat dan jelas dari masalah (misalnya: "SSH PermitRootLogin Enabled").
            - "description": Penjelasan singkat 1 kalimat tentang mengapa ini masalah.
            - "severity": Tingkat keparahan (pilih salah satu: "low", "medium", "high", "critical").
            - "current_value": Nilai atau baris konfigurasi yang bermasalah.
            - "recommended_value": Nilai atau konfigurasi yang direkomendasikan.

            Jika tidak ada masalah keamanan yang ditemukan, kembalikan list JSON kosong: `[]`.
            Contoh output jika ada masalah: `[ {{"title": "...", "description": "...", ...}}, {{"title": "...", ...}} ]`
            """

            messages = [{"role": "user", "content": prompt}]
            
            chat_response = self.client.chat(
                model=self.model,
                messages=messages,
                response_format={"type": "json_object"}
            )

            # AI mungkin mengembalikan JSON di dalam kunci 'issues' atau sejenisnya
            # Kita perlu parsing dengan aman
            raw_response = json.loads(chat_response.choices[0].message.content)
            found_issues = []
            # Coba cari list issues dari berbagai kemungkinan nama kunci
            possible_keys = ['issues', 'findings', 'problems', 'results']
            for key in possible_keys:
                if isinstance(raw_response.get(key), list):
                    found_issues = raw_response[key]
                    break
            
            # Jika tidak ada kunci yang cocok, mungkin responsnya adalah list itu sendiri
            if not found_issues and isinstance(raw_response, list):
                found_issues = raw_response

            # Standarisasi hasil agar cocok dengan format internal kita
            standardized_issues = []
            for issue in found_issues:
                standardized_issues.append({
                    'category': file_category,
                    'severity': issue.get('severity', 'medium'),
                    'title': issue.get('title', 'AI Detected Issue'),
                    'description': issue.get('description', 'AI analysis identified a potential misconfiguration.'),
                    'config_file': file_path,
                    'current_value': str(issue.get('current_value', 'N/A')),
                    'recommended_value': str(issue.get('recommended_value', 'See AI analysis')),
                    'is_auto_fixable': False,  # AI scan tidak menghasilkan auto-fix secara default
                    'source': 'ai' # Tandai bahwa ini dari AI
                })
            
            return standardized_issues

        except Exception as e:
            print(f"Error during AI-driven scan on {file_path}: {e}")
            return [] # Kembalikan list kosong jika terjadi error
    def get_system_info(self):
        """Gather basic system information"""
        return {
            'hostname': os.uname().nodename,
            'os': distro.name(),
            'version': distro.version(),
            'kernel': os.uname().release,
            'architecture': os.uname().machine,
            'cpu_count': psutil.cpu_count(),
            'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
            'disk_usage': {disk.mountpoint: {
                'total': round(psutil.disk_usage(disk.mountpoint).total / (1024**3), 2),
                'used': round(psutil.disk_usage(disk.mountpoint).used / (1024**3), 2),
                'free': round(psutil.disk_usage(disk.mountpoint).free / (1024**3), 2)
            } for disk in psutil.disk_partitions() if disk.mountpoint in ['/', '/home', '/var']}
        }
    
    def run_command(self, command):
        """Safely execute system commands"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, 
                                  text=True, timeout=30)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timeout", 1
        except Exception as e:
            return "", str(e), 1
        
    def get_ai_enhanced_analysis(self, issue):
        """
        Menggunakan Mistral AI untuk memberikan penjelasan mendalam tentang suatu isu.
        """
        if not self.use_ai_enhancement or not self.api_key:
            return None

        try:
            # Membuat prompt yang kaya konteks untuk AI
            prompt = f"""
            Anda adalah seorang ahli keamanan siber Linux (DevSecOps). Analisis masalah keamanan berikut yang ditemukan pada sebuah server.

            **Detail Masalah:**
            - **Judul:** {issue.get('title')}
            - **Deskripsi Awal:** {issue.get('description')}
            - **File Konfigurasi:** {issue.get('config_file', 'N/A')}
            - **Nilai Saat Ini:** `{issue.get('current_value', 'N/A')}`
            - **Nilai yang Direkomendasikan:** `{issue.get('recommended_value', 'N/A')}`

            **Tugas Anda:**
            1.  **Jelaskan Risikonya:** Jelaskan dengan jelas dalam 1-2 kalimat, apa risiko keamanan jika masalah ini tidak diperbaiki. Jelaskan untuk seorang administrator sistem.
            2.  **Berikan Rekomendasi Perbaikan:** Berikan langkah-langkah perbaikan yang lebih detail daripada sekadar perintah. Jelaskan mengapa rekomendasi tersebut penting.
            3.  **Sebutkan Dampak Perbaikan:** Sebutkan potensi dampak setelah perbaikan diterapkan (misalnya: "Perlu restart service", "Tidak ada dampak langsung pada pengguna").

            Berikan jawaban dalam format JSON dengan kunci: "ai_risk", "ai_recommendation", dan "ai_impact".
            """

            chat_response = self.client.chat.complete(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"}, # Meminta output JSON
                temperature=0.2 # Sedikit kreativitas tapi tetap faktual
            )
            
            ai_analysis = json.loads(chat_response.choices[0].message.content)
            return ai_analysis

        except Exception as e:
            # Jika AI gagal, jangan hentikan seluruh proses
            print(f"Error calling AI for analysis: {e}")
            return {
                "ai_risk": "Analisis AI tidak tersedia saat ini.",
                "ai_recommendation": "Gunakan rekomendasi standar.",
                "ai_impact": "N/A"
            }

    
    def check_ssh_config(self):
        """Analyze SSH configuration"""
        ssh_config = '/etc/ssh/sshd_config'
        if not os.path.exists(ssh_config):
            return
            
        try:
            with open(ssh_config, 'r') as f:
                content = f.read()
                
            for rule, config in self.security_rules['ssh'].items():
                pattern = rf'^{rule}\s+(.+)$'
                match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
                
                if match:
                    current_value = match.group(1).strip()
                    recommended = config['recommended']
                    
                    # Check if current value violates recommendation
                    violation = False
                    if recommended.startswith('!'):  # Not equal
                        if current_value == recommended[1:]:
                            violation = True
                    elif recommended.startswith('<='):  # Less than or equal
                        try:
                            if int(current_value) > int(recommended[2:]):
                                violation = True
                        except ValueError:
                            pass
                    else:  # Exact match
                        if current_value.lower() != recommended.lower():
                            violation = True
                    
                    if violation:
                        self.issues.append({
                            'category': 'security',
                            'severity': config['severity'],
                            'title': f'SSH {rule} misconfiguration',
                            'description': f'SSH {rule} is set to "{current_value}" but should be "{recommended}"',
                            'config_file': ssh_config,
                            'current_value': current_value,
                            'recommended_value': recommended.lstrip('!<='),
                            'fix_command': f'sudo sed -i "s/^{rule}.*/{rule} {recommended.lstrip("!<=")}/" {ssh_config} && sudo systemctl reload sshd',
                            'is_auto_fixable': True
                        })
                else:
                    # Rule not found, add with default
                    self.issues.append({
                        'category': 'security',
                        'severity': config['severity'],
                        'title': f'SSH {rule} not configured',
                        'description': f'SSH {rule} should be explicitly set to "{config["recommended"]}"',
                        'config_file': ssh_config,
                        'current_value': 'not set',
                        'recommended_value': config['recommended'].lstrip('!<='),
                        'fix_command': f'echo "{rule} {config["recommended"].lstrip("!<=")}" | sudo tee -a {ssh_config} && sudo systemctl reload sshd',
                        'is_auto_fixable': True
                    })
                    
        except PermissionError:
            self.issues.append({
                'category': 'system',
                'severity': 'medium',
                'title': 'Cannot read SSH config',
                'description': 'Permission denied reading SSH configuration file',
                'config_file': ssh_config
            })
    
    def check_kernel_parameters(self):
        """Check kernel parameters via sysctl"""
        for param, rule in self.security_rules['kernel'].items():
            stdout, stderr, returncode = self.run_command(f'sysctl {param}')
            
            if returncode == 0 and stdout:
                current_value = stdout.split('=')[1].strip()
                recommended = rule['recommended']
                
                if current_value != recommended:
                    self.issues.append({
                        'category': 'security',
                        'severity': rule['severity'],
                        'title': f'Kernel parameter {param} misconfigured',
                        'description': f'{param} is set to "{current_value}" but should be "{recommended}"',
                        'config_file': '/etc/sysctl.conf',
                        'current_value': current_value,
                        'recommended_value': recommended,
                        'fix_command': f'echo "{param} = {recommended}" | sudo tee -a /etc/sysctl.conf && sudo sysctl -p',
                        'is_auto_fixable': True
                    })
    
    def check_services_security(self):
        """Check running services for security issues"""
        # Check for unnecessary services
        dangerous_services = [
            'telnet', 'ftp', 'rsh', 'rlogin', 'tftp', 'xinetd'
        ]
        
        for service in psutil.process_iter(['pid', 'name', 'status']):
            try:
                if service.info['name'] in dangerous_services:
                    self.issues.append({
                        'category': 'security',
                        'severity': 'high',
                        'title': f'Insecure service running: {service.info["name"]}',
                        'description': f'Service {service.info["name"]} is running and poses security risks',
                        'fix_command': f'sudo systemctl stop {service.info["name"]} && sudo systemctl disable {service.info["name"]}',
                        'is_auto_fixable': True
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def check_file_permissions(self):
        """Check critical file permissions"""
        critical_files = {
            '/etc/passwd': '644',
            '/etc/shadow': '640',
            '/etc/group': '644',
            '/etc/gshadow': '640',
            '/etc/ssh/sshd_config': '600',
        }
        
        for file_path, expected_perm in critical_files.items():
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                current_perm = oct(stat_info.st_mode)[-3:]
                
                if current_perm != expected_perm:
                    self.issues.append({
                        'category': 'security',
                        'severity': 'high',
                        'title': f'Incorrect permissions on {file_path}',
                        'description': f'{file_path} has permissions {current_perm} but should be {expected_perm}',
                        'config_file': file_path,
                        'current_value': current_perm,
                        'recommended_value': expected_perm,
                        'fix_command': f'sudo chmod {expected_perm} {file_path}',
                        'is_auto_fixable': True
                    })
    
    def check_system_performance(self):
        """Check system performance issues"""
        # Check memory usage
        memory = psutil.virtual_memory()
        if memory.percent > 90:
            self.issues.append({
                'category': 'performance',
                'severity': 'high',
                'title': 'High memory usage',
                'description': f'Memory usage is {memory.percent:.1f}%, consider investigating high memory processes',
                'current_value': f'{memory.percent:.1f}%'
            })
        
        # Check disk usage
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                if usage.percent > 90:
                    self.issues.append({
                        'category': 'storage',
                        'severity': 'high',
                        'title': f'High disk usage on {partition.mountpoint}',
                        'description': f'Disk usage on {partition.mountpoint} is {usage.percent:.1f}%',
                        'current_value': f'{usage.percent:.1f}%'
                    })
            except PermissionError:
                continue
        
        # Check swap usage
        swap = psutil.swap_memory()
        if swap.percent > 80:
            self.issues.append({
                'category': 'performance',  
                'severity': 'medium',
                'title': 'High swap usage',
                'description': f'Swap usage is {swap.percent:.1f}%, system may be under memory pressure',
                'current_value': f'{swap.percent:.1f}%'
            })
    
    def check_network_security(self):
        """Check network configuration security"""
        # Check for open ports
        connections = psutil.net_connections(kind='inet')
        listening_ports = [conn.laddr.port for conn in connections if conn.status == 'LISTEN']
        
        dangerous_ports = {
            21: 'FTP',
            23: 'Telnet', 
            53: 'DNS (if not DNS server)',
            69: 'TFTP',
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB'
        }
        
        for port, service in dangerous_ports.items():
            if port in listening_ports:
                self.issues.append({
                    'category': 'network',
                    'severity': 'medium',
                    'title': f'Potentially insecure port {port} open',
                    'description': f'Port {port} ({service}) is listening and may pose security risks',
                    'current_value': f'Port {port} open'
                })
    
    def check_log_configuration(self):
        """Check logging configuration"""
        log_files = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/secure'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    stat_info = os.stat(log_file)
                    # Check if log file is too old (no recent writes)
                    import time
                    if time.time() - stat_info.st_mtime > 86400 * 7:  # 7 days
                        self.issues.append({
                            'category': 'system',
                            'severity': 'medium',
                            'title': f'Log file {log_file} not updated recently',
                            'description': f'{log_file} has not been updated in over 7 days',
                            'config_file': log_file
                        })
                except OSError:
                    continue
    
    def analyze_system(self, scan_type='full'):
        """Run complete system analysis"""
        self.issues = []  # Reset issues
        
        if scan_type in ['full', 'security']:
            self.check_ssh_config()
            self.check_kernel_parameters()
            self.check_services_security()
            self.check_file_permissions()
            self.check_network_security()
        
        if scan_type in ['full', 'performance']:
            self.check_system_performance()
        
        if scan_type in ['full', 'system']:
            self.check_log_configuration()
        if scan_type in ['full', 'ai_deep_scan']:
            print("\nRunning AI-Driven Deep Scan...")
            # Tentukan file mana yang ingin di-scan oleh AI
            files_to_scan_with_ai = {
                '/etc/ssh/sshd_config': 'ssh',
                '/etc/sudoers': 'sudo',
                '/etc/nginx/nginx.conf': 'nginx'
                # Tambahkan file lain yang kompleks di sini
            }
            
            for file_path, category in files_to_scan_with_ai.items():
                ai_detected_issues = self.scan_configuration_with_ai(file_path, category)
                self.issues.extend(ai_detected_issues)

        # 3. HAPUS DUPLIKAT & LAKUKAN PENINGKATAN AI
        print("\nFinalizing results and enhancing with AI...")
        final_issues = []
        seen_titles = set()
        # Logika untuk menghapus duplikat antara rule-based dan AI scan
        for issue in self.issues:
            # Kunci unik untuk setiap isu, misalnya berdasarkan file dan judul
            unique_key = f"{issue.get('config_file')}:{issue.get('title')}"
            if unique_key not in seen_titles:
                # Panggil AI untuk memperkaya penjelasan jika belum ada
                if 'ai_risk' not in issue and self.use_ai_enhancement and issue.get('severity') in ['high', 'critical']:
                    print(f"Enhancing '{issue['title']}' with AI analysis...")
                    ai_enhancement = self.get_ai_enhanced_analysis(issue)
                    if ai_enhancement:
                        issue.update(ai_enhancement)
                
                final_issues.append(issue)
                seen_titles.add(unique_key)
                
        self.issues = final_issues

        return {
            'system_info': self.system_info,
            'total_issues': len(self.issues),
            'issues_by_severity': {
                'critical': len([i for i in self.issues if i['severity'] == 'critical']),
                'high': len([i for i in self.issues if i['severity'] == 'high']),
                'medium': len([i for i in self.issues if i['severity'] == 'medium']),
                'low': len([i for i in self.issues if i['severity'] == 'low']),
            },
            'issues_by_category': {
                'security': len([i for i in self.issues if i['category'] == 'security']),
                'performance': len([i for i in self.issues if i['category'] == 'performance']),
                'network': len([i for i in self.issues if i['category'] == 'network']),
                'system': len([i for i in self.issues if i['category'] == 'system']),
                'storage': len([i for i in self.issues if i['category'] == 'storage']),
            },
            'auto_fixable': len([i for i in self.issues if i.get('is_auto_fixable', False)]),
            'issues': self.issues
        }