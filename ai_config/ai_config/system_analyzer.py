import os
import re
import subprocess
import psutil
import distro
from pathlib import Path
import json
from collections import defaultdict

class LinuxConfigAnalyzer:
    def __init__(self):
        self.issues = []
        self.system_info = self.get_system_info()
        
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