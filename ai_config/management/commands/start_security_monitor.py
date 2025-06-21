
from django.core.management.base import BaseCommand
from django.core.management import call_command
import subprocess
import threading
import time

class Command(BaseCommand):
    help = 'Start security monitoring system'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--suricata-log',
            type=str,
            default='/var/log/suricata/eve.json',
            help='Path to Suricata log file'
        )
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting Security Monitor...')
        )
        
        # Start log monitoring in separate thread
        log_thread = threading.Thread(
            target=self.monitor_suricata_logs,
            args=(options['suricata_log'],)
        )
        log_thread.daemon = True
        log_thread.start()
        
        self.stdout.write(
            self.style.SUCCESS('Security Monitor started successfully!')
        )
        
        # Keep the command running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stdout.write(
                self.style.WARNING('Stopping Security Monitor...')
            )
    
    def monitor_suricata_logs(self, log_file):
        """Monitor Suricata logs and create database entries"""
        import json
        import os
        from datetime import datetime
        from your_app.models import SuricataLog
        
        if not os.path.exists(log_file):
            self.stdout.write(
                self.style.ERROR(f'Suricata log file not found: {log_file}')
            )
            return
        
        # Follow log file (like tail -f)
        with open(log_file, 'r') as f:
            # Go to end of file
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if line:
                    try:
                        log_data = json.loads(line.strip())
                        self.process_suricata_log(log_data)
                    except json.JSONDecodeError:
                        continue
                else:
                    time.sleep(0.1)
    
    def process_suricata_log(self, log_data):
        """Process individual Suricata log entry"""
        from your_app.models import SuricataLog
        from dateutil import parser as date_parser
        
        # Only process alert events
        if log_data.get('event_type') == 'alert':
            try:
                # Parse timestamp
                timestamp = date_parser.parse(log_data.get('timestamp'))
                
                # Extract alert data
                alert = log_data.get('alert', {})
                src_ip = log_data.get('src_ip')
                dest_ip = log_data.get('dest_ip')
                src_port = log_data.get('src_port')
                dest_port = log_data.get('dest_port')
                proto = log_data.get('proto')
                
                # Create SuricataLog entry
                suricata_log = SuricataLog.objects.create(
                    timestamp=timestamp,
                    message=alert.get('signature', 'Unknown alert'),
                    severity=alert.get('severity_name', 'Unknown'),
                    source_ip=src_ip,
                    source_port=src_port,
                    destination_ip=dest_ip,
                    destination_port=dest_port,
                    protocol=proto,
                    classification=alert.get('category', ''),
                    priority=alert.get('severity', 3)
                )
                
                self.stdout.write(
                    f"New alert: {src_ip} -> {dest_ip} | {alert.get('signature', 'Unknown')}"
                )
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error processing log: {str(e)}')
                )

# management/commands/setup_suricata_rules.py - Setup Suricata rules for better detection
