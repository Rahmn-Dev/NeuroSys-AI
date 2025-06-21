import json
import re
from datetime import datetime
from your_app.models import SuricataLog

class LogParser:
    """Parser untuk berbagai format log Suricata"""
    
    @staticmethod
    def parse_fast_log(line):
        """Parse Suricata fast.log format"""
        # Format: MM/DD/YYYY-HH:MM:SS.ssssss  [**] [GID:SID:REV] MSG [**] [Classification: class] [Priority: N] {PROTO} SRC:PORT -> DST:PORT
        pattern = r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\].*?\[Classification:\s+(.*?)\].*?\[Priority:\s+(\d+)\].*?\{(\w+)\}\s+([^:]+):(\d+)\s+->\s+([^:]+):(\d+)'
        
        match = re.match(pattern, line)
        if match:
            timestamp_str, gid, sid, rev, message, classification, priority, protocol, src_ip, src_port, dst_ip, dst_port = match.groups()
            
            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y-%H:%M:%S.%f')
            
            return {
                'timestamp': timestamp,
                'message': message,
                'classification': classification,
                'priority': int(priority),
                'protocol': protocol,
                'source_ip': src_ip,
                'source_port': int(src_port),
                'destination_ip': dst_ip,
                'destination_port': int(dst_port),
                'severity': 'High' if int(priority) <= 2 else 'Medium' if int(priority) <= 3 else 'Low'
            }
        return None
    
    @staticmethod
    def parse_eve_json(line):
        """Parse Suricata eve.json format"""
        try:
            data = json.loads(line.strip())
            if data.get('event_type') == 'alert':
                alert = data.get('alert', {})
                return {
                    'timestamp': datetime.fromisoformat(data.get('timestamp').replace('Z', '+00:00')),
                    'message': alert.get('signature', 'Unknown alert'),
                    'classification': alert.get('category', ''),
                    'priority': alert.get('severity', 3),
                    'protocol': data.get('proto', ''),
                    'source_ip': data.get('src_ip', ''),
                    'source_port': data.get('src_port', 0),
                    'destination_ip': data.get('dest_ip', ''),
                    'destination_port': data.get('dest_port', 0),
                    'severity': alert.get('severity_name', 'Unknown')
                }
        except (json.JSONDecodeError, ValueError, KeyError):
            pass
        return None
