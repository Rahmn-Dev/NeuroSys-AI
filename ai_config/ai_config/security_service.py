import subprocess
import logging
import json
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from chatbot.models import BlockedIP, WhitelistedIP, SuricataLog

logger = logging.getLogger(__name__)

class SecurityService:
    
    @staticmethod
    def send_websocket_notification(message_type, data):
        """Send real-time notification via WebSocket"""
        channel_layer = get_channel_layer()
        if channel_layer:
            async_to_sync(channel_layer.group_send)(
                "security_alerts",  # Group name
                {
                    "type": "security_alert",
                    "message_type": message_type,
                    "data": data
                }
            )
    
    @staticmethod
    def is_whitelisted(ip_address):
        """Check if IP is in whitelist"""
        return WhitelistedIP.objects.filter(ip_address=ip_address).exists()
    
    @staticmethod
    def is_already_blocked(ip_address):
        """Check if IP is already blocked"""
        return BlockedIP.objects.filter(
            ip_address=ip_address,
            blocked_until__gt=timezone.now()
        ).exists() or BlockedIP.objects.filter(
            ip_address=ip_address,
            is_permanent=True
        ).exists()
    
    @staticmethod
    def block_ip_iptables(ip_address, permanent=False):
        """Block IP using iptables"""
        try:
            # Add to iptables DROP rule
            cmd = f"sudo iptables -I INPUT -s {ip_address} -j DROP"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully blocked IP {ip_address} with iptables")
                return True
            else:
                logger.error(f"Failed to block IP {ip_address}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {str(e)}")
            return False
    
    @staticmethod
    def unblock_ip_iptables(ip_address):
        """Unblock IP from iptables"""
        try:
            cmd = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Successfully unblocked IP {ip_address}")
                return True
            else:
                logger.error(f"Failed to unblock IP {ip_address}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {str(e)}")
            return False
    
    @staticmethod
    def should_auto_block(suricata_log):
        """Determine if should auto-block based on Suricata log"""
        auto_block_conditions = [
            'port scan' in suricata_log.message.lower() if suricata_log.message else False,
            'nmap' in suricata_log.message.lower() if suricata_log.message else False,
            'masscan' in suricata_log.message.lower() if suricata_log.message else False,
            'reconnaissance' in suricata_log.message.lower() if suricata_log.message else False,
            suricata_log.classification and 'attempted-recon' in suricata_log.classification.lower(),
            suricata_log.classification and 'attempted-admin' in suricata_log.classification.lower(),
            suricata_log.priority and suricata_log.priority <= 2,  # High priority alerts
        ]
        
        return any(auto_block_conditions)
    
    @staticmethod
    def should_permanent_block(suricata_log):
        """Determine if IP should be permanently blocked"""
        permanent_triggers = [
            'attempted-admin',
            'trojan-activity',
            'malware',
            'botnet',
            'brute-force'
        ]
        
        classification = suricata_log.classification.lower() if suricata_log.classification else ""
        message = suricata_log.message.lower() if suricata_log.message else ""
        
        return any(trigger in classification or trigger in message for trigger in permanent_triggers)
    
    @classmethod
    def auto_block_suspicious_ip(cls, suricata_log, block_duration_hours=24):
        """Main method to auto-block suspicious IPs with real-time notification"""
        ip_address = suricata_log.source_ip
        
        if not ip_address:
            return False
            
        # Check whitelist first
        if cls.is_whitelisted(ip_address):
            logger.info(f"IP {ip_address} is whitelisted, skipping block")
            # Send notification about whitelisted IP
            cls.send_websocket_notification("whitelist_skip", {
                "ip": ip_address,
                "reason": "IP is whitelisted",
                "timestamp": timezone.now().isoformat()
            })
            return False
        
        # Check if already blocked
        if cls.is_already_blocked(ip_address):
            logger.info(f"IP {ip_address} is already blocked")
            return True
        
        # Determine if should be permanently blocked
        permanent_block = cls.should_permanent_block(suricata_log)
        
        # Block using iptables
        if cls.block_ip_iptables(ip_address, permanent_block):
            # Save to database
            blocked_until = None if permanent_block else timezone.now() + timedelta(hours=block_duration_hours)
            
            blocked_ip = BlockedIP.objects.create(
                ip_address=ip_address,
                reason=f"Auto-blocked: {suricata_log.classification or 'Suspicious activity'}",
                blocked_until=blocked_until,
                is_permanent=permanent_block,
                suricata_log=suricata_log
            )
            
            # Send real-time notification via WebSocket
            cls.send_websocket_notification("ip_blocked", {
                "ip": ip_address,
                "reason": blocked_ip.reason,
                "permanent": permanent_block,
                "blocked_until": blocked_until.isoformat() if blocked_until else None,
                "timestamp": blocked_ip.blocked_at.isoformat(),
                "suricata_message": suricata_log.message,
                "classification": suricata_log.classification,
                "priority": suricata_log.priority
            })
            
            logger.info(f"IP {ip_address} blocked successfully")
            return True
        
        return False
