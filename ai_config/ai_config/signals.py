from django.db.models.signals import post_save
from django.dispatch import receiver
from services.security_service import SecurityService
from .models import SuricataLog
import logging

logger = logging.getLogger(__name__)

@receiver(post_save, sender=SuricataLog)
def process_new_suricata_log(sender, instance, created, **kwargs):
    """Process new Suricata logs in real-time"""
    if created:
        try:
            # Check if should auto-block
            if SecurityService.should_auto_block(instance):
                logger.info(f"Processing potential threat from {instance.source_ip}")
                SecurityService.auto_block_suspicious_ip(instance)
            else:
                # Send notification about new log even if not blocking
                SecurityService.send_websocket_notification("new_log", {
                    "ip": instance.source_ip,
                    "message": instance.message,
                    "classification": instance.classification,
                    "priority": instance.priority,
                    "timestamp": instance.timestamp.isoformat()
                })
        except Exception as e:
            logger.error(f"Error processing Suricata log {instance.id}: {str(e)}")