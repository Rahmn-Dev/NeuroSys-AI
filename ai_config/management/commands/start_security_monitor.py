"""Single ingestion worker; run independently of WebSocket clients."""
import time
from django.core.management.base import BaseCommand
from ai_config.utils.eve import EveFollower, parse_eve
from sre_agent.security_boundary import audit

class Command(BaseCommand):
    help = "Ingest validated Suricata EVE alerts without automatic blocking"

    def add_arguments(self, parser):
        parser.add_argument("--suricata-log", default="/var/log/suricata/eve.json")
        parser.add_argument("--replay", action="store_true", help="Read existing records too")

    def handle(self, *args, **options):
        follower = EveFollower(options["suricata_log"], replay=options["replay"])
        self.stdout.write("Starting EVE monitor")
        try:
            while True:
                line = follower.poll()
                if line is None:
                    time.sleep(0.1)
                else:
                    self.process_suricata_log(line)
        except KeyboardInterrupt:
            pass
        finally:
            follower.close()

    def process_suricata_log(self, line):
        from chatbot.models import SuricataLog
        from datetime import timedelta
        from django.conf import settings
        from django.utils import timezone
        data = parse_eve(line)
        if data is None:
            return
        message = str(data.get("message", ""))
        # Defaults live here (not only in settings) so the filter behaves
        # identically under test settings that don't define them.
        default_suppressed = ["SURICATA STREAM Packet with invalid timestamp"]
        suppressed = [s for s in (getattr(settings, "SURICATA_SUPPRESS_SIGNATURES", None)
                                  or default_suppressed)
                      if s.lower() in message.lower()]
        if suppressed:
            # Operator-classified benign noise (e.g. per-packet stream events
            # on dev traffic). Not stored; the decision is audited.
            audit("eve_suppressed", verdict="benign_signature")
            return
        window = getattr(settings, "SURICATA_DEDUP_SECONDS", None) or 600
        try:
            window = max(60, int(window))
        except (TypeError, ValueError):
            window = 600
        cutoff = timezone.now() - timedelta(seconds=window)
        duplicate = SuricataLog.objects.filter(
            message=data.get("message", "")[:4096],
            source_ip=data.get("source_ip"), destination_ip=data.get("destination_ip"),
            source_port=data.get("source_port"), destination_port=data.get("destination_port"),
            timestamp__gte=cutoff,
        ).exists()
        if duplicate:
            audit("eve_duplicate_skipped", verdict="dedup_window")
            return
        # Fail visibly on storage errors instead of silently losing alerts.
        SuricataLog.objects.create(**data)
        audit("eve_ingested", verdict="stored")
