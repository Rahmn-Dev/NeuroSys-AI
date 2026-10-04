import json

import pytest
from django.db import connection

from chatbot.models import SuricataLog
from management.commands.start_security_monitor import Command


@pytest.fixture()
def suricata_table():
    try:
        with connection.schema_editor() as editor:
            editor.create_model(SuricataLog)
        created = True
    except Exception:
        created = False
    try:
        yield
    finally:
        if created:
            with connection.schema_editor() as editor:
                editor.delete_model(SuricataLog)


def _eve_line(signature="SURICATA STREAM Packet with invalid timestamp",
              src_ip="192.168.101.16", src_port=65344,
              dest_ip="192.168.101.25", dest_port=8000):
    from django.utils import timezone
    return json.dumps({
        "timestamp": timezone.now().isoformat(),
        "event_type": "alert",
        "src_ip": src_ip, "src_port": src_port,
        "dest_ip": dest_ip, "dest_port": dest_port,
        "proto": "TCP",
        "alert": {"signature": signature, "category": "Generic Protocol Command Decode",
                  "severity": 3, "action": "allowed", "gid": 1, "signature_id": 2210044},
    })


def test_noisy_stream_signature_is_not_stored(suricata_table):
    Command().process_suricata_log(_eve_line())
    assert SuricataLog.objects.count() == 0


def test_identical_alert_is_stored_once_per_window(suricata_table):
    line = _eve_line(signature="ET MALWARE Something Bad", src_port=1111)
    Command().process_suricata_log(line)
    Command().process_suricata_log(line)
    assert SuricataLog.objects.count() == 1


def test_different_alerts_are_all_stored(suricata_table):
    Command().process_suricata_log(_eve_line(signature="ET MALWARE A", src_port=1111))
    Command().process_suricata_log(_eve_line(signature="ET MALWARE B", src_port=2222))
    assert SuricataLog.objects.count() == 2
