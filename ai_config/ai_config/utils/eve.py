"""Bounded EVE parsing and rotation-aware following; no firewall side effects."""
import ipaddress
import json
import os
import time
from datetime import datetime
from sre_agent.security_boundary import audit

MAX_LINE = 65536

def parse_eve(line):
    try:
        if not isinstance(line, str) or len(line) > MAX_LINE:
            raise ValueError("oversized")
        data = json.loads(line)
        if not isinstance(data, dict):
            raise ValueError("object expected")
        if data.get("event_type") != "alert":
            return None
        alert = data["alert"]
        if not isinstance(alert, dict):
            raise ValueError("alert object expected")
        priority = alert["severity"]
        if type(priority) is not int or priority not in (1, 2, 3):
            raise ValueError("severity")
        timestamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("timezone required")
        result = {"timestamp": timestamp, "priority": priority,
                  "severity": {1: "High", 2: "Medium", 3: "Low"}[priority]}
        for source, target in (("src_ip", "source_ip"), ("dest_ip", "destination_ip")):
            result[target] = str(ipaddress.ip_address(data[source]))
        for source, target in (("src_port", "source_port"), ("dest_port", "destination_port")):
            port = data.get(source)
            if port is not None and (type(port) is not int or not 0 <= port <= 65535):
                raise ValueError("port")
            result[target] = port
        for value, target, limit in ((alert.get("signature", "Unknown alert"), "message", 4096),
                                     (alert.get("category", ""), "classification", 100),
                                     (data.get("proto", ""), "protocol", 10)):
            if not isinstance(value, str) or len(value) > limit:
                raise ValueError("invalid text")
            result[target] = value
        return result
    except (ValueError, TypeError, KeyError, AttributeError):
        audit("eve_rejected", verdict="invalid")
        return None

class EveFollower:
    """At-most-once in-process reader; starts at EOF unless replay is explicit.

    Retains incomplete lines, bounds oversized records, handles rename/copytruncate.
    No persistent checkpoint: events during restart may be missed (documented).
    """
    def __init__(self, path, replay=False):
        self.path, self.replay = path, replay
        self.file = None
        self.first = True
        self.discarding = False

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def poll(self):
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return None
        if self.file is None or (stat.st_dev, stat.st_ino) != (os.fstat(self.file.fileno()).st_dev, os.fstat(self.file.fileno()).st_ino):
            self.close()
            self.file = open(self.path, "rb")
            if self.first and not self.replay:
                self.file.seek(0, 2)
            self.first = False
            self.discarding = False
        if stat.st_size < self.file.tell():
            self.file.seek(0)
            self.discarding = False
        position = self.file.tell()
        line = self.file.readline(MAX_LINE + 1)
        if not line:
            return None
        if self.discarding or len(line) > MAX_LINE:
            self.discarding = not line.endswith(b"\n")
            audit("eve_rejected", verdict="oversized")
            return None
        if not line.endswith(b"\n"):
            self.file.seek(position)
            return None
        return line.decode("utf-8", errors="replace")
