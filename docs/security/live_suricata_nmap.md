# Live Suricata/Nmap validation

Not run. `nmap` and `suricata` binaries are present and `/var/log/suricata/eve.json` is readable, but no specific lab target with explicit authorization could be established from the connected project context. Scanning an ambiguous host would not be valid evidence. No EVE alert, database persistence, dashboard observation, or ATT&CK T1046 claim is made.

Auto-block remains disabled. A future authorized run must record reduced timestamp, source/destination IP, port, protocol, signature, severity, an EVE excerpt, the `SuricataLog` row, and the system analysis. A single alert must not trigger blocking without a reviewed policy.
