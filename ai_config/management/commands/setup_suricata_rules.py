from django.core.management.base import BaseCommand
import os

class Command(BaseCommand):
    help = 'Setup enhanced Suricata rules for port scanning detection'
    
    def handle(self, *args, **options):
        rules = '''
# Enhanced Port Scanning Detection Rules
alert tcp any any -> $HOME_NET any (msg:"ET SCAN Nmap TCP Ping"; flags:A; ack:0; reference:url,doc.emergingthreats.net/2001569; classtype:attempted-recon; sid:2001569; rev:14;)

alert tcp any any -> $HOME_NET any (msg:"ET SCAN Potential VNC Scan 5900-5920"; flags:S,12; dsize:0; ports:5900:5920; threshold:type both,track by_src,count 5,seconds 60; reference:url,doc.emergingthreats.net/2001569; classtype:attempted-recon; sid:2010935; rev:3;)

alert tcp any any -> $HOME_NET any (msg:"ET SCAN Suspicious inbound to mySQL port 3306"; flags:S,12; dsize:0; ports:3306; threshold:type both,track by_src,count 5,seconds 60; reference:url,doc.emergingthreats.net/2010963; classtype:attempted-recon; sid:2010963; rev:3;)

alert tcp any any -> $HOME_NET any (msg:"ET SCAN Suspicious inbound to PostgreSQL port 5432"; flags:S,12; dsize:0; ports:5432; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-recon; sid:2010964; rev:3;)

alert tcp any any -> $HOME_NET any (msg:"ET SCAN Potential SSH Scan"; flags:S,12; dsize:0; ports:22; threshold:type both,track by_src,count 5,seconds 60; reference:url,doc.emergingthreats.net/2001569; classtype:attempted-recon; sid:2001569; rev:14;)

# Masscan Detection
alert tcp any any -> $HOME_NET any (msg:"ET SCAN Masscan User-Agent Detected"; flow:established,to_server; content:"User-Agent|3a 20|masscan"; http_header; reference:url,github.com/robertdavidgraham/masscan; classtype:attempted-recon; sid:2024001; rev:1;)

# Nmap OS Detection
alert tcp any any -> $HOME_NET any (msg:"ET SCAN Nmap OS Detection Probe"; flags:FPU; dsize:0; reference:url,nmap.org; classtype:attempted-recon; sid:2024002; rev:1;)

# Multiple Port Scan Detection
alert tcp any any -> $HOME_NET any (msg:"ET SCAN Multiple Port Scan Detected"; flags:S; threshold:type both,track by_src,count 20,seconds 60; classtype:attempted-recon; sid:2024003; rev:1;)
'''
        
        rules_file = '/etc/suricata/rules/local.rules'
        
        try:
            with open(rules_file, 'w') as f:
                f.write(rules)
            
            self.stdout.write(
                self.style.SUCCESS(f'Suricata rules written to {rules_file}')
            )
            self.stdout.write(
                self.style.WARNING('Please reload Suricata configuration: sudo systemctl reload suricata')
            )
            
        except PermissionError:
            self.stdout.write(
                self.style.ERROR(f'Permission denied. Run with sudo or check permissions for {rules_file}')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error writing rules: {str(e)}')
            )