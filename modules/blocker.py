import subprocess

class Blocker:
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip):
        if ip in self.blocked_ips:
            return  # Already blocked

        cmd = f'netsh advfirewall firewall add rule name="IDS_BLOCK_{ip}" dir=in action=block remoteip={ip}'

        try:
            subprocess.run(cmd, shell=True, check=True)
            self.blocked_ips.add(ip)
            print(f"🛑 FIREWALL BLOCKED IP → {ip}")
        except Exception as e:
            print(f"[ERROR] Failed to block IP {ip}: {e}")
