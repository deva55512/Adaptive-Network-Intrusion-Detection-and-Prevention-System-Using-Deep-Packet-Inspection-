from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR

class DPIEngine:
    def __init__(self):
        self.suspicious_signatures = [
            "union select", "or 1=1", "drop table", "sleep(",
            "<script>", "../", "%00", "cmd=", "bash -i",
            "wget http", "curl http", "base64", "powershell",
            "nc -e", "chmod +x", "&&", "||"
        ]

        self.malicious_domains = [
            "tor", "onion", "darkweb", "botnet", "malware",
            "rat", "keylogger"
        ]

    def inspect(self, pkt):
        # ---------- HTTP DPI ----------
        if pkt.haslayer(HTTPRequest):
            http = pkt[HTTPRequest]

            host = http.Host.decode(errors="ignore") if http.Host else ""
            path = http.Path.decode(errors="ignore") if http.Path else ""

            url = f"{host}{path}"

            for sig in self.suspicious_signatures:
                if sig.lower() in url.lower():
                    return f"🚨 HTTP Attack Detected: '{sig}' in URL → {url}"

        # ---------- DNS DPI ----------
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="ignore")

            for bad in self.malicious_domains:
                if bad in qname.lower():
                    return f"🚨 Suspicious DNS Query Detected → {qname}"

        # ---------- PAYLOAD DPI ----------
        if pkt.haslayer(TCP):
            raw = bytes(pkt[TCP].payload).decode("latin-1", errors="ignore")

            for sig in self.suspicious_signatures:
                if sig.lower() in raw.lower():
                    return f"🚨 Malicious Payload Pattern Detected → '{sig}'"

        return None
