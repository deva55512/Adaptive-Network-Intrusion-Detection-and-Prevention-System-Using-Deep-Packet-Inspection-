from scapy.layers.inet import IP, TCP, ICMP

class DetectionEngine:
    def __init__(self):
        self.packet_count = 0
        self.icmp_count = 0
        self.syn_count = 0
        self.flood_threshold = 400
        self.icmp_threshold = 40
        self.syn_threshold = 30

    def process_packet(self, pkt):
        """
        Main packet analysis using advanced Scapy access.
        Ensures NO string indexing errors occur.
        """

        # Count all packets
        self.packet_count += 1

        # -----------------------------
        # ICMP FLOOD DETECTION
        # -----------------------------
        if pkt.haslayer(ICMP):
            self.icmp_count += 1
            if self.icmp_count > self.icmp_threshold:
                self.icmp_count = 0
                return "ICMP Flood Detected"

        # -----------------------------
        # TCP BASED ANALYSIS
        # -----------------------------
        if pkt.haslayer(TCP) and pkt.haslayer(IP):

            tcp = pkt[TCP]
            ip = pkt[IP]

            # SYN Flood Detection
            if tcp.flags == "S":  # SYN only
                self.syn_count += 1
                if self.syn_count > self.syn_threshold:
                    self.syn_count = 0
                    return f"SYN Flood Detected from {ip.src}"

            # SYN Scan detection (SYN without ACK)
            if tcp.flags == "S" and "A" not in str(tcp.flags):
                return f"SYN Scan Detected → Source: {ip.src}, Port: {tcp.dport}"

        # -----------------------------
        # GENERAL PACKET FLOOD
        # -----------------------------
        if self.packet_count > self.flood_threshold:
            self.packet_count = 0
            return "High Packet Flood Detected"

        return None

