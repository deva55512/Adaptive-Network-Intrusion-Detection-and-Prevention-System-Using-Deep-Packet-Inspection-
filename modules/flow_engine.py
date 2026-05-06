from scapy.layers.inet import IP

class FlowEngine:

    def __init__(self):
        self.flows = {}

    def analyze(self, pkt):

        if IP in pkt:

            src = pkt[IP].src
            dst = pkt[IP].dst

            flow_key = (src, dst)

            if flow_key not in self.flows:
                self.flows[flow_key] = 0

            self.flows[flow_key] += 1

            return {
                "src_ip": src,
                "dst_ip": dst,
                "packet_count": self.flows[flow_key]
            }

        return None