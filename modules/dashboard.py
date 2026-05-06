import os
import time
from modules.detection import DetectionEngine
from modules.flow_engine import FlowEngine
from modules.blocker import Blocker

class Dashboard:
    def __init__(self, detector: DetectionEngine, flow: FlowEngine, blocker: Blocker):
        self.detector = detector
        self.flow = flow
        self.blocker = blocker

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def render(self):
        while True:
            self.clear_screen()

            print("=============== REALTIME IDS DASHBOARD ===============\n")
            
            print(f"📡 Total Packets: {self.detector.packet_count}")
            print(f"🔵 ICMP Packets: {self.detector.icmp_count}")
            print(f"🟡 SYN Count:    {self.detector.syn_count}")
            print(f"🔥 Flow Entries: {len(self.flow.flow_table)}")
            print(f"⛔ Blocked IPs:  {self.blocker.blocked_ips}\n")

            print("------------------ FLOW TABLE -------------------")
            for key, data in list(self.flow.flow_table.items())[:8]:
                print(f"{key} → {data['count']} packets")

            print("\n------------------ LIVE ALERTS ------------------")
            print("Check terminal for alert messages...\n")

            time.sleep(1)
