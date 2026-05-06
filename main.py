import sys
import threading
from scapy.all import sniff
from scapy.layers.inet import IP

from modules.flow_engine import FlowEngine
from modules.detection import DetectionEngine
from modules.logger import Logger
from modules.blocker import Blocker


# Initialize engines
flow_engine = FlowEngine()
detector = DetectionEngine()
logger = Logger("logs/attacks.log")
blocker = Blocker()


def handle_packet(pkt):

    try:

        # Detection engine
        detect_result = detector.process_packet(pkt)

        if detect_result:
            print(detect_result)
            logger.write(detect_result)

            if IP in pkt:
                attacker_ip = pkt[IP].src
                blocker.block_ip(attacker_ip)

        # Flow engine
        flow_result = flow_engine.analyze(pkt)

        if flow_result and flow_result["packet_count"] > 50:
            print("FLOW ALERT:", flow_result)

            if IP in pkt:
                attacker_ip = pkt[IP].src
                blocker.block_ip(attacker_ip)

    except Exception as e:
        print("Packet error:", e)


def start_capture():

    print("Realtime IDS Started")
    print("Listening for packets...")

    sniff(
        prn=handle_packet,
        store=False
    )


def main():

    print("Starting IDS system...")

    capture_thread = threading.Thread(target=start_capture)
    capture_thread.daemon = True
    capture_thread.start()

    print("IDS running. Press CTRL+C to stop")

    try:
        while True:
            pass

    except KeyboardInterrupt:
        print("IDS stopped")
        sys.exit(0)


if __name__ == "__main__":
    main()