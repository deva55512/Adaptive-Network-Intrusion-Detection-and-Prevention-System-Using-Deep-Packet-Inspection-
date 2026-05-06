import os
import json
import datetime


class Logger:

    def __init__(self, log_file="logs/attacks.log", json_file="logs/security_events.json"):
        self.log_file = log_file
        self.json_file = json_file

        # Create logs directory if not exists
        os.makedirs("logs", exist_ok=True)

    def write(self, message):
        """
        Write simple log message
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {message}\n"

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line)

    def write_event(self, attack_type, source_ip="Unknown", protocol="Unknown", severity="MEDIUM"):
        """
        Write structured JSON security event
        """

        event = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": attack_type,
            "source_ip": source_ip,
            "protocol": protocol,
            "severity": severity
        }

        try:

            # Load previous events
            if os.path.exists(self.json_file):
                with open(self.json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = []

            # Append new event
            data.append(event)

            # Save updated events
            with open(self.json_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

        except Exception as e:
            print(f"[LOGGER ERROR] {e}")


