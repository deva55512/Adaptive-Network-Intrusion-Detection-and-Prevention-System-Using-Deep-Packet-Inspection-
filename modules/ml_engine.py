from sklearn.ensemble import IsolationForest
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
import time

class MLEngine:

    def __init__(self):
        self.model = IsolationForest(
            contamination=0.05,
            n_estimators=200,
            random_state=42
        )

        self.training_data = []
        self.trained = False

    def extract_features(self, pkt):
        """
        Convert packet into ML-friendly features
        """

        size = len(pkt)

        src, dst = "0.0.0.0", "0.0.0.0"
        sport, dport = 0, 0
        proto = 0

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src, dst = ip.src, ip.dst

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto = 6

        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto = 17

        return np.array([size, sport, dport, proto]).reshape(1, -1)

    def train(self, pkt):
        """Collect normal traffic samples for training"""
        features = self.extract_features(pkt)
        self.training_data.append(features[0])

        if len(self.training_data) > 500 and not self.trained:
            self.model.fit(self.training_data)
            self.trained = True
            print("🤖 ML Engine Trained Successfully!")

    def predict(self, pkt):
        """Return anomaly score"""
        if not self.trained:
            self.train(pkt)
            return None

        features = self.extract_features(pkt)

        prediction = self.model.predict(features)[0]
        score = self.model.decision_function(features)[0]

        if prediction == -1:  # anomaly
            return score

        return None
