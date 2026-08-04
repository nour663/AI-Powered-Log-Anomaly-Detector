import joblib
import pandas as pd
import numpy as np
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import Fore, Style
import time
from src.parser import parse_ssh_log
from src.features import engineer_ssh_features

FEATURE_COLS = [
    'total_attempts', 'failed_attempts', 'successful_logins',
    'invalid_users', 'failure_rate', 'success_rate'
]

# MITRE ATT&CK mapping
MITRE_MAP = {
    'brute_force':    'T1110 - Brute Force',
    'port_scan':      'T1046 - Network Service Discovery',
    'web_scan':       'T1190 - Exploit Public-Facing Application',
    'invalid_users':  'T1078 - Valid Accounts',
}

class LogDetector:
    def __init__(
        self,
        model_path="models/isolation_forest.pkl",
        log_type="ssh"
    ):

        self.log_type = log_type

        self.model = joblib.load(model_path)

        self.scaler = joblib.load("models/scaler.pkl")

        self.alerts = []

    def analyze(self, log_path):
        # Parse the raw log file
        df = parse_ssh_log(log_path)

        # Build one feature vector per IP
        features = engineer_ssh_features(df)

        X = features[FEATURE_COLS].fillna(0)
        X_scaled = self.scaler.transform(X)

        features["anomaly_score"] = self.model.decision_function(X_scaled)
        features["is_anomaly"] = self.model.predict(X_scaled)

        # Suspicious IPs
        anomalous_ips = features[features["is_anomaly"] == -1]

        # Clear previous alerts
        self.alerts = []

        # Build alerts
        for _, row in anomalous_ips.iterrows():
            alert = self.build_alert(row)
            self.alerts.append(alert)
            self.print_alert(alert)

        # Merge anomaly information back into ALL logs
        all_logs = df.merge(
            features[["ip", "anomaly_score", "is_anomaly"]],
            on="ip",
            how="left"
        )

        # Replace missing values (IPs not found in features)
        all_logs["anomaly_score"] = all_logs["anomaly_score"].fillna(0)

        # model.predict() returns -1 for anomaly and 1 for normal
        all_logs["is_anomaly"] = (
            all_logs["is_anomaly"]
            .fillna(1)
            .astype(int)
            .eq(-1)
        )

        return all_logs
    def build_alert(self, row):
        # Classify the type of anomaly
        if row['failure_rate'] > 0.8 and row['total_attempts'] > 10:
            attack_type = 'brute_force'
        elif row['invalid_users'] > 5:
            attack_type = 'invalid_users'
        else:
            attack_type = 'unknown'

        return {
            'ip':           row['ip'],
            'attack_type':  attack_type,
            'mitre':        MITRE_MAP.get(attack_type, 'Unknown'),
            'score':        round(row['anomaly_score'], 4),
            'attempts':     int(row['total_attempts']),
            'failures':     int(row['failed_attempts']),
            'failure_rate': round(row['failure_rate'], 2),
        }

    def print_alert(self, alert):
        print(f"\n{Fore.RED}[ALERT]{Style.RESET_ALL} Anomaly detected!")
        print(f"  IP:           {alert['ip']}")
        print(f"  Attack Type:  {alert['attack_type']}")
        print(f"  MITRE ATT&CK: {alert['mitre']}")
        print(f"  Attempts:     {alert['attempts']}")
        print(f"  Failure Rate: {alert['failure_rate']}")
        print(f"  Score:        {alert['score']}")


class LogWatcher(FileSystemEventHandler):
    """Watch a log file for changes and re-analyze"""
    def __init__(self, log_path, detector):
        self.log_path = log_path
        self.detector = detector

    def on_modified(self, event):
        if event.src_path == self.log_path:
            print(f"\n[*] Log file changed, re-analyzing...")
            self.detector.analyze(self.log_path)

def watch_log(log_path, detector):
    observer = Observer()
    handler  = LogWatcher(log_path, detector)
    observer.schedule(handler, path='.', recursive=False)
    observer.start()
    print(f"[*] Watching {log_path} for changes...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()