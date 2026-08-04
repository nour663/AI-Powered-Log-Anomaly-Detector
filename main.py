import argparse
from src.parser import parse_ssh_log, parse_apache_log
from src.features import engineer_ssh_features, engineer_apache_features
from src.trainer import train_unsupervised
from src.detector import LogDetector, watch_log

FEATURE_COLS = [
    'total_attempts', 'failed_attempts', 'successful_logins',
    'invalid_users', 'failure_rate', 'success_rate'
]

parser = argparse.ArgumentParser(description='AI Log Anomaly Detector')
parser.add_argument('--train',   help='Path to log file to train on')
parser.add_argument('--analyze', help='Path to log file to analyze')
parser.add_argument('--watch',   help='Path to log file to watch live')
parser.add_argument('--type',    choices=['ssh', 'apache'], default='ssh')
args = parser.parse_args()

if args.train:
    print(f"[*] Training on {args.train}")

    if args.type == "ssh":
        df = parse_ssh_log(args.train)
        features = engineer_ssh_features(df)

        FEATURE_COLS = [
            "total_attempts",
            "failed_attempts",
            "successful_logins",
            "invalid_users",
            "failure_rate",
            "success_rate",
        ]

    elif args.type == "apache":
        df = parse_apache_log(args.train)
        features = engineer_apache_features(df)

        FEATURE_COLS = [
            "total_requests",
            "error_requests",
            "post_requests",
            "error_rate",
            "post_rate",
        ]

    train_unsupervised(features, FEATURE_COLS)
elif args.analyze:

    detector = LogDetector(log_type=args.type)

    anomalies = detector.analyze(args.analyze)

    print(f"\nFound {len(anomalies)} anomalies")
elif args.watch:
    detector = LogDetector()
    watch_log(args.watch, detector)