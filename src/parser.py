import re
import pandas as pd
from datetime import datetime

# SSH auth log pattern
SSH_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+'
    r'(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)'
)

# Apache access log pattern
APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)'
)

def parse_ssh_log(filepath):
    records = []
    with open(filepath, 'r') as f:
        for line in f:
            match = SSH_PATTERN.match(line)
            if match:
                d = match.groupdict()
                records.append({
                    'timestamp': d['time'],
                    'host': d['host'],
                    'pid': int(d['pid']),
                    'message': d['message'],
                    'failed': 1 if 'Failed' in d['message'] else 0,
                    'accepted': 1 if 'Accepted' in d['message'] else 0,
                    'invalid_user': 1 if 'Invalid user' in d['message'] else 0,
                    'ip': extract_ip(d['message'])
                })
    return pd.DataFrame(records)

def parse_apache_log(filepath):
    records = []
    with open(filepath, 'r') as f:
        for line in f:
            match = APACHE_PATTERN.match(line)
            if match:
                d = match.groupdict()
                records.append({
                    'ip': d['ip'],
                    'timestamp': d['time'],
                    'method': d['method'],
                    'path': d['path'],
                    'status': int(d['status']),
                    'size': 0 if d['size'] == '-' else int(d['size']),
                    'is_error': 1 if int(d['status']) >= 400 else 0,
                    'is_post': 1 if d['method'] == 'POST' else 0
                })
    return pd.DataFrame(records)

def extract_ip(message):
    match = re.search(r'\d+\.\d+\.\d+\.\d+', message)
    return match.group() if match else None