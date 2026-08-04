import pandas as pd
import numpy as np

def engineer_ssh_features(df):
    """
    Turn raw log data into ML features
    """
    # Group by IP and create behavioral features
    features = df.groupby('ip').agg(
        total_attempts    = ('failed', 'count'),
        failed_attempts   = ('failed', 'sum'),
        successful_logins = ('accepted', 'sum'),
        invalid_users     = ('invalid_user', 'sum'),
    ).reset_index()

    # Derived features
    features['failure_rate'] = (
        features['failed_attempts'] / features['total_attempts']
    )
    features['success_rate'] = (
        features['successful_logins'] / features['total_attempts']
    )

    # Flag likely brute force: many attempts, high failure rate
    features['is_brute_force'] = (
        (features['total_attempts'] > 10) &
        (features['failure_rate'] > 0.8)
    ).astype(int)

    return features

def engineer_apache_features(df):
    features = df.groupby('ip').agg(
        total_requests  = ('status', 'count'),
        error_count     = ('is_error', 'sum'),
        post_count      = ('is_post', 'sum'),
        unique_paths    = ('path', 'nunique'),
        avg_size        = ('size', 'mean'),
        status_404      = ('status', lambda x: (x == 404).sum()),
        status_500      = ('status', lambda x: (x == 500).sum()),
    ).reset_index()

    features['error_rate']   = features['error_count'] / features['total_requests']
    features['path_entropy'] = features['unique_paths'] / features['total_requests']

    return features