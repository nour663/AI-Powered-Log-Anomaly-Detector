import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def train_unsupervised(features_df, feature_cols, model_path='models/isolation_forest.pkl'):
 
    os.makedirs('models', exist_ok=True)

    X = features_df[feature_cols].fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # contamination = expected % of anomalies in data
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,   # expect 5% anomalies
        random_state=42
    )
    model.fit(X_scaled)

    # Save model and scaler
    joblib.dump(model, model_path)
    joblib.dump(scaler, 'models/scaler.pkl')
    print(f"Model saved to {model_path}")

    # Score the training data
    features_df['anomaly_score'] = model.decision_function(X_scaled)
    features_df['is_anomaly'] = model.predict(X_scaled)  # -1 = anomaly, 1 = normal

    return features_df

def train_supervised(features_df, feature_cols, label_col,
                     model_path='models/random_forest.pkl'):

    X = features_df[feature_cols].fillna(0)
    y = features_df[label_col]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    joblib.dump(model, model_path)
    return model