# preprocess.py
import pandas as pd
from sklearn.preprocessing import StandardScaler

def preprocess_features(features_df):
    print("[INFO] Preprocessing features...")
    scaler = StandardScaler()
    features = features_df.drop(columns=["URL"])  # Drop non-numeric columns
    features_scaled = scaler.fit_transform(features)
    preprocessed_df = pd.DataFrame(features_scaled, columns=features.columns)
    print("[INFO] Preprocessing complete.")
    return preprocessed_df
