# model.py
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def classify_urls(features_df):
    print("[INFO] Classifying URLs...")
    # Dummy labels: Replace with real data
    labels = [0, 1]  # 0 = Legitimate, 1 = Phishing

    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        features_df, labels, test_size=0.5, random_state=42
    )
    
    # Train model (use a saved/trained model in production)
    model = RandomForestClassifier()
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    
    print("[INFO] Classification results:")
    print(classification_report(y_test, predictions))
    return predictions


