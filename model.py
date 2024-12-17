import pandas as pd
import joblib

def preprocess_and_classify(features_csv):
    """
    Reads extracted features, preprocesses them, and classifies URLs as spam or ham.
    """
    # Step 1: Load extracted features (with URLs)
    test_df = pd.read_csv(features_csv)

    # Debug: Check the first few rows of the dataset to verify 'url' column
    print("Dataset Preview:")
    print(test_df.head())

    # Ensure the dataset contains the 'url' column
    if 'url' not in test_df.columns:
        raise KeyError("The 'url' column is missing from the dataset. Check the CSV file.")

    # Separate the 'url' column (to attach later)
    urls = test_df['url']
    features_df = test_df.drop(columns=['url'])  # Drop the 'url' column to keep only features

    # Step 2: Load the pre-trained model
    print("[INFO] Loading pre-trained model...")
    model = joblib.load('decision_tree_model.pkl')

    # Get the list of features that the model was trained on
    trained_features = model.feature_names_in_

    # Step 3: Align the features in the test set to match the training set
    # Add missing features in the test set
    missing_features = set(trained_features) - set(features_df.columns)
    if missing_features:
        print(f"[INFO] Adding missing features: {missing_features}")
        for feature in missing_features:
            features_df[feature] = 0  # Add missing features with value 0

    # Drop extra features in the test set
    extra_features = set(features_df.columns) - set(trained_features)
    if extra_features:
        print(f"[INFO] Dropping extra features: {extra_features}")
        features_df.drop(columns=extra_features, inplace=True)

    # Reorder columns to match the training set
    features_df = features_df[trained_features]

    # Step 4: Predict the labels
    print("[INFO] Predicting labels...")
    predictions = model.predict(features_df)
    labels = ["ham" if pred == 0 else "spam" for pred in predictions]

    # Step 5: Create a results DataFrame
    results_df = pd.DataFrame({
        'url': urls,
        'predicted_label': labels
    })

    # Return the results DataFrame
    return results_df

if __name__ == "__main__":
    # Process and classify URLs
    results = preprocess_and_classify("extracted_features.csv")

    # Save the results to a CSV file
    results.to_csv("classified_results.csv", index=False)
    print("\n[INFO] Classification results saved to 'classified_results.csv'")
    print(results)
