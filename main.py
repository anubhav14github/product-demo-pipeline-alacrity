# main.py
import json
from web_crawler import web_crawler
from feature_extraction import URLFeatureExtractor

if __name__ == "__main__":
    # Step 1: Crawl the web (read from CSV in this case)
    urls = web_crawler("first_100_domains.csv")
    
    # Step 2: Process each URL
    for url in urls:
        print(f"\n[INFO] Processing URL: {url}")
        extractor = URLFeatureExtractor(url)
        features = extractor.extract_url_features()
        
        # Print the features in the terminal
        print(json.dumps(features, indent=4))
        
        # Save the features to a JSON file (append mode)
        with open("features_output.json", "a") as outfile:
            outfile.write(json.dumps({url: features}, indent=4) + ",\n")


# # main.py
# from web_crawler import web_crawler
# from feature_extraction import feature_extraction
# from preprocess import preprocess_features
# from model import classify_urls

# if __name__ == "__main__":
#     # Step 1: Crawl the web for URLs
#     urls = web_crawler()
    
#     # Step 2: Extract features from the URLs
#     features_df = feature_extraction(urls)
    
#     # Step 3: Preprocess the features
#     preprocessed_features = preprocess_features(features_df)
    
#     # Step 4: Classify URLs using the ML model
#     predictions = classify_urls(preprocessed_features)
    
#     # Output final results
#     print("[INFO] Final Results:")
#     for url, pred in zip(urls, predictions):
#         print(f"URL: {url} | Prediction: {'Phishing' if pred else 'Legitimate'}")
