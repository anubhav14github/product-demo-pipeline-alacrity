# web_crawler.py
import csv

def web_crawler(csv_file="testNewURLs.csv"):
    """
    Reads full URLs from a CSV file and returns them as a list.
    """
    print("[INFO] Reading URLs from CSV...")
    urls = []
    with open(csv_file, "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            url = row['url'].strip()  # Directly read the 'url' column
            urls.append(url)
    print(f"[INFO] Found {len(urls)} URLs.")
    return urls


# web_crawler.py
# import csv

# def web_crawler(csv_file="first_100_domains.csv"):
#     """
#     Reads domains from a CSV file and converts them to HTTPS URLs.
#     """
#     print("[INFO] Reading domains from CSV...")
#     urls = []
#     with open(csv_file, "r") as file:
#         reader = csv.DictReader(file)
#         for row in reader:
#             domain = row['domain'].strip()
#             url = f"https://{domain}"  # Convert domain to full URL
#             urls.append(url)
#     print(f"[INFO] Found {len(urls)} URLs.")
#     return urls


# # web_crawler.py
# def web_crawler():
#     print("[INFO] Crawling the web for URLs...")
#     urls = ["http://example.com", "http://phishingsite.com"]  # Dummy data
#     print(f"[INFO] Found URLs: {urls}")
#     return urls
