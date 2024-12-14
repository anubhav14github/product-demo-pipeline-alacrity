import json
import math
import re
from spellchecker import SpellChecker
import requests
from urllib.parse import urlparse, urljoin
import tldextract
import whois
from datetime import datetime
import socket
import ssl
from bs4 import BeautifulSoup, Comment
import dns.resolver
from collections import Counter


class URLFeatureExtractor:
    def __init__(self, url):
        self.url = url
        self.features = {}
        self.parsed_url = urlparse(url)
        self.domain_info = tldextract.extract(url)
        self.domain = f"{self.domain_info.domain}.{self.domain_info.suffix}" if self.domain_info.suffix else self.domain_info.domain
        self.now = datetime.now()
        self.response = None
        try:
            self.response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if self.response.status_code == 200:
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
            else:
                self.soup = None
        except Exception as e:
            print(f"Error fetching URL: {e}")
            self.soup = None
        # set

    def extract_url_features(self):
        """
        Extracts all features and stores them in the features dictionary.
        """
        ttl, num_of_ips = self.get_dns_info()
        self.features['url_len'] = self.get_url_length()
        self.features['url_whois_info'] = self.has_whois_info()
        self.features['url_certificate_age'] = self.get_ssl_certificate_age()
        self.features['dns_TTL'] = ttl
        self.features['dns_IP_count'] = num_of_ips
        self.features['domain_registration_length'] = self.get_domain_registration_length()
        self.features['abnormal_url'] = self.is_abnormal_url()
        self.features['age_of_domain'] = self.get_domain_age()
        self.features['is_https'] = self.is_https()
        self.features['url_unusual_symbols'] = self.has_unusual_symbols()

        # Page Content Features
        self.extract_page_content_features()

        return self.features

    def get_url_length(self):
        return len(self.url)

    def get_whois_info(self):
        # Get WHOIS information
        try:
            return whois.whois(self.domain)
        except Exception:
            return None

    def has_whois_info(self):
        try:
            # Check for essential WHOIS fields
            whois_info = self.get_whois_info()
            essential_fields = ['registrar', 'country', 'emails', 'creation_date']
            for field in essential_fields:
                if not whois_info.get(field):
                    return 0  # Incomplete WHOIS information

            # print(f"{url} whois exists")
            return 1  # Complete WHOIS information
        except Exception:
            return 0  # Incomplete WHOIS information due to error

    def get_ssl_certificate_age(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    return (self.now - not_before).days
        except Exception:
            return 0

    def get_dns_info(self):
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.timeout = 10  # Set timeout to 10 seconds
            resolver.lifetime = 10  # Set lifetime to 10 seconds
            resolver.nameservers = ['8.8.8.8', '2001:4860:4860::8888',
                                    '8.8.4.4', '2001:4860:4860::8844']

            answers = resolver.resolve(self.domain)
            ttl = answers.rrset.ttl
            num_of_ips = len(answers)
            return ttl, num_of_ips
        except Exception:
            return 0

    def get_domain_registration_length(self):
        try:
            whois_info = self.get_whois_info()
            if whois_info and whois_info.expiration_date:
                expiration_date = whois_info.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                return (expiration_date - self.now).days
        except Exception:
            pass
        return 0

    def is_abnormal_url(self):
        whois_info = self.get_whois_info()
        host_name = whois_info.domain.split('.')[0]
        if host_name not in self.url:
            return 1
        return 0

    def get_domain_age(self):
        try:
            whois_info = self.get_whois_info()
            if whois_info and whois_info.creation_date:
                creation_date = whois_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                return (self.now - creation_date).days
        except Exception:
            pass
        return 0

    # def is_https(self):
    #     if self.parsed_url.scheme not in ['http', 'https']:
    #         self.url = 'http://' + self.url
    #     try:
    #         return 1 if self.response.url.startswith('https://') else 0
    #     except requests.RequestException:
    #         return 0

    def is_https(self):
        if self.parsed_url.scheme not in ['http', 'https']:
            self.url = 'http://' + self.url
        try:
            if self.response and self.response.url.startswith('https://'):
                return 1
            else:
                return 0
        except Exception as e:
            print(f"[ERROR] Failed to check HTTPS status for {self.url}: {e}")
            return 0


    def has_unusual_symbols(self):
        return 1 if re.search(r'[^\w\-._~:/?#&=%]', self.url) else 0

    def get_js(self):
        """
        Extracts JavaScript content (inline and external) from the given URL.

        Returns:
            list: A list of JavaScript code snippets (str) from the page.
        """
        try:
            # Step 1: Fetch the HTML content of the webpage
            self.response.raise_for_status()  # Raise exception for HTTP errors
            # Step 2: Parse the HTML for <script> tags
            scripts = self.soup.find_all('script')

            # Step 3: Extract the script content
            js_content = []
            for script in scripts:
                if script.get('src'):  # External JS
                    js_url = script.get('src')
                    if not js_url.startswith(('http://', 'https://')):  # Handle relative URLs
                        js_url = urljoin(self.url, js_url)

                    try:
                        js_response = requests.get(js_url, timeout=10)
                        js_response.raise_for_status()
                        js_content.append(js_response.text)  # Decode external JS content
                    except Exception as e:
                        print(f"Failed to fetch external JS ({js_url}): {e}")
                else:  # Inline JS
                    if script.text:
                        js_content.append(script.text)

            # Step 4: Return all JavaScript content
            return js_content

        except Exception as e:
            print(f"Error fetching {self.url}: {e}")
            return []

    @staticmethod
    def calculate_entropy(script):
        """
        Calculate Shannon entropy of a given script.

        Args:
            script (str): JavaScript code as a string.

        Returns:
            float: Shannon entropy value of the script.
        """
        if not script:
            return 0
        counts = Counter(script)
        total = len(script)
        entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
        return entropy

    def is_obfuscated(self, script):
        if not script:
            return False

        # Shannon entropy
        entropy = self.calculate_entropy(script)

        # Refined keyword matching
        keyword_match = re.search(r'eval\(|Function\(|atob\(', script, re.IGNORECASE)

        # Minification ratio
        minified_ratio = len(script.replace(' ', '').replace('\n', '')) / len(script)

        # Adjusted thresholds
        entropy_threshold = 6.0
        minified_threshold = 0.95

        # Decision logic
        if entropy > entropy_threshold:
            if keyword_match or minified_ratio > minified_threshold:
                return True  # Obfuscation suspected
        return False

    def calculate_script_percentage(self):
        scripts = self.soup.find_all('script')
        total_page_size = len(self.response.text)
        script_size = sum(len(script.text) for script in scripts if script.text)  # Inline JS size
        return round((script_size / total_page_size), 3) if total_page_size > 0 else 0

    def calculate_link_percentage(self):
        total_tags = len(self.soup.find_all())
        link_tags = len(self.soup.find_all('a'))
        return round((link_tags / total_tags), 3) if total_tags > 0 else 0

    def calculate_request_url_percentage(self):

        # Gather all resource links
        links = [link.get('href') for link in self.soup.find_all('a')]
        images = [img.get('src') for img in self.soup.find_all('img')]
        scripts = [script.get('src') for script in self.soup.find_all('script')]
        resources = links + images + scripts

        external_links = 0
        total_links = 0

        for resource in resources:
            if resource:
                parsed_domain = urlparse(resource).netloc
                total_links += 1
                if parsed_domain and parsed_domain != self.domain:  # Count external resources
                    external_links += 1

        return round((external_links / total_links), 3) if total_links > 0 else 0

    @staticmethod
    def tag_visible(element):
        """
        Helper function to check if an HTML element's text is visible.
        """
        if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
            return False
        if isinstance(element, Comment):
            return False
        return True

    def extract_visible_text(self):
        """
        Extract visible text from HTML content, excluding script, style, and other non-visible elements.
        """
        texts = self.soup.find_all(string=True)
        vis = [texts for text in texts if self.tag_visible(text)]
        visible_texts = filter(self.tag_visible, texts)
        return " ".join(t.strip() for t in visible_texts)

    @staticmethod
    def calculate_spelling_mistakes(text):
        """
        Calculate the spelling mistake ratio in a given text.
        """

        spell = SpellChecker()

        words = text.split()
        total_words = len(words)
        misspelled_words = spell.unknown(words)
        num_misspelled = len(misspelled_words)

        # Calculate the ratio of misspelled words
        if total_words == 0:
            return 0.0
        misspelled_ratio = num_misspelled / total_words
        return round(misspelled_ratio, 2)

    def get_spelling_mistakes_ratio(self):
        """
        Wrapper function to extract visible text from HTML and calculate the spelling mistake ratio.
        """
        visible_text = self.extract_visible_text()
        misspelled_ratio = self.calculate_spelling_mistakes(visible_text)
        return misspelled_ratio

    def get_content_richness(self):
        visible_text = self.extract_visible_text()
        total_content_size = len(self.response.text)
        visible_text_size = len(visible_text)

        # Calculate content richness as the ratio of visible text size to total content size
        if total_content_size == 0:
            return 0.0
        content_richness = visible_text_size / total_content_size
        return round(content_richness, 3)

    def has_robots(self):
        try:
            # Construct the robots.txt URL using the domain
            robots_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}/robots.txt"

            # Make an HTTP GET request to check for robots.txt
            response = requests.get(robots_url, allow_redirects=True)

            if response.status_code == 200:
                return 1  # Robots.txt found
            else:
                return 0  # Robots.txt not found
        except requests.RequestException as e:
            print('has_robots error: ' + str(e))
            return 0

    # Feature - Check if the website is responsive(if there is a code for mobile size as well).
    def is_responsive(self):
        try:
            # Parse HTML content
            responsive_meta = self.soup.find('meta', {'name': 'viewport'})

            if responsive_meta and 'content' in responsive_meta.attrs:
                # Optionally validate viewport content
                content = responsive_meta['content']
                if 'width=device-width' in content or 'initial-scale' in content:
                    return 1  # Responsive
            return 0  # Not responsive
        except Exception as e:
            print('is_responsive error: ' + str(e))
            return 0

    # Feature - Check if the website has a description tag
    def has_description(self):
        try:
            # Search for the meta description tag
            meta_description = self.soup.find('meta', {'name': 'description'})

            # Check if the description exists and has content
            if meta_description and meta_description.get('content'):
                return 1  # Has description
            else:
                return 0  # Does not have description
        except Exception as e:
            print('has_description error: ' + str(e))
            return 0

    # Feature - Checks the number of popups a website has.
    def no_of_popup(self):
        try:
            # Find all scripts containing popup-related JavaScript methods
            popup_scripts = self.soup.find_all('script', string=re.compile(r'window\.open|alert|confirm|prompt'))

            # Count the number of such scripts
            popup_count = len(popup_scripts)
            return popup_count
        except Exception as e:
            print('no_of_popup error: ' + str(e))
            return 0

    # Feature - Checks the number of iframe a website has.
    def no_of_iframe(self):
        try:
            # Count the number of <iframe> tags
            iframe_count = len(self.soup.find_all('iframe'))
            return iframe_count
        except Exception as e:
            print('no_of_iframe error: ' + str(e))
            return 0

    # Feature - Check if the website is submitting a form to a different link than the actual domain.
    @staticmethod
    def has_external_form_submit(forms, parsed_url):
        try:
            # Check for external form submit
            external_form_submit = 0
            for form in forms:
                action = form.get('action')
                if action and urlparse(action).netloc and urlparse(action).netloc != parsed_url.netloc:
                    external_form_submit = 1
                    break

            return external_form_submit
        except Exception as e:
            print('has_external_form_submit error: ' + str(e))
            return 0

    # Feature - Checks if the website has a social network link.
    def has_social_network(self):
        social_networks = ['facebook.com', 'x.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'pinterest.com',
                           'youtube.com']
        try:

            links = self.soup.find_all('a', href=True)
            # Check for social media links
            has_social_net = 0
            for link in links:
                href = link.get('href')
                if any(social_network in href for social_network in social_networks):
                    has_social_net = 1
                    break

            return has_social_net
        except Exception as e:
            print('has_social_net error: ' + str(e))
            return 0

    # Feature - Checks if the website has a hidden field.
    def has_hidden_fields(self):
        try:

            hidden_fields = self.soup.find_all('input', {'type': 'hidden'})

            # Check for hidden fields
            has_hidden = 1 if hidden_fields else 0
            return has_hidden
        except Exception as e:
            print('has_hidden_fields error: ' + str(e))
            return 0

    # Feature - Checks if a form in a website is submitting to a http protocol.
    @staticmethod
    def has_insecure_form(forms):
        try:

            # Check for insecure forms
            for form in forms:
                action = form.get('action')
                if action and action.startswith('http://'):
                    return 1  # Insecure form found

            return 0  # No insecure forms found
        except Exception as e:
            print('insecure_forms error: ' + str(e))
            return 0

    # Feature - Checks if the website has forms with relative URLs(A url that does not include domain name just the path)
    @staticmethod
    def has_relative_form_action(forms):
        try:
            # Check for relative actions
            for form in forms:
                action = form.get('action')
                if action and not urlparse(action).netloc:
                    return 1  # Relative form action found

            return 0  # No relative form actions found
        except Exception as e:
            print('relative_form_action error: ' + str(e))
            return 0

    # Feature - Checks if any form on the webpage has an external URL that does not include the same domain as the current one.
    @staticmethod
    def has_external_form_action(forms, parsed_url):
        try:
            # Check for external actions
            for form in forms:
                action = form.get('action')
                if action and urlparse(action).netloc and urlparse(action).netloc != parsed_url.netloc:
                    return 1  # External form action found

            return 0  # No external form actions found
        except Exception as e:
            print('ext_form_action error: ' + str(e))
            return 0

    # Feature - Calculates the percentage of self-direct hyperlinks to the total number of links.
    def percentage_of_null_self_redirect_hyperlinks(self):
        try:

            links = self.soup.find_all('a', href=True)

            # Count self or null redirect links
            null_self_redirect_links = 0
            for link in links:
                href = link.get('href')
                if href in ['#', 'javascript:void(0)']:
                    null_self_redirect_links += 1

            total_links = len(links)
            if total_links == 0:
                return 0.0

            # Calculate percentage
            percentage = round((null_self_redirect_links / total_links), 3)
            return percentage
        except Exception as e:
            print('pct_null_self_redirect_hyperlinks error: ' + str(e))
            return 0

    # Feature - Checks if right click is disabled on a website
    def right_click_disabled(self):
        try:

            html_content = self.response.text

            # Check if right-click is disabled based on specific JavaScript events
            if 'event.button==2' in html_content or 'event.button == 2' in html_content:
                return 1  # Right click disabled
            else:
                return 0  # Right click not disabled

        except Exception as e:
            print('right_click_disabled error: ' + str(e))
            return 0

    # Feature - Checks if there is a form submission to an email.
    @staticmethod
    def has_submit_info_to_email(forms):
        try:

            submit_to_email = 0
            for form in forms:
                action = form.get('action')
                if action and action.startswith('mailto:'):
                    submit_to_email = 1
                    break

            return submit_to_email  # 1 for email submission, 0 for not

        except Exception as e:
            print('submit_info_to_email error: ' + str(e))
            return 0

    # Feature - Checks if a form only accepts image.
    @staticmethod
    def has_image_only_form(forms):
        try:
            # Variable to check if a form contains only image inputs
            images_only = 0

            # Loop through each form to check its input types
            for form in forms:
                inputs = form.find_all('input')
                # Check if all input fields in the form are of type "image"
                if inputs and all(input_.get('type') == 'image' for input_ in inputs):
                    images_only = 1
                    break

            return images_only  # Return 1 if image-only inputs found, otherwise 0

        except Exception as e:
            print('images_only_in_form error: ' + str(e))
            return 0

    # Checks if a webpage has a password field in forms.
    @staticmethod
    def has_password_field(forms):
        try:
            # Variable to track if any form contains a password field
            has_password = 0

            # Loop through each form and check for password fields
            for form in forms:
                password_fields = form.find_all('input', {'type': 'password'})
                if password_fields:
                    has_password = 1
                    break

            return has_password  # Return 1 if password field is found, otherwise 0

        except Exception as e:
            print('has_password_field error: ' + str(e))
            return 0

    # Checks if a webpage has a submit button in any form.
    @staticmethod
    def has_submit_button(forms):
        try:
            # Variable to track if any form contains a submit button
            has_submit = 0

            # Loop through each form and check for submit buttons
            for form in forms:
                inputs = form.find_all('input', {'type': 'submit'})
                buttons = form.find_all('button', {'type': 'submit'})
                if inputs or buttons:
                    has_submit = 1
                    break

            return has_submit  # Return 1 if a submit button is found, otherwise 0

        except Exception as e:
            print('has_submit_button error: ' + str(e))
            return 0

    """
        Analyzes all forms within the HTML content and extracts various security and structural features.

        Returns:
            tuple: A tuple containing the following features:
                - has_external_form_submit (int): Indicates if any form submits to an external domain (1 if true, 0 otherwise).
                - has_insecure_form (int): Indicates if any form uses an insecure 'http://' action (1 if true, 0 otherwise).
                - has_relative_form_action (int): Indicates if any form uses a relative action URL (1 if true, 0 otherwise).
                - has_external_form_action (int): Indicates if any form action points to an external domain (1 if true, 0 otherwise).
                - has_submit_info_to_email (int): Indicates if any form submits information to an email via 'mailto:' (1 if true, 0 otherwise).
                - has_image_only_form (int): Indicates if any form contains only image inputs (1 if true, 0 otherwise).
                - has_password_field (int): Indicates if any form contains a password input field (1 if true, 0 otherwise).
                - has_submit_button (int): Indicates if any form contains a submit button (1 if true, 0 otherwise).
    """

    def get_form_analysis(self):
        forms = self.soup.find_all('form')
        has_external_form_submit = self.has_external_form_submit(forms, self.parsed_url)
        has_insecure_form = self.has_insecure_form(forms)
        has_relative_form_action = self.has_relative_form_action(forms)
        has_external_form_action = self.has_external_form_action(forms, self.parsed_url)
        has_submit_info_to_email = self.has_submit_info_to_email(forms)
        has_image_only_form = self.has_image_only_form(forms)
        has_password_field = self.has_password_field(forms)
        has_submit_button = self.has_submit_button(forms)
        return (has_external_form_submit, has_insecure_form, has_relative_form_action,
                has_external_form_action, has_submit_info_to_email, has_image_only_form,
                has_password_field, has_submit_button)

    """
        Extracts page content features.

        This method extracts features from the HTML content of a webpage,
        including JavaScript content, link and request URL percentages,
        spelling mistakes ratio, content richness, social network presence,
        hidden fields, insecure forms, self-redirecting hyperlinks,
        right-click disabled, submit to email, image-only forms,
        password fields, and submit buttons.

        Returns:
            dict: A dictionary of extracted features.
        """

    def extract_page_content_features(self):

        try:
            all_js = self.get_js()
            total_js_size = round((sum(len(js.encode('utf-8')) for js in all_js) / 1024), 3) if all_js else 0
            obfuscated_js_size = round((sum(len(js.encode('utf-8')) for js in all_js if self.is_obfuscated(js)) / 1024),
                                       3) if all_js else 0
            self.features['js_size'] = total_js_size
            self.features['js_obfuscated_size'] = obfuscated_js_size
            self.features['script_percentage'] = self.calculate_script_percentage()
            self.features['link_percentage'] = self.calculate_link_percentage()
            self.features['request_url_percentage'] = self.calculate_request_url_percentage()
            self.features['spelling_mistakes_ratio'] = self.get_spelling_mistakes_ratio()
            self.features['content_richness'] = self.get_content_richness()
            self.features['has_robots'] = self.has_robots()
            self.features['is_responsive'] = self.is_responsive()
            self.features['has_description'] = self.has_description()
            self.features['no_of_popup'] = self.no_of_popup()
            self.features['no_of_iframe'] = self.no_of_iframe()
            (has_external_form_submit, has_insecure_form, has_relative_form_action,
             has_external_form_action, has_submit_info_to_email, has_image_only_form,
             has_password_field, has_submit_button) = self.get_form_analysis()

            self.features['has_external_form_submit'] = has_external_form_submit
            self.features['has_social_net'] = self.has_social_network()
            self.features['has_hidden_fields'] = self.has_hidden_fields()
            self.features['has_insecure_form'] = has_insecure_form
            self.features['has_relative_form_action'] = has_relative_form_action
            self.features['has_external_form_action'] = has_external_form_action
            self.features['percentage_of_null_self_redirect_hyperlinks'] = self.percentage_of_null_self_redirect_hyperlinks()
            self.features['right_click_disabled'] = self.right_click_disabled()
            self.features['has_submit_info_to_email'] = has_submit_info_to_email
            self.features['has_image_only_form'] = has_image_only_form
            self.features['has_password_field'] = has_password_field
            self.features['has_submit_button'] = has_submit_button
        except Exception as e:
            print(f"Error extracting page content features: {e}")


# if __name__ == "__main__":
#     check_url = 'https://throwgrammarfromthetrain.blogspot.com/2013/09/taboo-avoidance-by-typo.html'
#     extractor = URLFeatureExtractor(check_url)
#     features = extractor.extract_url_features()
#     print(features)
#     print(len(features))
#     features_json = json.dumps(features, indent=4)
#     with open("features.json", "w") as outfile:
#         outfile.write(features_json)


# # feature_extraction.py
# import pandas as pd

# def feature_extraction(urls):
#     print("[INFO] Extracting features from URLs...")
#     # Dummy data: Replace with your actual feature extraction logic
#     data = {
#         "URL": urls,
#         "Feature1": [0.1, 0.9],
#         "Feature2": [0.5, 0.4],
#     }
#     for i in range(3, 35):
#         data[f"Feature{i}"] = [0.2, 0.8]
#     features_df = pd.DataFrame(data)
#     print("[INFO] Feature extraction complete.")
#     return features_df
