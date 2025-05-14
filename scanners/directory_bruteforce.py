from urllib.parse import urlparse
import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

class DirectoryBruteforcer:
    def __init__(self, base_url, wordlist, max_workers=20):
        if not os.path.isfile(wordlist):
            raise FileNotFoundError(f"Wordlist not found: {wordlist}")
        
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Thunderscan/3.0', # Consistent with your tool's User-Agent
            'Accept-Encoding': 'gzip, deflate' # Important for content negotiation
        })

    def bruteforce(self):
        results = []
        valid_extensions = ['', '.php', '.html'] # Consider making this configurable or more extensive
        
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                directories = [line.strip() for line in f if line.strip()]
            
            # total_tests = len(directories) * len(valid_extensions) * 3 # Original calculation
            # The variants logic is handled per directory/ext pair, pbar updates 3 times per pair.
            # So, total tests for pbar should be len(directories) * len(valid_extensions) * number_of_variants_per_dir_ext_pair
            # number_of_variants_per_dir_ext_pair is 3 (original, upper, lower)
            total_pbar_updates = len(directories) * len(valid_extensions) * 3
            
            with tqdm(total=total_pbar_updates, desc="Bruteforce Progress", unit="test") as pbar:
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = []
                    
                    for directory in directories:
                        for ext in valid_extensions:
                            # Each call to _test_variants_for_item will perform up to 3 actual tests (variants)
                            # and update pbar accordingly.
                            futures.append(
                                executor.submit(
                                    self._test_item_variants, # Renamed for clarity
                                    directory,
                                    ext,
                                    pbar
                                )
                            )
                    
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            if result:
                                results.append(result)
                        except Exception as e:
                            # This catches errors from _test_item_variants if not handled internally,
                            # though internal handling is preferred.
                            tqdm.write(f"[!] Error processing a bruteforce item: {e}")
                            
            # Remove duplicates based on URL, keeping the first occurrence implicitly (dict behavior)
            # or choose based on status or other criteria if needed.
            return list({v['url']: v for v in results}.values()) 
            
        except Exception as e:
            tqdm.write(f"[!] Bruteforce error: {str(e)}")
            return []

    def _test_item_variants(self, item_name, ext, pbar): # Renamed from _test_variants for clarity
        # Define variants (e.g., original, uppercase, lowercase)
        # Note: ext can also be part of variations if desired (e.g. .PHP, .Html)
        # The original code applies upper/lower to both directory and ext together.
        base_item_with_ext = f"{item_name}{ext}"
        variants_to_test = list(set([ # Use set to avoid duplicate tests if item_name or ext is already mixed case
            base_item_with_ext,
            base_item_with_ext.upper(),
            base_item_with_ext.lower()
        ]))

        found_details = None
        for variant_path in variants_to_test:
            response = None # Ensure response is defined for each variant attempt
            try:
                url = f"{self.base_url}/{variant_path.lstrip('/')}"
                
                try:
                    # Try HEAD first - often faster if allowed
                    response = self.session.head(url, timeout=3, allow_redirects=False)
                    
                    # Fallback to GET if HEAD is not allowed (405) or sometimes for other non-successful HEAD responses
                    if response.status_code == 405 or not (200 <= response.status_code < 300): # Check if HEAD was not informative
                        # Be cautious with GET if HEAD failed for reasons other than 405,
                        # but for bruteforcing, sometimes GET reveals more.
                        response = self.session.get(url, timeout=3, allow_redirects=False) # Max timeout for GET
                
                except requests.exceptions.Timeout:
                    # tqdm.write(f"[Debug] Timeout for {url}")
                    continue # Try next variant
                except requests.exceptions.ConnectionError:
                    # tqdm.write(f"[Debug] Connection error for {url}")
                    # This might indicate a broader issue, potentially stop or slow down.
                    # For now, continue with other variants/items.
                    continue # Try next variant
                except requests.exceptions.RequestException:
                    # Catch other request-related issues
                    # tqdm.write(f"[Debug] Request exception for {url}: {e_req}")
                    continue # Try next variant
                
                # Process the response if one was received
                if response is not None:
                    is_interesting, content_bytes = self._get_interesting_response_data(response)
                    if is_interesting:
                        found_details = {
                            'url': response.url, # Use response.url to get the final URL after any (non-followed) redirects
                            'status': response.status_code,
                            'length': len(content_bytes) if content_bytes is not None else 0
                        }
                        break # Found an interesting response for this item_name/ext, no need to check other variants
            
            except Exception:
                # Catch any other unexpected error for this specific variant_path processing
                # tqdm.write(f"[Debug] Unexpected error processing variant {variant_path} for {url}: {e_inner}")
                # This ensures pbar is updated even if an unexpected error occurs.
                pass # Continue to the finally block to update pbar, then to the next variant.
            
            finally:
                # pbar.update should happen once per actual test attempt.
                # Since variants are looped here, and pbar total was based on variants:
                pbar.update(1) 
        
        return found_details

    def _get_interesting_response_data(self, response):
        """
        Checks if a response is "interesting" and returns its content if it is.
        Handles potential errors during content access (like deserialization issues).
        """
        if not response: # Should not be None if called after a successful request
            return False, None
            
        content_bytes = None
        text_content = None

        try:
            # Accessing .content or .text can trigger deserialization (e.g., for gzip)
            # This is where the "Unable to deserialize response" (TypeError) would occur.
            content_bytes = response.content
            # Only access text if needed by _is_default_page and content was accessible
            if content_bytes is not None: # Avoid accessing .text if .content already failed or was None
                 text_content = response.text
            
            if content_bytes is None: # If .content successfully accessed but is None
                return False, None 
        
        except Exception: # Catches TypeError from deserialization, or other errors.
            # tqdm.write(f"[Debug] Error accessing/deserializing content for {response.url}: {e_access}")
            return False, None # Treat as not interesting if content is inaccessible

        # Define what makes a response interesting
        interesting_status_codes = [200, 301, 302, 307, 403, 401]
        min_content_length = 100 # Adjust as needed; very small responses might be custom errors.

        if (response.status_code in interesting_status_codes and
            len(content_bytes) >= min_content_length and
            not self._is_default_page(text_content, response)): # Pass response for more context if needed
            return True, content_bytes
        else:
            return False, None

    def _is_default_page(self, response_text_content, response_obj): # Added response_obj for more context
        """
        Checks if the response content suggests it's a common default page (e.g., 404, server index).
        """
        if response_text_content is None or not isinstance(response_text_content, str):
            # If text content couldn't be retrieved or is not string,
            # it's hard to analyze. Could be an error page.
            # Depending on strictness, one might check response_obj.status_code here too.
            # For now, if no text, assume it might be a non-custom, uninteresting page.
            return True 

        default_page_indicators = [
            # Common in title or body
            "404 Not Found", "Page Not Found", "Not Found",
            "Access Denied", "Forbidden",
            "Index of /", "Directory Listing",
            "Apache Server at", "Welcome to nginx!",
            # Add more specific indicators based on common web servers or frameworks
            # "This page is used to test the proper operation of the Apache HTTP server",
            # "IIS Windows Server"
        ]
        # Check for indicators in lowercase for case-insensitivity
        text_lower = response_text_content.lower()
        for indicator in default_page_indicators:
            if indicator.lower() in text_lower:
                return True
        
        # Add additional checks, e.g. if the content length is suspiciously small for certain status codes
        # if response_obj.status_code == 200 and len(response_obj.content) < 50: # Example
        #     return True

        return False