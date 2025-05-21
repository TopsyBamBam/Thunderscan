from urllib.parse import urlparse, urljoin
import requests
import os
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import threading
import itertools

class DirectoryBruteforcer:
    def __init__(self, base_url, wordlist, max_workers=20, max_entries=20000):
        if not os.path.isfile(wordlist):
            raise FileNotFoundError(f"Wordlist not found: {wordlist}")
        
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist
        self.max_workers = max_workers
        self.max_entries = max_entries
        self.session = requests.Session()
        self.seen_content = set()
        self.lock = threading.Lock()
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })

    def bruteforce(self):
        results = []
        valid_extensions = ['', '.php', '.html']
        
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                directories = [line.strip() for line in itertools.islice(f, self.max_entries)]
            
            total_tests = len(directories) * len(valid_extensions) * 2
            with tqdm(total=total_tests, desc="Bruteforce Progress", unit="test") as pbar:
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = []
                    
                    for directory in directories:
                        for ext in valid_extensions:
                            futures.append(
                                executor.submit(
                                    self._test_item,
                                    directory,
                                    ext,
                                    pbar
                                )
                            )
                    
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            results.append(result)
            
            return self._filter_results(results)
            
        except Exception as e:
            tqdm.write(f"[!] Bruteforce error: {str(e)}")
            return []

    def _test_item(self, item_name, ext, pbar):
        base_item = f"{item_name}{ext}"
        variants = [base_item, base_item.lower()]
        
        for variant in variants:
            url = f"{self.base_url}/{variant.lstrip('/')}"
            try:
                response = self.session.get(url, timeout=3, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 307, 403]:
                    content_hash = hashlib.md5(response.content).hexdigest()
                    
                    with self.lock:
                        if content_hash in self.seen_content:
                            return None
                        self.seen_content.add(content_hash)
                    
                    if self._is_interesting(response):
                        return {
                            'url': response.url,
                            'status': response.status_code,
                            'length': len(response.content),
                            'headers': dict(response.headers)
                        }
                        
            except requests.exceptions.RequestException:
                continue
            finally:
                pbar.update(1)
        return None

    def _is_interesting(self, response):
        content = response.text.lower()
        error_indicators = [
            'page not found', '404 error', 'access denied',
            'forbidden', 'not found', 'invalid url'
        ]
        
        return (
            200 <= response.status_code < 500 and
            len(response.content) > 50 and
            not any(err in content for err in error_indicators) and
            not self._is_default_page(response)
        )

    def _is_default_page(self, response):
        server = response.headers.get('Server', '').lower()
        return any(
            server.startswith(s) for s in ['apache', 'nginx', 'iis']
        ) and len(response.content) < 1024

    def _filter_results(self, results):
        filtered = []
        for res in results:
            if res['length'] > 100 and res['status'] != 403:
                filtered.append(res)
        return filtered