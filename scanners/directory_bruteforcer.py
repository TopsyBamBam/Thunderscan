import requests
import os
from tqdm import tqdm

class DirectoryBruteforcer:
    def __init__(self, base_url, wordlist):
        # Validate inputs
        if not os.path.isfile(wordlist):
            raise FileNotFoundError(f"Wordlist not found: {wordlist}")
        
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Thunderscan/1.0 (+https://example.com/thunderscan)'
        })

    def bruteforce(self):
        """Execute directory bruteforce with reliable progress tracking"""
        results = []
        try:
            with open(self.wordlist, 'r') as f:
                directories = [line.strip() for line in f if line.strip()]
            
            with tqdm(total=len(directories), desc="Bruteforce Progress", unit="dir") as pbar:
                for directory in directories:
                    if not directory:
                        continue
                        
                    url = f"{self.base_url}/{directory}"
                    try:
                        response = self.session.get(
                            url,
                            timeout=5,
                            allow_redirects=False
                        )
                        if response.status_code in [200, 403]:
                            results.append({
                                'url': url,
                                'status': response.status_code,
                                'size': len(response.content)
                            })
                    except requests.RequestException:
                        pass
                    finally:
                        pbar.update(1)
                        
        except Exception as e:
            print(f"[!] Bruteforce error: {str(e)}")
            
        return results