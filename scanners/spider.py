import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from time import sleep, time
from bloom_filter import BloomFilter
import requests_cache
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from tqdm import tqdm

class Spider:
    def __init__(self, base_url, max_depth=3, max_workers=8, request_delay=0.5):
        self.base_url = base_url.rstrip('/')
        self.max_depth = max_depth
        self.request_delay = request_delay
        self.running = True
        self.start_time = time()
        
        # Thread-safe structures
        self.lock = threading.Lock()
        self.visited = BloomFilter(max_elements=100000, error_rate=0.01)
        
        # Session configuration
        self.session = requests.Session()
        self._configure_session()
        
        # Execution control
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.futures = set()
        self.progress = tqdm(total=1, desc="Crawling Progress", unit="page",
                            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")

    def _configure_session(self):
        """Configure HTTP session with caching and retries"""
        requests_cache.install_cache('thunderscan_cache', expire_after=3600)
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=100
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            'User-Agent': 'Thunderscan/1.0 (+https://example.com/thunderscan)',
            'Accept-Language': 'en-US,en;q=0.5'
        })

    def crawl(self):
        try:
            # Initial task
            self._submit_task(self.base_url, 0)
            last_activity = time()
            
            # Main processing loop
            while self.running:
                done = []
                try:
                    # Process completed tasks with timeout
                    for future in as_completed(self.futures, timeout=5):
                        done.append(future)
                        result = future.result()
                        self._handle_result(result)
                        last_activity = time()
                        self.progress.update(1)
                        
                except TimeoutError:
                    # Check for inactivity timeout
                    if time() - last_activity > 15:
                        print("\n[!] No activity for 15 seconds, stopping...")
                        break
                    continue
                
                # Remove completed futures
                with self.lock:
                    self.futures = {f for f in self.futures if f not in done}
                
                # Exit condition: No pending tasks
                if not self.futures:
                    break

        except KeyboardInterrupt:
            print("\n[!] Crawling interrupted by user")
        finally:
            self._safe_shutdown()
            return self._get_results()

    def _submit_task(self, url, depth):
        """Submit new crawling tasks with depth control"""
        if depth <= self.max_depth and self._should_visit(url):
            future = self.executor.submit(self._crawl_worker, url, depth)
            self.futures.add(future)
            with self.lock:
                self.progress.total += 1
                self.progress.refresh()

    def _should_visit(self, url):
        """Thread-safe URL tracking"""
        with self.lock:
            if url in self.visited:
                return False
            self.visited.add(url)
            return True

    def _crawl_worker(self, url, depth):
        """Core crawling logic"""
        if not self.running:
            return None
            
        try:
            sleep(self.request_delay)
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            links = self._extract_links(url, soup)
            
            # Submit child links if within depth limit
            if depth < self.max_depth:
                for link in links:
                    self._submit_task(link, depth + 1)
            
            return {
                'url': url,
                'links': links,
                'forms': soup.find_all('form'),
                'status': response.status_code
            }
            
        except Exception as e:
            return {'url': url, 'error': str(e)}

    def _extract_links(self, base_url, soup):
        """Extract and validate links from page"""
        return [
            urljoin(base_url, a['href'])
            for a in soup.find_all('a', href=True)
            if self._is_valid_link(a['href'])
        ]

    def _is_valid_link(self, href):
        """Improved link validation"""
        try:
            parsed = urlparse(href)
            base_netloc = urlparse(self.base_url).netloc
            return (
                parsed.scheme in ('http', 'https') and
                parsed.netloc.endswith(base_netloc) and  # Allow subdomains
                not parsed.path.lower().endswith(('.pdf', '.jpg', '.png', '.zip')) and
                not parsed.fragment and
                'logout' not in parsed.path.lower()  # Avoid logout links
            )
        except:
            return False

    def _handle_result(self, result):
        """Enhanced result processing"""
        if result:
            if 'error' in result:
                tqdm.write(f"[!] Error ({result['url']}): {result['error']}")
            else:
                tqdm.write(f"[+] Crawled {result['url']} ({len(result['links'])} links)")

    def _safe_shutdown(self):
        """Improved shutdown sequence"""
        self.running = False
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.session.close()
        self.progress.close()

    def _get_results(self):
        """Collect valid results"""
        return [f.result() for f in self.futures if f.done() and not f.result().get('error')]