from urllib.parse import urlparse, urljoin
import requests
import re
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from time import sleep, time
from bloom_filter import BloomFilter
from requests_cache import CachedSession
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
        self.last_activity = time()
        
        self.lock = threading.Lock()
        self.visited = BloomFilter(max_elements=100000, error_rate=0.01)
        
        self.session = self._create_session()
        self._configure_adapters()
        
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.futures = set()
        self.progress = tqdm(total=1, desc="Crawling Progress", unit="page",
                            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")

    def _create_session(self):
        """Create isolated cached session for spider only"""
        return CachedSession(
            'thunderscan_cache',
            expire_after=3600,
            backend='sqlite',
            allowable_methods=('GET', 'HEAD')
        )

    def _configure_adapters(self):
        """Configure retry and connection pooling"""
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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Accept-Language': 'en-US,en;q=0.5'
        })

    def crawl(self):
        try:
            self._submit_task(self.base_url, 0)
            
            while self.running:
                done = []
                try:
                    for future in as_completed(self.futures, timeout=5):
                        done.append(future)
                        result = future.result()
                        self._handle_result(result)
                        self.last_activity = time()
                        self.progress.update(1)
                        
                except TimeoutError:
                    if time() - self.last_activity > 30:
                        print("\n[!] No activity for 30 seconds, stopping...")
                        break
                    continue
                
                with self.lock:
                    self.futures = {f for f in self.futures if f not in done}
                
                if not self.futures:
                    break

        except KeyboardInterrupt:
            print("\n[!] Crawling interrupted by user")
        finally:
            self._safe_shutdown()
            return self._get_results()

    def _submit_task(self, url, depth):
        if depth <= self.max_depth and self._should_visit(url):
            future = self.executor.submit(self._crawl_worker, url, depth)
            self.futures.add(future)
            with self.lock:
                self.progress.total += 1
                self.progress.refresh()

    def _should_visit(self, url):
        with self.lock:
            if url in self.visited:
                return False
            self.visited.add(url)
            return True

    def _crawl_worker(self, url, depth):
        if not self.running:
            return None
            
        try:
            sleep(self.request_delay)
            
            if not self._is_valid_url(url):
                return {'url': url, 'error': 'Invalid URL format'}
            
            try:
                response = self.session.get(url, timeout=10)
            except requests.exceptions.RequestException as e:
                return {'url': url, 'error': f'Request failed: {str(e)}'}

            if response.status_code == 404:
                return {
                    'url': url,
                    'error': '404 Not Found',
                    'is_html': 'text/html' in response.headers.get('Content-Type', '')
                }
            if response.status_code >= 400:
                return {'url': url, 'error': f'{response.status_code} Error'}

            if 'text/html' not in response.headers.get('Content-Type', ''):
                return {'url': url, 'status': response.status_code, 'skipped': True}

            soup = BeautifulSoup(response.text, 'html.parser')
            links = self._extract_links(url, soup)
            
            if depth < self.max_depth:
                for link in links:
                    self._submit_task(link, depth + 1)
            
            return {
                'url': url,
                'links': links,
                'forms': self._find_forms(soup),
                'status': response.status_code
            }
            
        except Exception as e:
            return {'url': url, 'error': str(e)}

    def _extract_links(self, base_url, soup):
        links = []
        for tag in soup.find_all(['a', 'link'], href=True):
            absolute_url = urljoin(base_url, tag['href'])
            if self._is_valid_link(absolute_url):
                links.append(absolute_url)
        
        for script in soup.find_all('script'):
            if script.string:
                matches = re.findall(r"[\'\"](https?:\/\/[^\"\']+)[\'\"]", script.string)
                links.extend(m for m in matches if self._is_valid_link(m))
        
        return list(set(links))

    def _find_forms(self, soup):
        forms = []
        for form in soup.find_all('form'):
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inputs.append({
                    'name': inp.get('name'),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')
                })
            forms.append({
                'action': form.get('action'),
                'method': form.get('method', 'get').upper(),
                'inputs': inputs
            })
        return forms

    def _is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([
                result.scheme in ['http', 'https'],
                len(result.netloc) > 0,
                not re.search(r"[<>]", url)
            ])
        except ValueError:
            return False

    def _is_valid_link(self, url):
        if not self._is_valid_url(url):
            return False
            
        static_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2',
            '.ttf', '.ico', '.css', '.js', '.json', '.xml', '.pdf', '.webp'
        }
        
        static_paths = {
            '/static/', '/assets/', '/images/', '/img/', '/fonts/',
            '/css/', '/js/', '/build/', '/dist/', '_next/static'
        }

        parsed = urlparse(url)
        base_parsed = urlparse(self.base_url)
        path = parsed.path.lower()
        
        return (
            parsed.netloc == base_parsed.netloc and
            not any(path.endswith(ext) for ext in static_extensions) and
            not any(seg in path for seg in static_paths) and
            'wp-json' not in parsed.path and
            'logout' not in parsed.path.lower()
        )

    def _handle_result(self, result):
        if result:
            if 'error' in result:
                if '404' in result['error']:
                    msg = f"[⚠] Broken link ({result['url']}): {result['error']}"
                    if result.get('is_html'):
                        msg += " (HTML page)"
                    tqdm.write(msg)
                else:
                    tqdm.write(f"[!] Error ({result['url']}): {result['error']}")
            elif 'skipped' in result:
                pass
            else:
                tqdm.write(f"[+] Crawled {result['url']} ({len(result['links'])} links)")

    def _safe_shutdown(self):
        self.running = False
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.session.close()
        self.progress.close()

    def _get_results(self):
        return [f.result() for f in self.futures if f.done()]