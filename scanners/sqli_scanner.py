from urllib.parse import urlparse, parse_qs, urljoin
import requests
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from bs4 import BeautifulSoup
import os
import re
import difflib

class SQLiScanner:
    def __init__(self, base_url, forms=None, max_workers=10, payload_file="wordlists/sql_payloads.txt", time_threshold=10):
        self.base_url = base_url
        self.forms = forms or []
        self.max_workers = max_workers
        self.time_threshold = time_threshold
        self.session = requests.Session()
        self.vulnerabilities = []
        self.payloads = self._load_payloads(payload_file)
        self.lock = threading.Lock()
        self.true_responses = {}
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
            'X-Forwarded-For': f'127.0.0.{random.randint(1,255)}'
        })

    def _load_payloads(self, filename):
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Payload file {filename} not found")
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]

    def scan(self):
        print("[⚡] Starting SQLi vulnerability assessment...")
        parsed_url = urlparse(self.base_url)
        params = parse_qs(parsed_url.query)
        
        self._test_parameters(params)
        self._test_forms()
        return self.vulnerabilities

    def _test_parameters(self, params):
        if not params:
            return
            
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            total_tests = len(params) * len(self.payloads)
            
            with tqdm(total=total_tests, desc="Parameter Testing", unit="test") as pbar:
                for param in params:
                    original_values = params[param]
                    for original_value in original_values:
                        for payload in self.payloads:
                            futures.append(
                                executor.submit(
                                    self._test_param,
                                    param,
                                    original_value,
                                    payload,
                                    pbar
                                )
                            )
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        with self.lock:
                            self.vulnerabilities.append(result)

    def _test_param(self, param, original_value, payload, pbar):
        try:
            parsed = urlparse(self.base_url)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            params = parse_qs(parsed.query)
            params[param] = [original_value + payload]
            
            test_url = requests.Request('GET', test_url, params=params).prepare().url
            
            time.sleep(random.uniform(0.5, 1.5))
            
            if param not in self.true_responses:
                self.true_responses[param] = self.session.get(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={original_value}"
                ).text
            
            start_time = time.time()
            response = self.session.get(test_url, timeout=self.time_threshold*2)
            elapsed = time.time() - start_time
            
            detection_methods = []
            if any(cmd in payload.lower() for cmd in ['sleep', 'waitfor']) and elapsed >= self.time_threshold:
                detection_methods.append(f"Time-based ({elapsed:.2f}s)")
            
            similarity = self._calculate_similarity(
                self.true_responses[param],
                response.text
            )
            if similarity < 0.7:
                detection_methods.append(f"Boolean (Similarity: {similarity:.2f})")
            
            errors = self._detect_errors(response.text)
            if errors:
                detection_methods.append(f"Error: {errors[0]}")
            
            if detection_methods:
                return {
                    "type": "SQL Injection",
                    "param": param,
                    "payload": payload,
                    "method": ", ".join(detection_methods),
                    "url": test_url,
                    "status": response.status_code,
                    "length": len(response.content)
                }
                
        except Exception as e:
            return None
        finally:
            pbar.update(1)

    def _test_forms(self):
        if not self.forms:
            return
            
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            total_tests = len(self.forms) * len(self.payloads)
            
            with tqdm(total=total_tests, desc="Form Testing", unit="test") as pbar:
                for form in self.forms:
                    futures.append(executor.submit(
                        self._test_single_form, form, pbar
                    ))
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        with self.lock:
                            self.vulnerabilities.append(result)

    def _test_single_form(self, form, pbar):
        try:
            form_details = self._parse_form(form)
            csrf_token = self._find_csrf_token(form_details['inputs'])
            
            for payload in self.payloads:
                data = {}
                for inp in form_details['inputs']:
                    if inp['name']:
                        if csrf_token and inp['name'] == csrf_token['name']:
                            data[inp['name']] = csrf_token['value']
                        else:
                            data[inp['name']] = inp.get('value', '') + payload
                
                time.sleep(random.uniform(0.5, 1.5))
                
                response = self.session.request(
                    method=form_details['method'],
                    url=form_details['action'],
                    data=data,
                    timeout=15
                )
                
                if self._detect_errors(response.text) or self._detect_content_changes(response.text):
                    return {
                        "type": "SQL Injection",
                        "form": form_details['action'],
                        "payload": payload,
                        "method": "Form input manipulation",
                        "url": response.url,
                        "status": response.status_code
                    }
                pbar.update(1)
        except Exception as e:
            return None

    def _parse_form(self, form):
        return {
            'action': urljoin(self.base_url, form.get('action', '')),
            'method': form.get('method', 'get').lower(),
            'inputs': form.get('inputs', [])
        }

    def _find_csrf_token(self, inputs):
        csrf_names = ['csrf', 'token', 'csrf_token', 'authenticity_token']
        for inp in inputs:
            if inp['name'].lower() in csrf_names:
                return {'name': inp['name'], 'value': inp.get('value', '')}
        return None

    def _detect_errors(self, response_text):
        error_patterns = [
            (r"SQL (error|syntax)", "SQL Error"),
            (r"mysql_(fetch|query)", "MySQL Error"),
            (r"PostgreSQL.*ERROR", "PostgreSQL Error"),
            (r"ORA-\d{5}", "Oracle Error"),
            (r"unclosed quotation mark", "Unclosed Quote"),
            (r"Microsoft OLE DB", "OLEDB Error"),
            (r"SQL Server", "SQL Server Error")
        ]
        
        detected = []
        for pattern, name in error_patterns:
            if re.search(pattern, response_text, re.I):
                detected.append(name)
        return detected

    def _detect_content_changes(self, response_text):
        original_soup = BeautifulSoup(self.true_responses.get('control', ''), 'html.parser')
        test_soup = BeautifulSoup(response_text, 'html.parser')
        return (
            len(original_soup.find_all('form')) != len(test_soup.find_all('form')) or
            bool(test_soup.find(text=re.compile(r"error|exception", re.I))) or
            "SQL" in response_text.upper()
        )

    def _calculate_similarity(self, str1, str2):
        return difflib.SequenceMatcher(None, str1, str2).ratio()