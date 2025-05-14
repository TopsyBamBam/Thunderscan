# thunderscan.py
import argparse
import os
import sys
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "scanners"))

from scanners.spider import Spider
from scanners.directory_bruteforce import DirectoryBruteforcer
from scanners.sqli_scanner import SQLiScanner

def show_intro():
    print(r"""
          .-~~~-.
  .- ~ ~-(       )_ _
 /                     ~ -.
 |                           \
 \                         .'
   ~- . _____________ . -~
          \| | | | |/
            | | | |
            | | | |
            | | | |
            | | | |
    
     _   _ _  _ _  __
    | | | | || | |/ /___ 
    | |_| | || | ' <|_ /
    |____/|_____|_|\_\___|
    
    ██╗   ██╗██╗   ██╗██╗  ██╗██╗
    ╚██╗ ██╔╝██║   ██║██║ ██╔╝ ██║
     ╚████╔╝ ██║   ██║█████╔╝  ██║
      ╚██╔╝  ██║   ██║██╔═██╗  ██║
       ██║   ╚██████╔╝██║  ██╗██║
       ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝
    
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    [ THUNDERSCAN EDITION ]  Created by: TEMITOPE PAUL-BAMIDELE
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    """)

def main():
    parser = argparse.ArgumentParser(description="THUNDERSCAN Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-w", "--wordlist", default="wordlists/common.txt", help="Directory brute-force wordlist")
    parser.add_argument("-p", "--payloads", default="wordlists/sql_payloads.txt", help="SQLi payload file")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("--delay", type=float, default=1.0, help="Request delay in seconds (default: 1.0)")
    parser.add_argument("--timeout", type=int, default=10, help="SQLi time-based detection threshold (default: 10s)")
    
    args = parser.parse_args()

    if not all(os.path.exists(f) for f in [args.wordlist, args.payloads]):
        print("[!] Missing required files:")
        print(f" - Directory wordlist: {args.wordlist}")
        print(f" - SQLi payloads: {args.payloads}")
        sys.exit(1)
    
    try:
        show_intro()
        start_time = time.time()
        
        # Phase 1: Crawling
        print("\n[💧] Starting website crawling...")
        spider = Spider(args.url, max_depth=args.depth, request_delay=args.delay)
        pages = spider.crawl()
        
        # Collect forms
        forms = []
        for page in pages:
            if isinstance(page, dict) and 'forms' in page:
                forms.extend(page['forms'])
        
        # Phase 2: Directory Bruteforce
        print("\n[🌀] Running directory brute-force...")
        bruteforcer = DirectoryBruteforcer(args.url, args.wordlist)
        directories = bruteforcer.bruteforce()
        
        # Phase 3: SQL Injection Testing
        print("\n[⚡] Scanning for SQL injection vulnerabilities...")
        sql_scanner = SQLiScanner(args.url, forms=forms, payload_file=args.payloads, time_threshold=args.timeout)
        vulnerabilities = sql_scanner.scan()
        
        # Generate reports
        valid_pages = [p for p in pages if not p.get('error') and not p.get('skipped')]
        print(f"\n[🌦️] Scan Results:")
        print(f" - Crawled Pages: {len(valid_pages)}")
        print(f" - Hidden Resources Found: {len(directories)}")
        print(f" - SQLi Vulnerabilities Found: {len(vulnerabilities)}")
        
        if vulnerabilities:
            print("\n[!] Critical Findings:")
            for idx, vuln in enumerate(vulnerabilities, 1):
                print(f"{idx}. {vuln['method']} at {vuln['url']}")
                print(f"   Payload: {vuln['payload']}")
                print(f"   Status Code: {vuln['status']}")
        
        print("\n[🌈] Scan completed!" if not vulnerabilities else "\n[⚡] Immediate action required!")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[⚡] FATAL ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()