import argparse
import os
import sys
import time
from pathlib import Path
from datetime import datetime
import json

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

def show_help():
    print("""
THUNDERSCAN WEB VULNERABILITY SCANNER
-------------------------------------
Usage: python thunderscan.py -u URL [OPTIONS]

Required Arguments:
  -u, --url URL        Target URL to scan (e.g., http://example.com)

Scan Options:
  -w, --wordlist FILE  Directory brute-force wordlist 
                       (default: wordlists/common.txt)
  -p, --payloads FILE  SQL injection payload file 
                       (default: wordlists/sql_payloads.txt)
  -d, --depth DEPTH    Maximum crawling depth (default: 2)
  --delay SECONDS      Delay between requests in seconds (default: 0.3)
  --timeout SECONDS    SQLi time-based detection threshold (default: 5)

Information Options:
  -h, --help           Show this help message and exit

Examples:
  Basic scan:
  python thunderscan.py -u http://example.com
  
  Full scan with custom settings:
  python thunderscan.py -u http://example.com -w biglist.txt -d 3 --delay 0.5
  
  Use custom payloads:
  python thunderscan.py -u http://example.com -p custom_payloads.txt
""")

def generate_report(results, filename):
    report = {
        "meta": {
            "generated_at": datetime.now().isoformat(),
            "scan_duration": results['duration'],
            "target": results['target']
        },
        "findings": {
            "crawled_pages": results['crawled_pages'],
            "hidden_resources": results['directories'],
            "sql_injections": results['vulnerabilities']
        }
    }
    
    with open(f"{filename}.json", 'w') as f:
        json.dump(report, f, indent=2)

def main():
    parser = argparse.ArgumentParser(
        description="THUNDERSCAN Web Vulnerability Scanner",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Required arguments
    required = parser.add_argument_group('Required arguments')
    required.add_argument("-u", "--url", 
                        help="Target URL to scan (e.g., http://example.com)")

    # Scan options
    options = parser.add_argument_group('Scan options')
    options.add_argument("-w", "--wordlist", 
                       default="wordlists/common.txt",
                       help="Directory brute-force wordlist")
    options.add_argument("-p", "--payloads", 
                       default="wordlists/sql_payloads.txt",
                       help="SQLi payloads file")
    options.add_argument("-d", "--depth", 
                       type=int, default=2,
                       help="Crawling depth")
    options.add_argument("--delay", 
                       type=float, default=0.3,
                       help="Request delay in seconds")
    options.add_argument("--timeout", 
                       type=int, default=5,
                       help="SQLi time-based detection threshold")

    # Info options
    info = parser.add_argument_group('Information')
    info.add_argument("-h", "--help", 
                    action="store_true",
                    help="Show help message and exit")

    args = parser.parse_args()

    if args.help or not args.url:
        show_intro()
        show_help()
        sys.exit(0)

    if not all(os.path.exists(f) for f in [args.wordlist, args.payloads]):
        print("\n[!] Missing required files:")
        print(f" - Directory wordlist: {args.wordlist}")
        print(f" - SQLi payloads: {args.payloads}")
        sys.exit(1)
    
    try:
        show_intro()
        start_time = time.time()
        
        print("\n[💧] Starting website crawling...")
        spider = Spider(args.url, max_depth=args.depth, request_delay=args.delay)
        pages = spider.crawl()
        
        print("\n[🌀] Running directory brute-force...")
        bruteforcer = DirectoryBruteforcer(args.url, args.wordlist)
        directories = bruteforcer.bruteforce()
        
        print("\n[⚡] Scanning for SQL injection vulnerabilities...")
        forms = []
        for page in pages:
            if isinstance(page, dict) and 'forms' in page:
                forms.extend(page['forms'])
        
        sql_scanner = SQLiScanner(args.url, forms=forms, 
                                payload_file=args.payloads, 
                                time_threshold=args.timeout)
        vulnerabilities = sql_scanner.scan()
        
        scan_duration = time.time() - start_time
        report_data = {
            'duration': round(scan_duration, 2),
            'target': args.url,
            'crawled_pages': len([p for p in pages if not p.get('error')]),
            'directories': directories,
            'vulnerabilities': vulnerabilities
        }
        
        generate_report(report_data, "scan_report")
        
        print(f"\n[🌦️] Scan Results:")
        print(f" - Crawled Pages: {report_data['crawled_pages']}")
        print(f" - Hidden Resources Found: {len(directories)}")
        print(f" - SQLi Vulnerabilities Found: {len(vulnerabilities)}")
        print(f"\n[🌈] Storm Cleared(System Restored) in {scan_duration:.2f} seconds")
        print("    Report saved to scan_report.json")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[⚡] FATAL ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()