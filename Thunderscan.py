import argparse
from scanners.spider import Spider
from scanners.directory_bruteforcer import DirectoryBruteforcer
from scanners.sqli_scanner import SQLiScanner
import os
import time

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
    ╚██╗ ██╔╝██║   ██║██║ ██╔╝██║
     ╚████╔╝ ██║   ██║█████╔╝ ██║
      ╚██╔╝  ██║   ██║██╔═██╗ ██║
       ██║   ╚██████╔╝██║  ██╗██║
       ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝
    
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    [ THUNDERSCAN EDITION ]  Created by: TEMITOPE PAUL-BAMIDELE
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    """)
    # Animated rain effect
    for _ in range(2):
        print("\n".join([" "*(30+i%5) + "|"*(1+i%2) for i in range(5)]))
        time.sleep(0.3)
        print("\033[F"*6)

def main():
    parser = argparse.ArgumentParser(description="YUKI Rain Edition Web Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", default="wordlists/common.txt",
                      help="Directory brute-force wordlist")
    args = parser.parse_args()

    if not os.path.exists(args.wordlist):
        print(f"[!] Missing wordlist: {args.wordlist}")
        return

    try:
        show_intro()
        print("\n[🌧️] Initializing precipitation scan...")
        
        # Initialize security scanners
        print("[💧] Starting droplet analysis...")
        spider = Spider(args.url)
        pages = spider.crawl()
        
        print("\n[🌀] Initiating flood pattern detection...")
        bruteforcer = DirectoryBruteforcer(args.url, args.wordlist)
        directories = bruteforcer.bruteforce()
        
        print("\n[⚡] Scanning for SQL injection vulnerabilities...")
        sql_scanner = SQLiScanner(args.url)
        vulnerabilities = sql_scanner.scan()
        
        print(f"\n[🌦️] Scan Results:")
        print(f" - Surface droplets: {len(pages)}")
        print(f" - Hidden reservoirs: {len(directories)}")
        print(f" - SQLi vulnerabilities: {len(vulnerabilities)}")
        print("\n[🌈] Storm cleared! YUKI systems standby.")

        # Add code here to generate report with all findings

    except Exception as e:
        print(f"[⚡] Lightning strike detected: {str(e)}")

if __name__ == "__main__":
    main()