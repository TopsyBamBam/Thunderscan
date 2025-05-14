# scanners/report_generator.py
import os
import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, base_url):
        self.base_url = base_url
        self.report_dir = "reports"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def generate_text_report(self, pages, directories, vulnerabilities):
        filename = f"{self.report_dir}/{self.timestamp}_{self.base_url.split('//')[1]}_report.txt"
        
        with open(filename, 'w') as f:
            f.write(f"Thunderscan Report for {self.base_url}\n")
            f.write(f"Generated at: {datetime.now()}\n\n")
            
            f.write("=== Crawling Results ===\n")
            f.write(f"Crawled Pages: {len(pages)}\n")
            f.write("Top 10 Pages:\n")
            for page in pages[:10]:
                f.write(f"- {page['url']} ({len(page.get('links', []))} links)\n")
            
            f.write("\n=== Directory Bruteforce Findings ===\n")
            f.write(f"Hidden Resources Found: {len(directories)}\n")
            for dir in directories[:10]:
                f.write(f"- {dir['url']} (Status: {dir['status']})\n")
            
            f.write("\n=== Vulnerability Findings ===\n")
            f.write(f"Potential SQLi Vulnerabilities: {len(vulnerabilities)}\n")
            for vuln in vulnerabilities:
                f.write(f"- {vuln['method']} at {vuln['url']}\n")
                f.write(f"  Payload: {vuln['payload']}\n")
        
        return filename

    def generate_html_report(self, pages, directories, vulnerabilities):
        # Add HTML reporting logic here
        pass

    def generate_json_report(self, pages, directories, vulnerabilities):
        filename = f"{self.report_dir}/{self.timestamp}_{self.base_url.split('//')[1]}_report.json"
        
        report_data = {
            "meta": {
                "target": self.base_url,
                "generated_at": str(datetime.now()),
                "duration": None
            },
            "stats": {
                "crawled_pages": len(pages),
                "hidden_resources": len(directories),
                "vulnerabilities": len(vulnerabilities)
            },
            "findings": {
                "vulnerabilities": vulnerabilities,
                "directories": directories
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return filename