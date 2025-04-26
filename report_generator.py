
from jinja2 import Environment, FileSystemLoader
import datetime

def generate_report(endpoints, sql_vulns, hidden_dirs):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report.html")
    
    report = template.render(
        date=datetime.datetime.now().strftime("%Y-%m-%d"),
        target=endpoints["base_url"],
        endpoints=endpoints["links"],
        forms=endpoints["forms"],
        sql_vulns=sql_vulns,
        hidden_dirs=hidden_dirs
    )
    
    with open("report.html", "w") as f:
        f.write(report)