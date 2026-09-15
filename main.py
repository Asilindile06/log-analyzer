import random
from datetime import datetime, timedelta

# Pools of fake data to randomly pick from when building each log line
IPS = ["192.168.1.10", "10.0.0.5", "203.0.113.44", "198.51.100.7"]
PATHS = ["/index.html", "/about", "/login", "/dashboard", "/api/data"]
STATUS_CODES = [200, 200, 200, 404, 401, 403]

def random_log_line(ip, path, status, timestamp):
    """
    Build a single log line in Common Log Format, e.g.:
    192.168.1.10 - - [15/Sep/2026:14:32:01 +0200] "GET /login HTTP/1.1" 401 512
    """
    # Format the datetime object into the exact bracketed style servers use
    time_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0200")

    # Fake a response size in bytes, since real logs always include one
    size = random.randint(200, 5000)

    # Stitch everything into one line using an f-string
    return f'{ip} - - [{time_str}] "GET {path} HTTP/1.1" {status} {size}'
