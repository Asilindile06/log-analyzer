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

def generate_logs(filename, num_lines=200):
    """
    Create a fake access log file containing:
    - num_lines of random 'normal' traffic
    - one deliberate brute-force attack pattern (10 failed logins from one IP)
    """
    start_time = datetime.now()
    lines = []  # collect all lines here, write to file once at the end

    # --- Generate normal, random traffic ---
    for i in range(num_lines):
        ip = random.choice(IPS)
        path = random.choice(PATHS)
        status = random.choice(STATUS_CODES)
        timestamp = start_time + timedelta(seconds=i)  # each line 1 second apart
        lines.append(random_log_line(ip, path, status, timestamp))

    # --- Generate brute-force attack pattern ---
    attack_ip = random.choice(IPS)
    for i in range(10):
        timestamp = start_time + timedelta(seconds=num_lines + i)
        lines.append(random_log_line(attack_ip, "/login", 401, timestamp))

    # Write all lines to the file
    with open(filename, "w") as f:
        for line in lines:
            f.write(line + "\n")

generate_logs("sample.log")