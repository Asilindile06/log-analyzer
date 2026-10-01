def parse_log_line(log_line):
    parts = log_line.split()

    ip_address = parts[0]
    method = parts[4].replace('"', '')
    path = parts[5]
    status_code = parts[-1]

    return {
        "ip": ip_address,
        "method": method,
        "path": path,
        "status": status_code
    }


def is_failed_login(log):
    return log["status"] == "401"

def count_failed_logins(logs):
    failed_logins = {}

    for log in logs:
        if is_failed_login(log):
            ip_address = log["ip"]

            if ip_address in failed_logins:
                failed_logins[ip_address] += 1
            else:
                failed_logins[ip_address] = 1

    return failed_logins

def find_suspicious_ips(failed_logins, threshold=3):
    suspicious_ips = []

    for ip_address in failed_logins:
        if failed_logins[ip_address] >= threshold:
            suspicious_ips.append(ip_address)

    return suspicious_ips

failed_logins = {
    "198.168.1.10": 3,
    "192.168.1.20": 1,
    "203.0.113.44": 5
}

suspicious_ips = find_suspicious_ips(failed_logins)

print(suspicious_ips)