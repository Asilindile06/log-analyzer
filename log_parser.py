import json


def parse_log_line(log_line):
    parts = log_line.split()

    # Ignore lines that do not contain enough information.
    if len(parts) < 9:
        return None

    ip_address = parts[0]
    method = parts[5].replace('"', '')
    path = parts[6]
    status_code = parts[8]

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

# Count how many times each HTTP status code appears in the logs.
def count_status_codes(logs):
    status_codes = {}

    for log in logs:
        status = log["status"]

        if status in status_codes:
            status_codes[status] += 1
        else:
            status_codes[status] = 1

    return status_codes

# Count how many times each requested path appears in the logs.
def count_paths(logs):
    paths = {}

    for log in logs:
        path = log["path"]

        if path in paths:
            paths[path] += 1
        else:
            paths[path] = 1

    return paths


def total_failed_logins(failed_logins):
    total = 0

    for ip_address in failed_logins:
        total += failed_logins[ip_address]

    return total

# Find the IP address with the most failed login attempts.
def find_most_failed_ip(failed_logins):
    most_failed_ip = None
    highest_attempts = 0

    for ip_address in failed_logins:
        attempts = failed_logins[ip_address]

        if attempts > highest_attempts:
            highest_attempts = attempts
            most_failed_ip = ip_address

    return most_failed_ip, highest_attempts

def find_suspicious_ips(failed_logins, threshold=3):
    suspicious_ips = []

    for ip_address in failed_logins:
        if failed_logins[ip_address] >= threshold:
            suspicious_ips.append(ip_address)

    return suspicious_ips


def read_log_file(filename):
    logs = []

    with open(filename, "r") as file:
        for line in file:
            line = line.strip()

            if line:
                log = parse_log_line(line)
                if log is not None:
                    logs.append(log)

    return logs


def generate_security_report(failed_logins, suspicious_ips):
    print("\n=== Security Report ===")

    for ip_address in suspicious_ips:
        attempts = failed_logins[ip_address]

        print(f"Suspicious IP: {ip_address}")
        print(f"Failed login attempts: {attempts}")
        print()


def save_security_report(failed_logins, suspicious_ips, filename):
    with open(filename, "w") as file:
        file.write("=== Security Report ===\n\n")

        for ip_address in suspicious_ips:
            attempts = failed_logins[ip_address]

            file.write(f"Suspicious IP: {ip_address}\n")
            file.write(f"Failed login attempts: {attempts}\n\n")

# Save the security analysis results as a JSON file.
def save_json_report(failed_logins,suspicious_ips,status_codes,path_counts,
    most_failed_ip,highest_attempts,filename):
    report = {
        "total_failed_logins": total_failed_logins(failed_logins),
        "status_codes": status_codes,
        "path_counts": path_counts,
        "most_failed_ip": most_failed_ip,
        "highest_failed_attempts": highest_attempts,
        "suspicious_ips": {}
    }

    for ip_address in suspicious_ips:
        report["suspicious_ips"][ip_address] = failed_logins[ip_address]

    with open(filename, "w") as file:
        json.dump(report, file, indent=4)