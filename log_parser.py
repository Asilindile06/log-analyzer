def parse_log_line(log_line):
    parts = log_line.split()


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

def find_suspicious_ips(failed_logins, threshold=3):
    suspicious_ips = []

    for ip_address in failed_logins:
        if failed_logins[ip_address] >= threshold:
            suspicious_ips.append(ip_address)

    return suspicious_ips

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


def read_log_file(filename):
    logs = []

    with open(filename, "r") as file:
        for line in file:
            line = line.strip()

            if line:
                log = parse_log_line(line)
                logs.append(log)

    return logs
