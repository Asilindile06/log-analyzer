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


log_line = '198.168.1.10 - - [29/Sep/2026:14:32:10] "GET /login HTTP/1.1" 401'

result = parse_log_line(log_line)

print(result)
print(is_failed_login(result))