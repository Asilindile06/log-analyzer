import random
from datetime import datetime, timedelta
import random
from datetime import datetime, timedelta
from log_parser import (
    read_log_file,
    count_failed_logins,
    find_suspicious_ips,
    generate_security_report,
    save_security_report
)

# List of fake IP addresses that will be randomly used in the log entries.
IPS = [
    "192.168.1.10",
    "10.0.0.5",
    "203.0.113.44",
    "198.51.100.7"
]

# Different website paths that our fake users can request.
PATHS = [
    "/index.html",
    "/about",
    "/login",
    "/dashboard",
    "/api/data"
]

# HTTP status codes that can appear in our fake server logs.
# 200 = successful request
# 401 = unauthorized request
# 403 = forbidden request
# 404 = page not found
STATUS_CODES = [200, 200, 200, 404, 401, 403]


def random_log_line(ip, path, status, timestamp):
    """
    Create one fake server log entry using the information provided.
    The format is similar to the Common Log Format used by web servers.
    """

    # Convert the datetime object into the format used in our log file.
    time_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0200")

    # Generate a random response size between 200 and 5000 bytes.
    # This represents the amount of data returned by the server.
    size = random.randint(200, 5000)

    # Build the complete log line using an f-string.
    return f'{ip} - - [{time_str}] "GET {path} HTTP/1.1" {status} {size}'


def generate_logs(filename, num_lines=200):
    """
    Generate a fake server log file.

    The file contains:
    - Random normal traffic
    - A deliberate pattern of failed login attempts
      that we will later use to test our security detection.
    """

    # Get the current date and time to use as the starting point
    # for the timestamps in our generated log entries.
    start_time = datetime.now()

    # Create an empty list to store all generated log lines
    # before writing them to the file.
    lines = []

    # Generate the normal/random server traffic.
    for i in range(num_lines):

        # Randomly select an IP address from our list.
        ip = random.choice(IPS)

        # Randomly select a website path.
        path = random.choice(PATHS)

        # Randomly select an HTTP status code.
        status = random.choice(STATUS_CODES)

        # Create a timestamp for this log entry.
        # Each generated entry is one second after the previous entry.
        timestamp = start_time + timedelta(seconds=i)

        # Create the complete log line and add it to our list.
        lines.append(random_log_line(ip, path, status, timestamp))

    # Create a deliberate failed-login pattern.
    # This gives our future security analyzer something suspicious to detect.
    attack_ip = random.choice(IPS)

    # Generate 10 failed login attempts from the same IP address.
    for i in range(10):

        # Continue the timestamps from where the normal traffic ended.
        timestamp = start_time + timedelta(seconds=num_lines + i)

        # Generate a failed login request using HTTP status 401.
        lines.append(
            random_log_line(
                attack_ip,
                "/login",
                401,
                timestamp
            )
        )

    # Open the output file in write mode.
    # If the file already exists, its previous contents will be replaced.
    with open(filename, "w") as f:

        # Write every generated log line to the file.
        for line in lines:
            f.write(line + "\n")


# Start the log generator and save the generated logs
# in a file called sample.log.
generate_logs("sample.log")

# Read the generated log file.
logs = read_log_file("sample.log")

# Count failed login attempts for each IP address.
failed_logins = count_failed_logins(logs)

# Find IP addresses with multiple failed login attempts.
suspicious_ips = find_suspicious_ips(failed_logins)

generate_security_report(failed_logins, suspicious_ips)

save_security_report(
    failed_logins,
    suspicious_ips,
    "security_report.txt"
)
