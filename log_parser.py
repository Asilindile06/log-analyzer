import re


def parse_log_line(log_line):
    """
    Parse one server log line and extract its important information.
    """

    # Regular expression used to identify the different parts
    # of our Common Log Format log entry.
    pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'

    # Search the log line for a match against our pattern.
    match = re.match(pattern, log_line)
        # If the log line does not match our expected format,
    # return None instead of causing an error.
    if match is None:
        return None

    # Return the important information as a dictionary.
    return {
        "ip": match.group(1),
        "timestamp": match.group(2),
        "method": match.group(3),
        "path": match.group(4),
        "status": int(match.group(6)),
        "size": int(match.group(7))
    }