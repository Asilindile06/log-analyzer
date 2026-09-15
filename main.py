import random
from datetime import datetime, timedelta

# Pools of fake data to randomly pick from when building each log line
IPS = ["192.168.1.10", "10.0.0.5", "203.0.113.44", "198.51.100.7"]
PATHS = ["/index.html", "/about", "/login", "/dashboard", "/api/data"]
STATUS_CODES = [200, 200, 200, 404, 401, 403]
