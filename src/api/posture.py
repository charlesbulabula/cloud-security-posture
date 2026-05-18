from prometheus_client import Counter, Histogram, Gauge

REQUESTS_TOTAL = Counter(
    "app_requests_total", "Total requests", ["method", "path", "status"]
)
REQUEST_DURATION = Histogram(
    "app_request_duration_seconds", "Request duration", ["method", "path"]
)
ACTIVE_CONNECTIONS = Gauge("app_active_connections", "Active connections")

# rev 20260518141413-83016545
