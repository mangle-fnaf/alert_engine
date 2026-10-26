from collections import Counter


def detect_failed_logins(logs, threshold=5):
    """
    Detects possible brute-force activity by counting
    failed login attempts from the same IP.
    """

    # Store generated alerts
    alerts = []

    # Store failed login IPs
    failed_ips = []

    # Look through all log entries
    for log in logs:

        # Check if this event is a failed login
        if log.get("event_type") == "failed_login":
            failed_ips.append(log.get("source_ip"))

    # Count how many failed logins each IP has
    counts = Counter(failed_ips)

    # Generate alert if threshold is exceeded
    for ip, count in counts.items():

        if count >= threshold:

            alerts.append({
                "title": "Multiple Failed Logins",
                "severity": "MEDIUM",
                "source_ip": ip,
                "description": f"{count} failed login attempts detected.",
                "mitre_technique": "T1110"
            })

    return alerts