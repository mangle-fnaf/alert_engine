from collections import Counter
from datetime import datetime, timedelta


MITRE_MAPPINGS = {
    "Multiple Failed Logins": "T1110",
    "Suspicious PowerShell Activity": "T1059",
    "New Administrator Account": "T1136",
    "Known Malicious IP": "T1071",
    "Possible Account Compromise": "T1078"
}


MALICIOUS_IPS = [
    "45.33.22.10",
    "185.10.10.100"
]


def calculate_severity(score):

    if score >= 20:
        return "CRITICAL"

    if score >= 10:
        return "HIGH"

    if score >= 5:
        return "MEDIUM"

    return "LOW"


def get_mitre(alert_title):

    return MITRE_MAPPINGS.get(
        alert_title,
        "Unknown"
    )


# brute force
def detect_failed_logins(logs, threshold=5):

    alerts = []

    failed_ips = []

    for log in logs:

        if log.get("event_type") == "failed_login":
            failed_ips.append(log.get("source_ip"))

    counts = Counter(failed_ips)

    for ip, count in counts.items():

        if count >= threshold:

            alerts.append({
                "title": "Multiple Failed Logins",
                "score": 5,
                "severity": calculate_severity(5),
                "mitre": get_mitre("Multiple Failed Logins"),
                "source_ip": ip,
                "description": f"{count} failed login attempts detected."
            })

    return alerts


# powershell
def detect_suspicious_powershell(logs):

    alerts = []

    for log in logs:

        command = log.get("command", "").lower()

        if (
            "powershell" in command and
            "encodedcommand" in command
        ):

            alerts.append({
                "title": "Suspicious PowerShell Activity",
                "score": 10,
                "severity": calculate_severity(10),
                "mitre": get_mitre("Suspicious PowerShell Activity"),
                "command": log.get("command"),
                "description": "Encoded PowerShell command detected."
            })

    return alerts


# detects new admin account creation
def detect_admin_creation(logs):

    alerts = []

    for log in logs:

        if log.get("event_type") == "admin_created":

            alerts.append({
                "title": "New Administrator Account",
                "score": 15,
                "severity": calculate_severity(15),
                "mitre": get_mitre("New Administrator Account"),
                "username": log.get("username"),
                "description": "Administrator account created."
            })

    return alerts


# ioc matching
def detect_ioc_match(logs):

    alerts = []

    for log in logs:

        ip = log.get("source_ip")

        if ip in MALICIOUS_IPS:

            alerts.append({
                "title": "Known Malicious IP",
                "score": 20,
                "severity": calculate_severity(20),
                "mitre": get_mitre("Known Malicious IP"),
                "source_ip": ip,
                "description": "IP matched threat intelligence feed."
            })

    return alerts


# attack correlation
# Only raises an alert when the events happen in the order an attacker would perform them:
#   1. several failed logins from one IP address
#   2. then a successful login from that SAME IP address
#   3. then an administrator account created shortly afterwards
# Checking the order, the IP and the timing stops normal activity
# (e.g. a mistyped password and an unrelated admin account) being flagged.
def parse_timestamp(log):

    try:
        return datetime.fromisoformat(log.get("timestamp", ""))
    except (TypeError, ValueError):
        return None


def detect_account_compromise(logs, min_failed=3, window_minutes=60):

    # Only use events that have a valid timestamp, sorted oldest first
    events = []

    for log in logs:

        timestamp = parse_timestamp(log)

        if timestamp is not None:
            events.append((timestamp, log))

    events.sort(key=lambda item: item[0])

    alerts = []
    failed_counts = Counter()

    for index, (timestamp, log) in enumerate(events):

        event_type = log.get("event_type")
        ip = log.get("source_ip")

        if event_type == "failed_login" and ip:
            failed_counts[ip] += 1
            continue

        # A successful login only matters if that IP failed several times first
        if event_type != "successful_login" or failed_counts[ip] < min_failed:
            continue

        deadline = timestamp + timedelta(minutes=window_minutes)

        # Look for an admin account created soon after the successful login
        for later_time, later_log in events[index + 1:]:

            if later_time > deadline:
                break

            if later_log.get("event_type") == "admin_created":

                alerts.append({
                    "title": "Possible Account Compromise",
                    "score": 25,
                    "severity": calculate_severity(25),
                    "mitre": get_mitre(
                        "Possible Account Compromise"
                    ),
                    "source_ip": ip,
                    "username": later_log.get("username"),
                    "description": (
                        f"{failed_counts[ip]} failed logins from {ip}, "
                        f"followed by a successful login and "
                        f"administrator account creation within "
                        f"{window_minutes} minutes."
                    )
                })

                # One alert per compromised login is enough
                break

        # Reset the count so the same failed logins aren't reused
        failed_counts[ip] = 0

    return alerts


# timeline generation
def generate_timeline(logs):

    timeline = []

    sorted_logs = sorted(
        logs,
        key=lambda log: log.get(
            "timestamp",
            ""
        )
    )

    for log in sorted_logs:

        timeline.append({
            "timestamp": log.get("timestamp"),
            "event": log.get("event_type")
        })

    return timeline


# alert statistics
def generate_alert_stats(alerts):

    stats = {
        "total": len(alerts),
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for alert in alerts:

        severity = alert["severity"]

        stats[severity] += 1

    return stats