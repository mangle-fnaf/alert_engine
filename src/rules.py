from collections import Counter


def calculate_severity(score):

    if score >= 20:
        return "CRITICAL"

    if score >= 10:
        return "HIGH"

    if score >= 5:
        return "MEDIUM"

    return "LOW"


# brute force
def detect_failed_logins(logs, threshold=5):

    # Store generated alerts
    alerts = []

    # Store failed IPs
    failed_ips = []

    # Go through logs
    for log in logs:

        if log.get("event_type") == "failed_login":
            failed_ips.append(log.get("source_ip"))

    # Count failed attempts
    counts = Counter(failed_ips)

    # Generate alert if threshold is reached
    for ip, count in counts.items():

        if count >= threshold:

            alerts.append({
                "title": "Multiple Failed Logins",
                "score": 5,
                "severity": calculate_severity(5),
                "source_ip": ip,
                "description": f"{count} failed login attempts detected."
            })

    return alerts


# powershell
def detect_suspicious_powershell(logs):

    # Store generated alerts
    alerts = []

    # Go through logs
    for log in logs:

        command = log.get("command", "").lower()

        # Check for encoded PowerShell
        if (
            "powershell" in command and
            "encodedcommand" in command
        ):

            alerts.append({
                "title": "Suspicious PowerShell Activity",
                "score": 10,
                "severity": calculate_severity(10),
                "command": log.get("command"),
                "description": "Encoded PowerShell command detected."
            })

    return alerts


# detects new admin account creation
def detect_admin_creation(logs):

    # Store generated alerts
    alerts = []

    # Go through logs
    for log in logs:

        if log.get("event_type") == "admin_created":

            alerts.append({
                "title": "New Administrator Account",
                "score": 15,
                "severity": calculate_severity(15),
                "username": log.get("username"),
                "description": "Administrator account created."
            })

    return alerts