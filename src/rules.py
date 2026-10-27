from collections import Counter


#brute force
def detect_failed_logins(logs, threshold=5):
    # Store generated alerts
    alerts = []

    # Store IPs that fail logins
    failed_ips = []

    # Look through all logs
    for log in logs:

        # Check for failed login events
        if log.get("event_type") == "failed_login":
            failed_ips.append(log.get("source_ip"))

    # Count failures per IP
    counts = Counter(failed_ips)

    # Generate alert if threshold exceeded
    for ip, count in counts.items():

        if count >= threshold:

            alerts.append({
                "title": "Multiple Failed Logins",
                "severity": "MEDIUM",
                "source_ip": ip,
                "description": f"{count} failed login attempts detected."
            })

    return alerts

#powershell
def detect_suspicious_powershell(logs):
    # Store generated alerts
    alerts = []

    # Look through all logs
    for log in logs:

        command = log.get("command", "").lower()

        # Look for encoded PowerShell usage
        if (
            "powershell" in command
            and "encodedcommand" in command
        ):

            alerts.append({
                "title": "Suspicious PowerShell Activity",
                "severity": "HIGH",
                "command": log.get("command"),
                "description": "Encoded PowerShell command detected."
            })

    return alerts

#detects new admin account creation
def detect_admin_creation(logs):
    # Store generated alerts
    alerts = []

    # Check all log entries
    for log in logs:

        # Look for admin account creation events
        if log.get("event_type") == "admin_created":

            alerts.append({
                "title": "New Administrator Account",
                "severity": "HIGH",
                "username": log.get("username"),
                "description": "Administrator account created."
            })

    return alerts