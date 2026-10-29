import json

from rules import (
    detect_failed_logins,
    detect_suspicious_powershell,
    detect_admin_creation,
    detect_ioc_match
)

def load_logs(filepath):

    with open(filepath, "r") as file:
        return json.load(file)


def display_alerts(alerts):

    if not alerts:
        print("No alerts detected.")
        return

    print("\n=== ALERTS DETECTED ===\n")

    for alert in alerts:

        print(f"Title: {alert['title']}")
        print(f"Score: {alert['score']}")
        print(f"Severity: {alert['severity']}")
        print(f"MITRE: {alert['mitre']}")

        if "source_ip" in alert:
            print(f"Source IP: {alert['source_ip']}")

        if "command" in alert:
            print(f"Command: {alert['command']}")

        if "username" in alert:
            print(f"Username: {alert['username']}")

        print(f"Description: {alert['description']}")

        print("-" * 40)


def main():

    # Load sample log file
    logs = load_logs("sample_logs.json")

    # Store all generated alerts
    alerts = []

    # Run failed login detection
    alerts.extend(
        detect_failed_logins(logs)
    )

    # Run PowerShell detection
    alerts.extend(
        detect_suspicious_powershell(logs)
    )

    # Run admin creation detection
    alerts.extend(
        detect_admin_creation(logs)
    )

    # Run IOC matching
    alerts.extend(
        detect_ioc_match(logs)
    )

    # Display results
    display_alerts(alerts)


if __name__ == "__main__":
    main()