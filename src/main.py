import json

from rules import (
    detect_failed_logins,
    detect_suspicious_powershell
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
        print(f"Severity: {alert['severity']}")

        # Only show IP if it exists
        if "source_ip" in alert:
            print(f"Source IP: {alert['source_ip']}")

        # Only show command if it exists
        if "command" in alert:
            print(f"Command: {alert['command']}")

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

    # Display results
    display_alerts(alerts)


if __name__ == "__main__":
    main()