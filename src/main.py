import json

from rules import detect_failed_logins


def load_logs(filepath):
    """
    Load logs from a JSON file.
    """

    with open(filepath, "r") as file:
        return json.load(file)


def main():

    # Load sample log file
    logs = load_logs("sample_logs.json")

    # Run detection rule
    alerts = detect_failed_logins(logs)

    # Display generated alerts
    if alerts:

        print("\n=== ALERTS DETECTED ===\n")

        for alert in alerts:

            print(f"Title: {alert['title']}")
            print(f"Severity: {alert['severity']}")
            print(f"Source IP: {alert['source_ip']}")
            print(f"Description: {alert['description']}")
            print(f"MITRE Technique: {alert['mitre_technique']}")
            print("-" * 40)

    else:
        print("No alerts detected.")


if __name__ == "__main__":
    main()