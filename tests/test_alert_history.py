import json
from pathlib import Path


def save_alerts(alerts, path):

    with open(path, "w") as file:

        json.dump(
            alerts,
            file,
            indent=4
        )


def test_alert_file_created(tmp_path):

    file_path = tmp_path / "alerts.json"

    alerts = [
        {
            "title": "Failed Login"
        }
    ]

    save_alerts(alerts, file_path)

    assert file_path.exists()


def test_alert_content_saved(tmp_path):

    file_path = tmp_path / "alerts.json"

    alerts = [
        {
            "title": "Failed Login"
        }
    ]

    save_alerts(alerts, file_path)

    with open(file_path, "r") as file:
        data = json.load(file)

    assert data[0]["title"] == "Failed Login"