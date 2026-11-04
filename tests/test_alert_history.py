import json

from src.main import save_alerts


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
