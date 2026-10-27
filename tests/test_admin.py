from src.rules import detect_admin_creation


def test_admin_account_detected():
    logs = [
        {
            "event_type": "admin_created",
            "username": "evil_admin"
        }
    ]

    alerts = detect_admin_creation(logs)

    assert len(alerts) == 1
    assert alerts[0]["title"] == "New Administrator Account"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["username"] == "evil_admin"


def test_regular_login_does_not_trigger():
    logs = [
        {
            "event_type": "login",
            "username": "maliyka"
        }
    ]

    alerts = detect_admin_creation(logs)

    assert len(alerts) == 0


def test_empty_logs():
    alerts = detect_admin_creation([])

    assert len(alerts) == 0