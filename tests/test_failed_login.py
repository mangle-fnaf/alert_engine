from src.rules import detect_failed_logins


def test_bruteforce_detection():

    logs = [
        {"event_type": "failed_login", "source_ip": "1.1.1.1"},
        {"event_type": "failed_login", "source_ip": "1.1.1.1"},
        {"event_type": "failed_login", "source_ip": "1.1.1.1"},
        {"event_type": "failed_login", "source_ip": "1.1.1.1"},
        {"event_type": "failed_login", "source_ip": "1.1.1.1"}
    ]

    alerts = detect_failed_logins(logs)

    assert len(alerts) == 1


def test_no_alert_below_threshold():

    logs = [
        {"event_type": "failed_login", "source_ip": "1.1.1.1"}
    ]

    alerts = detect_failed_logins(logs)

    assert len(alerts) == 0