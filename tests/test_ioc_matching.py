from src.rules import detect_ioc_match


def test_malicious_ip_detected():

    logs = [
        {
            "source_ip": "45.33.22.10"
        }
    ]

    alerts = detect_ioc_match(logs)

    assert len(alerts) == 1
    assert alerts[0]["title"] == "Known Malicious IP"


def test_safe_ip_not_detected():

    logs = [
        {
            "source_ip": "8.8.8.8"
        }
    ]

    alerts = detect_ioc_match(logs)

    assert len(alerts) == 0


def test_empty_logs():

    alerts = detect_ioc_match([])

    assert len(alerts) == 0