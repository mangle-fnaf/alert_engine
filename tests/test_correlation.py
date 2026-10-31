from src.rules import (
    detect_account_compromise
)


def test_attack_chain_detected():

    logs = [

        {"event_type": "failed_login"},

        {"event_type": "successful_login"},

        {"event_type": "admin_created"}
    ]

    alerts = detect_account_compromise(logs)

    assert len(alerts) == 1
    assert (
        alerts[0]["title"]
        == "Possible Account Compromise"
    )


def test_partial_chain_not_detected():

    logs = [

        {"event_type": "failed_login"},
        {"event_type": "successful_login"}

    ]

    alerts = detect_account_compromise(logs)

    assert len(alerts) == 0


def test_empty_logs():

    alerts = detect_account_compromise([])

    assert len(alerts) == 0