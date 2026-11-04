from src.rules import (
    detect_account_compromise
)


def make_attack_logs():

    return [
        {"timestamp": "2026-11-01T08:15:00", "event_type": "failed_login", "source_ip": "10.0.0.5"},
        {"timestamp": "2026-11-01T08:15:10", "event_type": "failed_login", "source_ip": "10.0.0.5"},
        {"timestamp": "2026-11-01T08:15:20", "event_type": "failed_login", "source_ip": "10.0.0.5"},
        {"timestamp": "2026-11-01T09:50:00", "event_type": "successful_login", "source_ip": "10.0.0.5"},
        {"timestamp": "2026-11-01T09:55:00", "event_type": "admin_created", "username": "compromised_admin"}
    ]


def test_attack_chain_detected():

    alerts = detect_account_compromise(make_attack_logs())

    assert len(alerts) == 1
    assert (
        alerts[0]["title"]
        == "Possible Account Compromise"
    )
    assert alerts[0]["source_ip"] == "10.0.0.5"


def test_partial_chain_not_detected():

    logs = make_attack_logs()[:-1]

    alerts = detect_account_compromise(logs)

    assert len(alerts) == 0


def test_empty_logs():

    alerts = detect_account_compromise([])

    assert len(alerts) == 0


def test_wrong_order_not_detected():

    # Admin account created BEFORE the logins - normal admin work, not an attack
    logs = [
        {"timestamp": "2026-11-01T09:00:00", "event_type": "admin_created", "username": "it_admin"},
        {"timestamp": "2026-11-01T09:30:00", "event_type": "failed_login", "source_ip": "10.0.0.1"},
        {"timestamp": "2026-11-01T09:31:00", "event_type": "failed_login", "source_ip": "10.0.0.1"},
        {"timestamp": "2026-11-01T09:32:00", "event_type": "failed_login", "source_ip": "10.0.0.1"},
        {"timestamp": "2026-11-01T09:33:00", "event_type": "successful_login", "source_ip": "10.0.0.1"}
    ]

    assert detect_account_compromise(logs) == []


def test_different_ip_not_detected():

    # Failed logins from one IP, successful login from a different IP
    logs = make_attack_logs()
    logs[3]["source_ip"] = "192.168.1.20"

    assert detect_account_compromise(logs) == []


def test_admin_created_too_late_not_detected():

    # Admin account created hours after the login - outside the time window
    logs = make_attack_logs()
    logs[4]["timestamp"] = "2026-11-01T15:00:00"

    assert detect_account_compromise(logs) == []


def test_single_failed_login_not_detected():

    # One mistyped password is normal and shouldn't count as an attack
    logs = [
        {"timestamp": "2026-11-01T09:00:00", "event_type": "failed_login", "source_ip": "10.0.0.5"},
        {"timestamp": "2026-11-01T09:01:00", "event_type": "successful_login", "source_ip": "10.0.0.5"},
        {"timestamp": "2026-11-01T09:05:00", "event_type": "admin_created", "username": "new_admin"}
    ]

    assert detect_account_compromise(logs) == []
