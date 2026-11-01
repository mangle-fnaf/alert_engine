from src.rules import generate_timeline


def test_timeline_sorted():

    logs = [
        {
            "timestamp": "2026-11-01T10:00:00",
            "event_type": "admin_created"
        },
        {
            "timestamp": "2026-11-01T08:00:00",
            "event_type": "failed_login"
        }
    ]

    timeline = generate_timeline(logs)

    assert timeline[0]["event"] == "failed_login"
    assert timeline[1]["event"] == "admin_created"