from src.rules import generate_timeline


def test_timeline_generation():

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

    assert len(timeline) == 2
    assert timeline[0]["event"] == "failed_login"


def test_empty_timeline():

    timeline = generate_timeline([])

    assert len(timeline) == 0