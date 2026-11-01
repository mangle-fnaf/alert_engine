from pathlib import Path


def test_report_creation(tmp_path):

    report_file = (
        tmp_path /
        "incident_report.txt"
    )

    with open(
        report_file,
        "w"
    ) as file:

        file.write(
            "=== INCIDENT REPORT ==="
        )

    assert report_file.exists()


def test_report_content(tmp_path):

    report_file = (
        tmp_path /
        "incident_report.txt"
    )

    with open(
        report_file,
        "w"
    ) as file:

        file.write(
            "Critical Alerts"
        )

    content = report_file.read_text()

    assert (
        "Critical Alerts"
        in content
    )