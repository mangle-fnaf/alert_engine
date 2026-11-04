from src.main import generate_incident_report


def make_alerts():

    return [
        {"title": "Known Malicious IP", "severity": "CRITICAL", "mitre": "T1071"},
        {"title": "Multiple Failed Logins", "severity": "MEDIUM", "mitre": "T1110"}
    ]


def test_report_creation(tmp_path):

    report_file = (
        tmp_path /
        "incident_report.txt"
    )

    generate_incident_report(make_alerts(), report_file)

    assert report_file.exists()


def test_report_content(tmp_path):

    report_file = (
        tmp_path /
        "incident_report.txt"
    )

    generate_incident_report(make_alerts(), report_file)

    content = report_file.read_text()

    assert "Total Alerts: 2" in content
    assert "- Known Malicious IP" in content

    # Only CRITICAL alerts should be listed under Critical Alerts
    critical_section = content.split("Critical Alerts:")[1].split("MITRE Techniques:")[0]
    assert "Multiple Failed Logins" not in critical_section

    assert "- T1071" in content
    assert "- T1110" in content
