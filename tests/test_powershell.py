from src.rules import detect_suspicious_powershell


def test_encoded_powershell_detected():

    logs = [
        {
            "command": "powershell.exe -EncodedCommand ABC123"
        }
    ]

    alerts = detect_suspicious_powershell(logs)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"


def test_legitimate_command_not_detected():

    logs = [
        {
            "command": "notepad.exe"
        }
    ]

    alerts = detect_suspicious_powershell(logs)

    assert len(alerts) == 0