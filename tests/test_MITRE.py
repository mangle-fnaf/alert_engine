from src.rules import get_mitre


def test_failed_login_mapping():

    assert get_mitre(
        "Multiple Failed Logins"
    ) == "T1110"


def test_powershell_mapping():

    assert get_mitre(
        "Suspicious PowerShell Activity"
    ) == "T1059"


def test_admin_mapping():

    assert get_mitre(
        "New Administrator Account"
    ) == "T1136"


def test_unknown_mapping():

    assert get_mitre(
        "Something Random"
    ) == "Unknown"