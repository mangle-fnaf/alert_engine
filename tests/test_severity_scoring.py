from src.rules import calculate_severity


def test_low_severity():

    assert calculate_severity(1) == "LOW"


def test_medium_severity():

    assert calculate_severity(5) == "MEDIUM"


def test_high_severity():

    assert calculate_severity(10) == "HIGH"


def test_critical_severity():

    assert calculate_severity(20) == "CRITICAL"