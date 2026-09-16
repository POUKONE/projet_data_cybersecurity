from app.parsers.log_parser import parse_log_line


def test_parse_valid_log():
    """
    Vérifie qu'une ligne valide est correctement parsée.
    """

    line = (
        "2026-09-15 08:30:10 "
        "LOGIN "
        "username=admin "
        "status=FAILED "
        "ip=192.168.1.15"
    )

    result = parse_log_line(line)

    # Vérifie que le parser retourne bien quelque chose.
    assert result is not None

    # Vérifie les valeurs extraites.
    assert result["timestamp"] == "2026-09-15 08:30:10"
    assert result["event_type"] == "LOGIN"
    assert result["username"] == "admin"
    assert result["status"] == "FAILED"
    assert result["ip_address"] == "192.168.1.15"


def test_parse_invalid_log():
    """
    Vérifie qu'une ligne incorrecte est rejetée.
    """

    line = "ceci n'est pas un log valide"

    result = parse_log_line(line)

    assert result is None