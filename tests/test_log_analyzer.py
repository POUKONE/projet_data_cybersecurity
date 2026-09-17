from app.analyzers.log_analyzer import (
    logs_to_dataframe,
    detect_failed_login_bursts
)


def test_failed_login_burst_detection():
    """
    Vérifie qu'une série de 5 connexions échouées
    depuis la même IP en moins de 5 minutes
    est correctement détectée.
    """

    logs = [
        {
            "timestamp": "2026-09-15 08:30:10",
            "event_type": "LOGIN",
            "username": "admin",
            "status": "FAILED",
            "ip_address": "192.168.1.15"
        },
        {
            "timestamp": "2026-09-15 08:30:20",
            "event_type": "LOGIN",
            "username": "admin",
            "status": "FAILED",
            "ip_address": "192.168.1.15"
        },
        {
            "timestamp": "2026-09-15 08:30:40",
            "event_type": "LOGIN",
            "username": "admin",
            "status": "FAILED",
            "ip_address": "192.168.1.15"
        },
        {
            "timestamp": "2026-09-15 08:31:05",
            "event_type": "LOGIN",
            "username": "admin",
            "status": "FAILED",
            "ip_address": "192.168.1.15"
        },
        {
            "timestamp": "2026-09-15 08:32:10",
            "event_type": "LOGIN",
            "username": "admin",
            "status": "FAILED",
            "ip_address": "192.168.1.15"
        }
    ]

    # Transformation en DataFrame.
    df = logs_to_dataframe(logs)

    # Lancement de la détection.
    result = detect_failed_login_bursts(
        df,
        threshold=5,
        window_minutes=5
    )

    # Une seule détection doit être produite.
    assert len(result) == 1

    # Vérification de l'adresse IP.
    assert (
        result[0]["ip_address"]
        == "192.168.1.15"
    )

    # Vérification du nombre de tentatives.
    assert result[0]["failed_attempts"] == 5

    # Vérification du type d'événement.
    assert (
        result[0]["event_type"]
        == "FAILED_LOGIN_BURST"
    )