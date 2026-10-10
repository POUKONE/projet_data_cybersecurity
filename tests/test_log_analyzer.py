from app.analyzers.log_analyzer import (
    logs_to_dataframe,
    detect_failed_login_bursts
)
from app.scoring.risk_engine import build_security_alert


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
    
def test_detection_can_generate_security_alert():
    """
    Vérifie qu'une détection produite par log_analyzer
    peut être transformée en alerte de sécurité complète.
    """

    logs = [
        {
            "timestamp": "2026-09-15 11:05:48",
            "event_type": "LOGIN",
            "username": "admin",
            "status": "FAILED",
            "ip_address": "172.16.0.12"
        },
        {
            "timestamp": "2026-09-15 11:06:02",
            "event_type": "LOGIN",
            "username": "ibrahima",
            "status": "FAILED",
            "ip_address": "172.16.0.12"
        },
        {
            "timestamp": "2026-09-15 11:06:19",
            "event_type": "LOGIN",
            "username": "amsa",
            "status": "FAILED",
            "ip_address": "172.16.0.12"
        },
        {
            "timestamp": "2026-09-15 11:06:47",
            "event_type": "LOGIN",
            "username": "user01",
            "status": "FAILED",
            "ip_address": "172.16.0.12"
        },
        {
            "timestamp": "2026-09-15 11:07:05",
            "event_type": "LOGIN",
            "username": "user02",
            "status": "FAILED",
            "ip_address": "172.16.0.12"
        },
        {
            "timestamp": "2026-09-15 11:07:22",
            "event_type": "LOGIN",
            "username": "admin",
            "status": "FAILED",
            "ip_address": "172.16.0.12"
        }
    ]

    # Transformation en DataFrame.
    df = logs_to_dataframe(
        logs
    )

    # Détection.
    detections = detect_failed_login_bursts(
        df,
        threshold=5,
        window_minutes=5
    )

    # On attend une seule détection.
    assert len(detections) == 1

    # Transformation en alerte.
    alert = build_security_alert(
        detections[0]
    )

    # Vérification de l'IP.
    assert (
        alert["ip_address"]
        == "172.16.0.12"
    )

    # Vérification du score attendu.
    assert alert["risk_score"] == 52

    # Vérification du niveau.
    assert alert["risk_level"] == "HIGH"

    # Vérification du type.
    assert (
        alert["event_type"]
        == "FAILED_LOGIN_BURST"
    )