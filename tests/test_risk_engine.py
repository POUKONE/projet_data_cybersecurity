from app.scoring.risk_engine import (
    calculate_risk_score,
    get_risk_level,
    build_security_alert
)


def test_get_risk_level():
    """
    Vérifie que chaque intervalle de score
    correspond au bon niveau de risque.
    """

    assert get_risk_level(10) == "LOW"
    assert get_risk_level(29) == "LOW"

    assert get_risk_level(30) == "MEDIUM"
    assert get_risk_level(49) == "MEDIUM"

    assert get_risk_level(50) == "HIGH"
    assert get_risk_level(69) == "HIGH"

    assert get_risk_level(70) == "CRITICAL"
    assert get_risk_level(100) == "CRITICAL"


def test_basic_failed_login_score():
    """
    Vérifie qu'une détection contenant exactement
    5 tentatives échouées sur un seul utilisateur
    conserve le score de base de 40.
    """

    detection = {
        "event_type": "FAILED_LOGIN_BURST",
        "failed_attempts": 5,
        "targeted_users": ["admin"]
    }

    score = calculate_risk_score(detection)

    assert score == 40


def test_extra_failed_attempts():
    """
    Vérifie que les tentatives supplémentaires
    augmentent le score de 2 points chacune.
    """

    detection = {
        "event_type": "FAILED_LOGIN_BURST",
        "failed_attempts": 10,
        "targeted_users": ["admin"]
    }

    score = calculate_risk_score(detection)

    # Score de base : 40
    # 10 - 5 = 5 tentatives supplémentaires
    # 5 x 2 = 10 points supplémentaires
    #
    # Total attendu : 50
    assert score == 50


def test_multiple_targeted_users():
    """
    Vérifie qu'une même IP ciblant plusieurs comptes
    reçoit un bonus de risque de 10 points.
    """

    detection = {
        "event_type": "FAILED_LOGIN_BURST",
        "failed_attempts": 6,
        "targeted_users": [
            "admin",
            "ibrahima",
            "amsa",
            "user01",
            "user02"
        ]
    }

    score = calculate_risk_score(detection)

    # Score de base : 40
    # 1 tentative supplémentaire : +2
    # plusieurs utilisateurs ciblés : +10
    #
    # Total attendu : 52
    assert score == 52


def test_score_cannot_exceed_100():
    """
    Vérifie que le score ne dépasse jamais 100,
    même lorsqu'un très grand nombre de tentatives
    est détecté.
    """

    detection = {
        "event_type": "FAILED_LOGIN_BURST",
        "failed_attempts": 100,
        "targeted_users": [
            "admin",
            "user01",
            "user02"
        ]
    }

    score = calculate_risk_score(detection)

    assert score == 100


def test_unknown_event_returns_zero():
    """
    Vérifie qu'un événement inconnu
    retourne un score nul.
    """

    detection = {
        "event_type": "UNKNOWN_EVENT"
    }

    score = calculate_risk_score(detection)

    assert score == 0


def test_missing_event_type_returns_zero():
    """
    Vérifie qu'une détection sans type
    d'événement retourne un score nul.
    """

    detection = {
        "failed_attempts": 10
    }

    score = calculate_risk_score(detection)

    assert score == 0


def test_build_security_alert():
    """
    Vérifie la création complète
    d'une alerte de sécurité.
    """

    detection = {
        "event_type": "FAILED_LOGIN_BURST",
        "ip_address": "172.16.0.12",
        "failed_attempts": 6,
        "targeted_users": [
            "admin",
            "ibrahima",
            "amsa",
            "user01",
            "user02"
        ]
    }

    alert = build_security_alert(detection)

    assert alert["event_type"] == "FAILED_LOGIN_BURST"

    assert alert["ip_address"] == "172.16.0.12"

    assert alert["failed_attempts"] == 6

    assert alert["risk_score"] == 52

    assert alert["risk_level"] == "HIGH"

    assert len(alert["targeted_users"]) == 5

    assert alert["description"] is not None


def test_lowercase_event_type():
    """
    Vérifie que le moteur fonctionne également
    lorsque le type d'événement est écrit
    en minuscules.
    """

    detection = {
        "event_type": "failed_login_burst",
        "failed_attempts": 10,
        "targeted_users": ["admin"]
    }

    score = calculate_risk_score(detection)

    assert score == 50


def test_targeted_users_none():
    """
    Vérifie que targeted_users=None
    ne provoque pas d'erreur.
    """

    detection = {
        "event_type": "FAILED_LOGIN_BURST",
        "failed_attempts": 5,
        "targeted_users": None
    }

    score = calculate_risk_score(detection)

    assert score == 40

def test_new_port_base_score():
    """
    Un nouveau port non sensible doit
    obtenir le score de base.
    """

    detection = {
        "event_type": "NEW_PORT_DETECTED",
        "ip_address": "127.0.0.1",
        "port": 8080,
        "protocol": "tcp",
        "service": "http-proxy"
    }

    score = calculate_risk_score(
        detection
    )

    assert score == 20

def test_sensitive_new_port_score():
    """
    Un nouveau port sensible doit recevoir
    un bonus de risque.
    """

    detection = {
        "event_type": "NEW_PORT_DETECTED",
        "ip_address": "127.0.0.1",
        "port": 1521,
        "protocol": "tcp",
        "service": "oracle-tns"
    }

    score = calculate_risk_score(
        detection
    )

    assert score == 40

def test_network_alert_creation():
    """
    Vérifie la création complète
    d'une alerte réseau.
    """

    detection = {
        "event_type": "NEW_PORT_DETECTED",
        "host": "127.0.0.1",
        "ip_address": "127.0.0.1",
        "protocol": "tcp",
        "port": 445,
        "state": "open",
        "service": "microsoft-ds",
        "product": "",
        "version": ""
    }

    alert = build_security_alert(
        detection
    )

    assert alert["event_type"] == "NEW_PORT_DETECTED"

    assert alert["port"] == 445

    assert alert["service"] == "microsoft-ds"

    assert alert["risk_score"] == 40

    assert alert["risk_level"] == "MEDIUM"

def test_new_service_score():
    """
    Vérifie le score de base
    d'un changement de service réseau.
    """

    detection = {
        "event_type": "NEW_SERVICE_DETECTED",
        "ip_address": "127.0.0.1",
        "port": 8080,
        "previous_service": "http",
        "service": "http-proxy"
    }

    score = calculate_risk_score(
        detection
    )

    assert score == 25

    assert get_risk_level(score) == "LOW"