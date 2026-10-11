import sqlite3

from app.database.db import (
    get_connection,
    initialize_database,
    DATABASE_PATH,
    save_alert,
    get_alerts,
    save_security_event,
    get_security_events
)


def test_database_creation():
    """
    Vérifie que la base SQLite est bien créée.
    """

    # On initialise la base.
    initialize_database()

    # Le fichier de base de données
    # doit maintenant exister.
    assert DATABASE_PATH.exists()


def test_database_connection():
    """
    Vérifie qu'une connexion SQLite
    peut être ouverte correctement.
    """

    connection = get_connection()

    # Vérifie que l'objet retourné est bien
    # une connexion SQLite.
    assert isinstance(
        connection,
        sqlite3.Connection
    )

    connection.close()


def test_security_events_table_exists():
    """
    Vérifie que la table security_events existe.
    """

    initialize_database()

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table'
        AND name='security_events'
        """
    )

    result = cursor.fetchone()

    connection.close()

    # Si la table existe, SQLite
    # doit retourner une ligne.
    assert result is not None


def test_alerts_table_exists():
    """
    Vérifie que la table alerts existe.
    """

    initialize_database()

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table'
        AND name='alerts'
        """
    )

    result = cursor.fetchone()

    connection.close()

    assert result is not None


def test_save_alert():
    """
    Vérifie qu'une alerte peut être enregistrée
    dans la base de données.
    """

    initialize_database()

    alert = {
        "event_type": "FAILED_LOGIN_BURST",
        "ip_address": "172.16.0.12",
        "risk_score": 52,
        "risk_level": "HIGH",
        "description": "Test d'alerte.",
        "failed_attempts": 6,
        "targeted_users": [
            "admin",
            "ibrahima",
            "amsa"
        ],
        "start_time": "2026-09-15 11:05:48",
        "end_time": "2026-09-15 11:07:22"
    }

    alert_id = save_alert(alert)

    assert isinstance(alert_id, int)
    assert alert_id > 0


def test_get_alerts():
    """
    Vérifie qu'une alerte enregistrée
    peut être récupérée depuis SQLite.
    """

    initialize_database()

    alert = {
        "event_type": "FAILED_LOGIN_BURST",
        "ip_address": "192.168.1.50",
        "risk_score": 40,
        "risk_level": "MEDIUM",
        "description": "Test récupération.",
        "failed_attempts": 5,
        "targeted_users": ["admin"],
        "start_time": "2026-09-15 08:10:44",
        "end_time": "2026-09-15 08:12:44"
    }

    save_alert(alert)

    alerts = get_alerts()

    assert len(alerts) > 0
    assert isinstance(
        alerts[0]["targeted_users"],
        list
    )


def test_save_security_event():
    """
    Vérifie qu'un événement peut être
    enregistré dans SQLite.
    """

    initialize_database()

    event = {
        "event_type": "LOGIN",
        "ip_address": "192.168.1.15",
        "timestamp": "2026-09-15 08:30:10",
        "message": "Tentative de connexion échouée."
    }

    event_id = save_security_event(
        event
    )

    assert isinstance(event_id, int)
    assert event_id > 0

def test_get_security_events():
    """
    Vérifie que les événements enregistrés
    peuvent être récupérés.
    """

    initialize_database()

    event = {
        "event_type": "LOGIN",
        "ip_address": "10.0.0.8",
        "timestamp": "2026-09-15 09:15:00",
        "message": "Connexion utilisateur."
    }

    save_security_event(
        event
    )

    events = get_security_events()

    assert len(events) > 0

    assert isinstance(
        events[0],
        dict
    )

    assert "event_type" in events[0]
    assert "ip_address" in events[0]