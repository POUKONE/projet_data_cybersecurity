import sqlite3
import uuid

import pytest

import app.database.db as db_module

from app.security.crypto_utils import generate_key

@pytest.fixture(autouse=True)
def isolated_database(
    tmp_path,
    monkeypatch
):
    """
    Chaque test utilise :
    - sa propre base SQLite temporaire ;
    - sa propre clé Fernet temporaire.

    Cela évite :
    - de modifier la vraie base du projet ;
    - les conflits entre anciennes et nouvelles clés ;
    - la dépendance au fichier .env.
    """

    # Base SQLite temporaire propre au test.
    temporary_database = (
        tmp_path
        / "test_security_project.db"
    )

    # Remplacement du chemin utilisé
    # par app.database.db.
    monkeypatch.setattr(
        db_module,
        "DATABASE_PATH",
        temporary_database
    )

    # Clé Fernet temporaire pour le test.
    key = generate_key()

    monkeypatch.setenv(
        "FERNET_KEY",
        key.decode("utf-8")
    )

from app.database.db import (
    get_connection,
    initialize_database,
    DATABASE_PATH,
    save_alert,
    get_alerts,
    save_security_event,
    get_security_events,
    save_network_scan,
    get_latest_network_scan,
    get_last_two_network_scans
)

def test_alert_ip_is_encrypted_in_database(
    monkeypatch
):
    """
    Vérifie que l'adresse IP n'est pas stockée
    en clair dans SQLite.
    """

    key = generate_key()

    monkeypatch.setenv(
        "FERNET_KEY",
        key.decode("utf-8")
    )

    initialize_database()

    alert = {
        "event_type": "FAILED_LOGIN_BURST",
        "ip_address": "192.168.1.99",
        "risk_score": 40,
        "risk_level": "MEDIUM",
        "description": "Test chiffrement.",
        "failed_attempts": 5,
        "targeted_users": ["admin"],
        "start_time": "2026-10-11 10:00:00",
        "end_time": "2026-10-11 10:01:00"
    }

    alert_id = save_alert(
        alert
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT ip_address
        FROM alerts
        WHERE id = ?
        """,
        (
            alert_id,
        )
    )

    row = cursor.fetchone()

    connection.close()

    stored_ip = row["ip_address"]

    # L'adresse IP ne doit pas apparaître
    # en clair dans SQLite.
    assert stored_ip != "192.168.1.99"

    assert stored_ip.startswith(
        "ENC:"
    )

def test_alert_ip_is_decrypted_when_read(
    monkeypatch
):
    """
    Vérifie que get_alerts() retourne
    l'adresse IP originale.
    """

    key = generate_key()

    monkeypatch.setenv(
        "FERNET_KEY",
        key.decode("utf-8")
    )

    initialize_database()

    alert = {
        "event_type": "FAILED_LOGIN_BURST",
        "ip_address": "10.0.0.77",
        "risk_score": 40,
        "risk_level": "MEDIUM",
        "description": "Test déchiffrement.",
        "failed_attempts": 5,
        "targeted_users": ["admin"],
        "start_time": None,
        "end_time": None
    }

    alert_id = save_alert(
        alert
    )

    alerts = get_alerts()

    saved_alert = next(
        item
        for item in alerts
        if item["id"] == alert_id
    )

    assert (
        saved_alert["ip_address"]
        == "10.0.0.77"
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


def test_save_network_scan():
    initialize_database()

    scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 135,
            "state": "open",
            "service": "msrpc",
            "product": "",
            "version": ""
        }
    ]

    scan_id = save_network_scan(
        scan
    )

    assert isinstance(
        scan_id,
        str
    )

    assert len(scan_id) > 0

def test_get_latest_network_scan():
    initialize_database()

    scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 445,
            "state": "open",
            "service": "microsoft-ds",
            "product": "",
            "version": ""
        }
    ]

    save_network_scan(
        scan
    )

    latest_scan = get_latest_network_scan()

    assert len(latest_scan) > 0

    assert latest_scan[0]["port"] == 445

def test_get_last_two_network_scans():
    """
    Vérifie la récupération correcte
    des deux derniers scans réseau.
    """

    initialize_database()

    # Identifiant unique pour éviter que les anciens
    # tests SQLite interfèrent avec ce test.
    unique_id = uuid.uuid4().hex

    first_scan_id = f"test_scan_1_{unique_id}"
    second_scan_id = f"test_scan_2_{unique_id}"

    first_scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 135,
            "state": "open",
            "service": "msrpc",
            "product": "",
            "version": ""
        }
    ]

    second_scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 135,
            "state": "open",
            "service": "msrpc",
            "product": "",
            "version": ""
        },
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 1521,
            "state": "open",
            "service": "oracle-tns",
            "product": "Oracle TNS listener",
            "version": ""
        }
    ]

    save_network_scan(
        first_scan,
        scan_id=first_scan_id
    )

    save_network_scan(
        second_scan,
        scan_id=second_scan_id
    )

    previous_scan, current_scan = (
        get_last_two_network_scans()
    )

    assert len(previous_scan) == 1
    assert len(current_scan) == 2

    assert previous_scan[0]["port"] == 135

    current_ports = {
        item["port"]
        for item in current_scan
    }

    assert current_ports == {
        135,
        1521
    }