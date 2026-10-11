"""
Gestion de la connexion à la base de données SQLite.

Ce module permet :
- de créer la base si elle n'existe pas ;
- d'ouvrir une connexion ;
- de créer les premières tables du projet.
"""

from asyncio import events
from asyncio import events
import sqlite3
from pathlib import Path
import json
from datetime import datetime

from streamlit import connection

from app.security.crypto_utils import (
    encrypt_sensitive_text,
    decrypt_sensitive_text
)

# ============================================================
# CONFIGURATION
# ============================================================

# Chemin vers la base de données.
#
# Le dossier data/processed est utilisé pour stocker
# les données générées par l'application.
DATABASE_PATH = Path(
    "data/processed/security_project.db"
)


# ============================================================
# CONNEXION
# ============================================================

def get_connection() -> sqlite3.Connection:
    """
    Crée et retourne une connexion SQLite.

    Retour
    ------
    sqlite3.Connection
        Connexion active vers la base de données.
    """

    # On s'assure que le dossier parent existe.
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Création / ouverture de la base.
    connection = sqlite3.connect(
        DATABASE_PATH
    )

    # row_factory permet de récupérer les résultats
    # sous une forme proche d'un dictionnaire.
    connection.row_factory = sqlite3.Row

    return connection


def ensure_alert_columns(connection):
    """
    Vérifie que la table alerts contient
    les colonnes utilisées par le nouveau
    modèle de supervision.

    Les colonnes manquantes sont ajoutées
    automatiquement.
    """

    cursor = connection.execute(
        "PRAGMA table_info(alerts)"
    )

    existing_columns = {
        row["name"]
        for row in cursor.fetchall()
    }

    required_columns = {
        "source_type": "TEXT",
        "target": "TEXT",
        "host": "TEXT",
        "url": "TEXT",
        "message": "TEXT",
        "status": "TEXT DEFAULT 'OPEN'",
    }

    for column_name, column_type in required_columns.items():

        if column_name not in existing_columns:

            connection.execute(
                f"""
                ALTER TABLE alerts
                ADD COLUMN {column_name} {column_type}
                """
            )

    connection.commit()

def initialize_database() -> None:
    """
    Initialise la base de données.

    Crée les tables nécessaires si elles
    n'existent pas encore.
    """

    connection = get_connection()

    cursor = connection.cursor()

    # --------------------------------------------------------
    # Table des événements de sécurité
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            timestamp TEXT,
            message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS network_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        protocol TEXT,
        port INTEGER NOT NULL,
        state TEXT,
        service TEXT,
        product TEXT,
        version TEXT,
        scan_id TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """
)

    # --------------------------------------------------------
    # Table des alertes
    # --------------------------------------------------------

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            source_type TEXT,
            target TEXT,

            event_type TEXT NOT NULL,

            ip_address TEXT,
            host TEXT,
            url TEXT,

            risk_score INTEGER,
            risk_level TEXT,

            message TEXT,
            description TEXT,

            status TEXT DEFAULT 'OPEN',

            failed_attempts INTEGER,
            targeted_users TEXT,

            start_time TEXT,
            end_time TEXT,

            created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """
)

    ensure_alert_columns(
        connection
)

    # Validation des changements.
    connection.commit()

    # Fermeture propre de la connexion.
    connection.close()

def encrypt_database_value(
    value: str | None
) -> str | None:
    """
    Chiffre une valeur avant stockage SQLite.

    Le préfixe ENC: permet de savoir
    qu'une valeur est chiffrée.
    """

    if value is None:
        return None

    value = str(value)

    encrypted = encrypt_sensitive_text(
        value
    )

    return f"ENC:{encrypted}"


def decrypt_database_value(
    value: str | None
) -> str | None:
    """
    Déchiffre une valeur provenant de SQLite.

    Les anciennes valeurs non chiffrées
    restent compatibles.
    """

    if value is None:
        return None

    # Anciennes données enregistrées
    # avant l'ajout du chiffrement.
    if not value.startswith("ENC:"):
        return value

    encrypted_value = value[4:]

    return decrypt_sensitive_text(
        encrypted_value
    )


def save_alert(alert: dict) -> int:
    """
    Enregistre une alerte de sécurité
    dans SQLite.

    Les données sensibles sont chiffrées
    avant stockage.
    """

    connection = get_connection()

    try:

        targeted_users = alert.get(
            "targeted_users"
        )

        if targeted_users is not None:
            targeted_users = json.dumps(
                targeted_users
            )

        ip_address = encrypt_database_value(
            alert.get("ip_address")
        )

        target = encrypt_database_value(
            alert.get("target")
        )

        host = encrypt_database_value(
            alert.get("host")
        )

        url = encrypt_database_value(
            alert.get("url")
        )

        cursor = connection.execute(
            """
            INSERT INTO alerts (
                source_type,
                target,
                event_type,
                ip_address,
                host,
                url,
                risk_score,
                risk_level,
                message,
                description,
                status,
                failed_attempts,
                targeted_users,
                start_time,
                end_time
            )
            VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            """,
            (
                alert.get("source_type"),
                target,
                alert.get("event_type"),
                ip_address,
                host,
                url,
                alert.get("risk_score"),
                alert.get("risk_level"),
                alert.get("message"),
                alert.get("description"),
                alert.get(
                    "status",
                    "OPEN"
                ),
                alert.get(
                    "failed_attempts"
                ),
                targeted_users,
                str(
                    alert.get("start_time")
                )
                if alert.get("start_time")
                is not None
                else None,
                str(
                    alert.get("end_time")
                )
                if alert.get("end_time")
                is not None
                else None,
            )
        )

        connection.commit()

        return cursor.lastrowid

    finally:

        connection.close()


def get_alerts() -> list[dict]:
    """
    Récupère toutes les alertes enregistrées
    dans la base SQLite.

    Retour
    ------
    list[dict]
        Liste des alertes enregistrées.
    """

    # Ouverture de la connexion.
    connection = get_connection()

    cursor = connection.cursor()

    # Récupération des alertes.
    # Les plus récentes apparaissent en premier.
    cursor.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()

    alerts = []

    for row in rows:

        # Conversion sqlite3.Row -> dictionnaire Python.
        alert = dict(row)

        alert["ip_address"] = decrypt_database_value(
            alert.get("ip_address")
)
       

        alert["target"] = decrypt_database_value(
            alert.get("target")
)

        alert["host"] = decrypt_database_value(
            alert.get("host")
)

        alert["url"] = decrypt_database_value(
            alert.get("url")
        )


        # targeted_users est stocké en JSON.
        # On le reconvertit en liste Python.
        if alert.get("targeted_users"):

            alert["targeted_users"] = json.loads(
                alert["targeted_users"]
            )

        else:
            alert["targeted_users"] = []

        alerts.append(alert)

    return alerts

def save_security_event(event: dict) -> int:
    """
    Enregistre un événement de sécurité dans SQLite.

    Paramètres
    ----------
    event : dict
        Événement provenant du parser ou de l'analyseur.

    Retour
    ------
    int
        Identifiant de l'événement enregistré.
    """

    connection = get_connection()
    cursor = connection.cursor()

    # Récupération du timestamp.
    timestamp = event.get("timestamp")

    # Les timestamps Pandas ou datetime
    # sont convertis en texte pour SQLite.
    if timestamp is not None:
        timestamp = str(timestamp)


    ip_address = encrypt_database_value(
        event.get("ip_address")
)

    cursor.execute(
        """
        INSERT INTO security_events (
            event_type,
            ip_address,
            timestamp,
            message
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            event.get("event_type"),
            ip_address,
            timestamp,
            event.get("message")
        )
    )

    connection.commit()

    event_id = cursor.lastrowid

    connection.close()

    return event_id

def get_security_events() -> list[dict]:
    """
    Récupère tous les événements de sécurité
    présents dans SQLite.

    Retour
    ------
    list[dict]
        Liste des événements enregistrés.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM security_events
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()
    events = []

    for row in rows:

        event = dict(row)

        event["ip_address"] = decrypt_database_value(
            event.get("ip_address")
    )

        events.append(
            event
    )

    return events
    

def save_network_scan(
    scan_results: list[dict],
    scan_id: str | None = None
) -> str:
    """
    Enregistre un scan Nmap complet dans SQLite.

    Paramètres
    ----------
    scan_results : list[dict]
        Résultats retournés par scan_target().

    scan_id : str | None
        Identifiant du scan. S'il n'est pas fourni,
        il est généré automatiquement.

    Retour
    ------
    str
        Identifiant du scan sauvegardé.
    """

    if scan_id is None:
        scan_id = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

    connection = get_connection()
    cursor = connection.cursor()

    for result in scan_results:

        cursor.execute(
            """
            INSERT INTO network_scans (
                host,
                protocol,
                port,
                state,
                service,
                product,
                version,
                scan_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.get("host"),
                result.get("protocol"),
                result.get("port"),
                result.get("state"),
                result.get("service"),
                result.get("product"),
                result.get("version"),
                scan_id
            )
        )

    connection.commit()
    connection.close()

    return scan_id


def get_latest_network_scan() -> list[dict]:
    """
    Récupère le scan réseau le plus récent.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT scan_id
        FROM network_scans
        ORDER BY id DESC
        LIMIT 1
        """
    )

    row = cursor.fetchone()

    if row is None:
        connection.close()
        return []

    scan_id = row["scan_id"]

    cursor.execute(
        """
        SELECT
            host,
            protocol,
            port,
            state,
            service,
            product,
            version
        FROM network_scans
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (
            scan_id,
        )
    )

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]

def get_last_two_network_scans() -> tuple[
    list[dict],
    list[dict]
]:
    """
    Récupère les deux derniers scans réseau.

    Retour
    ------
    tuple
        (scan précédent, scan actuel)
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT DISTINCT scan_id
        FROM network_scans
        ORDER BY id DESC
        LIMIT 2
        """
    )

    scan_ids = [
        row["scan_id"]
        for row in cursor.fetchall()
    ]

    if len(scan_ids) < 2:
        connection.close()
        return [], []

    current_scan_id = scan_ids[0]
    previous_scan_id = scan_ids[1]

    def fetch_scan(scan_id: str) -> list[dict]:

        cursor.execute(
            """
            SELECT
                host,
                protocol,
                port,
                state,
                service,
                product,
                version
            FROM network_scans
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (
                scan_id,
            )
        )

        return [
            dict(row)
            for row in cursor.fetchall()
        ]

    current_scan = fetch_scan(
        current_scan_id
    )

    previous_scan = fetch_scan(
        previous_scan_id
    )

    connection.close()

    return (
        previous_scan,
        current_scan
    )

if __name__ == "__main__":

    initialize_database()

    print(
        "Base de données initialisée avec succès."
    )

    print(
        f"Fichier : {DATABASE_PATH}"
    )

    test_alert = {
        "event_type": "FAILED_LOGIN_BURST",
        "ip_address": "172.16.0.12",
        "risk_score": 52,
        "risk_level": "HIGH",
        "description": (
            "Plusieurs tentatives de connexion "
            "échouées ont été détectées."
        ),
        "failed_attempts": 6,
        "targeted_users": [
            "admin",
            "ibrahima",
            "amsa"
        ],
        "start_time": "2026-09-15 11:05:48",
        "end_time": "2026-09-15 11:07:22"
    }

    alert_id = save_alert(
        test_alert
    )

    print(
        f"Alerte enregistrée avec l'ID : {alert_id}"
    )

    alerts = get_alerts()

    print("\nAlertes enregistrées :")

    for alert in alerts:
        print(alert)