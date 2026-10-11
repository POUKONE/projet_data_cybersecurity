"""
Gestion de la connexion à la base de données SQLite.

Ce module permet :
- de créer la base si elle n'existe pas ;
- d'ouvrir une connexion ;
- de créer les premières tables du projet.
"""

import sqlite3
from pathlib import Path
import json
from datetime import datetime

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

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            description TEXT,
            failed_attempts INTEGER,
            targeted_users TEXT,
            start_time TEXT,
            end_time TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Validation des changements.
    connection.commit()

    # Fermeture propre de la connexion.
    connection.close()

def save_alert(alert: dict) -> int:
    """
    Enregistre une alerte de sécurité dans SQLite.

    Paramètres
    ----------
    alert : dict
        Alerte générée par build_security_alert().

    Retour
    ------
    int
        Identifiant de l'alerte créée dans la base.
    """

    # Ouverture d'une connexion à SQLite.
    connection = get_connection()

    cursor = connection.cursor()

    # --------------------------------------------------------
    # Gestion de targeted_users
    # --------------------------------------------------------
    #
    # targeted_users est actuellement une liste Python :
    #
    # ["admin", "ibrahima", "amsa"]
    #
    # SQLite ne stocke pas directement les listes Python.
    # On transforme donc la liste en chaîne JSON.
    targeted_users = alert.get(
        "targeted_users"
    ) or []

    targeted_users_json = json.dumps(
        targeted_users
    )

    # --------------------------------------------------------
    # Conversion des dates
    # --------------------------------------------------------
    #
    # start_time et end_time peuvent être des Timestamp Pandas.
    # On les convertit en texte avant stockage.

    start_time = alert.get(
        "start_time"
    )

    end_time = alert.get(
        "end_time"
    )

    if start_time is not None:
        start_time = str(start_time)

    if end_time is not None:
        end_time = str(end_time)

    # --------------------------------------------------------
    # Insertion SQL
    # --------------------------------------------------------

    cursor.execute(
        """
        INSERT INTO alerts (
            event_type,
            ip_address,
            risk_score,
            risk_level,
            description,
            failed_attempts,
            targeted_users,
            start_time,
            end_time
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.get("event_type"),
            alert.get("ip_address"),
            alert.get("risk_score", 0),
            alert.get("risk_level"),
            alert.get("description"),
            alert.get("failed_attempts"),
            targeted_users_json,
            start_time,
            end_time,
        )
    )

    # Validation de l'insertion.
    connection.commit()

    # lastrowid correspond à l'identifiant
    # automatiquement attribué par SQLite.
    alert_id = cursor.lastrowid

    # Fermeture propre de la connexion.
    connection.close()

    return alert_id

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
            event.get("ip_address"),
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

    return [
        dict(row)
        for row in rows
    ]

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