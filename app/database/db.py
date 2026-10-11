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