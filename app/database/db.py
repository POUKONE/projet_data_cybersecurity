"""
Gestion de la connexion à la base de données SQLite.

Ce module permet :
- de créer la base si elle n'existe pas ;
- d'ouvrir une connexion ;
- de créer les premières tables du projet.
"""

import sqlite3
from pathlib import Path


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

if __name__ == "__main__":

    initialize_database()

    print(
        "Base de données initialisée avec succès."
    )

    print(
        f"Fichier : {DATABASE_PATH}"
    )