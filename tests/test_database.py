import sqlite3

from app.database.db import (
    get_connection,
    initialize_database,
    DATABASE_PATH
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