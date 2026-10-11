import pytest

from fastapi.testclient import TestClient

import app.database.db as db_module

from app.api.main import app
from app.database.db import initialize_database
from app.security.crypto_utils import generate_key


client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_api_environment(
    tmp_path,
    monkeypatch
):
    """
    Crée un environnement isolé pour chaque test API.

    Chaque test utilise :
    - une base SQLite temporaire ;
    - une clé Fernet temporaire.

    Cela évite de dépendre :
    - de la vraie base du projet ;
    - du fichier .env local ;
    - des données créées par les autres tests.
    """

    # --------------------------------------------------------
    # BASE SQLITE TEMPORAIRE
    # --------------------------------------------------------

    temporary_database = (
        tmp_path
        / "test_api_security.db"
    )

    monkeypatch.setattr(
        db_module,
        "DATABASE_PATH",
        temporary_database
    )

    # --------------------------------------------------------
    # CLÉ FERNET TEMPORAIRE
    # --------------------------------------------------------

    key = generate_key()

    monkeypatch.setenv(
        "FERNET_KEY",
        key.decode("utf-8")
    )

    # --------------------------------------------------------
    # INITIALISATION SQLITE
    # --------------------------------------------------------

    initialize_database()


def test_root():
    """
    Vérifie que la route principale répond.
    """

    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"


def test_health():
    """
    Vérifie l'état de santé de l'API.
    """

    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"


def test_alerts_endpoint():
    """
    Vérifie que /alerts retourne
    une structure valide.
    """

    response = client.get("/alerts")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "alerts" in data

    assert isinstance(
        data["alerts"],
        list
    )


def test_events_endpoint():
    """
    Vérifie que /events retourne
    une structure valide.
    """

    response = client.get("/events")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "events" in data

    assert isinstance(
        data["events"],
        list
    )