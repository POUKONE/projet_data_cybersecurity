import pytest

from fastapi.testclient import TestClient
from unittest.mock import patch
import app.database.db as db_module

from app.api.main import app
from app.database.db import initialize_database
from app.security.crypto_utils import generate_key

from unittest.mock import patch

client = TestClient(app)

@patch(
    "app.api.main.get_latest_network_scan"
)
def test_network_scans_endpoint(
    mock_get_scan
):
    """
    Vérifie la récupération
    du dernier scan réseau.
    """

    mock_get_scan.return_value = [
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

    response = client.get(
        "/network/scans"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["count"] == 1
    assert data["scan"][0]["port"] == 445

@patch(
    "app.api.main.run_network_analysis"
)
def test_launch_network_scan(
    mock_run_network
):
    """
    Vérifie l'endpoint de lancement Nmap
    sans effectuer de vrai scan pendant le test.
    """

    mock_run_network.return_value = [
        {
            "event_type": "NEW_PORT_DETECTED",
            "port": 1521,
            "risk_score": 40,
            "risk_level": "MEDIUM"
        }
    ]

    response = client.post(
        "/network/scan",
        json={
            "target": "127.0.0.1"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["target"] == "127.0.0.1"
    assert data["alert_count"] == 1

    mock_run_network.assert_called_once_with(
        "127.0.0.1"
    )

@patch(
    "app.api.main.run_web_analysis"
)
def test_launch_web_audit(
    mock_run_web
):

    mock_run_web.return_value = {
        "audit_status": "COMPLETED",

        "requested_url": (
            "https://example.com"
        ),

        "final_url": (
            "https://example.com"
        ),

        "http_status": 200,

        "redirects": [],

        "request_count": 1,

        "coverage": {
            "executed": 6,
            "passed": 5,
            "failed": 1,
            "skipped": 0,
            "indeterminate": 0,
        },

        "checks": [],

        "detections": [
            {
                "event_type": (
                    "CSP_MISSING"
                )
            }
        ],

        "alerts": [
            {
                "event_type": (
                    "CSP_MISSING"
                ),

                "risk_score": 15,
            }
        ],

        "finding_count": 1,

        "alert_count": 1,

        "errors": [],
    }


    response = client.post(
        "/web/audit",
        json={
            "url": (
                "https://example.com"
            )
        }
    )


    assert (
        response.status_code
        == 200
    )


    data = response.json()


    assert (
        data["audit_status"]
        == "COMPLETED"
    )

    assert (
        data["finding_count"]
        == 1
    )

    assert (
        data["coverage"][
            "executed"
        ]
        == 6
    )


    mock_run_web.assert_called_once_with(
        url="https://example.com",
        max_depth=2,
        max_pages=20,
        max_duration_seconds=30,
        delay_seconds=0.2,
    )



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

@patch(
    "app.api.main.run_web_analysis"
)
def test_web_audit_forwards_crawl_parameters(
    mock_run_web_analysis,
):
    """
    Vérifie que l'API transmet correctement
    les paramètres du crawler à l'analyseur Web.
    """

    mock_run_web_analysis.return_value = {
        "audit_status": "COMPLETED",
        "mode": "PASSIVE",
        "pages": [],
        "findings": [],
        "alerts": [],
    }


    response = client.post(
        "/web/audit",
        json={
            "url": (
                "https://example.com"
            ),
            "max_depth": 3,
            "max_pages": 15,
            "max_duration_seconds": 45,
            "delay_seconds": 0.5,
        },
    )


    assert (
        response.status_code
        == 200
    )


    mock_run_web_analysis.assert_called_once_with(
        url="https://example.com",
        max_depth=3,
        max_pages=15,
        max_duration_seconds=45,
        delay_seconds=0.5,
    )

def test_web_audit_rejects_invalid_crawl_limits():
    """
    Vérifie que FastAPI/Pydantic refuse
    des limites dangereuses ou incohérentes.
    """

    response = client.post(
        "/web/audit",
        json={
            "url": (
                "https://example.com"
            ),

            "max_depth": 100,

            "max_pages": 10000,

            "max_duration_seconds": 5000,

            "delay_seconds": -1,
        },
    )


    assert (
        response.status_code
        == 422
    )