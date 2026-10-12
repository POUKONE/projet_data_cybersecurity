"""
Client HTTP utilisé par le dashboard Streamlit.
"""

import requests


API_URL = (
    "http://127.0.0.1:8000"
)


def check_health() -> bool:
    """
    Vérifie si FastAPI répond.
    """

    try:

        response = requests.get(
            f"{API_URL}/health",
            timeout=3
        )

        response.raise_for_status()

        return (
            response.json().get(
                "status"
            )
            == "healthy"
        )

    except requests.RequestException:

        return False


def get_alerts() -> list[dict]:
    """
    Récupère les alertes.
    """

    response = requests.get(
        f"{API_URL}/alerts",
        timeout=5
    )

    response.raise_for_status()

    return response.json().get(
        "alerts",
        []
    )


def get_events() -> list[dict]:
    """
    Récupère les événements.
    """

    response = requests.get(
        f"{API_URL}/events",
        timeout=5
    )

    response.raise_for_status()

    return response.json().get(
        "events",
        []
    )


def get_network_scan() -> list[dict]:
    """
    Récupère le dernier scan réseau.
    """

    response = requests.get(
        f"{API_URL}/network/scans",
        timeout=5
    )

    response.raise_for_status()

    return response.json().get(
        "scan",
        []
    )


def run_network_scan(
    target: str
) -> dict:
    """
    Lance un scan réseau.
    """

    response = requests.post(
        f"{API_URL}/network/scan",
        json={
            "target": target
        },
        timeout=60
    )

    response.raise_for_status()

    return response.json()

def run_web_audit(
    url: str,
    max_depth: int = 2,
    max_pages: int = 20,
    max_duration_seconds: int = 30,
    delay_seconds: float = 0.2,
) -> dict:
    """
    Lance un audit Web passif via l'API FastAPI.
    """

    payload = {
        "url": url,
        "max_depth": max_depth,
        "max_pages": max_pages,
        "max_duration_seconds": (
            max_duration_seconds
        ),
        "delay_seconds": delay_seconds,
    }


    response = requests.post(
        f"{API_BASE_URL}/web/audit",
        json=payload,
        timeout=(
            max_duration_seconds
            + 20
        ),
    )


    response.raise_for_status()


    return response.json()