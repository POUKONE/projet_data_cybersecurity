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
    url: str
) -> dict:
    """
    Lance un audit Web passif.

    Le rapport complet est retourné :
    - statut ;
    - couverture ;
    - contrôles ;
    - erreurs ;
    - détections ;
    - alertes.
    """

    response = requests.post(
        f"{API_URL}/web/audit",
        json={
            "url": url
        },
        timeout=30
    )

    response.raise_for_status()

    return response.json()