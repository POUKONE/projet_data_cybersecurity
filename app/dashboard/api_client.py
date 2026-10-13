import requests


# ============================================================
# CONFIGURATION API
# ============================================================


API_BASE_URL = "http://127.0.0.1:8000"


# ============================================================
# OUTILS GÉNÉRIQUES
# ============================================================


def api_get(
    endpoint: str,
    timeout: int = 10,
):
    """
    Effectue une requête GET vers l'API.
    """

    response = requests.get(
        f"{API_BASE_URL}{endpoint}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


def api_post(
    endpoint: str,
    payload: dict | None = None,
    timeout: int = 30,
):
    """
    Effectue une requête POST vers l'API.
    """

    response = requests.post(
        f"{API_BASE_URL}{endpoint}",
        json=payload or {},
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# HEALTH
# ============================================================


def get_health() -> dict:
    """
    Vérifie l'état de l'API.
    """

    return api_get(
        "/health"
    )

def get_health() -> dict:
    """
    Vérifie l'état de l'API.
    """

    return api_get(
        "/health"
    )


def check_health() -> dict:
    """
    Alias conservé pour compatibilité
    avec les pages existantes du dashboard.
    """

    return get_health()


# ============================================================
# ALERTES
# ============================================================


def get_alerts() -> list:
    """
    Récupère les alertes de sécurité.
    """

    return api_get(
        "/alerts"
    )


# ============================================================
# ÉVÉNEMENTS
# ============================================================


def get_events() -> list:
    """
    Récupère les événements de sécurité.
    """

    return api_get(
        "/events"
    )


# ============================================================
# SCANS RÉSEAU
# ============================================================


def get_network_scans() -> list:
    """
    Récupère les scans réseau enregistrés.
    """

    return api_get(
        "/network/scans"
    )

def get_network_scan(scan_id: str) -> dict:
    """
    Alias conservé pour compatibilité avec
    les pages existantes du dashboard.
    """

    return get_network_scans()


def run_network_scan(
    target: str,
) -> dict:
    """
    Lance un scan réseau via l'API.
    """

    return api_post(
        "/network/scan",
        payload={
            "target": target,
        },
        timeout=120,
    )


# ============================================================
# AUDIT WEB
# ============================================================


def run_web_audit(
    url: str,
    max_depth: int = 2,
    max_pages: int = 20,
    max_duration_seconds: int = 30,
    delay_seconds: float = 0.2,
) -> dict:
    """
    Lance un audit Web passif via FastAPI.

    Les limites du crawler sont transmises
    directement au backend.
    """

    payload = {
        "url": url,

        "max_depth": (
            max_depth
        ),

        "max_pages": (
            max_pages
        ),

        "max_duration_seconds": (
            max_duration_seconds
        ),

        "delay_seconds": (
            delay_seconds
        ),
    }


    response = requests.post(
        f"{API_BASE_URL}/web/audit",
        json=payload,

        # On laisse une marge au client HTTP
        # par rapport à la durée maximale du crawl.
        timeout=(
            max_duration_seconds
            + 20
        ),
    )


    response.raise_for_status()


    return response.json()


