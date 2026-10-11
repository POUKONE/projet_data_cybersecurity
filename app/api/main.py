"""
API principale du projet Data & Cybersécurité.

Cette API permettra notamment :
- de vérifier l'état de l'application ;
- de récupérer les alertes ;
- de récupérer les événements de sécurité ;
- d'exposer les analyses au dashboard.
"""

from fastapi import FastAPI

from app.database.db import (
    initialize_database,
    get_alerts,
    get_security_events,
)


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="Data & Cybersecurity API",
    description=(
        "API de supervision et d'analyse "
        "des événements de cybersécurité."
    ),
    version="1.0.0"
)


# ============================================================
# INITIALISATION
# ============================================================

@app.on_event("startup")
def startup_event():
    """
    Initialise SQLite au démarrage de l'API.
    """

    initialize_database()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def root():
    """
    Vérifie que l'API fonctionne.
    """

    return {
        "status": "ok",
        "message": (
            "Data & Cybersecurity API is running."
        )
    }


@app.get("/health")
def health():
    """
    Endpoint de supervision de l'API.
    """

    return {
        "status": "healthy"
    }


# ============================================================
# ALERTES
# ============================================================

@app.get("/alerts")
def list_alerts():
    """
    Retourne toutes les alertes enregistrées.
    """

    alerts = get_alerts()

    return {
        "count": len(alerts),
        "alerts": alerts
    }


# ============================================================
# ÉVÉNEMENTS
# ============================================================

@app.get("/events")
def list_events():
    """
    Retourne les événements de sécurité.
    """

    events = get_security_events()

    return {
        "count": len(events),
        "events": events
    }