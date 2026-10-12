"""
API principale du projet Data & Cybersécurité.

Cette API permet notamment :
- de vérifier l'état de l'application ;
- de récupérer les alertes ;
- de récupérer les événements ;
- de récupérer les scans réseau ;
- de lancer une analyse Nmap ;
- de lancer un audit Web.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.database.db import (
    initialize_database,
    get_alerts,
    get_security_events,
    get_latest_network_scan,
)

from app.analyzers.network_analyzer import (
    run_network_analysis,
)

from app.analyzers.web_analyzer import (
    run_web_analysis,
)


# ============================================================
# LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Initialise les ressources nécessaires
    au démarrage de l'application.
    """

    initialize_database()

    yield


# ============================================================
# APPLICATION FASTAPI
# ============================================================

app = FastAPI(
    title="Data & Cybersecurity API",
    description=(
        "API de supervision et d'analyse "
        "des événements de cybersécurité."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ============================================================
# MODÈLES DE REQUÊTES
# ============================================================

class NetworkScanRequest(BaseModel):
    """
    Requête utilisée pour lancer
    une analyse réseau.
    """

    target: str


class WebAuditRequest(BaseModel):
    """
    Requête utilisée pour lancer
    un audit Web.
    """

    url: str


# ============================================================
# ROUTE PRINCIPALE
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


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    """
    Vérifie l'état de santé de l'API.
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
    Retourne tous les événements de sécurité.
    """

    events = get_security_events()

    return {
        "count": len(events),
        "events": events
    }


# ============================================================
# DERNIER SCAN RÉSEAU
# ============================================================

@app.get("/network/scans")
def latest_network_scan():
    """
    Retourne le dernier scan réseau
    enregistré dans SQLite.
    """

    scan = get_latest_network_scan()

    return {
        "count": len(scan),
        "scan": scan
    }


# ============================================================
# LANCEMENT D'UN SCAN NMAP
# ============================================================

@app.post("/network/scan")
def launch_network_scan(
    request: NetworkScanRequest
):
    """
    Lance le pipeline réseau complet.

    Nmap
    → comparaison
    → détection
    → scoring
    → alertes
    → SQLite
    """

    try:

        alerts = run_network_analysis(
            request.target
        )

        return {
            "target": request.target,
            "alert_count": len(alerts),
            "alerts": alerts
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# AUDIT WEB
# ============================================================

@app.post("/web/audit")
def launch_web_audit(
    request: WebAuditRequest
):
    """
    Lance un audit Web passif.

    Une erreur d'analyse est renvoyée
    dans le rapport et n'est jamais
    interprétée comme zéro vulnérabilité.
    """

    try:

        report = run_web_analysis(
            request.url
        )

        return report

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Erreur interne pendant "
                f"l'audit Web : {error}"
            )
        )