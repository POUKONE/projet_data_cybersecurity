"""
Analyse de sécurité Web.

Ce module permet :
- de vérifier l'utilisation de HTTPS ;
- de vérifier certains headers de sécurité ;
- de générer des détections exploitables
  par le moteur de scoring.
"""

import requests
from app.scoring.risk_engine import build_security_alert
from app.database.db import save_alert

def process_web_detections(
    detections: list[dict]
) -> list[dict]:
    """
    Transforme les détections Web en alertes
    puis les enregistre dans SQLite.
    """

    alerts = []

    for detection in detections:

        # Création de l'alerte avec
        # score et niveau de risque.
        alert = build_security_alert(
            detection
        )

        # Enregistrement en base.
        save_alert(
            alert
        )

        alerts.append(
            alert
        )

    return alerts

def run_web_analysis(
    url: str
) -> list[dict]:
    """
    Lance l'audit Web complet.

    Étapes :
    - analyse de l'URL ;
    - détection des problèmes ;
    - scoring ;
    - génération des alertes ;
    - stockage SQLite.
    """

    detections = analyze_web_security(
        url
    )

    alerts = process_web_detections(
        detections
    )

    return alerts

def analyze_web_security(
    url: str,
    timeout: int = 10
) -> list[dict]:
    """
    Analyse les principaux éléments de sécurité
    d'une URL.

    Paramètres
    ----------
    url : str
        URL à analyser.

    timeout : int
        Temps maximum d'attente de la requête.

    Retour
    ------
    list[dict]
        Liste des problèmes de sécurité détectés.
    """

    detections = []

    # ========================================================
    # VÉRIFICATION HTTPS
    # ========================================================

    if not url.lower().startswith("https://"):

        detections.append(
            {
                "event_type": "HTTPS_MISSING",
                "url": url,
                "message": (
                    "L'URL analysée n'utilise pas HTTPS."
                )
            }
        )

    # ========================================================
    # REQUÊTE HTTP
    # ========================================================

    try:

        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True
        )

    except requests.RequestException as error:

        return [
            {
                "event_type": "WEB_REQUEST_ERROR",
                "url": url,
                "message": str(error)
            }
        ]

    # ========================================================
    # CONTENT SECURITY POLICY
    # ========================================================

    csp = response.headers.get(
        "Content-Security-Policy"
    )

    if not csp:

        detections.append(
            {
                "event_type": "CSP_MISSING",
                "url": response.url,
                "status_code": response.status_code,
                "message": (
                    "Le header Content-Security-Policy "
                    "est absent."
                )
            }
        )

    return detections

if __name__ == "__main__":

    url = "https://fala-ai-three.vercel.app/"

    detections = analyze_web_security(
        url
    )

    print("\n--- Résultats de l'audit Web ---")

    if not detections:
        print(
            "Aucun problème détecté."
        )

    for detection in detections:
        print(detection)