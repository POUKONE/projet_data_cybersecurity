"""
Analyse de sécurité Web.

Ce module permet :
- de vérifier l'utilisation de HTTPS ;
- de vérifier plusieurs headers de sécurité ;
- de générer des détections exploitables
  par le moteur de scoring ;
- de transformer ces détections en alertes ;
- d'enregistrer les alertes dans SQLite.
"""

import requests

from app.scoring.risk_engine import build_security_alert
from app.database.db import save_alert


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

    # ========================================================
    # STRICT TRANSPORT SECURITY
    # ========================================================

    hsts = response.headers.get(
        "Strict-Transport-Security"
    )

    # HSTS est uniquement pertinent pour HTTPS.
    if (
        response.url.lower().startswith("https://")
        and not hsts
    ):

        detections.append(
            {
                "event_type": "HSTS_MISSING",
                "url": response.url,
                "status_code": response.status_code,
                "message": (
                    "Le header Strict-Transport-Security "
                    "est absent."
                )
            }
        )

    # ========================================================
    # X-CONTENT-TYPE-OPTIONS
    # ========================================================

    content_type_options = response.headers.get(
        "X-Content-Type-Options"
    )

    if not content_type_options:

        detections.append(
            {
                "event_type": (
                    "X_CONTENT_TYPE_OPTIONS_MISSING"
                ),
                "url": response.url,
                "status_code": response.status_code,
                "message": (
                    "Le header X-Content-Type-Options "
                    "est absent."
                )
            }
        )

    # ========================================================
    # X-FRAME-OPTIONS
    # ========================================================

    frame_options = response.headers.get(
        "X-Frame-Options"
    )

    if not frame_options:

        detections.append(
            {
                "event_type": "X_FRAME_OPTIONS_MISSING",
                "url": response.url,
                "status_code": response.status_code,
                "message": (
                    "Le header X-Frame-Options "
                    "est absent."
                )
            }
        )

    # ========================================================
    # REFERRER POLICY
    # ========================================================

    referrer_policy = response.headers.get(
        "Referrer-Policy"
    )

    if not referrer_policy:

        detections.append(
            {
                "event_type": "REFERRER_POLICY_MISSING",
                "url": response.url,
                "status_code": response.status_code,
                "message": (
                    "Le header Referrer-Policy "
                    "est absent."
                )
            }
        )

    # IMPORTANT :
    # le return doit rester tout en bas,
    # après tous les contrôles.
    return detections


def process_web_detections(
    detections: list[dict]
) -> list[dict]:
    """
    Transforme les détections Web en alertes
    puis les enregistre dans SQLite.

    Paramètres
    ----------
    detections : list[dict]
        Liste des problèmes détectés pendant l'audit Web.

    Retour
    ------
    list[dict]
        Liste des alertes générées.
    """

    alerts = []

    for detection in detections:

        # Transformation de la détection
        # en alerte avec score et niveau de risque.
        alert = build_security_alert(
            detection
        )

        # Stockage dans SQLite.
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
    Lance le pipeline complet d'audit Web.

    Étapes :
    - analyse de l'URL ;
    - détection des problèmes ;
    - génération des alertes ;
    - calcul du score de risque ;
    - stockage SQLite.

    Paramètres
    ----------
    url : str
        URL à analyser.

    Retour
    ------
    list[dict]
        Liste des alertes générées.
    """

    detections = analyze_web_security(
        url
    )

    alerts = process_web_detections(
        detections
    )

    return alerts


if __name__ == "__main__":

    # URL utilisée pour le test manuel.
    url = "https://example.com"

    print(
        f"\n--- Audit Web : {url} ---"
    )

    detections = analyze_web_security(
        url
    )

    if not detections:

        print(
            "Aucun problème de sécurité détecté."
        )

    else:

        print(
            f"{len(detections)} problème(s) détecté(s).\n"
        )

        for detection in detections:

            print(
                f"Type : "
                f"{detection.get('event_type')}"
            )

            print(
                f"URL : "
                f"{detection.get('url')}"
            )

            print(
                f"Code HTTP : "
                f"{detection.get('status_code')}"
            )

            print(
                f"Message : "
                f"{detection.get('message')}"
            )

            print("-" * 50)