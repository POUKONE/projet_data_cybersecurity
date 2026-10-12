"""
Analyse de sécurité Web.

Ce module permet notamment de vérifier :
- l'utilisation de HTTPS ;
- la présence de Content-Security-Policy ;
- la présence de HSTS ;
- la présence de X-Content-Type-Options ;
- la présence de X-Frame-Options ;
- la présence de Referrer-Policy.

Les détections sont ensuite transformées
en alertes normalisées et enregistrées dans SQLite.
"""

import requests

from app.database.db import save_alert
from app.scoring.risk_engine import build_security_alert


# ============================================================
# ANALYSE WEB
# ============================================================

def analyze_web_security(
    url: str,
    timeout: int = 10
) -> list[dict]:
    """
    Analyse les principaux éléments de sécurité HTTP.

    Paramètres
    ----------
    url : str
        URL du site à analyser.

    timeout : int
        Temps maximum d'attente de la requête HTTP.

    Retour
    ------
    list[dict]
        Liste des détections de sécurité.
    """

    detections = []


    # ========================================================
    # VÉRIFICATION DE L'URL
    # ========================================================

    if not url:
        return detections


    url = url.strip()


    # ========================================================
    # HTTPS
    # ========================================================

    if not url.lower().startswith(
        "https://"
    ):

        detections.append(
            {
                "event_type": (
                    "HTTPS_MISSING"
                ),

                "source_type": "WEB",

                "target": url,

                "url": url,

                "message": (
                    "Le site analysé "
                    "n'utilise pas HTTPS."
                ),

                "description": (
                    "La communication avec le site "
                    "n'est pas protégée par HTTPS."
                ),

                "status": "OPEN",
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
                "event_type": (
                    "WEB_REQUEST_ERROR"
                ),

                "source_type": "WEB",

                "target": url,

                "url": url,

                "message": (
                    "Impossible d'accéder "
                    "au site analysé."
                ),

                "description": str(
                    error
                ),

                "status": "OPEN",
            }
        ]


    # ========================================================
    # URL FINALE
    # ========================================================

    final_url = str(
        response.url
    )


    # ========================================================
    # HEADERS
    # ========================================================

    headers = response.headers


    # ========================================================
    # CONTENT SECURITY POLICY
    # ========================================================

    if (
        "Content-Security-Policy"
        not in headers
    ):

        detections.append(
            {
                "event_type": (
                    "CSP_MISSING"
                ),

                "source_type": "WEB",

                "target": final_url,

                "url": final_url,

                "status_code": (
                    response.status_code
                ),

                "message": (
                    "L'en-tête "
                    "Content-Security-Policy "
                    "est absent."
                ),

                "description": (
                    "Aucune politique CSP "
                    "n'a été détectée dans "
                    "les en-têtes HTTP."
                ),

                "status": "OPEN",
            }
        )


    # ========================================================
    # HSTS
    # ========================================================

    if (
        final_url.lower().startswith(
            "https://"
        )
        and
        "Strict-Transport-Security"
        not in headers
    ):

        detections.append(
            {
                "event_type": (
                    "HSTS_MISSING"
                ),

                "source_type": "WEB",

                "target": final_url,

                "url": final_url,

                "status_code": (
                    response.status_code
                ),

                "message": (
                    "L'en-tête "
                    "Strict-Transport-Security "
                    "est absent."
                ),

                "description": (
                    "Le site utilise HTTPS "
                    "mais ne fournit pas "
                    "de politique HSTS."
                ),

                "status": "OPEN",
            }
        )


    # ========================================================
    # X-CONTENT-TYPE-OPTIONS
    # ========================================================

    if (
        "X-Content-Type-Options"
        not in headers
    ):

        detections.append(
            {
                "event_type": (
                    "X_CONTENT_TYPE_OPTIONS_MISSING"
                ),

                "source_type": "WEB",

                "target": final_url,

                "url": final_url,

                "status_code": (
                    response.status_code
                ),

                "message": (
                    "L'en-tête "
                    "X-Content-Type-Options "
                    "est absent."
                ),

                "description": (
                    "Le navigateur peut tenter "
                    "d'interpréter automatiquement "
                    "le type de certains contenus."
                ),

                "status": "OPEN",
            }
        )


    # ========================================================
    # X-FRAME-OPTIONS
    # ========================================================

    if (
        "X-Frame-Options"
        not in headers
    ):

        detections.append(
            {
                "event_type": (
                    "X_FRAME_OPTIONS_MISSING"
                ),

                "source_type": "WEB",

                "target": final_url,

                "url": final_url,

                "status_code": (
                    response.status_code
                ),

                "message": (
                    "L'en-tête "
                    "X-Frame-Options "
                    "est absent."
                ),

                "description": (
                    "Le site ne fournit pas "
                    "de protection explicite "
                    "contre son affichage "
                    "dans certaines frames."
                ),

                "status": "OPEN",
            }
        )


    # ========================================================
    # REFERRER POLICY
    # ========================================================

    if (
        "Referrer-Policy"
        not in headers
    ):

        detections.append(
            {
                "event_type": (
                    "REFERRER_POLICY_MISSING"
                ),

                "source_type": "WEB",

                "target": final_url,

                "url": final_url,

                "status_code": (
                    response.status_code
                ),

                "message": (
                    "L'en-tête "
                    "Referrer-Policy "
                    "est absent."
                ),

                "description": (
                    "Aucune politique explicite "
                    "de gestion du référent HTTP "
                    "n'a été détectée."
                ),

                "status": "OPEN",
            }
        )


    return detections


# ============================================================
# TRANSFORMATION DES DÉTECTIONS
# ============================================================

def process_web_detections(
    detections: list[dict]
) -> list[dict]:
    """
    Transforme les détections Web
    en alertes normalisées puis les
    enregistre dans SQLite.
    """

    alerts = []


    for detection in detections:

        # WEB_REQUEST_ERROR n'est pas encore
        # une règle de scoring du Risk Engine.
        if (
            detection.get("event_type")
            == "WEB_REQUEST_ERROR"
        ):

            continue


        alert = build_security_alert(
            detection
        )

        alert_id = save_alert(
            alert
        )

        alert["id"] = alert_id

        alerts.append(
            alert
        )


    return alerts


# ============================================================
# PIPELINE WEB COMPLET
# ============================================================

def run_web_analysis(
    url: str,
    timeout: int = 10
) -> list[dict]:
    """
    Lance le pipeline complet d'analyse Web.

    Étapes :
    1. audit HTTP ;
    2. détection des problèmes ;
    3. scoring ;
    4. création des alertes ;
    5. sauvegarde SQLite.
    """

    detections = analyze_web_security(
        url=url,
        timeout=timeout
    )

    alerts = process_web_detections(
        detections
    )

    return alerts


# ============================================================
# TEST MANUEL
# ============================================================

if __name__ == "__main__":

    test_url = (
        "https://example.com"
    )

    results = run_web_analysis(
        test_url
    )

    for result in results:
        print(result)