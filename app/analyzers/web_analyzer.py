"""
Analyse de sécurité Web.

Étape 2 de la refonte :
- collecte fiable ;
- distinction entre résultats et erreurs ;
- suivi des contrôles exécutés ;
- statut global de l'audit ;
- aucune erreur réseau ne doit être interprétée
  comme une absence de vulnérabilité.

Cette version réalise uniquement un audit passif.
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

from app.database.db import save_alert
from app.scoring.risk_engine import build_security_alert


# ============================================================
# UTILITAIRES
# ============================================================

def validate_web_url(url: str) -> tuple[bool, str | None]:
    """
    Valide une URL HTTP ou HTTPS.

    Retour
    ------
    tuple[bool, str | None]
        (valide, message_erreur)
    """

    if not url:
        return False, "L'URL est vide."

    url = url.strip()

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "L'URL n'est pas valide."

    if parsed.scheme not in {
        "http",
        "https",
    }:
        return (
            False,
            "Seuls les protocoles HTTP et HTTPS sont autorisés."
        )

    if not parsed.hostname:
        return (
            False,
            "Aucun nom d'hôte valide n'a été détecté."
        )

    return True, None


def build_check_result(
    check_id: str,
    name: str,
    status: str,
    message: str,
) -> dict:
    """
    Construit le résultat standardisé d'un contrôle.

    status :
    - PASSED
    - FAILED
    - SKIPPED
    - INDETERMINATE
    """

    return {
        "check_id": check_id,
        "name": name,
        "status": status,
        "message": message,
    }


def build_web_detection(
    *,
    event_type: str,
    target: str,
    message: str,
    description: str,
    status_code: int | None = None,
    classification: str = "MISCONFIGURATION",
    confidence: str = "HIGH",
) -> dict:
    """
    Construit une détection Web standardisée.
    """

    return {
        "event_type": event_type,
        "source_type": "WEB",
        "target": target,
        "url": target,
        "status_code": status_code,
        "message": message,
        "description": description,
        "status": "OPEN",
        "classification": classification,
        "confidence": confidence,
    }


# ============================================================
# RAPPORT VIDE
# ============================================================

def create_empty_audit_report(
    url: str
) -> dict:
    """
    Initialise la structure du rapport Web.
    """

    return {
        "audit_status": "PENDING",

        "requested_url": url,

        "final_url": None,

        "http_status": None,

        "redirects": [],

        "request_count": 0,

        "checks": [],

        "detections": [],

        "alerts": [],

        "errors": [],

        "coverage": {
            "executed": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "indeterminate": 0,
        },
    }


# ============================================================
# CALCUL DE COUVERTURE
# ============================================================

def update_coverage(
    report: dict
) -> None:
    """
    Met à jour les statistiques des contrôles.
    """

    checks = report.get(
        "checks",
        []
    )

    report["coverage"] = {
        "executed": len(
            [
                check
                for check in checks
                if check["status"]
                in {
                    "PASSED",
                    "FAILED",
                }
            ]
        ),

        "passed": len(
            [
                check
                for check in checks
                if check["status"]
                == "PASSED"
            ]
        ),

        "failed": len(
            [
                check
                for check in checks
                if check["status"]
                == "FAILED"
            ]
        ),

        "skipped": len(
            [
                check
                for check in checks
                if check["status"]
                == "SKIPPED"
            ]
        ),

        "indeterminate": len(
            [
                check
                for check in checks
                if check["status"]
                == "INDETERMINATE"
            ]
        ),
    }


# ============================================================
# ANALYSE PASSIVE
# ============================================================

def analyze_web_security(
    url: str,
    timeout: int = 10
) -> dict:
    """
    Exécute l'audit Web passif actuel.

    Contrôles :
    - validité URL ;
    - HTTPS ;
    - CSP ;
    - HSTS ;
    - X-Content-Type-Options ;
    - X-Frame-Options ;
    - Referrer-Policy.

    Les erreurs réseau sont conservées dans
    le rapport et ne sont jamais converties
    en absence de vulnérabilité.
    """

    report = create_empty_audit_report(
        url
    )


    # ========================================================
    # VALIDATION URL
    # ========================================================

    valid, validation_error = (
        validate_web_url(
            url
        )
    )

    if not valid:

        report["audit_status"] = "FAILED"

        report["errors"].append(
            {
                "type": "INVALID_URL",
                "message": validation_error,
            }
        )

        report["checks"].append(
            build_check_result(
                check_id="URL_VALIDATION",
                name="Validation de l'URL",
                status="FAILED",
                message=validation_error,
            )
        )

        update_coverage(
            report
        )

        return report


    url = url.strip()


    report["checks"].append(
        build_check_result(
            check_id="URL_VALIDATION",
            name="Validation de l'URL",
            status="PASSED",
            message="URL valide."
        )
    )


    # ========================================================
    # HTTPS
    # ========================================================

    if url.lower().startswith(
        "https://"
    ):

        report["checks"].append(
            build_check_result(
                check_id="HTTPS",
                name="Utilisation de HTTPS",
                status="PASSED",
                message=(
                    "L'URL demandée utilise HTTPS."
                )
            )
        )

    else:

        report["checks"].append(
            build_check_result(
                check_id="HTTPS",
                name="Utilisation de HTTPS",
                status="FAILED",
                message=(
                    "L'URL demandée utilise HTTP."
                )
            )
        )

        report["detections"].append(
            build_web_detection(
                event_type="HTTPS_MISSING",
                target=url,
                message=(
                    "Le site analysé n'utilise pas HTTPS."
                ),
                description=(
                    "La connexion initiale est effectuée "
                    "via HTTP et n'est donc pas protégée "
                    "par TLS."
                ),
                classification="MISCONFIGURATION",
                confidence="HIGH",
            )
        )


    # ========================================================
    # REQUÊTE
    # ========================================================

    try:

        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
        )

        report["request_count"] += 1


    except requests.exceptions.SSLError as error:

        report["audit_status"] = "FAILED"

        report["errors"].append(
            {
                "type": "TLS_ERROR",
                "message": str(error),
            }
        )

        report["checks"].append(
            build_check_result(
                check_id="HTTP_REQUEST",
                name="Requête HTTP",
                status="INDETERMINATE",
                message=(
                    "La requête a échoué à cause "
                    "d'une erreur TLS."
                )
            )
        )

        update_coverage(
            report
        )

        return report


    except requests.exceptions.ConnectTimeout as error:

        report["audit_status"] = "FAILED"

        report["errors"].append(
            {
                "type": "CONNECTION_TIMEOUT",
                "message": str(error),
            }
        )

        report["checks"].append(
            build_check_result(
                check_id="HTTP_REQUEST",
                name="Requête HTTP",
                status="INDETERMINATE",
                message=(
                    "Délai de connexion dépassé."
                )
            )
        )

        update_coverage(
            report
        )

        return report


    except requests.exceptions.ReadTimeout as error:

        report["audit_status"] = "FAILED"

        report["errors"].append(
            {
                "type": "READ_TIMEOUT",
                "message": str(error),
            }
        )

        report["checks"].append(
            build_check_result(
                check_id="HTTP_REQUEST",
                name="Requête HTTP",
                status="INDETERMINATE",
                message=(
                    "Le serveur n'a pas répondu "
                    "dans le délai prévu."
                )
            )
        )

        update_coverage(
            report
        )

        return report


    except requests.exceptions.ConnectionError as error:

        report["audit_status"] = "FAILED"

        report["errors"].append(
            {
                "type": "CONNECTION_ERROR",
                "message": str(error),
            }
        )

        report["checks"].append(
            build_check_result(
                check_id="HTTP_REQUEST",
                name="Requête HTTP",
                status="INDETERMINATE",
                message=(
                    "Impossible d'établir "
                    "la connexion avec la cible."
                )
            )
        )

        update_coverage(
            report
        )

        return report


    except requests.RequestException as error:

        report["audit_status"] = "FAILED"

        report["errors"].append(
            {
                "type": "REQUEST_ERROR",
                "message": str(error),
            }
        )

        report["checks"].append(
            build_check_result(
                check_id="HTTP_REQUEST",
                name="Requête HTTP",
                status="INDETERMINATE",
                message=(
                    "Erreur HTTP pendant l'analyse."
                )
            )
        )

        update_coverage(
            report
        )

        return report


    # ========================================================
    # REQUÊTE RÉUSSIE
    # ========================================================

    report["checks"].append(
        build_check_result(
            check_id="HTTP_REQUEST",
            name="Requête HTTP",
            status="PASSED",
            message="La cible a répondu."
        )
    )


    report["final_url"] = str(
        response.url
    )

    report["http_status"] = (
        response.status_code
    )


    # ========================================================
    # REDIRECTIONS
    # ========================================================

    for history_response in response.history:

        report[
            "redirects"
        ].append(
            {
                "status_code": (
                    history_response.status_code
                ),

                "url": str(
                    history_response.url
                ),

                "location": (
                    history_response.headers.get(
                        "Location"
                    )
                ),
            }
        )


    final_url = report[
        "final_url"
    ]

    headers = response.headers


    # ========================================================
    # CSP
    # ========================================================

    if headers.get(
        "Content-Security-Policy"
    ):

        report["checks"].append(
            build_check_result(
                check_id="CSP",
                name="Content-Security-Policy",
                status="PASSED",
                message=(
                    "Une politique CSP est présente."
                )
            )
        )

    else:

        report["checks"].append(
            build_check_result(
                check_id="CSP",
                name="Content-Security-Policy",
                status="FAILED",
                message=(
                    "Aucune politique CSP détectée."
                )
            )
        )

        report["detections"].append(
            build_web_detection(
                event_type="CSP_MISSING",
                target=final_url,
                status_code=response.status_code,
                message=(
                    "L'en-tête Content-Security-Policy "
                    "est absent."
                ),
                description=(
                    "Le site ne définit pas explicitement "
                    "de politique Content-Security-Policy."
                ),
            )
        )


    # ========================================================
    # HSTS
    # ========================================================

    if final_url.lower().startswith(
        "https://"
    ):

        if headers.get(
            "Strict-Transport-Security"
        ):

            report["checks"].append(
                build_check_result(
                    check_id="HSTS",
                    name="Strict-Transport-Security",
                    status="PASSED",
                    message=(
                        "L'en-tête HSTS est présent."
                    )
                )
            )

        else:

            report["checks"].append(
                build_check_result(
                    check_id="HSTS",
                    name="Strict-Transport-Security",
                    status="FAILED",
                    message=(
                        "L'en-tête HSTS est absent."
                    )
                )
            )

            report["detections"].append(
                build_web_detection(
                    event_type="HSTS_MISSING",
                    target=final_url,
                    status_code=response.status_code,
                    message=(
                        "L'en-tête "
                        "Strict-Transport-Security "
                        "est absent."
                    ),
                    description=(
                        "Le site répond via HTTPS mais "
                        "n'impose pas HSTS."
                    ),
                )
            )

    else:

        report["checks"].append(
            build_check_result(
                check_id="HSTS",
                name="Strict-Transport-Security",
                status="SKIPPED",
                message=(
                    "Contrôle HSTS non pertinent "
                    "sur une réponse HTTP."
                )
            )
        )


    # ========================================================
    # X-CONTENT-TYPE-OPTIONS
    # ========================================================

    if headers.get(
        "X-Content-Type-Options"
    ):

        report["checks"].append(
            build_check_result(
                check_id="X_CONTENT_TYPE_OPTIONS",
                name="X-Content-Type-Options",
                status="PASSED",
                message=(
                    "L'en-tête est présent."
                )
            )
        )

    else:

        report["checks"].append(
            build_check_result(
                check_id="X_CONTENT_TYPE_OPTIONS",
                name="X-Content-Type-Options",
                status="FAILED",
                message=(
                    "L'en-tête est absent."
                )
            )
        )

        report["detections"].append(
            build_web_detection(
                event_type=(
                    "X_CONTENT_TYPE_OPTIONS_MISSING"
                ),
                target=final_url,
                status_code=response.status_code,
                message=(
                    "L'en-tête X-Content-Type-Options "
                    "est absent."
                ),
                description=(
                    "Le serveur ne fournit pas "
                    "X-Content-Type-Options."
                ),
            )
        )


    # ========================================================
    # PROTECTION CONTRE LE FRAMING
    # ========================================================

    csp = headers.get(
        "Content-Security-Policy",
        ""
    )

    has_frame_ancestors = (
        "frame-ancestors"
        in csp.lower()
    )

    has_x_frame_options = bool(
        headers.get(
            "X-Frame-Options"
        )
    )


    if (
        has_frame_ancestors
        or has_x_frame_options
    ):

        report["checks"].append(
            build_check_result(
                check_id="FRAME_PROTECTION",
                name="Protection contre le framing",
                status="PASSED",
                message=(
                    "Une protection contre "
                    "le framing est présente."
                )
            )
        )

    else:

        report["checks"].append(
            build_check_result(
                check_id="FRAME_PROTECTION",
                name="Protection contre le framing",
                status="FAILED",
                message=(
                    "Aucune protection explicite "
                    "contre le framing n'a été détectée."
                )
            )
        )

        report["detections"].append(
            build_web_detection(
                event_type=(
                    "X_FRAME_OPTIONS_MISSING"
                ),
                target=final_url,
                status_code=response.status_code,
                message=(
                    "Aucune protection explicite "
                    "contre le framing n'a été détectée."
                ),
                description=(
                    "Ni X-Frame-Options ni une directive "
                    "CSP frame-ancestors n'a été détectée."
                ),
            )
        )


    # ========================================================
    # REFERRER POLICY
    # ========================================================

    if headers.get(
        "Referrer-Policy"
    ):

        report["checks"].append(
            build_check_result(
                check_id="REFERRER_POLICY",
                name="Referrer-Policy",
                status="PASSED",
                message=(
                    "Une politique Referrer-Policy "
                    "est présente."
                )
            )
        )

    else:

        report["checks"].append(
            build_check_result(
                check_id="REFERRER_POLICY",
                name="Referrer-Policy",
                status="FAILED",
                message=(
                    "Referrer-Policy est absent."
                )
            )
        )

        report["detections"].append(
            build_web_detection(
                event_type=(
                    "REFERRER_POLICY_MISSING"
                ),
                target=final_url,
                status_code=response.status_code,
                message=(
                    "L'en-tête Referrer-Policy "
                    "est absent."
                ),
                description=(
                    "Le serveur ne fournit pas "
                    "de politique Referrer-Policy."
                ),
            )
        )


    # ========================================================
    # FIN DE L'ANALYSE
    # ========================================================

    update_coverage(
        report
    )


    if report["errors"]:

        report["audit_status"] = (
            "PARTIAL"
        )

    else:

        report["audit_status"] = (
            "COMPLETED"
        )


    return report


# ============================================================
# TRANSFORMATION EN ALERTES
# ============================================================

def process_web_detections(
    detections: list[dict]
) -> list[dict]:
    """
    Transforme uniquement les détections
    de sécurité en alertes persistantes.
    """

    alerts = []


    for detection in detections:

        alert = build_security_alert(
            detection
        )

        alert_id = save_alert(
            alert
        )

        alert["id"] = (
            alert_id
        )

        alerts.append(
            alert
        )


    return alerts


# ============================================================
# PIPELINE COMPLET
# ============================================================

def run_web_analysis(
    url: str,
    timeout: int = 10
) -> dict:
    """
    Lance l'audit Web puis transforme
    ses détections en alertes.
    """

    report = analyze_web_security(
        url=url,
        timeout=timeout
    )


    detections = report.get(
        "detections",
        []
    )


    alerts = process_web_detections(
        detections
    )


    report["alerts"] = alerts

    report["alert_count"] = len(
        alerts
    )

    report["finding_count"] = len(
        detections
    )


    return report