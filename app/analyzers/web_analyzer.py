"""
Orchestrateur principal de l'audit Web.

Responsabilités :
- validation de l'URL ;
- définition du périmètre autorisé ;
- collecte HTTP contrôlée ;
- contrôle des redirections ;
- exécution des contrôles passifs ;
- agrégation des résultats ;
- calcul de la couverture ;
- transformation des findings en alertes ;
- persistance des alertes.

Cette version exécute uniquement des contrôles passifs.
Les vérifications actives seront ajoutées séparément.
"""

from app.scoring.rules import (
    get_rule,
)


from app.analyzers.web_checks.cookies import (
    check_cookie_security,
)
from app.analyzers.web_checks.cors import (
    check_cors,
)
from app.analyzers.web_checks.disclosure import (
    check_information_disclosure,
)
from app.analyzers.web_checks.forms import (
    check_forms_security,
)
from app.analyzers.web_checks.headers import (
    check_security_headers,
)
from app.analyzers.web_checks.tls import (
    check_tls_usage,
)
from app.collectors.web_collector import (
    WebCollectionError,
    request_with_scope,
    validate_url,
)
from app.database.db import (
    save_alert,
)
from app.scoring.risk_engine import (
    build_security_alert,
)
from app.security.web_scope import (
    build_allowed_domains,
)


# ============================================================
# RAPPORT
# ============================================================


def create_empty_report(
    url: str,
) -> dict:
    """
    Crée la structure standard d'un rapport d'audit Web.
    """

    return {
        "audit_status": "PENDING",
        "mode": "PASSIVE",
        "requested_url": url,
        "final_url": None,
        "http_status": None,
        "request_count": 0,
        "redirects": [],
        "pages": [],
        "forms": [],
        "checks": [],
        "findings": [],

        # Compatibilité temporaire avec les anciennes
        # parties du projet utilisant encore "detections".
        "detections": [],

        "alerts": [],
        "errors": [],

        "limitations": [
            (
                "Une seule page est analysée dans cette "
                "version de l'audit."
            ),
            (
                "Le JavaScript côté client n'est pas exécuté."
            ),
            (
                "Les zones nécessitant une authentification "
                "ne sont pas analysées automatiquement."
            ),
            (
                "Les contrôles d'accès ne sont pas "
                "automatiquement validés."
            ),
            (
                "La présence d'une protection CSRF n'est pas "
                "encore analysée automatiquement."
            ),
            (
                "Les XSS stockées ne sont pas recherchées."
            ),
            (
                "Les vulnérabilités de logique métier "
                "nécessitent une validation manuelle."
            ),
            (
                "Aucun contrôle actif SQLi, XSS réfléchie "
                "ou redirection ouverte n'est exécuté."
            ),
        ],

        "coverage": {
            "executed": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "indeterminate": 0,
        },

        "metadata": {
            "active_checks_enabled": False,
            "allowed_domains": [],
        },

        "finding_count": 0,
        "alert_count": 0,
    }


# ============================================================
# COUVERTURE
# ============================================================


def update_coverage(
    report: dict,
) -> None:
    """
    Recalcule les statistiques de couverture.
    """

    checks = report.get(
        "checks",
        [],
    )

    report["coverage"] = {
        "executed": sum(
            1
            for check in checks
            if check.get("status")
            in {
                "PASSED",
                "FAILED",
            }
        ),

        "passed": sum(
            1
            for check in checks
            if check.get("status")
            == "PASSED"
        ),

        "failed": sum(
            1
            for check in checks
            if check.get("status")
            == "FAILED"
        ),

        "skipped": sum(
            1
            for check in checks
            if check.get("status")
            == "SKIPPED"
        ),

        "indeterminate": sum(
            1
            for check in checks
            if check.get("status")
            == "INDETERMINATE"
        ),
    }


# ============================================================
# ERREURS DE COLLECTE
# ============================================================


def get_collection_error_type(
    message: str,
) -> str:
    """
    Transforme une erreur du collecteur en type exploitable.
    """

    upper_message = (
        message.upper()
    )

    known_errors = [
        "TLS_ERROR",
        "CONNECTION_TIMEOUT",
        "READ_TIMEOUT",
        "CONNECTION_ERROR",
        "REQUEST_ERROR",
    ]

    for error_type in known_errors:

        if error_type in upper_message:

            return error_type

    if (
        "REDIRECTION"
        in upper_message
        and (
            "PÉRIMÈTRE"
            in upper_message
            or "PERIMETRE"
            in upper_message
        )
    ):
        return "OUT_OF_SCOPE_REDIRECT"

    if (
        "HORS PÉRIMÈTRE"
        in upper_message
        or "HORS PERIMETRE"
        in upper_message
    ):
        return "OUT_OF_SCOPE"

    if (
        "REDIRECTIONS"
        in upper_message
        and "MAXIMAL"
        in upper_message
    ):
        return "TOO_MANY_REDIRECTS"

    return "COLLECTION_ERROR"


# ============================================================
# AGRÉGATION
# ============================================================


def merge_check_result(
    report: dict,
    result: dict,
) -> None:
    """
    Fusionne le résultat d'un module de contrôle
    dans le rapport principal.
    """

    if not isinstance(
        result,
        dict,
    ):
        return

    checks = result.get(
        "checks",
        [],
    )

    findings = result.get(
        "findings",
        [],
    )

    if checks:

        report[
            "checks"
        ].extend(
            checks
        )

    if findings:

        report[
            "findings"
        ].extend(
            findings
        )


# ============================================================
# ANALYSE PASSIVE
# ============================================================


def analyze_web_security(
    url: str,
    timeout: int = 10,
    allowed_domains: list[str] | None = None,
) -> dict:
    """
    Exécute l'audit passif d'une page Web.

    Aucun payload d'injection n'est envoyé.
    """

    report = create_empty_report(
        url
    )


    # ========================================================
    # VALIDATION DE L'URL
    # ========================================================

    valid, validation_error = (
        validate_url(
            url
        )
    )

    if not valid:

        report[
            "audit_status"
        ] = "FAILED"

        report[
            "errors"
        ].append(
            {
                "type": "INVALID_URL",
                "message": (
                    validation_error
                    or "URL invalide."
                ),
            }
        )

        report[
            "checks"
        ].append(
            {
                "check_id": "URL_VALIDATION",
                "name": "Validation de l'URL",
                "status": "FAILED",
                "message": (
                    validation_error
                    or "URL invalide."
                ),
            }
        )

        update_coverage(
            report
        )

        return report


    url = url.strip()


    report[
        "checks"
    ].append(
        {
            "check_id": "URL_VALIDATION",
            "name": "Validation de l'URL",
            "status": "PASSED",
            "message": "URL valide.",
        }
    )


    # ========================================================
    # PÉRIMÈTRE AUTORISÉ
    # ========================================================

    scope = (
        build_allowed_domains(
            start_url=url,
            extra_domains=allowed_domains,
        )
    )

    report[
        "metadata"
    ][
        "allowed_domains"
    ] = sorted(
        scope
    )


    if not scope:

        report[
            "audit_status"
        ] = "FAILED"

        report[
            "errors"
        ].append(
            {
                "type": "INVALID_SCOPE",
                "message": (
                    "Aucun domaine autorisé "
                    "n'a pu être déterminé."
                ),
            }
        )

        report[
            "checks"
        ].append(
            {
                "check_id": "WEB_SCOPE",
                "name": "Périmètre de l'audit",
                "status": "FAILED",
                "message": (
                    "Le périmètre autorisé "
                    "est vide."
                ),
            }
        )

        update_coverage(
            report
        )

        return report


    report[
        "checks"
    ].append(
        {
            "check_id": "WEB_SCOPE",
            "name": "Périmètre de l'audit",
            "status": "PASSED",
            "message": (
                "Le périmètre de l'audit "
                "a été défini."
            ),
        }
    )


    # ========================================================
    # COLLECTE HTTP
    # ========================================================

    try:

        collection = (
            request_with_scope(
                url=url,
                allowed_domains=scope,
                timeout=timeout,
            )
        )

    except WebCollectionError as error:

        error_message = str(
            error
        )

        error_type = (
            get_collection_error_type(
                error_message
            )
        )

        report[
            "audit_status"
        ] = "FAILED"

        report[
            "errors"
        ].append(
            {
                "type": error_type,
                "message": error_message,
            }
        )

        report[
            "checks"
        ].append(
            {
                "check_id": "HTTP_COLLECTION",
                "name": "Collecte HTTP",
                "status": "INDETERMINATE",
                "message": (
                    "La collecte HTTP n'a "
                    "pas pu être terminée."
                ),
            }
        )

        update_coverage(
            report
        )

        return report


    response = collection[
        "response"
    ]

    final_url = collection[
        "final_url"
    ]


    report[
        "final_url"
    ] = final_url

    report[
        "http_status"
    ] = response.status_code

    report[
        "request_count"
    ] = collection.get(
        "request_count",
        0,
    )

    report[
        "redirects"
    ] = collection.get(
        "redirects",
        [],
    )


    report[
        "checks"
    ].append(
        {
            "check_id": "HTTP_COLLECTION",
            "name": "Collecte HTTP",
            "status": "PASSED",
            "message": (
                "La réponse HTTP "
                "a été collectée."
            ),
        }
    )


    # ========================================================
    # INVENTAIRE DE LA PAGE
    # ========================================================

    content_type = (
        response.headers.get(
            "Content-Type",
            "",
        )
    )


    report[
        "pages"
    ].append(
        {
            "url": final_url,
            "status_code": (
                response.status_code
            ),
            "content_type": (
                content_type
            ),
        }
    )


    # ========================================================
    # TLS / HTTPS
    # ========================================================

    tls_result = (
        check_tls_usage(
            requested_url=url,
            final_url=final_url,
            response=response,
        )
    )

    merge_check_result(
        report,
        tls_result,
    )


    # ========================================================
    # HEADERS HTTP
    # ========================================================

    headers_result = (
        check_security_headers(
            response=response,
            target_url=final_url,
        )
    )

    merge_check_result(
        report,
        headers_result,
    )


    # ========================================================
    # COOKIES
    # ========================================================

    cookies_result = (
        check_cookie_security(
            response=response,
            target_url=final_url,
        )
    )

    merge_check_result(
        report,
        cookies_result,
    )


    # ========================================================
    # CORS
    # ========================================================

    cors_result = (
        check_cors(
            response=response,
            target_url=final_url,
        )
    )

    merge_check_result(
        report,
        cors_result,
    )


    # ========================================================
    # DIVULGATION D'INFORMATIONS
    # ========================================================

    disclosure_result = (
        check_information_disclosure(
            response=response,
            target_url=final_url,
        )
    )

    merge_check_result(
        report,
        disclosure_result,
    )


    # ========================================================
    # FORMULAIRES
    # ========================================================

    content_type_lower = (
        content_type.lower()
    )


    if (
        "text/html"
        in content_type_lower
        or not content_type
    ):

        forms_result = (
            check_forms_security(
                html=response.text,
                page_url=final_url,
            )
        )

        merge_check_result(
            report,
            forms_result,
        )

        report[
            "forms"
        ] = forms_result.get(
            "forms",
            [],
        )

    else:

        report[
            "checks"
        ].append(
            {
                "check_id": "FORMS_PRESENT",
                "name": "Analyse des formulaires",
                "status": "SKIPPED",
                "message": (
                    "Le contenu reçu "
                    "n'est pas HTML."
                ),
            }
        )


    # ========================================================
    # COMPATIBILITÉ TEMPORAIRE
    # ========================================================

    report[
        "detections"
    ] = list(
        report[
            "findings"
        ]
    )


    # ========================================================
    # STATISTIQUES
    # ========================================================

    report[
        "finding_count"
    ] = len(
        report[
            "findings"
        ]
    )


    update_coverage(
        report
    )


    if report[
        "errors"
    ]:

        report[
            "audit_status"
        ] = "PARTIAL"

    else:

        report[
            "audit_status"
        ] = "COMPLETED"


    return report


# ============================================================
# PERSISTANCE DES FINDINGS
# ============================================================


def process_web_detections(
    detections: list[dict],
) -> list[dict]:
    """
    Transforme les findings compatibles avec
    le moteur de scoring en alertes persistantes.

    Un finding sans règle de scoring ne doit jamais
    faire échouer l'intégralité de l'audit.
    """

    alerts = []


    for detection in detections:

        event_type = detection.get(
            "event_type"
        )
        if get_rule(
            event_type
        ) is None:
            continue

        try:
            alert = build_security_alert(
                detection
            )
        except ValueError:
            continue


        alert_id = (
            save_alert(
                alert
            )
        )

        alert[
            "id"
        ] = alert_id


        # ----------------------------------------------------
        # Métadonnées propres au rapport Web
        # ----------------------------------------------------

        alert[
            "classification"
        ] = detection.get(
            "classification"
        )

        alert[
            "severity"
        ] = detection.get(
            "severity"
        )

        alert[
            "confidence"
        ] = detection.get(
            "confidence"
        )

        alert[
            "parameter"
        ] = detection.get(
            "parameter"
        )

        alert[
            "evidence"
        ] = detection.get(
            "evidence"
        )

        alert[
            "recommendation"
        ] = detection.get(
            "recommendation"
        )

        alert[
            "validation_method"
        ] = detection.get(
            "validation_method"
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
    timeout: int = 10,
    allowed_domains: list[str] | None = None,
) -> dict:
    """
    Lance l'audit Web passif complet.

    Le résultat contient :
    - état de l'audit ;
    - couverture ;
    - pages ;
    - formulaires ;
    - findings ;
    - alertes ;
    - erreurs ;
    - limitations.
    """

    report = (
        analyze_web_security(
            url=url,
            timeout=timeout,
            allowed_domains=allowed_domains,
        )
    )


    findings = report.get(
        "findings",
        [],
    )


    alerts = (
        process_web_detections(
            findings
        )
    )


    report[
        "alerts"
    ] = alerts

    report[
        "finding_count"
    ] = len(
        findings
    )

    report[
        "alert_count"
    ] = len(
        alerts
    )


    return report