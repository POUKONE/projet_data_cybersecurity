"""
Orchestrateur principal de l'audit Web passif.

Responsabilités :
- validation de l'URL ;
- définition du périmètre autorisé ;
- crawl passif multi-pages ;
- analyse TLS ;
- analyse des headers ;
- analyse des cookies ;
- analyse CORS ;
- recherche de divulgation d'informations ;
- analyse des formulaires ;
- agrégation des résultats ;
- génération d'alertes ;
- persistance des alertes.

Aucun test actif n'est exécuté ici.
"""

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
    crawl_site,
    validate_url,
)
from app.database.db import (
    save_alert,
)
from app.scoring.risk_engine import (
    build_security_alert,
)
from app.scoring.rules import (
    get_rule,
)
from app.security.web_scope import (
    build_allowed_domains,
)


# ============================================================
# RAPPORT VIDE
# ============================================================


def create_empty_report(
    url: str,
) -> dict:
    """
    Crée la structure standard du rapport Web.
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
        "finding_summary": [],

        # Compatibilité avec les anciennes parties
        # du projet.
        "detections": [],

        "alerts": [],
        "errors": [],

        "skipped_urls": [],

        "crawl": {
            "enabled": True,
            "visited_count": 0,
            "discovered_count": 0,
            "duration_seconds": 0,
            "max_depth": 0,
            "max_pages": 0,
        },

        "limitations": [
            (
                "Le JavaScript n'est pas exécuté."
            ),
            (
                "Les pages nécessitant une authentification "
                "ne sont pas automatiquement explorées."
            ),
            (
                "Les contrôles d'accès nécessitent "
                "une validation manuelle ou un contexte authentifié."
            ),
            (
                "Les protections CSRF ne sont pas encore "
                "analysées automatiquement."
            ),
            (
                "Les vulnérabilités XSS stockées ne sont "
                "pas testées."
            ),
            (
                "La logique métier nécessite "
                "une validation manuelle."
            ),
            (
                "Aucun test actif SQLi, XSS réfléchi "
                "ou open redirect n'est exécuté."
            ),
        ],

        "coverage": {
            "total": 0,
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

        "site_risk": {
            "score": 0,
            "level": "LOW",
            "contributors": [],
        },
    }


# ============================================================
# COUVERTURE
# ============================================================


def update_coverage(
    report: dict,
) -> None:
    """
    Recalcule les statistiques de couverture
    à partir des contrôles exécutés.
    """

    coverage = {
        "total": 0,
        "executed": 0,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "indeterminate": 0,
    }


    for check in report.get(
        "checks",
        [],
    ):

        coverage["total"] += 1

        status = str(
            check.get(
                "status",
                "",
            )
        ).upper()


        if status == "PASSED":

            coverage["executed"] += 1
            coverage["passed"] += 1


        elif status == "FAILED":

            coverage["executed"] += 1
            coverage["failed"] += 1


        elif status == "SKIPPED":

            coverage["skipped"] += 1


        elif status == "INDETERMINATE":

            coverage["indeterminate"] += 1


        else:

            coverage["indeterminate"] += 1


    report["coverage"] = coverage


# ============================================================
# ERREURS DE COLLECTE
# ============================================================


def get_collection_error_type(
    error_message: str,
) -> str:
    """
    Détermine le type d'erreur de collecte.
    """

    message = (
        str(
            error_message
        ).upper()
    )


    if "TLS_ERROR" in message:

        return "TLS_ERROR"


    if "READ_TIMEOUT" in message:

        return "READ_TIMEOUT"


    if "CONNECTION_TIMEOUT" in message:

        return "CONNECTION_TIMEOUT"


    if "CONNECTION_ERROR" in message:

        return "CONNECTION_ERROR"


    if "INVALID_URL" in message:

        return "INVALID_URL"


    if "HORS PÉRIMÈTRE" in message:

        return "OUT_OF_SCOPE"


    return "WEB_REQUEST_ERROR"


# ============================================================
# AJOUT D'UN RESULTAT DE CHECK
# ============================================================


def merge_check_result(
    report: dict,
    result: dict,
    page_url: str | None = None,
) -> None:
    """
    Fusionne checks et findings dans le rapport.

    page_url permet de conserver la page d'origine.
    """

    for check in result.get(
        "checks",
        [],
    ):

        check_copy = dict(
            check
        )

        if page_url:

            check_copy.setdefault(
                "url",
                page_url,
            )

        report["checks"].append(
            check_copy
        )


    for finding in result.get(
        "findings",
        [],
    ):

        finding_copy = dict(
            finding
        )

        if page_url:

            finding_copy.setdefault(
                "url",
                page_url,
            )

            finding_copy.setdefault(
                "target",
                page_url,
            )

        report["findings"].append(
            finding_copy
        )


# ============================================================
# ANALYSE D'UNE PAGE
# ============================================================


def analyze_page(
    report: dict,
    response,
    requested_url: str,
    final_url: str,
) -> None:
    """
    Exécute tous les contrôles passifs
    applicables à une page.
    """

    # --------------------------------------------------------
    # TLS / HTTPS
    # --------------------------------------------------------

    merge_check_result(
        report,
        check_tls_usage(
            requested_url=requested_url,
            final_url=final_url,
            response=response,
        ),
        page_url=final_url,
    )


    # --------------------------------------------------------
    # HEADERS
    # --------------------------------------------------------

    merge_check_result(
        report,
        check_security_headers(
            response=response,
            target_url=final_url,
        ),
        page_url=final_url,
    )


    # --------------------------------------------------------
    # COOKIES
    # --------------------------------------------------------

    merge_check_result(
        report,
        check_cookie_security(
            response=response,
            target_url=final_url,
        ),
        page_url=final_url,
    )


    # --------------------------------------------------------
    # CORS
    # --------------------------------------------------------

    merge_check_result(
        report,
        check_cors(
            response=response,
            target_url=final_url,
        ),
        page_url=final_url,
    )


    # --------------------------------------------------------
    # DIVULGATION D'INFORMATIONS
    # --------------------------------------------------------

    merge_check_result(
        report,
        check_information_disclosure(
            response=response,
            target_url=final_url,
        ),
        page_url=final_url,
    )


    # --------------------------------------------------------
    # FORMULAIRES
    # --------------------------------------------------------

    content_type = (
        response.headers.get(
            "Content-Type",
            "",
        )
    )


    if (
        not content_type
        or "text/html"
        in content_type.lower()
    ):

        forms_result = (
            check_forms_security(
                html=response.text,
                page_url=final_url,
            )
        )


        forms = forms_result.get(
            "forms",
            [],
        )


        for form in forms:

            form_copy = dict(
                form
            )

            form_copy.setdefault(
                "page_url",
                final_url,
            )

            report["forms"].append(
                form_copy
            )


        merge_check_result(
            report,
            forms_result,
            page_url=final_url,
        )


    else:

        report["checks"].append(
            {
                "check_id": (
                    "FORM_ANALYSIS"
                ),

                "name": (
                    "Analyse des formulaires"
                ),

                "status": "SKIPPED",

                "message": (
                    "La réponse n'est pas "
                    "de type HTML."
                ),

                "url": final_url,
            }
        )


def aggregate_web_findings(
    findings: list[dict],
    total_pages: int = 0,
) -> list[dict]:
    """
    Agrège les findings Web par type d'événement.

    Le détail page par page reste conservé dans
    report["findings"].

    Cette fonction produit uniquement une synthèse.
    """

    grouped = {}


    for finding in findings:

        event_type = (
            finding.get(
                "event_type"
            )
            or "UNKNOWN"
        )


        if event_type not in grouped:

            grouped[event_type] = {
                "event_type": event_type,

                "classification": (
                    finding.get(
                        "classification"
                    )
                ),

                "severity": (
                    finding.get(
                        "severity"
                    )
                ),

                "confidence": (
                    finding.get(
                        "confidence"
                    )
                ),

                "message": (
                    finding.get(
                        "message"
                    )
                ),

                "recommendation": (
                    finding.get(
                        "recommendation"
                    )
                ),

                "validation_method": (
                    finding.get(
                        "validation_method"
                    )
                ),

                "affected_urls": set(),

                "parameters": set(),

                "occurrence_count": 0,
            }


        item = grouped[
            event_type
        ]


        item[
            "occurrence_count"
        ] += 1


        target_url = (
            finding.get(
                "url"
            )
            or finding.get(
                "target"
            )
        )


        if target_url:

            item[
                "affected_urls"
            ].add(
                target_url
            )


        parameter = finding.get(
            "parameter"
        )


        if parameter:

            item[
                "parameters"
            ].add(
                str(
                    parameter
                )
            )


    summary = []


    for item in grouped.values():

        affected_urls = sorted(
            item[
                "affected_urls"
            ]
        )


        affected_page_count = len(
            affected_urls
        )


        coverage_percentage = 0.0


        if total_pages > 0:

            coverage_percentage = round(
                (
                    affected_page_count
                    / total_pages
                )
                * 100,
                2,
            )


        summary.append(
            {
                "event_type": (
                    item[
                        "event_type"
                    ]
                ),

                "classification": (
                    item[
                        "classification"
                    ]
                ),

                "severity": (
                    item[
                        "severity"
                    ]
                ),

                "confidence": (
                    item[
                        "confidence"
                    ]
                ),

                "occurrence_count": (
                    item[
                        "occurrence_count"
                    ]
                ),

                "affected_page_count": (
                    affected_page_count
                ),

                "total_pages": (
                    total_pages
                ),

                "coverage_percentage": (
                    coverage_percentage
                ),

                "affected_urls": (
                    affected_urls
                ),

                "parameters": sorted(
                    item[
                        "parameters"
                    ]
                ),

                "message": (
                    item[
                        "message"
                    ]
                ),

                "recommendation": (
                    item[
                        "recommendation"
                    ]
                ),

                "validation_method": (
                    item[
                        "validation_method"
                    ]
                ),
            }
        )


    summary.sort(
        key=lambda item: (
            -item[
                "affected_page_count"
            ],
            item[
                "event_type"
            ],
        )
    )


    return summary

# ============================================================
# ANALYSE PRINCIPALE
# ============================================================


def analyze_web_security(
    url: str,
    timeout: int = 10,
    allowed_domains: list[str] | None = None,
    max_depth: int = 2,
    max_pages: int = 20,
    max_duration_seconds: int = 30,
    delay_seconds: float = 0.2,
) -> dict:
    """
    Exécute un audit Web passif multi-pages.
    """

    report = create_empty_report(
        url
    )


    # ========================================================
    # VALIDATION URL
    # ========================================================

    valid, validation_error = (
        validate_url(
            url
        )
    )


    if not valid:

        report["audit_status"] = "FAILED"

        report["errors"].append(
            {
                "type": "INVALID_URL",
                "message": validation_error,
                "url": url,
            }
        )

        report["checks"].append(
            {
                "check_id": (
                    "URL_VALIDATION"
                ),

                "name": (
                    "Validation de l'URL"
                ),

                "status": (
                    "INDETERMINATE"
                ),

                "message": (
                    validation_error
                ),

                "url": url,
            }
        )

        update_coverage(
            report
        )

        return report


    report["checks"].append(
        {
            "check_id": (
                "URL_VALIDATION"
            ),

            "name": (
                "Validation de l'URL"
            ),

            "status": "PASSED",

            "message": (
                "URL valide."
            ),

            "url": url,
        }
    )


    # ========================================================
    # SCOPE
    # ========================================================

    scope = build_allowed_domains(
        url,
        allowed_domains,
    )


    if not scope:

        report["audit_status"] = "FAILED"

        report["errors"].append(
            {
                "type": "INVALID_SCOPE",
                "message": (
                    "Aucun domaine autorisé "
                    "n'a pu être déterminé."
                ),
                "url": url,
            }
        )

        report["checks"].append(
            {
                "check_id": (
                    "WEB_SCOPE"
                ),

                "name": (
                    "Périmètre de l'audit"
                ),

                "status": (
                    "INDETERMINATE"
                ),

                "message": (
                    "Périmètre invalide."
                ),

                "url": url,
            }
        )

        update_coverage(
            report
        )

        return report


    report["metadata"][
        "allowed_domains"
    ] = sorted(
        scope
    )


    report["checks"].append(
        {
            "check_id": (
                "WEB_SCOPE"
            ),

            "name": (
                "Périmètre de l'audit"
            ),

            "status": "PASSED",

            "message": (
                "Périmètre défini."
            ),

            "url": url,
        }
    )


    # ========================================================
    # CRAWL
    # ========================================================

    try:

        crawl_result = crawl_site(
            start_url=url,
            allowed_domains=scope,
            max_depth=max_depth,
            max_pages=max_pages,
            max_duration_seconds=(
                max_duration_seconds
            ),
            delay_seconds=delay_seconds,
            timeout=timeout,
        )


    except WebCollectionError as error:

        error_type = (
            get_collection_error_type(
                str(
                    error
                )
            )
        )


        report["audit_status"] = "FAILED"

        report["errors"].append(
            {
                "type": error_type,
                "message": str(
                    error
                ),
                "url": url,
            }
        )

        report["checks"].append(
            {
                "check_id": (
                    "HTTP_COLLECTION"
                ),

                "name": (
                    "Collecte HTTP"
                ),

                "status": (
                    "INDETERMINATE"
                ),

                "message": str(
                    error
                ),

                "url": url,
            }
        )

        update_coverage(
            report
        )

        return report


    report["crawl"] = {
        "enabled": True,

        "visited_count": (
            crawl_result.get(
                "visited_count",
                0,
            )
        ),

        "discovered_count": (
            crawl_result.get(
                "discovered_count",
                0,
            )
        ),

        "duration_seconds": (
            crawl_result.get(
                "duration_seconds",
                0,
            )
        ),

        "max_depth": max_depth,

        "max_pages": max_pages,
    }


    report["request_count"] = (
        crawl_result.get(
            "request_count",
            0,
        )
    )


    report["skipped_urls"] = (
        crawl_result.get(
            "skipped",
            [],
        )
    )


    # ========================================================
    # ERREURS PARTIELLES DE CRAWL
    # ========================================================

    for crawl_error in (
        crawl_result.get(
            "errors",
            [],
        )
    ):

        report["errors"].append(
            {
                "type": (
                    get_collection_error_type(
                        crawl_error.get(
                            "message",
                            "",
                        )
                    )
                ),

                "message": (
                    crawl_error.get(
                        "message",
                        "",
                    )
                ),

                "url": (
                    crawl_error.get(
                        "url"
                    )
                ),
            }
        )


    # ========================================================
    # PAGES
    # ========================================================

    crawl_pages = (
        crawl_result.get(
            "pages",
            [],
        )
    )


    if not crawl_pages:

        report["audit_status"] = "FAILED"

        report["checks"].append(
            {
                "check_id": (
                    "HTTP_COLLECTION"
                ),

                "name": (
                    "Collecte HTTP"
                ),

                "status": (
                    "INDETERMINATE"
                ),

                "message": (
                    "Aucune page n'a pu "
                    "être collectée."
                ),

                "url": url,
            }
        )

        update_coverage(
            report
        )

        return report


    report["checks"].append(
        {
            "check_id": (
                "HTTP_COLLECTION"
            ),

            "name": (
                "Collecte HTTP"
            ),

            "status": "PASSED",

            "message": (
                f"{len(crawl_pages)} "
                "page(s) collectée(s)."
            ),

            "url": url,
        }
    )


    # ========================================================
    # ANALYSE PAGE PAR PAGE
    # ========================================================

    for index, page in enumerate(
        crawl_pages
    ):

        page_url = (
            page.get(
                "url"
            )
        )

        final_url = (
            page.get(
                "final_url"
            )
            or page_url
        )


        # ----------------------------------------------------
        # INVENTAIRE
        # ----------------------------------------------------

        report["pages"].append(
            {
                "url": page_url,
                "final_url": final_url,
                "depth": (
                    page.get(
                        "depth"
                    )
                ),
                "status_code": (
                    page.get(
                        "status_code"
                    )
                ),
                "content_type": (
                    page.get(
                        "content_type"
                    )
                ),
            }
        )


        # ----------------------------------------------------
        # PREMIÈRE PAGE
        # ----------------------------------------------------

        if index == 0:

            report["final_url"] = (
                final_url
            )

            report["http_status"] = (
                page.get(
                    "status_code"
                )
            )

            report["redirects"] = (
                page.get(
                    "redirects",
                    [],
                )
            )


        # ----------------------------------------------------
        # RÉUTILISER LA RÉPONSE DU CRAWLER
        # ----------------------------------------------------
        #
        # crawl_site() a déjà téléchargé cette page.
        # On réutilise directement la réponse HTTP afin
        # d'éviter une seconde requête réseau.
        # ----------------------------------------------------

        response = page.get(
            "_response"
        )


        if response is None:

            report["errors"].append(
                {
                    "type": (
                        "MISSING_PAGE_RESPONSE"
                    ),

                    "message": (
                        "La réponse HTTP collectée "
                        "n'est pas disponible pour "
                        "l'analyse de la page."
                    ),

                    "url": page_url,
                }
            )


            report["checks"].append(
                {
                    "check_id": (
                        "PAGE_ANALYSIS"
                    ),

                    "name": (
                        "Analyse de la page"
                    ),

                    "status": (
                        "INDETERMINATE"
                    ),

                    "message": (
                        "Réponse HTTP indisponible."
                    ),

                    "url": page_url,
                }
            )


            continue


        analyze_page(
            report=report,

            response=response,

            requested_url=page_url,

            final_url=final_url,
        )
        

    # ========================================================
    # FINALISATION
    # ========================================================

    report["detections"] = list(
        report["findings"]
    )


    report["finding_count"] = len(
        report["findings"]
    )

    report["finding_summary"] = aggregate_web_findings(
        findings=report["findings"],
        total_pages=len(
            report["pages"]
        ),
    )

    report["site_risk"] = calculate_site_risk(report.get("finding_summary", []))
      


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
# TRANSFORMATION FINDINGS -> ALERTES
# ============================================================


def process_web_detections(
    detections: list[dict],
) -> list[dict]:
    """
    Transforme les findings disposant d'une règle
    de scoring en alertes persistantes.
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

            alert = (
                build_security_alert(
                    detection
                )
            )

        except ValueError:

            continue


        alert_id = save_alert(
            alert
        )


        alert["id"] = (
            alert_id
        )


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
# PIPELINE PUBLIC
# ============================================================


def run_web_analysis(
    url: str,
    timeout: int = 10,
    allowed_domains: list[str] | None = None,
    max_depth: int = 2,
    max_pages: int = 20,
    max_duration_seconds: int = 30,
    delay_seconds: float = 0.2,
) -> dict:
    """
    Exécute l'audit Web complet passif
    puis génère les alertes.
    """

    report = analyze_web_security(
        url=url,
        timeout=timeout,
        allowed_domains=allowed_domains,
        max_depth=max_depth,
        max_pages=max_pages,
        max_duration_seconds=(
            max_duration_seconds
        ),
        delay_seconds=delay_seconds,
    )


    findings = report.get(
        "findings",
        [],
    )


    alerts = process_web_detections(
        findings
    )


    report["alerts"] = alerts

    report["finding_count"] = len(
        findings
    )
    

    report["alert_count"] = len(
        alerts
    )


    return report


def aggregate_web_findings(
    findings: list[dict],
    total_pages: int = 0,
) -> list[dict]:
    """
    Agrège les findings Web par type d'événement.

    Le détail page par page reste disponible
    dans report["findings"].
    """

    grouped = {}


    for finding in findings:

        event_type = (
            finding.get("event_type")
            or "UNKNOWN"
        )


        if event_type not in grouped:

            grouped[event_type] = {
                "event_type": event_type,

                "classification": (
                    finding.get(
                        "classification"
                    )
                ),

                "severity": (
                    finding.get(
                        "severity"
                    )
                ),

                "confidence": (
                    finding.get(
                        "confidence"
                    )
                ),

                "message": (
                    finding.get(
                        "message"
                    )
                ),

                "recommendation": (
                    finding.get(
                        "recommendation"
                    )
                ),

                "validation_method": (
                    finding.get(
                        "validation_method"
                    )
                ),

                "affected_urls": set(),

                "parameters": set(),

                "occurrence_count": 0,
            }


        item = grouped[event_type]

        item["occurrence_count"] += 1


        target_url = (
            finding.get("url")
            or finding.get("target")
        )


        if target_url:

            item["affected_urls"].add(
                target_url
            )


        parameter = finding.get(
            "parameter"
        )


        if parameter:

            item["parameters"].add(
                str(parameter)
            )


    summary = []


    for item in grouped.values():

        affected_urls = sorted(
            item["affected_urls"]
        )

        affected_page_count = len(
            affected_urls
        )


        coverage_percentage = 0.0


        if total_pages > 0:

            coverage_percentage = round(
                (
                    affected_page_count
                    / total_pages
                )
                * 100,
                2,
            )


        summary.append(
            {
                "event_type": (
                    item["event_type"]
                ),

                "classification": (
                    item["classification"]
                ),

                "severity": (
                    item["severity"]
                ),

                "confidence": (
                    item["confidence"]
                ),

                "occurrence_count": (
                    item["occurrence_count"]
                ),

                "affected_page_count": (
                    affected_page_count
                ),

                "total_pages": total_pages,

                "coverage_percentage": (
                    coverage_percentage
                ),

                "affected_urls": (
                    affected_urls
                ),

                "parameters": sorted(
                    item["parameters"]
                ),

                "message": (
                    item["message"]
                ),

                "recommendation": (
                    item["recommendation"]
                ),

                "validation_method": (
                    item[
                        "validation_method"
                    ]
                ),
            }
        )


    summary.sort(
        key=lambda item: (
            -item["affected_page_count"],
            item["event_type"],
        )
    )


    return summary

def calculate_site_risk(
    finding_summary: list[dict],
) -> dict:
    """
    Calcule un niveau de risque global du site
    à partir des findings agrégés.

    Un même type de finding n'est compté qu'une fois
    afin d'éviter de gonfler artificiellement le score
    lorsqu'il apparaît sur plusieurs pages.
    """

    total_score = 0

    contributors = []


    for item in finding_summary:

        event_type = item.get(
            "event_type"
        )


        if not event_type:

            continue


        rule = get_rule(
            event_type
        )


        if rule is None:

            continue


        base_score = int(
            rule.get(
                "base_score",
                0,
            )
        )


        affected_page_count = int(
            item.get(
                "affected_page_count",
                0,
            )
        )


        total_pages = int(
            item.get(
                "total_pages",
                0,
            )
        )


        coverage_percentage = float(
            item.get(
                "coverage_percentage",
                0,
            )
        )


        # ----------------------------------------------------
        # BONUS DE PROPAGATION
        # ----------------------------------------------------
        #
        # On n'additionne PAS le score pour chaque page.
        # On ajoute seulement un petit bonus si la faiblesse
        # est largement répandue.
        # ----------------------------------------------------

        propagation_bonus = 0


        if (
            total_pages > 0
            and affected_page_count > 0
        ):

            if coverage_percentage >= 80:

                propagation_bonus = 10

            elif coverage_percentage >= 50:

                propagation_bonus = 5

            elif coverage_percentage >= 20:

                propagation_bonus = 2


        finding_score = (
            base_score
            + propagation_bonus
        )


        total_score += (
            finding_score
        )


        contributors.append(
            {
                "event_type": (
                    event_type
                ),

                "base_score": (
                    base_score
                ),

                "propagation_bonus": (
                    propagation_bonus
                ),

                "score": (
                    finding_score
                ),

                "affected_page_count": (
                    affected_page_count
                ),

                "total_pages": (
                    total_pages
                ),

                "coverage_percentage": (
                    coverage_percentage
                ),
            }
        )


    total_score = min(
        total_score,
        100,
    )


    if total_score >= 70:

        risk_level = "CRITICAL"

    elif total_score >= 50:

        risk_level = "HIGH"

    elif total_score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    contributors.sort(
        key=lambda item: (
            -item["score"],
            item["event_type"],
        )
    )


    return {
        "score": total_score,
        "level": risk_level,
        "contributors": contributors,
    }