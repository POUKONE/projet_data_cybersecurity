from unittest.mock import Mock, patch

import requests

from requests.cookies import (
    RequestsCookieJar,
)

from app.analyzers.web_analyzer import (
    analyze_web_security,
    process_web_detections,
    run_web_analysis,
)

from app.collectors.web_collector import (
    validate_url,
)


# ============================================================
# VALIDATION URL
# ============================================================


def test_valid_https_url():
    """
    Vérifie qu'une URL HTTPS valide
    est correctement acceptée.
    """

    valid, error = validate_url(
        "https://example.com"
    )

    assert valid is True
    assert error is None


def test_invalid_url_scheme():
    """
    Vérifie qu'un protocole non HTTP/HTTPS
    est refusé.
    """

    valid, error = validate_url(
        "ftp://example.com"
    )

    assert valid is False
    assert error is not None


def test_invalid_url_without_host():
    """
    Vérifie qu'une URL sans hostname
    est refusée.
    """

    valid, error = validate_url(
        "https://"
    )

    assert valid is False
    assert error is not None


# ============================================================
# HEADERS DE SÉCURITÉ MANQUANTS
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_missing_security_headers(
    mock_get
):
    """
    Vérifie que les principaux headers manquants
    sont détectés.
    """

    response = Mock()

    response.url = (
        "https://example.com"
    )

    response.status_code = 200

    response.headers = {
        "Content-Type": "text/html",
    }

    response.cookies = (
        RequestsCookieJar()
    )

    response.text = (
        "<html><body></body></html>"
    )

    response.is_redirect = False
    response.is_permanent_redirect = False

    mock_get.return_value = response


    report = analyze_web_security(
        "https://example.com"
    )


    event_types = {
        item["event_type"]
        for item
        in report["findings"]
    }


    assert (
        "CSP_MISSING"
        in event_types
    )

    assert (
        "HSTS_MISSING"
        in event_types
    )

    assert (
        "X_CONTENT_TYPE_OPTIONS_MISSING"
        in event_types
    )

    assert (
        "X_FRAME_OPTIONS_MISSING"
        in event_types
    )

    assert (
        "REFERRER_POLICY_MISSING"
        in event_types
    )


    assert (
        report["audit_status"]
        == "COMPLETED"
    )


# ============================================================
# HEADERS CORRECTEMENT CONFIGURÉS
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_secure_headers(
    mock_get
):
    """
    Vérifie que des headers correctement configurés
    ne génèrent pas de finding correspondant.
    """

    response = Mock()

    response.url = (
        "https://example.com"
    )

    response.status_code = 200

    response.headers = {
        "Content-Type": "text/html",

        "Content-Security-Policy": (
            "default-src 'self'; "
            "frame-ancestors 'none'"
        ),

        "Strict-Transport-Security": (
            "max-age=31536000"
        ),

        "X-Content-Type-Options": (
            "nosniff"
        ),

        "X-Frame-Options": (
            "DENY"
        ),

        "Referrer-Policy": (
            "strict-origin-when-cross-origin"
        ),
    }

    response.cookies = (
        RequestsCookieJar()
    )

    response.text = (
        "<html><body></body></html>"
    )

    response.is_redirect = False
    response.is_permanent_redirect = False

    mock_get.return_value = response


    report = analyze_web_security(
        "https://example.com"
    )


    relevant_events = {
        finding["event_type"]
        for finding
        in report["findings"]
        if finding["event_type"]
        in {
            "CSP_MISSING",
            "HSTS_MISSING",
            "X_CONTENT_TYPE_OPTIONS_MISSING",
            "X_FRAME_OPTIONS_MISSING",
            "REFERRER_POLICY_MISSING",
        }
    }


    assert (
        relevant_events
        == set()
    )


    assert (
        report["audit_status"]
        == "COMPLETED"
    )


# ============================================================
# HTTP
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_http_is_detected(
    mock_get
):
    """
    Vérifie qu'une URL HTTP génère
    une détection HTTPS_MISSING.
    """

    response = Mock()

    response.url = (
        "http://example.com"
    )

    response.status_code = 200

    response.headers = {
        "Content-Type": "text/html",
    }

    response.cookies = (
        RequestsCookieJar()
    )

    response.text = (
        "<html></html>"
    )

    response.is_redirect = False
    response.is_permanent_redirect = False

    mock_get.return_value = response


    report = analyze_web_security(
        "http://example.com"
    )


    event_types = {
        item["event_type"]
        for item
        in report["findings"]
    }


    assert (
        "HTTPS_MISSING"
        in event_types
    )


# ============================================================
# TIMEOUT
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_timeout_is_not_zero_findings(
    mock_get
):
    """
    Vérifie qu'un timeout ne soit jamais interprété
    comme une absence de vulnérabilité.
    """

    mock_get.side_effect = (
        requests.exceptions.ReadTimeout(
            "timeout"
        )
    )


    report = analyze_web_security(
        "https://example.com"
    )


    assert (
        report["audit_status"]
        == "FAILED"
    )


    assert (
        len(
            report["errors"]
        )
        == 1
    )


    assert (
        report["errors"][0]["type"]
        == "READ_TIMEOUT"
    )


    assert (
        report["coverage"][
            "indeterminate"
        ]
        >= 1
    )


# ============================================================
# TLS
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_tls_error_is_reported(
    mock_get
):
    """
    Vérifie qu'une erreur TLS soit signalée
    comme erreur d'analyse.
    """

    mock_get.side_effect = (
        requests.exceptions.SSLError(
            "certificate error"
        )
    )


    report = analyze_web_security(
        "https://example.com"
    )


    assert (
        report["audit_status"]
        == "FAILED"
    )


    assert (
        len(
            report["errors"]
        )
        == 1
    )


    assert (
        report["errors"][0]["type"]
        == "TLS_ERROR"
    )


# ============================================================
# REDIRECTION
# ============================================================

@patch(
    "app.collectors.web_collector.requests.get"
)
def test_redirect_is_recorded(
    mock_get
):
    """
    Vérifie qu'une redirection interne au scope
    est correctement suivie et enregistrée.

    La réponse obtenue pendant le crawl est ensuite
    réutilisée par les analyseurs.
    """

    # ========================================================
    # REDIRECTION
    # ========================================================

    redirect_response = Mock()

    redirect_response.status_code = 301

    redirect_response.headers = {
        "Location": (
            "https://example.com"
        )
    }

    redirect_response.is_redirect = True
    redirect_response.is_permanent_redirect = True


    # ========================================================
    # RÉPONSE FINALE
    # ========================================================

    final_response = Mock()

    final_response.status_code = 200

    final_response.headers = {
        "Content-Type": "text/html",

        "Content-Security-Policy": (
            "default-src 'self'"
        ),

        "Strict-Transport-Security": (
            "max-age=31536000"
        ),

        "X-Content-Type-Options": (
            "nosniff"
        ),

        "X-Frame-Options": (
            "DENY"
        ),

        "Referrer-Policy": (
            "same-origin"
        ),
    }

    final_response.cookies = (
        RequestsCookieJar()
    )

    final_response.text = (
        "<html></html>"
    )

    final_response.is_redirect = False
    final_response.is_permanent_redirect = False


    # ========================================================
    # ORDRE DES APPELS
    # ========================================================

    mock_get.side_effect = [
        redirect_response,
        final_response,
    ]


    # ========================================================
    # AUDIT
    # ========================================================

    report = analyze_web_security(
        "http://example.com",
        max_depth=0,
        delay_seconds=0,
    )


    # ========================================================
    # ASSERTIONS
    # ========================================================

    assert (
        len(
            report["redirects"]
        )
        == 1
    )


    assert (
        report["final_url"]
        == "https://example.com/"
    )


    assert (
        report["http_status"]
        == 200
    )


    assert (
        report["audit_status"]
        == "COMPLETED"
    )


    assert (
        report["crawl"][
            "visited_count"
        ]
        == 1
    )


    # Une requête HTTP initiale
    # + une requête après redirection.
    assert (
        report["request_count"]
        == 2
    )


    assert (
        mock_get.call_count
        == 2
    )


# ============================================================
# PROCESS WEB DETECTIONS
# ============================================================


@patch(
    "app.analyzers.web_analyzer.save_alert"
)
def test_process_web_detections(
    mock_save
):
    """
    Vérifie la transformation d'un finding
    connu en alerte persistante.
    """

    mock_save.return_value = 10


    detections = [
        {
            "event_type": (
                "CSP_MISSING"
            ),

            "source_type": "WEB",

            "target": (
                "https://example.com"
            ),

            "url": (
                "https://example.com"
            ),

            "classification": (
                "MISCONFIGURATION"
            ),

            "severity": "LOW",

            "confidence": "HIGH",

            "message": (
                "CSP absent."
            ),

            "description": (
                "CSP absent."
            ),

            "recommendation": (
                "Configurer une politique CSP."
            ),

            "validation_method": (
                "Inspecter les headers HTTP."
            ),

            "status": "OPEN",
        }
    ]


    alerts = (
        process_web_detections(
            detections
        )
    )


    assert (
        len(
            alerts
        )
        == 1
    )


    assert (
        alerts[0]["id"]
        == 10
    )


    assert (
        alerts[0]["source_type"]
        == "WEB"
    )


    assert (
        alerts[0]["event_type"]
        == "CSP_MISSING"
    )


# ============================================================
# FINDING INCONNU
# ============================================================


@patch(
    "app.analyzers.web_analyzer.save_alert"
)
def test_unknown_web_finding_is_not_persisted(
    mock_save
):
    """
    Un finding sans règle de scoring doit rester
    exploitable dans le rapport mais ne doit pas
    devenir une alerte persistante.
    """

    detections = [
        {
            "event_type": (
                "UNKNOWN_WEB_CHECK"
            ),

            "source_type": "WEB",

            "target": (
                "https://example.com"
            ),

            "message": (
                "Résultat expérimental."
            ),

            "description": (
                "Aucune règle de scoring."
            ),
        }
    ]


    alerts = (
        process_web_detections(
            detections
        )
    )


    assert (
        alerts
        == []
    )


    mock_save.assert_not_called()


# ============================================================
# PIPELINE COMPLET
# ============================================================


@patch(
    "app.analyzers.web_analyzer.process_web_detections"
)
@patch(
    "app.analyzers.web_analyzer.analyze_web_security"
)
def test_run_web_analysis(
    mock_analyze,
    mock_process
):
    """
    Vérifie que run_web_analysis utilise désormais
    findings comme source principale des alertes.
    """

    findings = [
        {
            "event_type": (
                "CSP_MISSING"
            )
        }
    ]


    report = {
        "audit_status": (
            "COMPLETED"
        ),

        "mode": "PASSIVE",

        "requested_url": (
            "https://example.com"
        ),

        "final_url": (
            "https://example.com"
        ),

        "findings": findings,

        "detections": findings,

        "checks": [],

        "errors": [],

        "coverage": {},

        "alerts": [],
    }


    mock_analyze.return_value = (
        report
    )


    mock_process.return_value = [
        {
            "event_type": (
                "CSP_MISSING"
            ),

            "risk_score": 15,

            "risk_level": "LOW",
        }
    ]


    result = run_web_analysis(
        "https://example.com"
    )


    assert (
        result["finding_count"]
        == 1
    )


    assert (
        result["alert_count"]
        == 1
    )


    assert (
        len(
            result["alerts"]
        )
        == 1
    )


    mock_analyze.assert_called_once_with(
        url="https://example.com",
        timeout=10,
        allowed_domains=None,
        max_depth=2,
        max_pages=20,
        max_duration_seconds=30,
        delay_seconds=0.2,
)


    mock_process.assert_called_once_with(
        findings
    )