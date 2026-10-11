from unittest.mock import patch, Mock

from app.analyzers.web_analyzer import (
    analyze_web_security,
    process_web_detections,
    run_web_analysis
)


@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_missing_security_headers(
    mock_get
):
    response = Mock()

    response.url = "https://example.com"
    response.status_code = 200
    response.headers = {}

    mock_get.return_value = response

    detections = analyze_web_security(
        "https://example.com"
    )

    event_types = {
        detection["event_type"]
        for detection in detections
    }

    assert "CSP_MISSING" in event_types
    assert "HSTS_MISSING" in event_types
    assert (
        "X_CONTENT_TYPE_OPTIONS_MISSING"
        in event_types
    )
    assert "X_FRAME_OPTIONS_MISSING" in event_types
    assert "REFERRER_POLICY_MISSING" in event_types

@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_all_security_headers_present(
    mock_get
):
    response = Mock()

    response.url = "https://example.com"
    response.status_code = 200

    response.headers = {
        "Content-Security-Policy": (
            "default-src 'self'"
        ),
        "Strict-Transport-Security": (
            "max-age=31536000"
        ),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": (
            "strict-origin-when-cross-origin"
        )
    }

    mock_get.return_value = response

    detections = analyze_web_security(
        "https://example.com"
    )

    assert detections == []

@patch(
    "app.analyzers.web_analyzer.save_alert"
)
def test_process_web_detections(
    mock_save_alert
):
    """
    Vérifie qu'une détection Web devient
    une alerte puis est envoyée vers SQLite.
    """

    detections = [
        {
            "event_type": "CSP_MISSING",
            "url": "https://example.com",
            "status_code": 200,
            "message": "CSP absent."
        }
    ]

    alerts = process_web_detections(
        detections
    )

    assert len(alerts) == 1

    assert alerts[0]["risk_score"] == 15
    assert alerts[0]["risk_level"] == "LOW"

    mock_save_alert.assert_called_once()

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
    Vérifie le pipeline Web complet.
    """

    detections = [
        {
            "event_type": "HTTPS_MISSING",
            "url": "http://example.com"
        }
    ]

    expected_alerts = [
        {
            "event_type": "HTTPS_MISSING",
            "risk_score": 30,
            "risk_level": "MEDIUM"
        }
    ]

    mock_analyze.return_value = detections
    mock_process.return_value = expected_alerts

    alerts = run_web_analysis(
        "http://example.com"
    )

    assert alerts == expected_alerts

    mock_analyze.assert_called_once_with(
        "http://example.com"
    )

    mock_process.assert_called_once_with(
        detections
    )

@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_https_missing(
    mock_get
):
    response = Mock()

    response.url = "http://example.com"
    response.status_code = 200
    response.headers = {
        "Content-Security-Policy": "default-src 'self'"
    }

    mock_get.return_value = response

    detections = analyze_web_security(
        "http://example.com"
    )

    event_types = {
        detection["event_type"]
        for detection in detections
    }

    assert "HTTPS_MISSING" in event_types


@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_csp_missing(
    mock_get
):
    response = Mock()

    response.url = "https://example.com"
    response.status_code = 200
    response.headers = {}

    mock_get.return_value = response

    detections = analyze_web_security(
        "https://example.com"
    )

    event_types = {
        detection["event_type"]
        for detection in detections
    }

    assert "CSP_MISSING" in event_types


@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_secure_web_configuration(
    mock_get
):
    """
    Vérifie qu'aucune alerte n'est générée
    lorsque tous les headers de sécurité
    attendus sont présents.
    """

    response = Mock()

    response.url = "https://example.com"
    response.status_code = 200

    response.headers = {
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
            "strict-origin-when-cross-origin"
        )
    }

    mock_get.return_value = response

    detections = analyze_web_security(
        "https://example.com"
    )

    assert detections == []