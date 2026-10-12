from unittest.mock import Mock, patch

import requests

from app.analyzers.web_analyzer import (
    analyze_web_security,
    process_web_detections,
    run_web_analysis,
    validate_web_url,
)


def test_valid_https_url():

    valid, error = validate_web_url(
        "https://example.com"
    )

    assert valid is True
    assert error is None


def test_invalid_url_scheme():

    valid, error = validate_web_url(
        "ftp://example.com"
    )

    assert valid is False
    assert error is not None


def test_invalid_url_without_host():

    valid, error = validate_web_url(
        "https://"
    )

    assert valid is False
    assert error is not None


@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_missing_security_headers(
    mock_get
):

    response = Mock()

    response.url = (
        "https://example.com"
    )

    response.status_code = 200

    response.headers = {}

    response.history = []

    mock_get.return_value = (
        response
    )


    report = analyze_web_security(
        "https://example.com"
    )


    event_types = {
        item["event_type"]
        for item
        in report["detections"]
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


@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_secure_headers(
    mock_get
):

    response = Mock()

    response.url = (
        "https://example.com"
    )

    response.status_code = 200

    response.headers = {
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

    response.history = []

    mock_get.return_value = (
        response
    )


    report = analyze_web_security(
        "https://example.com"
    )


    assert (
        report["detections"]
        == []
    )

    assert (
        report["audit_status"]
        == "COMPLETED"
    )


@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_http_is_detected(
    mock_get
):

    response = Mock()

    response.url = (
        "http://example.com"
    )

    response.status_code = 200

    response.headers = {}

    response.history = []

    mock_get.return_value = (
        response
    )


    report = analyze_web_security(
        "http://example.com"
    )


    event_types = {
        item["event_type"]
        for item
        in report["detections"]
    }


    assert (
        "HTTPS_MISSING"
        in event_types
    )


@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_timeout_is_not_zero_findings(
    mock_get
):

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


@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_tls_error_is_reported(
    mock_get
):

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
        report["errors"][0]["type"]
        == "TLS_ERROR"
    )


@patch(
    "app.analyzers.web_analyzer.requests.get"
)
def test_redirect_is_recorded(
    mock_get
):

    redirect = Mock()

    redirect.status_code = 301

    redirect.url = (
        "http://example.com"
    )

    redirect.headers = {
        "Location": (
            "https://example.com"
        )
    }


    response = Mock()

    response.url = (
        "https://example.com"
    )

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
            "same-origin"
        ),
    }

    response.history = [
        redirect
    ]

    mock_get.return_value = (
        response
    )


    report = analyze_web_security(
        "http://example.com"
    )


    assert (
        len(
            report["redirects"]
        )
        == 1
    )

    assert (
        report["final_url"]
        == "https://example.com"
    )


@patch(
    "app.analyzers.web_analyzer.save_alert"
)
def test_process_web_detections(
    mock_save
):

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

            "message": (
                "CSP absent."
            ),

            "description": (
                "CSP absent."
            ),

            "classification": (
                "MISCONFIGURATION"
            ),

            "confidence": "HIGH",
        }
    ]


    alerts = (
        process_web_detections(
            detections
        )
    )


    assert len(
        alerts
    ) == 1

    assert (
        alerts[0]["id"]
        == 10
    )


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

    report = {
        "audit_status": (
            "COMPLETED"
        ),

        "detections": [
            {
                "event_type": (
                    "CSP_MISSING"
                )
            }
        ],

        "checks": [],

        "errors": [],

        "coverage": {},
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


    mock_analyze.assert_called_once_with(
        url="https://example.com",
        timeout=10
    )