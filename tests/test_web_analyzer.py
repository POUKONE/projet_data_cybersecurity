from unittest.mock import patch, Mock

from app.analyzers.web_analyzer import (
    analyze_web_security
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
    response = Mock()

    response.url = "https://example.com"
    response.status_code = 200

    response.headers = {
        "Content-Security-Policy": (
            "default-src 'self'"
        )
    }

    mock_get.return_value = response

    detections = analyze_web_security(
        "https://example.com"
    )

    assert detections == []