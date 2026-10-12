from unittest.mock import Mock

from app.analyzers.web_checks.headers import (
    check_security_headers,
)


def test_missing_headers():

    response = Mock()

    response.status_code = 200
    response.headers = {}

    result = check_security_headers(
        response,
        "https://example.com"
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert "CSP_MISSING" in event_types

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


def test_secure_headers():

    response = Mock()

    response.status_code = 200

    response.headers = {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "frame-ancestors 'none'"
        ),

        "X-Content-Type-Options": (
            "nosniff"
        ),

        "Referrer-Policy": (
            "strict-origin-when-cross-origin"
        ),
    }

    result = check_security_headers(
        response,
        "https://example.com"
    )

    assert (
        result["findings"]
        == []
    )