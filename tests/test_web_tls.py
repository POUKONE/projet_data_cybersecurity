from unittest.mock import Mock

from app.analyzers.web_checks.tls import (
    check_tls_usage,
)


def test_http_request():

    response = Mock()
    response.headers = {}

    result = check_tls_usage(
        requested_url="http://example.com",
        final_url="http://example.com",
        response=response,
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "HTTPS_MISSING"
        in event_types
    )


def test_https_without_hsts():

    response = Mock()
    response.headers = {}

    result = check_tls_usage(
        requested_url="https://example.com",
        final_url="https://example.com",
        response=response,
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "HSTS_MISSING"
        in event_types
    )


def test_https_with_hsts():

    response = Mock()

    response.headers = {
        "Strict-Transport-Security": (
            "max-age=31536000"
        )
    }

    result = check_tls_usage(
        requested_url="https://example.com",
        final_url="https://example.com",
        response=response,
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "HSTS_MISSING"
        not in event_types
    )