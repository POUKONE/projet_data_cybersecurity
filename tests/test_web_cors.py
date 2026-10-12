from unittest.mock import Mock

from app.analyzers.web_checks.cors import (
    check_cors,
)


def test_no_cors_headers():

    response = Mock()

    response.headers = {}

    result = check_cors(
        response,
        "https://example.com"
    )

    assert (
        result["findings"]
        == []
    )


def test_cors_wildcard():

    response = Mock()

    response.headers = {
        "Access-Control-Allow-Origin": "*"
    }

    result = check_cors(
        response,
        "https://example.com"
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "CORS_WILDCARD_ORIGIN"
        in event_types
    )


def test_cors_wildcard_credentials():

    response = Mock()

    response.headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }

    result = check_cors(
        response,
        "https://example.com"
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "CORS_WILDCARD_WITH_CREDENTIALS"
        in event_types
    )