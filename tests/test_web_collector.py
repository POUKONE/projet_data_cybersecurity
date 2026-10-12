from unittest.mock import Mock, patch

import pytest
import requests

from app.collectors.web_collector import (
    WebCollectionError,
    request_with_scope,
    validate_url,
)


def test_validate_url():

    valid, error = validate_url(
        "https://example.com"
    )

    assert valid is True
    assert error is None


def test_invalid_scheme():

    valid, error = validate_url(
        "ftp://example.com"
    )

    assert valid is False
    assert error is not None


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_simple_request(
    mock_get
):

    response = Mock()

    response.status_code = 200
    response.headers = {}
    response.is_redirect = False
    response.is_permanent_redirect = False

    mock_get.return_value = response


    result = request_with_scope(
        "https://example.com",
        {
            "example.com"
        }
    )


    assert (
        result["final_url"]
        == "https://example.com"
    )

    assert (
        result["request_count"]
        == 1
    )


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_redirect_inside_scope(
    mock_get
):

    first = Mock()

    first.status_code = 302
    first.headers = {
        "Location": "/home"
    }

    first.is_redirect = True
    first.is_permanent_redirect = False


    second = Mock()

    second.status_code = 200
    second.headers = {}
    second.is_redirect = False
    second.is_permanent_redirect = False


    mock_get.side_effect = [
        first,
        second,
    ]


    result = request_with_scope(
        "https://example.com",
        {
            "example.com"
        }
    )


    assert (
        result["final_url"]
        == "https://example.com/home"
    )

    assert (
        len(
            result["redirects"]
        )
        == 1
    )


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_redirect_outside_scope_blocked(
    mock_get
):

    response = Mock()

    response.status_code = 302

    response.headers = {
        "Location": (
            "https://other.com"
        )
    }

    response.is_redirect = True
    response.is_permanent_redirect = False


    mock_get.return_value = (
        response
    )


    with pytest.raises(
        WebCollectionError
    ):

        request_with_scope(
            "https://example.com",
            {
                "example.com"
            }
        )


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_timeout_is_reported(
    mock_get
):

    mock_get.side_effect = (
        requests.exceptions.ReadTimeout(
            "timeout"
        )
    )


    with pytest.raises(
        WebCollectionError
    ):

        request_with_scope(
            "https://example.com",
            {
                "example.com"
            }
        )