from unittest.mock import Mock

from app.analyzers.web_checks.disclosure import (
    check_information_disclosure,
)


def test_server_header_disclosure():

    response = Mock()

    response.headers = {
        "Server": "Apache/2.4.57"
    }

    response.text = "<html></html>"

    result = check_information_disclosure(
        response,
        "https://example.com"
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "TECHNOLOGY_DISCLOSURE"
        in event_types
    )


def test_debug_trace_disclosure():

    response = Mock()

    response.headers = {}

    response.text = """
    Traceback (most recent call last):
    File "/app/main.py"
    """

    result = check_information_disclosure(
        response,
        "https://example.com"
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "DEBUG_INFORMATION_DISCLOSURE"
        in event_types
    )


def test_no_disclosure():

    response = Mock()

    response.headers = {}

    response.text = (
        "<html><body>Welcome</body></html>"
    )

    result = check_information_disclosure(
        response,
        "https://example.com"
    )

    assert (
        result["findings"]
        == []
    )