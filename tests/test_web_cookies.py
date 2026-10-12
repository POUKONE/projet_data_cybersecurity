from requests.cookies import (
    RequestsCookieJar,
    create_cookie,
)

from unittest.mock import Mock

from app.analyzers.web_checks.cookies import (
    check_cookie_security,
)


def test_no_cookies():

    response = Mock()

    response.cookies = (
        RequestsCookieJar()
    )

    result = check_cookie_security(
        response,
        "https://example.com"
    )

    assert (
        result["findings"]
        == []
    )

def test_insecure_cookie():

    jar = RequestsCookieJar()

    cookie = create_cookie(
        name="session",
        value="test",
        secure=False,
        rest={},
    )

    jar.set_cookie(
        cookie
    )

    response = Mock()
    response.cookies = jar

    result = check_cookie_security(
        response,
        "https://example.com"
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "COOKIE_SECURE_MISSING"
        in event_types
    )

    assert (
        "COOKIE_HTTPONLY_MISSING"
        in event_types
    )

    assert (
        "COOKIE_SAMESITE_MISSING"
        in event_types
    )

def test_secure_cookie():

    jar = RequestsCookieJar()

    cookie = create_cookie(
        name="session",
        value="test",
        secure=True,
        rest={
            "HttpOnly": None,
            "SameSite": "Lax",
        },
    )

    jar.set_cookie(
        cookie
    )

    response = Mock()
    response.cookies = jar

    result = check_cookie_security(
        response,
        "https://example.com"
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "COOKIE_SECURE_MISSING"
        not in event_types
    )

    assert (
        "COOKIE_HTTPONLY_MISSING"
        not in event_types
    )

    assert (
        "COOKIE_SAMESITE_MISSING"
        not in event_types
    )