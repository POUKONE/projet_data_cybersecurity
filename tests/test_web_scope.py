from app.security.web_scope import (
    build_allowed_domains,
    get_hostname,
    is_domain_allowed,
    should_exclude_url,
)


def test_get_hostname():

    assert (
        get_hostname(
            "https://www.example.com/test"
        )
        == "example.com"
    )


def test_build_allowed_domains():

    allowed = build_allowed_domains(
        "https://example.com"
    )

    assert (
        "example.com"
        in allowed
    )


def test_domain_allowed():

    allowed = {
        "example.com"
    }

    assert is_domain_allowed(
        "https://example.com/page",
        allowed
    )


def test_domain_not_allowed():

    allowed = {
        "example.com"
    }

    assert not is_domain_allowed(
        "https://other.com",
        allowed
    )


def test_dangerous_action_is_excluded():

    assert should_exclude_url(
        "https://example.com/logout"
    )

    assert should_exclude_url(
        "https://example.com/delete?id=10"
    )