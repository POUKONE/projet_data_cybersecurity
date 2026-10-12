from unittest.mock import (
    Mock,
    patch,
)

import pytest
import requests

from app.collectors.web_collector import (
    WebCollectionError,
    crawl_site,
    extract_links,
    normalize_url,
    request_with_scope,
    validate_url,
)


# ============================================================
# VALIDATION
# ============================================================


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


def test_invalid_url_without_hostname():

    valid, error = validate_url(
        "https://"
    )

    assert valid is False
    assert error is not None


# ============================================================
# NORMALISATION
# ============================================================


def test_normalize_url_removes_fragment():

    result = normalize_url(
        "https://Example.com/page#section"
    )

    assert (
        result
        == "https://example.com/page"
    )


def test_normalize_default_https_port():

    result = normalize_url(
        "https://example.com:443/page"
    )

    assert (
        result
        == "https://example.com/page"
    )


# ============================================================
# EXTRACTION DES LIENS
# ============================================================


def test_extract_links():

    html = """
    <html>
        <body>
            <a href="/about">About</a>
            <a href="/contact#form">Contact</a>
            <a href="mailto:test@example.com">Email</a>
            <a href="javascript:void(0)">JS</a>
        </body>
    </html>
    """

    links = extract_links(
        html=html,
        base_url="https://example.com",
    )

    assert (
        "https://example.com/about"
        in links
    )

    assert (
        "https://example.com/contact"
        in links
    )

    assert len(
        links
    ) == 2


# ============================================================
# REQUÊTE SIMPLE
# ============================================================


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
        },
    )


    assert (
        result["final_url"]
        == "https://example.com/"
    )

    assert (
        result["request_count"]
        == 1
    )


# ============================================================
# REDIRECTION INTERNE
# ============================================================


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
        },
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

    assert (
        result["request_count"]
        == 2
    )


# ============================================================
# REDIRECTION HORS SCOPE
# ============================================================


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

    mock_get.return_value = response


    with pytest.raises(
        WebCollectionError
    ):

        request_with_scope(
            "https://example.com",
            {
                "example.com"
            },
        )


# ============================================================
# TIMEOUT
# ============================================================


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
    ) as error:

        request_with_scope(
            "https://example.com",
            {
                "example.com"
            },
        )


    assert (
        "READ_TIMEOUT"
        in str(
            error.value
        )
    )


# ============================================================
# CRAWL DE BASE
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_crawl_two_pages(
    mock_get
):

    page_one = Mock()

    page_one.status_code = 200

    page_one.headers = {
        "Content-Type": "text/html"
    }

    page_one.text = """
    <html>
        <body>
            <a href="/about">About</a>
        </body>
    </html>
    """

    page_one.is_redirect = False
    page_one.is_permanent_redirect = False


    page_two = Mock()

    page_two.status_code = 200

    page_two.headers = {
        "Content-Type": "text/html"
    }

    page_two.text = """
    <html>
        <body>
            About page
        </body>
    </html>
    """

    page_two.is_redirect = False
    page_two.is_permanent_redirect = False


    mock_get.side_effect = [
        page_one,
        page_two,
    ]


    result = crawl_site(
        start_url="https://example.com",
        allowed_domains={
            "example.com"
        },
        max_depth=1,
        max_pages=5,
        delay_seconds=0,
    )


    assert (
        result["visited_count"]
        == 2
    )

    assert (
        len(
            result["pages"]
        )
        == 2
    )

    urls = {
        page["final_url"]
        for page
        in result["pages"]
    }

    assert (
        "https://example.com/"
        in urls
    )

    assert (
        "https://example.com/about"
        in urls
    )


# ============================================================
# DÉDUPLICATION
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_crawl_deduplicates_links(
    mock_get
):

    page_one = Mock()

    page_one.status_code = 200

    page_one.headers = {
        "Content-Type": "text/html"
    }

    page_one.text = """
    <html>
        <body>
            <a href="/about">A</a>
            <a href="/about">B</a>
            <a href="/about#section">C</a>
        </body>
    </html>
    """

    page_one.is_redirect = False
    page_one.is_permanent_redirect = False


    page_two = Mock()

    page_two.status_code = 200

    page_two.headers = {
        "Content-Type": "text/html"
    }

    page_two.text = ""

    page_two.is_redirect = False
    page_two.is_permanent_redirect = False


    mock_get.side_effect = [
        page_one,
        page_two,
    ]


    result = crawl_site(
        start_url="https://example.com",
        allowed_domains={
            "example.com"
        },
        max_depth=1,
        max_pages=10,
        delay_seconds=0,
    )


    assert (
        result["visited_count"]
        == 2
    )

    assert (
        mock_get.call_count
        == 2
    )


# ============================================================
# LIEN HORS SCOPE
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_crawl_does_not_follow_external_link(
    mock_get
):

    response = Mock()

    response.status_code = 200

    response.headers = {
        "Content-Type": "text/html"
    }

    response.text = """
    <html>
        <body>
            <a href="https://other.com/private">
                External
            </a>
        </body>
    </html>
    """

    response.is_redirect = False
    response.is_permanent_redirect = False


    mock_get.return_value = response


    result = crawl_site(
        start_url="https://example.com",
        allowed_domains={
            "example.com"
        },
        max_depth=2,
        delay_seconds=0,
    )


    assert (
        result["visited_count"]
        == 1
    )

    assert (
        mock_get.call_count
        == 1
    )

    reasons = {
        item["reason"]
        for item
        in result["skipped"]
    }

    assert (
        "OUT_OF_SCOPE"
        in reasons
    )


# ============================================================
# ACTION EXCLUE
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_crawl_excludes_logout(
    mock_get
):

    response = Mock()

    response.status_code = 200

    response.headers = {
        "Content-Type": "text/html"
    }

    response.text = """
    <html>
        <body>
            <a href="/logout">
                Logout
            </a>
        </body>
    </html>
    """

    response.is_redirect = False
    response.is_permanent_redirect = False


    mock_get.return_value = response


    result = crawl_site(
        start_url="https://example.com",
        allowed_domains={
            "example.com"
        },
        max_depth=2,
        delay_seconds=0,
    )


    assert (
        mock_get.call_count
        == 1
    )

    reasons = {
        item["reason"]
        for item
        in result["skipped"]
    }

    assert (
        "EXCLUDED_ACTION"
        in reasons
    )


# ============================================================
# MAX PAGES
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_crawl_respects_max_pages(
    mock_get
):

    first = Mock()

    first.status_code = 200

    first.headers = {
        "Content-Type": "text/html"
    }

    first.text = """
    <a href="/a">A</a>
    <a href="/b">B</a>
    <a href="/c">C</a>
    """

    first.is_redirect = False
    first.is_permanent_redirect = False


    page = Mock()

    page.status_code = 200

    page.headers = {
        "Content-Type": "text/html"
    }

    page.text = ""

    page.is_redirect = False
    page.is_permanent_redirect = False


    mock_get.side_effect = [
        first,
        page,
    ]


    result = crawl_site(
        start_url="https://example.com",
        allowed_domains={
            "example.com"
        },
        max_depth=2,
        max_pages=2,
        delay_seconds=0,
    )


    assert (
        result["visited_count"]
        <= 2
    )

    assert (
        mock_get.call_count
        <= 2
    )


# ============================================================
# PROFONDEUR MAX
# ============================================================


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_crawl_respects_depth(
    mock_get
):

    root = Mock()

    root.status_code = 200

    root.headers = {
        "Content-Type": "text/html"
    }

    root.text = """
    <a href="/level1">Level1</a>
    """

    root.is_redirect = False
    root.is_permanent_redirect = False


    level_one = Mock()

    level_one.status_code = 200

    level_one.headers = {
        "Content-Type": "text/html"
    }

    level_one.text = """
    <a href="/level2">Level2</a>
    """

    level_one.is_redirect = False
    level_one.is_permanent_redirect = False


    mock_get.side_effect = [
        root,
        level_one,
    ]


    result = crawl_site(
        start_url="https://example.com",
        allowed_domains={
            "example.com"
        },
        max_depth=1,
        max_pages=10,
        delay_seconds=0,
    )


    urls = {
        page["final_url"]
        for page
        in result["pages"]
    }


    assert (
        "https://example.com/"
        in urls
    )

    assert (
        "https://example.com/level1"
        in urls
    )

    assert (
        "https://example.com/level2"
        not in urls
    )