from unittest.mock import (
    Mock,
    patch,
)

from requests.cookies import (
    RequestsCookieJar,
)

from app.analyzers.web_analyzer import (
    analyze_web_security,
)


def build_response(
    html: str,
    headers: dict | None = None,
    status_code: int = 200,
):
    """
    Crée une réponse HTTP simulée.
    """

    response = Mock()

    response.status_code = (
        status_code
    )

    response.headers = (
        headers
        or {
            "Content-Type": (
                "text/html"
            )
        }
    )

    response.text = html

    response.cookies = (
        RequestsCookieJar()
    )

    response.is_redirect = False
    response.is_permanent_redirect = False

    return response


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_multi_page_passive_audit(
    mock_get
):
    """
    Vérifie qu'un audit passif multi-pages :
    - visite plusieurs pages ;
    - ne télécharge chaque page qu'une seule fois ;
    - analyse les formulaires ;
    - agrège les findings.
    """

    root_response = build_response(
        """
        <html>
            <body>

                <a href="/login">
                    Login
                </a>

                <a href="/about">
                    About
                </a>

            </body>
        </html>
        """
    )


    login_response = build_response(
        """
        <html>
            <body>

                <form
                    action="/login"
                    method="post"
                >

                    <input
                        type="text"
                        name="username"
                    >

                    <input
                        type="password"
                        name="password"
                    >

                </form>

            </body>
        </html>
        """
    )


    about_response = build_response(
        """
        <html>
            <body>
                About
            </body>
        </html>
        """
    )


    mock_get.side_effect = [
        root_response,
        login_response,
        about_response,
    ]


    report = analyze_web_security(
        url="http://example.com",
        max_depth=1,
        max_pages=5,
        delay_seconds=0,
    )


    assert (
        report["audit_status"]
        == "COMPLETED"
    )


    assert (
        report["crawl"][
            "visited_count"
        ]
        == 3
    )


    assert (
        len(
            report["pages"]
        )
        == 3
    )


    page_urls = {
        page["final_url"]
        for page
        in report["pages"]
    }


    assert (
        "http://example.com/"
        in page_urls
    )


    assert (
        "http://example.com/login"
        in page_urls
    )


    assert (
        "http://example.com/about"
        in page_urls
    )


    assert (
        len(
            report["forms"]
        )
        >= 1
    )


    event_types = {
        finding["event_type"]
        for finding
        in report["findings"]
    }


    assert (
        "HTTPS_MISSING"
        in event_types
    )


    assert (
        "SENSITIVE_FORM_OVER_HTTP"
        in event_types
    )


    assert (
        report["finding_count"]
        == len(
            report["findings"]
        )
    )


    # 3 pages visitées = 3 requêtes HTTP.
    assert (
        report["request_count"]
        == 3
    )


    assert (
        mock_get.call_count
        == 3
    )