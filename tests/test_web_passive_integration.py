from unittest.mock import Mock, patch

from requests.cookies import (
    RequestsCookieJar,
    create_cookie,
)

from app.analyzers.web_analyzer import (
    analyze_web_security,
)


@patch(
    "app.collectors.web_collector.requests.get"
)
def test_passive_web_audit_integration(
    mock_get
):
    """
    Vérifie l'intégration complète de l'audit Web passif :
    - collecte HTTP ;
    - TLS/HTTPS ;
    - headers ;
    - cookies ;
    - formulaires ;
    - divulgation d'informations.
    """

    response = Mock()

    response.status_code = 200
    response.is_redirect = False
    response.is_permanent_redirect = False

    response.headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.57",
    }

    response.text = """
    <html>
        <body>

            <form
                action="/login"
                method="post"
            >
                <input
                    name="username"
                    type="text"
                >

                <input
                    name="password"
                    type="password"
                >

            </form>

        </body>
    </html>
    """

    jar = RequestsCookieJar()

    jar.set_cookie(
        create_cookie(
            name="session",
            value="test",
            secure=False,
            rest={},
        )
    )

    response.cookies = jar

    mock_get.return_value = response


    result = analyze_web_security(
        "http://example.com"
    )


    # ========================================================
    # AUDIT GLOBAL
    # ========================================================

    assert (
        result["audit_status"]
        == "COMPLETED"
    )

    assert (
        result["mode"]
        == "PASSIVE"
    )

    assert (
        result["request_count"]
        == 1
    )


    # ========================================================
    # PAGE
    # ========================================================

    assert (
        len(
            result["pages"]
        )
        == 1
    )

    assert (
        result["pages"][0][
            "url"
        ]
        == "http://example.com"
    )

    assert (
        result["pages"][0][
            "status_code"
        ]
        == 200
    )


    # ========================================================
    # FORMULAIRE
    # ========================================================

    assert (
        len(
            result["forms"]
        )
        == 1
    )

    form = result[
        "forms"
    ][0]

    assert (
        form["method"]
        == "POST"
    )

    assert (
        form["action"]
        == "http://example.com/login"
    )

    assert (
        len(
            form["fields"]
        )
        == 2
    )


    # ========================================================
    # FINDINGS
    # ========================================================

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }


    assert (
        "HTTPS_MISSING"
        in event_types
    )

    assert (
        "CSP_MISSING"
        in event_types
    )

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

    assert (
        "COOKIE_HTTPONLY_MISSING"
        in event_types
    )

    assert (
        "COOKIE_SAMESITE_MISSING"
        in event_types
    )

    assert (
        "SENSITIVE_FORM_OVER_HTTP"
        in event_types
    )

    assert (
        "TECHNOLOGY_DISCLOSURE"
        in event_types
    )


    # ========================================================
    # COMPATIBILITÉ DETECTIONS
    # ========================================================

    assert (
        result["detections"]
        == result["findings"]
    )


    # ========================================================
    # COUVERTURE
    # ========================================================

    coverage = result[
        "coverage"
    ]

    assert (
        coverage["executed"]
        > 0
    )

    assert (
        coverage["failed"]
        > 0
    )


    # ========================================================
    # LIMITATIONS
    # ========================================================

    assert (
        len(
            result["limitations"]
        )
        > 0
    )