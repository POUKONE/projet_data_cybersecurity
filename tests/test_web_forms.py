from app.analyzers.web_checks.forms import (
    check_forms_security,
    extract_forms,
)


def test_extract_form():

    html = """
    <html>
        <body>
            <form action="/login" method="post">
                <input name="username" type="text">
                <input name="password" type="password">
            </form>
        </body>
    </html>
    """

    forms = extract_forms(
        html=html,
        page_url="https://example.com"
    )

    assert len(forms) == 1

    assert (
        forms[0]["method"]
        == "POST"
    )

    assert (
        forms[0]["action"]
        == "https://example.com/login"
    )

    assert (
        len(forms[0]["fields"])
        == 2
    )


def test_sensitive_form_over_http():

    html = """
    <form action="/login" method="post">
        <input name="username">
        <input name="password" type="password">
    </form>
    """

    result = check_forms_security(
        html=html,
        page_url="http://example.com"
    )

    event_types = {
        finding["event_type"]
        for finding
        in result["findings"]
    }

    assert (
        "SENSITIVE_FORM_OVER_HTTP"
        in event_types
    )


def test_sensitive_form_over_https():

    html = """
    <form action="/login" method="post">
        <input name="password" type="password">
    </form>
    """

    result = check_forms_security(
        html=html,
        page_url="https://example.com"
    )

    assert (
        result["findings"]
        == []
    )