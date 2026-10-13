from app.analyzers.web_analyzer import (
    calculate_site_risk,
)


def test_empty_site_risk():

    result = calculate_site_risk(
        []
    )


    assert (
        result["score"]
        == 0
    )

    assert (
        result["level"]
        == "LOW"
    )

    assert (
        result["contributors"]
        == []
    )


def test_single_csp_risk():

    summary = [
        {
            "event_type": (
                "CSP_MISSING"
            ),

            "affected_page_count": 1,

            "total_pages": 10,

            "coverage_percentage": 10.0,
        }
    ]


    result = calculate_site_risk(
        summary
    )


    assert (
        result["score"]
        == 15
    )

    assert (
        result["level"]
        == "LOW"
    )


def test_widespread_csp_gets_small_bonus():

    summary = [
        {
            "event_type": (
                "CSP_MISSING"
            ),

            "affected_page_count": 9,

            "total_pages": 10,

            "coverage_percentage": 90.0,
        }
    ]


    result = calculate_site_risk(
        summary
    )


    assert (
        result["score"]
        == 25
    )


def test_duplicate_pages_do_not_multiply_score():

    summary = [
        {
            "event_type": (
                "CSP_MISSING"
            ),

            "affected_page_count": 100,

            "total_pages": 100,

            "coverage_percentage": 100.0,
        }
    ]


    result = calculate_site_risk(
        summary
    )


    # CSP base = 15
    # propagation bonus max = 10
    assert (
        result["score"]
        == 25
    )


def test_multiple_unique_findings_are_combined():

    summary = [
        {
            "event_type": (
                "CSP_MISSING"
            ),

            "affected_page_count": 5,

            "total_pages": 10,

            "coverage_percentage": 50.0,
        },

        {
            "event_type": (
                "HTTPS_MISSING"
            ),

            "affected_page_count": 10,

            "total_pages": 10,

            "coverage_percentage": 100.0,
        },
    ]


    result = calculate_site_risk(
        summary
    )


    # CSP = 15 + 5
    # HTTPS = 30 + 10
    assert (
        result["score"]
        == 60
    )

    assert (
        result["level"]
        == "HIGH"
    )


def test_site_risk_is_capped_at_100():

    summary = [
        {
            "event_type": (
                "HTTPS_MISSING"
            ),

            "affected_page_count": 10,

            "total_pages": 10,

            "coverage_percentage": 100.0,
        },

        {
            "event_type": (
                "SENSITIVE_FORM_OVER_HTTP"
            ),

            "affected_page_count": 10,

            "total_pages": 10,

            "coverage_percentage": 100.0,
        },

        {
            "event_type": (
                "CORS_WILDCARD_WITH_CREDENTIALS"
            ),

            "affected_page_count": 10,

            "total_pages": 10,

            "coverage_percentage": 100.0,
        },
    ]


    result = calculate_site_risk(
        summary
    )


    assert (
        result["score"]
        == 100
    )

    assert (
        result["level"]
        == "CRITICAL"
    )


def test_unknown_finding_is_ignored():

    summary = [
        {
            "event_type": (
                "UNKNOWN_WEB_FINDING"
            ),

            "affected_page_count": 10,

            "total_pages": 10,

            "coverage_percentage": 100.0,
        }
    ]


    result = calculate_site_risk(
        summary
    )


    assert (
        result["score"]
        == 0
    )