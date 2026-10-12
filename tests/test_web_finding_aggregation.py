from app.analyzers.web_analyzer import (
    aggregate_web_findings,
)


def test_aggregate_same_finding_on_multiple_pages():

    findings = [
        {
            "event_type": "CSP_MISSING",
            "classification": "MISCONFIGURATION",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "url": "https://example.com/",
            "message": "CSP absent.",
        },
        {
            "event_type": "CSP_MISSING",
            "classification": "MISCONFIGURATION",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "url": "https://example.com/login",
            "message": "CSP absent.",
        },
        {
            "event_type": "CSP_MISSING",
            "classification": "MISCONFIGURATION",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "url": "https://example.com/about",
            "message": "CSP absent.",
        },
    ]


    summary = aggregate_web_findings(
        findings=findings,
        total_pages=5,
    )


    assert len(
        summary
    ) == 1


    item = summary[0]


    assert (
        item[
            "event_type"
        ]
        == "CSP_MISSING"
    )


    assert (
        item[
            "occurrence_count"
        ]
        == 3
    )


    assert (
        item[
            "affected_page_count"
        ]
        == 3
    )


    assert (
        item[
            "total_pages"
        ]
        == 5
    )


    assert (
        item[
            "coverage_percentage"
        ]
        == 60.0
    )


def test_same_url_is_not_counted_twice():

    findings = [
        {
            "event_type": (
                "CSP_MISSING"
            ),

            "url": (
                "https://example.com/"
            ),
        },
        {
            "event_type": (
                "CSP_MISSING"
            ),

            "url": (
                "https://example.com/"
            ),
        },
    ]


    summary = aggregate_web_findings(
        findings=findings,
        total_pages=1,
    )


    assert (
        summary[0][
            "occurrence_count"
        ]
        == 2
    )


    assert (
        summary[0][
            "affected_page_count"
        ]
        == 1
    )


    assert (
        summary[0][
            "coverage_percentage"
        ]
        == 100.0
    )


def test_different_findings_are_separated():

    findings = [
        {
            "event_type": (
                "CSP_MISSING"
            ),

            "url": (
                "https://example.com/"
            ),
        },

        {
            "event_type": (
                "HSTS_MISSING"
            ),

            "url": (
                "https://example.com/"
            ),
        },
    ]


    summary = aggregate_web_findings(
        findings=findings,
        total_pages=1,
    )


    assert len(
        summary
    ) == 2


    event_types = {
        item[
            "event_type"
        ]
        for item
        in summary
    }


    assert (
        "CSP_MISSING"
        in event_types
    )


    assert (
        "HSTS_MISSING"
        in event_types
    )


def test_empty_findings():

    summary = aggregate_web_findings(
        findings=[],
        total_pages=5,
    )


    assert (
        summary
        == []
    )