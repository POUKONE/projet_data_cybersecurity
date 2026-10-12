"""
Contrôles passifs des attributs de sécurité des cookies.
"""


def make_check(
    check_id: str,
    name: str,
    status: str,
    message: str,
) -> dict:

    return {
        "check_id": check_id,
        "name": name,
        "status": status,
        "message": message,
    }


def make_cookie_finding(
    *,
    event_type: str,
    target_url: str,
    cookie_name: str,
    message: str,
    description: str,
    severity: str = "LOW",
) -> dict:

    return {
        "event_type": event_type,
        "source_type": "WEB",
        "target": target_url,
        "url": target_url,
        "classification": "MISCONFIGURATION",
        "severity": severity,
        "confidence": "HIGH",
        "parameter": cookie_name,
        "message": message,
        "description": description,
        "evidence": (
            f"Cookie concerné : {cookie_name}"
        ),
        "recommendation": (
            "Configurer les attributs de sécurité "
            "adaptés au rôle du cookie."
        ),
        "validation_method": (
            "Inspecter l'en-tête Set-Cookie de la réponse."
        ),
        "status": "OPEN",
    }


def check_cookie_security(
    response,
    target_url: str,
) -> dict:
    """
    Vérifie les attributs Secure, HttpOnly et SameSite
    des cookies présents dans la réponse.

    Ce contrôle ne suppose pas automatiquement qu'un
    cookie est sensible. Les absences sont donc traitées
    comme des faiblesses de configuration.
    """

    checks = []
    findings = []

    cookies = response.cookies


    if not cookies:

        checks.append(
            make_check(
                "COOKIES_PRESENT",
                "Présence de cookies",
                "SKIPPED",
                "Aucun cookie n'a été reçu.",
            )
        )

        return {
            "checks": checks,
            "findings": findings,
        }


    checks.append(
        make_check(
            "COOKIES_PRESENT",
            "Présence de cookies",
            "PASSED",
            f"{len(cookies)} cookie(s) reçu(s).",
        )
    )


    for cookie in cookies:

        cookie_name = cookie.name


        # ====================================================
        # SECURE
        # ====================================================

        if target_url.lower().startswith(
            "https://"
        ):

            if not cookie.secure:

                findings.append(
                    make_cookie_finding(
                        event_type="COOKIE_SECURE_MISSING",
                        target_url=target_url,
                        cookie_name=cookie_name,
                        severity="MEDIUM",
                        message=(
                            f"Le cookie {cookie_name} "
                            "n'utilise pas l'attribut Secure."
                        ),
                        description=(
                            "Sur une connexion HTTPS, un cookie "
                            "sans Secure peut être transmis "
                            "sur une connexion non protégée "
                            "dans certains scénarios."
                        ),
                    )
                )


        # ====================================================
        # HTTPONLY
        # ====================================================
        cookie_rest = {
            str(key).lower(): value
            for key, value
            in cookie._rest.items()
}


        has_httponly = (
            "httponly"
            in cookie_rest
)


        if not has_httponly:

            findings.append(
                make_cookie_finding(
                event_type="COOKIE_HTTPONLY_MISSING",
                target_url=target_url,
                cookie_name=cookie_name,
                severity="LOW",
                message=(
                    f"Le cookie {cookie_name} "
                    "n'utilise pas HttpOnly."
            ),
                description=(
                    "Le cookie reste accessible au "
                    "JavaScript côté client. La pertinence "
                    "dépend du rôle réel du cookie."
            ),
        )
    )

        # ====================================================
        # SAMESITE
        # ====================================================

        same_site = cookie_rest.get(
            "samesite"
)
    

        if not same_site:

            findings.append(
                make_cookie_finding(
                    event_type="COOKIE_SAMESITE_MISSING",
                    target_url=target_url,
                    cookie_name=cookie_name,
                    severity="LOW",
                    message=(
                        f"Le cookie {cookie_name} "
                        "ne définit pas SameSite."
                    ),
                    description=(
                        "Le comportement cross-site du cookie "
                        "n'est pas explicitement limité."
                    ),
                )
            )


    checks.append(
        make_check(
            "COOKIE_ATTRIBUTES",
            "Attributs de sécurité des cookies",
            (
                "FAILED"
                if findings
                else "PASSED"
            ),
            (
                f"{len(findings)} faiblesse(s) "
                "de configuration détectée(s)."
                if findings
                else (
                    "Aucune faiblesse évidente "
                    "détectée sur les attributs "
                    "des cookies."
                )
            ),
        )
    )


    return {
        "checks": checks,
        "findings": findings,
    }