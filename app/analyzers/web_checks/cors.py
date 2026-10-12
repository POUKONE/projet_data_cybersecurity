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


def check_cors(
    response,
    target_url: str,
) -> dict:
    """
    Analyse passive des en-têtes CORS.

    Cette fonction ne confirme pas une vulnérabilité
    uniquement à partir d'un header permissif.
    """

    checks = []
    findings = []

    allow_origin = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    allow_credentials = response.headers.get(
        "Access-Control-Allow-Credentials"
    )

    if not allow_origin:

        checks.append(
            make_check(
                "CORS",
                "Configuration CORS",
                "SKIPPED",
                "Aucun en-tête CORS observé.",
            )
        )

        return {
            "checks": checks,
            "findings": findings,
        }

    checks.append(
        make_check(
            "CORS",
            "Configuration CORS",
            "PASSED",
            "Des en-têtes CORS sont présents.",
        )
    )

    normalized_origin = (
        allow_origin
        .strip()
        .lower()
    )

    credentials_enabled = (
        str(
            allow_credentials
            or ""
        )
        .strip()
        .lower()
        == "true"
    )

    if normalized_origin == "*":

        findings.append(
            {
                "event_type": (
                    "CORS_WILDCARD_ORIGIN"
                ),
                "source_type": "WEB",
                "target": target_url,
                "url": target_url,
                "classification": (
                    "SUSPICION"
                ),
                "severity": (
                    "MEDIUM"
                    if credentials_enabled
                    else "LOW"
                ),
                "confidence": "MEDIUM",
                "message": (
                    "Le serveur autorise les origines "
                    "CORS avec un wildcard."
                ),
                "description": (
                    "Une politique Access-Control-Allow-Origin "
                    "égale à * peut être trop permissive selon "
                    "les ressources exposées."
                ),
                "evidence": (
                    "Access-Control-Allow-Origin: *"
                ),
                "recommendation": (
                    "Limiter CORS aux origines réellement "
                    "nécessaires."
                ),
                "validation_method": (
                    "Vérifier manuellement quelles ressources "
                    "sont accessibles cross-origin et si elles "
                    "contiennent des données sensibles."
                ),
                "status": "OPEN",
            }
        )

    if (
        credentials_enabled
        and normalized_origin == "*"
    ):

        findings.append(
            {
                "event_type": (
                    "CORS_WILDCARD_WITH_CREDENTIALS"
                ),
                "source_type": "WEB",
                "target": target_url,
                "url": target_url,
                "classification": (
                    "SUSPICION"
                ),
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "message": (
                    "Une combinaison CORS potentiellement "
                    "dangereuse a été observée."
                ),
                "description": (
                    "Le serveur annonce à la fois une origine "
                    "wildcard et l'utilisation de credentials. "
                    "Cette observation doit être validée dans "
                    "le contexte réel du navigateur."
                ),
                "evidence": (
                    "Access-Control-Allow-Origin: * ; "
                    "Access-Control-Allow-Credentials: true"
                ),
                "recommendation": (
                    "Utiliser une liste explicite d'origines "
                    "et revoir la nécessité des credentials."
                ),
                "validation_method": (
                    "Tester manuellement le comportement CORS "
                    "depuis une origine contrôlée."
                ),
                "status": "OPEN",
            }
        )

    return {
        "checks": checks,
        "findings": findings,
    }