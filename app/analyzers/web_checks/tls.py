"""
Contrôles passifs liés à HTTPS et TLS.
"""

from urllib.parse import urlparse


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


def check_tls_usage(
    requested_url: str,
    final_url: str,
    response,
) -> dict:
    """
    Analyse l'utilisation de HTTPS et HSTS.

    La validation réelle du certificat est déjà
    effectuée par requests lorsque verify=True,
    qui est la valeur par défaut.
    """

    checks = []
    findings = []

    requested_scheme = (
        urlparse(
            requested_url
        ).scheme.lower()
    )

    final_scheme = (
        urlparse(
            final_url
        ).scheme.lower()
    )


    # ========================================================
    # HTTPS INITIAL
    # ========================================================

    if requested_scheme == "https":

        checks.append(
            make_check(
                "HTTPS_INITIAL",
                "HTTPS sur l'URL initiale",
                "PASSED",
                "La requête initiale utilise HTTPS.",
            )
        )

    else:

        checks.append(
            make_check(
                "HTTPS_INITIAL",
                "HTTPS sur l'URL initiale",
                "FAILED",
                "La requête initiale utilise HTTP.",
            )
        )

        findings.append(
            {
                "event_type": "HTTPS_MISSING",
                "source_type": "WEB",
                "target": requested_url,
                "url": requested_url,
                "classification": "MISCONFIGURATION",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "message": (
                    "La requête initiale utilise HTTP."
                ),
                "description": (
                    "La première connexion n'est pas "
                    "protégée par TLS."
                ),
                "recommendation": (
                    "Utiliser HTTPS dès l'URL initiale "
                    "et rediriger HTTP vers HTTPS."
                ),
                "validation_method": (
                    "Tester directement l'URL HTTP "
                    "et vérifier la politique HTTPS."
                ),
                "status": "OPEN",
            }
        )


    # ========================================================
    # URL FINALE
    # ========================================================

    if final_scheme == "https":

        checks.append(
            make_check(
                "HTTPS_FINAL",
                "HTTPS sur l'URL finale",
                "PASSED",
                "L'URL finale utilise HTTPS.",
            )
        )

    else:

        checks.append(
            make_check(
                "HTTPS_FINAL",
                "HTTPS sur l'URL finale",
                "FAILED",
                "L'URL finale utilise HTTP.",
            )
        )


    # ========================================================
    # HSTS
    # ========================================================

    if final_scheme != "https":

        checks.append(
            make_check(
                "HSTS",
                "Strict-Transport-Security",
                "SKIPPED",
                "HSTS n'est pertinent que sur HTTPS.",
            )
        )

    else:

        hsts = response.headers.get(
            "Strict-Transport-Security"
        )

        if hsts:

            checks.append(
                make_check(
                    "HSTS",
                    "Strict-Transport-Security",
                    "PASSED",
                    "L'en-tête HSTS est présent.",
                )
            )

        else:

            checks.append(
                make_check(
                    "HSTS",
                    "Strict-Transport-Security",
                    "FAILED",
                    "L'en-tête HSTS est absent.",
                )
            )

            findings.append(
                {
                    "event_type": "HSTS_MISSING",
                    "source_type": "WEB",
                    "target": final_url,
                    "url": final_url,
                    "classification": "MISCONFIGURATION",
                    "severity": "LOW",
                    "confidence": "HIGH",
                    "message": (
                        "Strict-Transport-Security "
                        "est absent."
                    ),
                    "description": (
                        "Le site utilise HTTPS mais "
                        "n'annonce pas HSTS."
                    ),
                    "recommendation": (
                        "Configurer HSTS après validation "
                        "de la politique HTTPS du domaine."
                    ),
                    "validation_method": (
                        "Inspecter Strict-Transport-Security "
                        "sur une réponse HTTPS."
                    ),
                    "status": "OPEN",
                }
            )


    # ========================================================
    # VALIDATION DU CERTIFICAT
    # ========================================================

    if final_scheme == "https":

        checks.append(
            make_check(
                "TLS_CERTIFICATE_VALIDATION",
                "Validation du certificat TLS",
                "PASSED",
                (
                    "La requête HTTPS a abouti avec "
                    "la validation TLS activée."
                ),
            )
        )

    else:

        checks.append(
            make_check(
                "TLS_CERTIFICATE_VALIDATION",
                "Validation du certificat TLS",
                "SKIPPED",
                "Aucune connexion TLS utilisée.",
            )
        )


    return {
        "checks": checks,
        "findings": findings,
    }