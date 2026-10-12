import re


TECHNICAL_HEADERS = {
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
}


DEBUG_PATTERNS = [
    re.compile(
        r"traceback \(most recent call last\)",
        re.IGNORECASE
    ),
    re.compile(
        r"stack trace",
        re.IGNORECASE
    ),
    re.compile(
        r"fatal error",
        re.IGNORECASE
    ),
    re.compile(
        r"uncaught exception",
        re.IGNORECASE
    ),
    re.compile(
        r"debug mode",
        re.IGNORECASE
    ),
    re.compile(
        r"sql syntax.*mysql",
        re.IGNORECASE
    ),
    re.compile(
        r"warning:.*php",
        re.IGNORECASE
    ),
]


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


def mask_evidence(
    value: str,
    max_length: int = 160,
) -> str:
    """
    Réduit la quantité de contenu conservé
    comme preuve.
    """

    value = (
        value
        .replace("\n", " ")
        .replace("\r", " ")
        .strip()
    )

    if len(value) > max_length:
        return (
            value[:max_length]
            + "..."
        )

    return value


def check_information_disclosure(
    response,
    target_url: str,
) -> dict:
    """
    Recherche passivement certains indices
    de divulgation d'informations techniques.
    """

    checks = []
    findings = []

    headers = response.headers

    body = (
        response.text
        if isinstance(
            response.text,
            str
        )
        else ""
    )


    # ========================================================
    # HEADERS TECHNIQUES
    # ========================================================

    exposed_headers = {}

    for header_name in TECHNICAL_HEADERS:

        value = headers.get(
            header_name
        )

        if value:

            exposed_headers[
                header_name
            ] = value

    if exposed_headers:

        checks.append(
            make_check(
                "TECHNICAL_HEADERS",
                "Informations techniques dans les headers",
                "FAILED",
                (
                    f"{len(exposed_headers)} "
                    "en-tête(s) technique(s) exposé(s)."
                ),
            )
        )

        for (
            header_name,
            header_value
        ) in exposed_headers.items():

            findings.append(
                {
                    "event_type": (
                        "TECHNOLOGY_DISCLOSURE"
                    ),
                    "source_type": "WEB",
                    "target": target_url,
                    "url": target_url,
                    "classification": "INFO",
                    "severity": "INFO",
                    "confidence": "HIGH",
                    "message": (
                        f"L'en-tête {header_name} "
                        "divulgue une information technique."
                    ),
                    "description": (
                        "La réponse HTTP révèle des informations "
                        "sur la technologie ou le serveur."
                    ),
                    "evidence": mask_evidence(
                        f"{header_name}: {header_value}"
                    ),
                    "recommendation": (
                        "Réduire les informations techniques "
                        "exposées lorsque cela est possible."
                    ),
                    "validation_method": (
                        "Inspecter les en-têtes HTTP."
                    ),
                    "status": "OPEN",
                }
            )

    else:

        checks.append(
            make_check(
                "TECHNICAL_HEADERS",
                "Informations techniques dans les headers",
                "PASSED",
                "Aucun header technique courant détecté.",
            )
        )


    # ========================================================
    # ERREURS / DEBUG
    # ========================================================

    matched_debug_pattern = None

    for pattern in DEBUG_PATTERNS:

        match = pattern.search(
            body
        )

        if match:

            matched_debug_pattern = (
                match.group(0)
            )

            break

    if matched_debug_pattern:

        checks.append(
            make_check(
                "DEBUG_DISCLOSURE",
                "Messages d'erreur détaillés",
                "FAILED",
                "Une trace ou erreur technique a été détectée.",
            )
        )

        findings.append(
            {
                "event_type": (
                    "DEBUG_INFORMATION_DISCLOSURE"
                ),
                "source_type": "WEB",
                "target": target_url,
                "url": target_url,
                "classification": (
                    "SUSPICION"
                ),
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "message": (
                    "La réponse semble contenir une "
                    "trace d'erreur ou de débogage."
                ),
                "description": (
                    "Une page d'erreur détaillée peut révéler "
                    "des chemins, technologies ou détails "
                    "internes de l'application."
                ),
                "evidence": mask_evidence(
                    matched_debug_pattern
                ),
                "recommendation": (
                    "Désactiver l'affichage détaillé des "
                    "erreurs en production et utiliser une "
                    "journalisation côté serveur."
                ),
                "validation_method": (
                    "Examiner manuellement la réponse afin de "
                    "confirmer qu'il s'agit réellement d'une "
                    "information interne."
                ),
                "status": "OPEN",
            }
        )

    else:

        checks.append(
            make_check(
                "DEBUG_DISCLOSURE",
                "Messages d'erreur détaillés",
                "PASSED",
                "Aucune signature d'erreur détaillée détectée.",
            )
        )

    return {
        "checks": checks,
        "findings": findings,
    }