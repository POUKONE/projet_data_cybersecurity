"""
Contrôles passifs des en-têtes HTTP de sécurité.
"""


def make_finding(
    *,
    event_type: str,
    target: str,
    message: str,
    description: str,
    severity: str,
    confidence: str = "HIGH",
    classification: str = "MISCONFIGURATION",
    status_code: int | None = None,
    evidence: str | None = None,
    recommendation: str | None = None,
    validation_method: str | None = None,
) -> dict:
    """
    Construit un finding Web normalisé.
    """

    return {
        "event_type": event_type,
        "source_type": "WEB",
        "target": target,
        "url": target,
        "classification": classification,
        "severity": severity,
        "confidence": confidence,
        "message": message,
        "description": description,
        "status_code": status_code,
        "evidence": evidence,
        "recommendation": recommendation,
        "validation_method": validation_method,
        "status": "OPEN",
    }


def make_check(
    check_id: str,
    name: str,
    status: str,
    message: str,
) -> dict:
    """
    Construit le résultat standardisé d'un contrôle.
    """

    return {
        "check_id": check_id,
        "name": name,
        "status": status,
        "message": message,
    }


def check_security_headers(
    response,
    target_url: str,
) -> dict:
    """
    Vérifie les principaux en-têtes HTTP
    de sécurité.

    Retour :
    {
        "checks": [...],
        "findings": [...]
    }
    """

    checks = []
    findings = []

    headers = response.headers
    status_code = response.status_code


    # ========================================================
    # CONTENT-SECURITY-POLICY
    # ========================================================

    csp = headers.get(
        "Content-Security-Policy"
    )

    if csp:

        checks.append(
            make_check(
                "CSP",
                "Content-Security-Policy",
                "PASSED",
                "Une politique CSP est présente.",
            )
        )

    else:

        checks.append(
            make_check(
                "CSP",
                "Content-Security-Policy",
                "FAILED",
                "Aucune politique CSP détectée.",
            )
        )

        findings.append(
            make_finding(
                event_type="CSP_MISSING",
                target=target_url,
                status_code=status_code,
                severity="LOW",
                confidence="HIGH",
                message=(
                    "L'en-tête Content-Security-Policy "
                    "est absent."
                ),
                description=(
                    "Le serveur ne définit pas de politique "
                    "Content-Security-Policy."
                ),
                recommendation=(
                    "Définir une politique CSP adaptée aux "
                    "ressources réellement utilisées."
                ),
                validation_method=(
                    "Vérifier la réponse HTTP et confirmer "
                    "la présence de Content-Security-Policy."
                ),
            )
        )


    # ========================================================
    # X-CONTENT-TYPE-OPTIONS
    # ========================================================

    content_type_options = headers.get(
        "X-Content-Type-Options"
    )

    if (
        content_type_options
        and content_type_options.lower()
        == "nosniff"
    ):

        checks.append(
            make_check(
                "X_CONTENT_TYPE_OPTIONS",
                "X-Content-Type-Options",
                "PASSED",
                "X-Content-Type-Options est correctement configuré.",
            )
        )

    else:

        checks.append(
            make_check(
                "X_CONTENT_TYPE_OPTIONS",
                "X-Content-Type-Options",
                "FAILED",
                "X-Content-Type-Options est absent ou incorrect.",
            )
        )

        findings.append(
            make_finding(
                event_type="X_CONTENT_TYPE_OPTIONS_MISSING",
                target=target_url,
                status_code=status_code,
                severity="LOW",
                message=(
                    "X-Content-Type-Options: nosniff "
                    "n'a pas été détecté."
                ),
                description=(
                    "Le navigateur peut tenter d'interpréter "
                    "le type de certains contenus."
                ),
                evidence=(
                    str(content_type_options)
                    if content_type_options
                    else "Header absent"
                ),
                recommendation=(
                    "Ajouter X-Content-Type-Options: nosniff."
                ),
                validation_method=(
                    "Inspecter les en-têtes HTTP de la réponse."
                ),
            )
        )


    # ========================================================
    # PROTECTION CONTRE LE FRAMING
    # ========================================================

    frame_options = headers.get(
        "X-Frame-Options"
    )

    csp_lower = (
        csp.lower()
        if csp
        else ""
    )

    has_frame_ancestors = (
        "frame-ancestors"
        in csp_lower
    )

    if (
        frame_options
        or has_frame_ancestors
    ):

        checks.append(
            make_check(
                "FRAME_PROTECTION",
                "Protection contre le framing",
                "PASSED",
                "Une protection contre le framing est présente.",
            )
        )

    else:

        checks.append(
            make_check(
                "FRAME_PROTECTION",
                "Protection contre le framing",
                "FAILED",
                "Aucune protection contre le framing détectée.",
            )
        )

        findings.append(
            make_finding(
                event_type="X_FRAME_OPTIONS_MISSING",
                target=target_url,
                status_code=status_code,
                severity="LOW",
                message=(
                    "Aucune protection explicite contre "
                    "le framing n'a été détectée."
                ),
                description=(
                    "Ni X-Frame-Options ni une directive "
                    "CSP frame-ancestors n'a été détectée."
                ),
                recommendation=(
                    "Définir frame-ancestors dans CSP ou "
                    "X-Frame-Options selon le contexte."
                ),
                validation_method=(
                    "Inspecter CSP et X-Frame-Options."
                ),
            )
        )


    # ========================================================
    # REFERRER-POLICY
    # ========================================================

    referrer_policy = headers.get(
        "Referrer-Policy"
    )

    if referrer_policy:

        checks.append(
            make_check(
                "REFERRER_POLICY",
                "Referrer-Policy",
                "PASSED",
                "Une politique Referrer-Policy est présente.",
            )
        )

    else:

        checks.append(
            make_check(
                "REFERRER_POLICY",
                "Referrer-Policy",
                "FAILED",
                "Referrer-Policy est absent.",
            )
        )

        findings.append(
            make_finding(
                event_type="REFERRER_POLICY_MISSING",
                target=target_url,
                status_code=status_code,
                severity="LOW",
                message=(
                    "L'en-tête Referrer-Policy est absent."
                ),
                description=(
                    "Le serveur ne définit pas explicitement "
                    "la quantité d'information envoyée dans "
                    "le champ Referer."
                ),
                recommendation=(
                    "Définir une Referrer-Policy appropriée, "
                    "par exemple strict-origin-when-cross-origin."
                ),
                validation_method=(
                    "Inspecter les en-têtes HTTP."
                ),
            )
        )


    return {
        "checks": checks,
        "findings": findings,
    }