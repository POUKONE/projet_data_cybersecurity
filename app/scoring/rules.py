"""
Règles de scoring du projet Data & Cybersécurité.

Chaque événement possède :
- un score de base ;
- une sévérité indicative.

Le score peut ensuite être ajusté par
le moteur de scoring selon le contexte.
"""


SECURITY_RULES = {

    # ========================================================
    # LOGS
    # ========================================================

    "FAILED_LOGIN_BURST": {
        "base_score": 40,
        "severity": "HIGH",
    },


    # ========================================================
    # RÉSEAU
    # ========================================================

    "NEW_PORT_DETECTED": {
        "base_score": 20,
        "severity": "MEDIUM",
    },

    "NEW_SERVICE_DETECTED": {
        "base_score": 25,
        "severity": "MEDIUM",
    },


    # ========================================================
    # WEB - HTTPS / HEADERS
    # ========================================================

    "HTTPS_MISSING": {
        "base_score": 30,
        "severity": "HIGH",
    },

    "CSP_MISSING": {
        "base_score": 15,
        "severity": "MEDIUM",
    },

    "HSTS_MISSING": {
        "base_score": 20,
        "severity": "MEDIUM",
    },

    "X_CONTENT_TYPE_OPTIONS_MISSING": {
        "base_score": 10,
        "severity": "LOW",
    },

    "X_FRAME_OPTIONS_MISSING": {
        "base_score": 15,
        "severity": "MEDIUM",
    },

    "REFERRER_POLICY_MISSING": {
        "base_score": 10,
        "severity": "LOW",
    },


    # ========================================================
    # WEB - COOKIES
    # ========================================================

    "COOKIE_SECURE_MISSING": {
        "base_score": 30,
        "severity": "MEDIUM",
    },

    "COOKIE_HTTPONLY_MISSING": {
        "base_score": 15,
        "severity": "LOW",
    },

    "COOKIE_SAMESITE_MISSING": {
        "base_score": 15,
        "severity": "LOW",
    },


    # ========================================================
    # WEB - FORMULAIRES
    # ========================================================

    "SENSITIVE_FORM_OVER_HTTP": {
        "base_score": 55,
        "severity": "HIGH",
    },


    # ========================================================
    # WEB - CORS
    # ========================================================

    "CORS_WILDCARD_ORIGIN": {
        "base_score": 20,
        "severity": "LOW",
    },

    "CORS_WILDCARD_WITH_CREDENTIALS": {
        "base_score": 45,
        "severity": "MEDIUM",
    },


    # ========================================================
    # WEB - DIVULGATION
    # ========================================================

    "TECHNOLOGY_DISCLOSURE": {
        "base_score": 10,
        "severity": "LOW",
    },

    "DEBUG_INFORMATION_DISCLOSURE": {
        "base_score": 35,
        "severity": "MEDIUM",
    },


    # ========================================================
    # TRAFIC
    # ========================================================

    "HIGH_PACKET_ACTIVITY": {
        "base_score": 30,
        "severity": "HIGH",
    },

    "PORT_SCAN_ACTIVITY": {
        "base_score": 45,
        "severity": "HIGH",
    },
}


# ============================================================
# RÉCUPÉRATION D'UNE RÈGLE
# ============================================================


def get_rule(
    event_type: str,
) -> dict | None:
    """
    Retourne la règle associée à un type d'événement.

    La recherche est insensible à la casse.
    """

    if not event_type:

        return None


    normalized_event_type = (
        str(
            event_type
        )
        .strip()
        .upper()
    )


    return SECURITY_RULES.get(
        normalized_event_type
    )