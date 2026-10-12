"""
Moteur central de scoring des événements de sécurité.

Responsabilités :
- récupérer les règles de scoring ;
- calculer le score de risque ;
- déterminer le niveau de risque ;
- déterminer la source de l'événement ;
- générer une description par défaut ;
- construire une alerte normalisée.

Le score de risque est indépendant de la confiance
du finding Web.
"""

from __future__ import annotations

from app.scoring.rules import (
    get_rule,
)


# ============================================================
# CONSTANTES
# ============================================================


SENSITIVE_PORTS = {
    21,
    22,
    23,
    25,
    445,
    1433,
    1521,
    3306,
    3389,
    5432,
    6379,
    27017,
}


WEB_EVENTS = {
    "HTTPS_MISSING",
    "CSP_MISSING",
    "HSTS_MISSING",
    "X_CONTENT_TYPE_OPTIONS_MISSING",
    "X_FRAME_OPTIONS_MISSING",
    "REFERRER_POLICY_MISSING",
    "COOKIE_SECURE_MISSING",
    "COOKIE_HTTPONLY_MISSING",
    "COOKIE_SAMESITE_MISSING",
    "SENSITIVE_FORM_OVER_HTTP",
    "CORS_WILDCARD_ORIGIN",
    "CORS_WILDCARD_WITH_CREDENTIALS",
    "TECHNOLOGY_DISCLOSURE",
    "DEBUG_INFORMATION_DISCLOSURE",
}


LOG_EVENTS = {
    "FAILED_LOGIN_BURST",
}


NETWORK_EVENTS = {
    "NEW_PORT_DETECTED",
    "NEW_SERVICE_DETECTED",
}


TRAFFIC_EVENTS = {
    "HIGH_PACKET_ACTIVITY",
    "PORT_SCAN_ACTIVITY",
}


# ============================================================
# NORMALISATION
# ============================================================


def normalize_event_type(
    event_type: str | None,
) -> str:
    """
    Normalise un type d'événement.
    """

    if not event_type:
        return ""

    return (
        str(event_type)
        .strip()
        .upper()
    )


# ============================================================
# NIVEAU DE RISQUE
# ============================================================


def get_risk_level(
    score: int | float,
) -> str:
    """
    Convertit un score numérique en niveau de risque.

    0 - 29   : LOW
    30 - 49  : MEDIUM
    50 - 69  : HIGH
    70 - 100 : CRITICAL
    """

    try:
        numeric_score = int(
            score
        )
    except (
        TypeError,
        ValueError,
    ):
        numeric_score = 0


    if numeric_score >= 70:
        return "CRITICAL"

    if numeric_score >= 50:
        return "HIGH"

    if numeric_score >= 30:
        return "MEDIUM"

    return "LOW"


# ============================================================
# SOURCE
# ============================================================


def get_source_type(
    event_type: str | None,
) -> str:
    """
    Détermine le module source à partir du type d'événement.
    """

    normalized = normalize_event_type(
        event_type
    )


    if normalized in LOG_EVENTS:
        return "LOG"


    if normalized in NETWORK_EVENTS:
        return "NETWORK"


    if normalized in WEB_EVENTS:
        return "WEB"


    if normalized in TRAFFIC_EVENTS:
        return "TRAFFIC"


    return "UNKNOWN"


# ============================================================
# SCORING
# ============================================================


def calculate_risk_score(
    detection: dict,
) -> int:
    """
    Calcule le score de risque à partir du type
    d'événement et de son contexte.

    Le score est toujours limité entre 0 et 100.
    """

    event_type = normalize_event_type(
        detection.get(
            "event_type"
        )
    )


    rule = get_rule(
        event_type
    )


    if rule is None:
       return 0


    score = int(
        rule.get(
            "base_score",
            0,
        )
    )


    # ========================================================
    # FAILED LOGIN BURST
    # ========================================================

    if (
        event_type
        == "FAILED_LOGIN_BURST"
    ):

        failed_attempts = int(
            detection.get(
                "failed_attempts",
                0,
            )
            or 0
        )


        if failed_attempts > 5:

            score += (
                failed_attempts
                - 5
            ) * 2


        targeted_users = detection.get(
            "targeted_users",
            [],
        )


        if isinstance(
            targeted_users,
            (list, tuple, set),
        ):

            unique_users = {
                str(user)
                for user
                in targeted_users
                if user is not None
            }


            if len(
                unique_users
            ) > 1:

                score += 10


    # ========================================================
    # NOUVEAU PORT
    # ========================================================

    elif (
        event_type
        == "NEW_PORT_DETECTED"
    ):

        try:

            port = int(
                detection.get(
                    "port"
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            port = None


        if (
            port is not None
            and port in SENSITIVE_PORTS
        ):

            score += 20


    # ========================================================
    # ACTIVITÉ PAQUETS
    # ========================================================

    elif (
        event_type
        == "HIGH_PACKET_ACTIVITY"
    ):

        packet_count = int(
            detection.get(
                "packet_count",
                0,
            )
            or 0
        )


        if packet_count > 50:

            score += min(
                (
                    packet_count
                    - 50
                )
                // 10,
                20,
            )


    # ========================================================
    # PORT SCAN
    # ========================================================

    elif (
        event_type
        == "PORT_SCAN_ACTIVITY"
    ):

        unique_ports = int(
            detection.get(
                "unique_ports",
                0,
            )
            or 0
        )


        if unique_ports >= 50:

            score += 35

        elif unique_ports >= 20:

            score += 15


    # ========================================================
    # LIMITE DU SCORE
    # ========================================================

    return max(
        0,
        min(
            int(score),
            100,
        ),
    )


# ============================================================
# DESCRIPTION PAR DÉFAUT
# ============================================================


def build_default_description(
    event_type: str,
    detection: dict,
) -> str:
    """
    Génère une description lisible lorsque le détecteur
    n'en fournit pas.
    """

    event_type = normalize_event_type(
        event_type
    )


    descriptions = {

        # ----------------------------------------------------
        # LOG
        # ----------------------------------------------------

        "FAILED_LOGIN_BURST": (
            "Plusieurs échecs de connexion ont été détectés "
            "dans une courte période."
        ),

        # ----------------------------------------------------
        # NETWORK
        # ----------------------------------------------------

        "NEW_PORT_DETECTED": (
            "Un nouveau port ouvert a été détecté "
            "sur la cible réseau."
        ),

        "NEW_SERVICE_DETECTED": (
            "Un changement de service réseau a été détecté "
            "sur un port déjà connu."
        ),

        # ----------------------------------------------------
        # WEB
        # ----------------------------------------------------

        "HTTPS_MISSING": (
            "La communication avec l'application Web "
            "n'utilise pas HTTPS."
        ),

        "CSP_MISSING": (
            "L'en-tête Content-Security-Policy "
            "n'a pas été détecté."
        ),

        "HSTS_MISSING": (
            "L'application utilise HTTPS mais "
            "Strict-Transport-Security est absent."
        ),

        "X_CONTENT_TYPE_OPTIONS_MISSING": (
            "L'en-tête X-Content-Type-Options "
            "n'a pas été détecté."
        ),

        "X_FRAME_OPTIONS_MISSING": (
            "Aucune protection explicite contre "
            "le framing n'a été détectée."
        ),

        "REFERRER_POLICY_MISSING": (
            "L'en-tête Referrer-Policy "
            "n'a pas été détecté."
        ),

        "COOKIE_SECURE_MISSING": (
            "Un cookie ne possède pas l'attribut Secure "
            "alors que la page utilise HTTPS."
        ),

        "COOKIE_HTTPONLY_MISSING": (
            "Un cookie ne possède pas l'attribut HttpOnly."
        ),

        "COOKIE_SAMESITE_MISSING": (
            "Un cookie ne définit pas explicitement "
            "l'attribut SameSite."
        ),

        "SENSITIVE_FORM_OVER_HTTP": (
            "Un formulaire potentiellement sensible "
            "est transmis via HTTP."
        ),

        "CORS_WILDCARD_ORIGIN": (
            "Une politique CORS utilisant une origine "
            "wildcard a été observée."
        ),

        "CORS_WILDCARD_WITH_CREDENTIALS": (
            "Une configuration CORS potentiellement "
            "dangereuse a été observée."
        ),

        "TECHNOLOGY_DISCLOSURE": (
            "La réponse HTTP expose une information "
            "technique sur l'application ou le serveur."
        ),

        "DEBUG_INFORMATION_DISCLOSURE": (
            "La réponse semble contenir une trace "
            "d'erreur ou de débogage détaillée."
        ),

        # ----------------------------------------------------
        # TRAFFIC
        # ----------------------------------------------------

        "HIGH_PACKET_ACTIVITY": (
            "Une activité réseau anormalement élevée "
            "a été observée pour une adresse IP."
        ),

        "PORT_SCAN_ACTIVITY": (
            "Une même source a communiqué avec un nombre "
            "important de ports différents."
        ),
    }


    if event_type in descriptions:
        return descriptions[
            event_type
        ]


    target = (
        detection.get(
            "target"
        )
        or detection.get(
            "ip_address"
        )
        or detection.get(
            "host"
        )
        or detection.get(
            "url"
        )
    )


    if target:

        return (
            f"Événement de sécurité "
            f"{event_type} détecté sur {target}."
        )


    return (
        f"Événement de sécurité "
        f"{event_type} détecté."
    )


# ============================================================
# CONSTRUCTION D'UNE ALERTE
# ============================================================


def build_security_alert(
    detection: dict,
) -> dict:
    """
    Transforme une détection en alerte normalisée.
    """

    if not isinstance(
        detection,
        dict,
    ):
        raise ValueError(
            "La détection doit être un dictionnaire."
        )


    event_type = normalize_event_type(
        detection.get(
            "event_type"
        )
    )


    if not event_type:
        raise ValueError(
            "event_type est obligatoire."
        )


    # ========================================================
    # SCORE
    # ========================================================

    risk_score = calculate_risk_score(
        detection
    )


    risk_level = get_risk_level(
        risk_score
    )


    # ========================================================
    # SOURCE
    # ========================================================

    source_type = (
        detection.get(
            "source_type"
        )
        or get_source_type(
            event_type
        )
    )


    source_type = (
        str(
            source_type
        )
        .strip()
        .upper()
    )


    # ========================================================
    # CIBLE
    # ========================================================

    ip_address = detection.get(
        "ip_address"
    )

    host = detection.get(
        "host"
    )

    url = detection.get(
        "url"
    )

    target = detection.get(
        "target"
    )


    if not target:

        target = (
            url
            or host
            or ip_address
        )


    if target is not None:
        target = str(
            target
        )


    if ip_address is not None:
        ip_address = str(
            ip_address
        )


    if host is not None:
        host = str(
            host
        )


    if url is not None:
        url = str(
            url
        )


    # ========================================================
    # DESCRIPTION
    # ========================================================

    description = (
        detection.get(
            "description"
        )
        or build_default_description(
            event_type,
            detection,
        )
    )


    message = (
        detection.get(
            "message"
        )
        or description
    )


    # ========================================================
    # ALERTE COMMUNE
    # ========================================================

    alert = {
        "source_type": source_type,
        "target": target,
        "event_type": event_type,

        "ip_address": ip_address,
        "host": host,
        "url": url,

        "risk_score": risk_score,
        "risk_level": risk_level,

        "message": message,
        "description": description,

        "status": detection.get(
            "status",
            "OPEN",
        ),
    }


    # ========================================================
    # DONNÉES LOG
    # ========================================================

    if (
        "start_time"
        in detection
    ):

        alert[
            "start_time"
        ] = detection.get(
            "start_time"
        )


    if (
        "end_time"
        in detection
    ):

        alert[
            "end_time"
        ] = detection.get(
            "end_time"
        )


    if (
        "failed_attempts"
        in detection
    ):

        alert[
            "failed_attempts"
        ] = detection.get(
            "failed_attempts"
        )


    if (
        "targeted_users"
        in detection
    ):

        alert[
            "targeted_users"
        ] = (
            detection.get(
                "targeted_users"
            )
            or []
        )


    # ========================================================
    # DONNÉES RÉSEAU
    # ========================================================

    network_fields = [
        "protocol",
        "port",
        "state",
        "service",
        "previous_service",
        "product",
        "version",
    ]


    for field_name in network_fields:

        if field_name in detection:

            alert[
                field_name
            ] = detection.get(
                field_name
            )


    # ========================================================
    # DONNÉES WEB
    # ========================================================

    web_fields = [
        "status_code",
        "classification",
        "severity",
        "confidence",
        "parameter",
        "evidence",
        "recommendation",
        "validation_method",
    ]


    for field_name in web_fields:

        if field_name in detection:

            alert[
                field_name
            ] = detection.get(
                field_name
            )


    # ========================================================
    # DONNÉES TRAFIC
    # ========================================================

    traffic_fields = [
        "packet_count",
        "unique_ports",
        "ports",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
    ]


    for field_name in traffic_fields:

        if field_name in detection:

            value = detection.get(
                field_name
            )


            if (
                field_name == "ports"
                and value is None
            ):

                value = []


            alert[
                field_name
            ] = value


    # ========================================================
    # AUTRES INFORMATIONS UTILES
    # ========================================================

    if (
        "username"
        in detection
    ):

        alert[
            "username"
        ] = detection.get(
            "username"
        )


    return alert