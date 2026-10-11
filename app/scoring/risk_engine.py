from app.scoring.rules import get_rule


def get_risk_level(score: int) -> str:
    """
    Convertit un score numérique en niveau de risque.

    Paramètres
    ----------
    score : int
        Score compris entre 0 et 100.

    Retour
    ------
    str
        Niveau de risque.
    """

    # On sécurise le score afin qu'il reste
    # toujours compris entre 0 et 100.
    score = max(0, min(score, 100))

    if score <= 29:
        return "LOW"

    if score <= 49:
        return "MEDIUM"

    if score <= 69:
        return "HIGH"

    return "CRITICAL"

def calculate_risk_score(detection: dict) -> int:
    """
    Calcule le score de risque d'une détection.
    """

    event_type = detection.get("event_type")

    if not event_type:
        return 0

    rule = get_rule(event_type)

    if rule is None:
        return 0

    score = rule["base_score"]


        # ========================================================
    # HIGH PACKET ACTIVITY
    # ========================================================

    if event_type.upper() == "HIGH_PACKET_ACTIVITY":

        packet_count = detection.get(
            "packet_count",
            0
        )

        # Plus le volume dépasse le seuil,
        # plus le score augmente.
        if packet_count > 50:
            extra_packets = packet_count - 50

            score += min(
                extra_packets // 10,
                20
            )

    # ========================================================
    # PORT SCAN ACTIVITY
    # ========================================================

    if event_type.upper() == "PORT_SCAN_ACTIVITY":

        unique_ports = detection.get(
            "unique_ports",
            0
        )

        # Bonus si beaucoup de ports
        # différents ont été contactés.
        if unique_ports >= 20:
            score += 15

        if unique_ports >= 50:
            score += 20

    # ========================================================
    # FAILED LOGIN BURST
    # ========================================================

    if event_type.upper() == "FAILED_LOGIN_BURST":

        failed_attempts = detection.get(
            "failed_attempts",
            0
        )

        if failed_attempts > 5:
            extra_attempts = failed_attempts - 5
            score += extra_attempts * 2

        targeted_users = (
            detection.get("targeted_users")
            or []
        )

        if len(targeted_users) > 1:
            score += 10

    # ========================================================
    # NOUVEAU PORT DÉTECTÉ
    # ========================================================

    if event_type.upper() == "NEW_PORT_DETECTED":

        port = detection.get("port")

        sensitive_ports = {
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
            27017
        }

        if port in sensitive_ports:
            score += 20

    # Le score ne doit jamais dépasser 100.
    score = max(0, min(score, 100))

    return score

def build_default_description(
    event_type: str | None,
    detection: dict
) -> str:
    """
    Génère une description lisible
    lorsqu'aucune description explicite
    n'est fournie par la détection.
    """

    descriptions = {
        "FAILED_LOGIN_BURST": (
            "Plusieurs tentatives de connexion échouées "
            "ont été détectées sur une courte période."
        ),

        "NEW_PORT_DETECTED": (
            "Un nouveau port réseau a été détecté "
            "sur la cible analysée."
        ),

        "NEW_SERVICE_DETECTED": (
            "Un nouveau service réseau a été détecté "
            "sur un port existant."
        ),

        "HTTPS_MISSING": (
            "Le site analysé n'utilise pas HTTPS."
        ),

        "CSP_MISSING": (
            "L'en-tête Content-Security-Policy est absent."
        ),

        "HSTS_MISSING": (
            "L'en-tête Strict-Transport-Security est absent."
        ),

        "X_CONTENT_TYPE_OPTIONS_MISSING": (
            "L'en-tête X-Content-Type-Options est absent."
        ),

        "X_FRAME_OPTIONS_MISSING": (
            "L'en-tête X-Frame-Options est absent."
        ),

        "REFERRER_POLICY_MISSING": (
            "L'en-tête Referrer-Policy est absent."
        ),

        "HIGH_PACKET_ACTIVITY": (
            "Une activité réseau anormalement élevée "
            "a été détectée."
        ),

        "PORT_SCAN_ACTIVITY": (
            "Une activité ressemblant à un scan de ports "
            "a été détectée."
        ),
    }

    if not event_type:
        return "Observation de sécurité détectée."

    return descriptions.get(
        event_type.upper(),
        "Observation de sécurité détectée."
    )


def build_security_alert(detection: dict) -> dict:
    """
    Transforme une détection technique en alerte
    de sécurité normalisée.

    Cette fonction :
    - calcule le score de risque ;
    - détermine le niveau de risque ;
    - identifie la source de la détection ;
    - détermine la cible concernée ;
    - construit un message lisible ;
    - conserve les informations spécifiques
      aux logs, au réseau, au Web et au trafic.
    """

    # ========================================================
    # INFORMATIONS PRINCIPALES
    # ========================================================

    event_type = detection.get(
        "event_type"
    )

    risk_score = calculate_risk_score(
        detection
    )

    risk_level = get_risk_level(
        risk_score
    )


    # ========================================================
    # SOURCE DE L'ALERTE
    # ========================================================

    source_type = (
        detection.get(
            "source_type"
        )
        or get_source_type(
            event_type
        )
    )


    # ========================================================
    # INFORMATIONS SUR LA CIBLE
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


    # Si aucune cible n'a été fournie explicitement,
    # on essaie de la déterminer automatiquement.
    if not target:

        if url:
            target = url

        elif host:
            target = host

        elif ip_address:
            target = ip_address


    # ========================================================
    # MESSAGE
    # ========================================================

    description = (
        detection.get(
            "description"
    )
        or build_default_description(
            event_type,
            detection
    )
)


    message = (
        detection.get(
            "message"
    )
        or description
)


    # ========================================================
    # ALERTE NORMALISÉE
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
            "OPEN"
        ),
    }


    # ========================================================
    # INFORMATIONS LOGS
    # ========================================================

    alert["start_time"] = detection.get(
        "start_time"
    )

    alert["end_time"] = detection.get(
        "end_time"
    )

    alert["failed_attempts"] = detection.get(
        "failed_attempts"
    )

    alert["targeted_users"] = (
        detection.get(
            "targeted_users"
        )
        or []
    )


    # ========================================================
    # INFORMATIONS RÉSEAU / NMAP
    # ========================================================

    alert["protocol"] = detection.get(
        "protocol"
    )

    alert["port"] = detection.get(
        "port"
    )

    alert["state"] = detection.get(
        "state"
    )

    alert["service"] = detection.get(
        "service"
    )

    alert["previous_service"] = detection.get(
        "previous_service"
    )

    alert["product"] = detection.get(
        "product"
    )

    alert["version"] = detection.get(
        "version"
    )


    # ========================================================
    # INFORMATIONS WEB
    # ========================================================

    alert["status_code"] = detection.get(
        "status_code"
    )


    # ========================================================
    # INFORMATIONS TRAFIC / SCAPY
    # ========================================================

    alert["packet_count"] = detection.get(
        "packet_count"
    )

    alert["unique_ports"] = detection.get(
        "unique_ports"
    )

    alert["ports"] = (
        detection.get(
            "ports"
        )
        or []
    )


    # ========================================================
    # AUTRES INFORMATIONS UTILES
    # ========================================================

    alert["username"] = detection.get(
        "username"
    )

    alert["protocol"] = detection.get(
        "protocol"
    )

    alert["src_port"] = detection.get(
        "src_port"
    )

    alert["dst_port"] = detection.get(
        "dst_port"
    )

    alert["src_ip"] = detection.get(
        "src_ip"
    )

    alert["dst_ip"] = detection.get(
        "dst_ip"
    )


    return alert

def get_source_type(
    event_type: str | None
) -> str:
    """
    Détermine la source technique
    d'une alerte selon son type.
    """

    if not event_type:
        return "UNKNOWN"

    event_type = event_type.upper()

    log_events = {
        "FAILED_LOGIN_BURST",
    }

    network_events = {
        "NEW_PORT_DETECTED",
        "NEW_SERVICE_DETECTED",
    }

    web_events = {
        "HTTPS_MISSING",
        "CSP_MISSING",
        "HSTS_MISSING",
        "X_CONTENT_TYPE_OPTIONS_MISSING",
        "X_FRAME_OPTIONS_MISSING",
        "REFERRER_POLICY_MISSING",
    }

    traffic_events = {
        "HIGH_PACKET_ACTIVITY",
        "PORT_SCAN_ACTIVITY",
    }

    if event_type in log_events:
        return "LOG"

    if event_type in network_events:
        return "NETWORK"

    if event_type in web_events:
        return "WEB"

    if event_type in traffic_events:
        return "TRAFFIC"

    return "UNKNOWN"