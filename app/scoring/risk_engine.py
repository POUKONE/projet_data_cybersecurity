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

def build_security_alert(detection: dict) -> dict:
    """
    Transforme une détection brute en alerte de sécurité.

    Paramètres
    ----------
    detection : dict
        Résultat produit par un analyseur.

    Retour
    ------
    dict
        Alerte enrichie avec score, gravité
        et description.
    """

    # Type d'événement.
    event_type = detection.get(
        "event_type",
        "UNKNOWN"
    )

    # Récupération de la règle.
    rule = get_rule(event_type)

    # Calcul du score.
    risk_score = calculate_risk_score(
        detection
    )

    # Conversion du score en niveau de risque.
    risk_level = get_risk_level(
        risk_score
    )

    # Description par défaut.
    description = (
        "Événement de sécurité détecté."
    )

    # Si une règle existe,
    # on récupère sa description.
    if rule is not None:
        description = rule["description"]

    # Construction de l'alerte finale.
    alert = {
        "event_type": event_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "description": description,
        "host": detection.get("host"),
        "protocol": detection.get("protocol"),
        "port": detection.get("port"),
        "service": detection.get("service"),
        "product": detection.get("product"),
        "version": detection.get("version"),

        # Informations utiles si disponibles.
        "ip_address": detection.get(
            "ip_address"
        ),

        "start_time": detection.get(
            "start_time"
        ),

        "end_time": detection.get(
            "end_time"
        ),

        "failed_attempts": detection.get(
            "failed_attempts"
        ),

        "targeted_users": detection.get(
            "targeted_users",
            []
        ),

        "previous_service": detection.get(
            "previous_service"
),
    }

    return alert