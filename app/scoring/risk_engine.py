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
    Calcule le score de risque associé à une détection.

    Pour le moment, le score repose principalement
    sur la règle de sécurité correspondante.

    Des ajustements dynamiques sont ensuite appliqués
    selon les informations contenues dans la détection.

    Paramètres
    ----------
    detection : dict
        Détection générée par un analyseur.

    Retour
    ------
    int
        Score compris entre 0 et 100.
    """

    # On récupère le type d'événement.
    event_type = detection.get("event_type")

    # Si aucun type n'est présent,
    # impossible de déterminer la règle.
    if not event_type:
        return 0

    # Recherche de la règle correspondante.
    rule = get_rule(event_type)

    # Si aucune règle n'existe,
    # on retourne un risque nul.
    if rule is None:
        return 0

    # Score de base défini dans rules.py.
    score = rule["base_score"]

    
    if event_type.upper() == "FAILED_LOGIN_BURST":

        # Nombre de tentatives observées.
        failed_attempts = detection.get(
            "failed_attempts",
            0
        )

        # Plus il y a de tentatives,
        # plus le score augmente.
        #
        # Exemple :
        # 5 tentatives  -> +0
        # 10 tentatives -> +10
        # 20 tentatives -> +30
        if failed_attempts > 5:
            extra_attempts = failed_attempts - 5

            score += extra_attempts * 2

        # Si plusieurs comptes sont ciblés,
        # cela peut indiquer un comportement plus large.
        targeted_users = (
            detection.get("targeted_users")
            or []
)

        if len(targeted_users) > 1:
            score += 10

    # Le score final ne doit jamais dépasser 100.
    score = min(score, 100)

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
    }

    return alert