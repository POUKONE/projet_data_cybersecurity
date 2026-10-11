"""
Règles de sécurité utilisées par le moteur de scoring.

Ce fichier contient uniquement la définition des règles :
- type d'événement ;
- score de base ;
- sévérité ;
- description.

L'objectif est de séparer les règles métier
du code qui calcule réellement le score.
"""


# ============================================================
# RÈGLES DE SÉCURITÉ
# ============================================================

SECURITY_RULES = {

    # --------------------------------------------------------
    # Tentatives de connexion échouées répétées
    # --------------------------------------------------------
    "FAILED_LOGIN_BURST": {
        "base_score": 40,
        "severity": "HIGH",
        "description": (
            "Plusieurs tentatives de connexion échouées "
            "ont été détectées depuis la même adresse IP."
        ),
    },

    # --------------------------------------------------------
    # Nouveau port réseau détecté
    # --------------------------------------------------------
    "NEW_PORT_DETECTED": {
        "base_score": 20,
        "severity": "MEDIUM",
        "description": (
            "Un nouveau port ouvert a été détecté "
            "sur un hôte du réseau."
        ),
    },

    # --------------------------------------------------------
    # Nouveau service réseau détecté
    # --------------------------------------------------------
    "NEW_SERVICE_DETECTED": {
        "base_score": 25,
        "severity": "MEDIUM",
        "description": (
            "Un nouveau service réseau a été détecté."
        ),
    },

    # --------------------------------------------------------
    # HTTPS absent
    # --------------------------------------------------------
    "HTTPS_MISSING": {
        "base_score": 30,
        "severity": "HIGH",
        "description": (
            "Le service web analysé n'utilise pas HTTPS."
        ),
    },

    # --------------------------------------------------------
    # Content-Security-Policy absent
    # --------------------------------------------------------
    "CSP_MISSING": {
        "base_score": 15,
        "severity": "MEDIUM",
        "description": (
            "Le header Content-Security-Policy est absent."
        ),
    },
}


# ============================================================
# RÉCUPÉRATION D'UNE RÈGLE
# ============================================================

def get_rule(event_type: str) -> dict | None:
    """
    Retourne la règle associée à un type d'événement.

    Paramètres
    ----------
    event_type : str
        Type d'événement de sécurité.

    Retour
    ------
    dict | None
        Règle correspondante si elle existe.
        Sinon None.
    """

    # Protection contre une valeur vide ou None.
    if not event_type:
        return None

    # Normalisation du nom afin d'éviter
    # les problèmes liés à la casse.
    normalized_event_type = event_type.upper()

    # dict.get() retourne None
    # lorsque la règle n'existe pas.
    return SECURITY_RULES.get(
        normalized_event_type
    )