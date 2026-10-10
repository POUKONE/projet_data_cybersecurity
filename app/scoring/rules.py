"""
Règles de sécurité utilisées par le moteur de scoring.

Ce fichier contient uniquement la définition des règles : 
-type d'événement 
-score de base
-sévérité
-description

 L'objectif est de séparer les règles métier du code qui calcule réellement le score.
"""

SECURITY_RULES = {

    #Plusieurs échecs de connexion rapprochés.
    "FAILED_LOGIN_BURST" : {
        "base_score": 40,
        "severity": "HIGH",
        "description": (
            "Plusieurs tentatives de connexion échouées"
            "ont été détectées depuis la meme adresse IP"
        ),
    },
    # Nouveau port détecté sur une machine,
    # Cette règle sera utilisée plus tard avec Nmap,
    "NEW_PORT_DETECTED": {
        "base_score" : 20,
        "severity" : "MEDIUM",
        "description" : (
            "Un nouveau port réseau a été détecté"
            "sur une machine surveillée"
        ),
    },
    #Nouveau service réseau détecté.
    "NEW_SERVICE_DETECTED": {
        "base_score": 25,
        "severity": "MEDIUM",
        "description": (
            "Un nouveau service réseau a été détecté."
        ),
    },

    # Configuration HTTPS absente.
    # Sera utilisée  plus tard dans l'audit web.
    "HTTPS_MISSING": {
        "base_score": 30,
        "severity": "HIGH",
        "description": (
            "Le service web analysé n'utilise pas HTTPS."
        ),
    },

    # Header Content-Security-Policy absent.
    "CSP_MISSING": {
        "base_score": 15,
        "severity": "MEDIUM",
        "description": (
            "Le header Content-Security-Policy est absent."
        ),
    },
}

def get_rule(event_type: str) -> dict | None :
    """
    Retourne la règle associée à un type d'événement.

    Paramètres
    -------------
    event_type : str 
        Type d'événement de sécurité.

    Retour
    -------------
    dict | None
        La règle correspondante si elle existe.
        Sinon None.
    """

    # On normalise le nom en majuscules
    # afin d'éviter les problèmes de casse.
    normalized_event_type = event_type.upper()

    #dict.get() retourne None si la clé n'existe pas.

    return SECURITY_RULES.get(normalized_event_type)