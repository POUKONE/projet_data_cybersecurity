def get_overview_kpis():
    """
    Retourne les KPI pour la page Vue d'ensemble.
    A relier plus tard au modèle de données commun.
    """
    return {
        "Score_securite":85,
        "nombre_machine_surveillé":15000,
        "alertes_critiques":4,
        "machines_compromises":10,  
        "anomalies_détecté":15,

    }


def get_network_metrics():
    """
    Retourne les métriques issues de l'analyse Scapy.
    """
    return {
        "total_connexions": 14500,
        "top_ports_exposes": {"Port 80 (HTTP)": 4500, "Port 443 (HTTPS)": 8000, "Port 22 (SSH)": 150},
        "ip_suspectes": ["192.168.1.105", "10.0.0.42"]
    }

def get_logs_metrics():
    """
    Retourne les statistiques des événements de sécurité.
    """
    return {
        "total_logs": 14500,
        "echecs_connexion": 124,
        "top_users_erreurs": {"admin": 45, "guest": 30}
    }


def get_alertes_metrics():
    """
    Retourne les métriques issues de l'analyse des alertes.
    """
    return {
        "nombre_machine_surveillé":30,
        "alertes_critiques": 4,
        "alertes_importantes": 8,
        "alertes_mineures": 12,
    }

def get_ml_metrics():
    """
    Retourne les performances et résultats de l'Isolation Forest.
    """
    return {
        "anomalies_detectees": 18,
        "taux_faux_positifs_estime": "4.5%",
        "precision_modele": "92%"
    }
    

    