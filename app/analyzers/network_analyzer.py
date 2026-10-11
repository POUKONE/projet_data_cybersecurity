"""
Analyse des résultats réseau.

Ce module permet notamment :
- de comparer deux scans Nmap ;
- de détecter les nouveaux ports ouverts ;
- de générer des événements de sécurité.
"""

from app.scoring.risk_engine import build_security_alert
from app.database.db import save_alert

from app.collectors.nmap_collector import scan_target

from app.database.db import (
    get_latest_network_scan,
    save_network_scan
)

def run_network_analysis(
    target: str
) -> list[dict]:
    """
    Lance un scan réseau complet.

    Étapes :
    - récupérer le dernier scan enregistré ;
    - lancer un nouveau scan Nmap ;
    - sauvegarder le nouveau scan ;
    - comparer avec le précédent ;
    - détecter les nouveaux ports ;
    - générer et stocker les alertes.

    Paramètres
    ----------
    target : str
        Cible à analyser.

    Retour
    ------
    list[dict]
        Alertes générées.
    """

    # Récupération du dernier scan disponible.
    previous_scan = get_latest_network_scan()

    # Nouveau scan Nmap.
    current_scan = scan_target(
        target
    )

    # Sauvegarde du nouveau scan.
    save_network_scan(
        current_scan
    )

    # Cas particulier :
    # s'il n'existe aucun scan précédent,
    # on crée simplement la référence initiale.
    if not previous_scan:
        return []

    # Détection des nouveaux ports.
    new_port_detections = detect_new_ports(
        previous_scan,
        current_scan
)

    # Détection des changements de services.
    new_service_detections = detect_new_services(
        previous_scan,
        current_scan
)

    # Regroupement de toutes les détections réseau.
    detections = (
        new_port_detections
        + new_service_detections
)

    # Génération des alertes et stockage SQLite.
    alerts = process_network_detections(
        detections
)

    return alerts

def process_network_detections(
    detections: list[dict]
) -> list[dict]:
    """
    Transforme les détections réseau en alertes
    et les enregistre dans SQLite.
    """

    alerts = []

    for detection in detections:

        alert = build_security_alert(
            detection
        )

        save_alert(
            alert
        )

        alerts.append(
            alert
        )

    return alerts


def detect_new_ports(
    previous_scan: list[dict],
    current_scan: list[dict]
) -> list[dict]:
    """
    Compare deux scans réseau et détecte
    les nouveaux ports ouverts.

    Paramètres
    ----------
    previous_scan : list[dict]
        Résultats du scan précédent.

    current_scan : list[dict]
        Résultats du scan actuel.

    Retour
    ------
    list[dict]
        Liste des nouveaux ports détectés.
    """

    # Ensemble des couples :
    # (host, protocol, port)
    previous_ports = {
        (
            item.get("host"),
            item.get("protocol"),
            item.get("port")
        )
        for item in previous_scan
        if item.get("state") == "open"
    }

    new_ports = []

    for item in current_scan:

        # On ignore les ports qui ne sont pas ouverts.
        if item.get("state") != "open":
            continue

        port_key = (
            item.get("host"),
            item.get("protocol"),
            item.get("port")
        )

        # Si ce port n'existait pas dans le scan précédent,
        # alors il est considéré comme nouveau.
        if port_key not in previous_ports:

            detection = {
                "event_type": "NEW_PORT_DETECTED",
                "host": item.get("host"),
                "ip_address": item.get("host"),
                "protocol": item.get("protocol"),
                "port": item.get("port"),
                "state": item.get("state"),
                "service": item.get("service"),
                "product": item.get("product"),
                "version": item.get("version"),
            }

            new_ports.append(
                detection
            )

    return new_ports

def detect_new_services(
    previous_scan: list[dict],
    current_scan: list[dict]
) -> list[dict]:
    """
    Détecte les changements ou nouveaux services
    exposés sur des ports déjà connus.

    Retour
    ------
    list[dict]
        Liste des services nouvellement détectés.
    """

    previous_services = {
        (
            item.get("host"),
            item.get("protocol"),
            item.get("port")
        ): item.get("service")
        for item in previous_scan
        if item.get("state") == "open"
    }

    detections = []

    for item in current_scan:

        if item.get("state") != "open":
            continue

        key = (
            item.get("host"),
            item.get("protocol"),
            item.get("port")
        )

        current_service = item.get("service")

        previous_service = previous_services.get(
            key
        )

        # Le port existait déjà mais le service
        # exposé a changé.
        if (
            previous_service is not None
            and current_service != previous_service
        ):

            detections.append(
                {
                    "event_type": "NEW_SERVICE_DETECTED",
                    "host": item.get("host"),
                    "ip_address": item.get("host"),
                    "protocol": item.get("protocol"),
                    "port": item.get("port"),
                    "state": item.get("state"),
                    "service": current_service,
                    "previous_service": previous_service,
                    "product": item.get("product"),
                    "version": item.get("version"),
                }
            )

    return detections

def detect_new_services(
    previous_scan: list[dict],
    current_scan: list[dict]
) -> list[dict]:
    """
    Détecte un changement de service sur un port
    qui existait déjà dans le scan précédent.

    Exemple :
    ancien scan : port 8080 -> http
    nouveau scan : port 8080 -> http-proxy

    Retour
    ------
    list[dict]
        Liste des changements de service détectés.
    """

    # On construit un dictionnaire :
    # (host, protocol, port) -> service
    previous_services = {
        (
            item.get("host"),
            item.get("protocol"),
            item.get("port")
        ): item.get("service")
        for item in previous_scan
        if item.get("state") == "open"
    }

    detections = []

    for item in current_scan:

        # On analyse uniquement les ports ouverts.
        if item.get("state") != "open":
            continue

        key = (
            item.get("host"),
            item.get("protocol"),
            item.get("port")
        )

        previous_service = previous_services.get(
            key
        )

        current_service = item.get(
            "service"
        )

        # Le port doit déjà avoir existé.
        if previous_service is None:
            continue

        # Si le service a changé,
        # on génère une détection.
        if current_service != previous_service:

            detection = {
                "event_type": "NEW_SERVICE_DETECTED",
                "host": item.get("host"),
                "ip_address": item.get("host"),
                "protocol": item.get("protocol"),
                "port": item.get("port"),
                "state": item.get("state"),
                "previous_service": previous_service,
                "service": current_service,
                "product": item.get("product"),
                "version": item.get("version"),
            }

            detections.append(
                detection
            )

    return detections