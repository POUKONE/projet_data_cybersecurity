"""
Analyse des résultats réseau.

Ce module permet notamment :
- de comparer deux scans Nmap ;
- de détecter les nouveaux ports ouverts ;
- de générer des événements de sécurité.
"""


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