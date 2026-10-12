"""
Analyse du trafic réseau.

Ce module permet notamment de :
- résumer le trafic réseau collecté ;
- détecter une activité réseau élevée ;
- détecter une activité ressemblant à un scan de ports ;
- transformer les détections en alertes normalisées ;
- enregistrer les alertes dans SQLite.
"""

from collections import Counter, defaultdict

from app.database.db import save_alert
from app.scoring.risk_engine import build_security_alert


# ============================================================
# RÉSUMÉ DU TRAFIC
# ============================================================

def summarize_traffic(
    packets: list[dict]
) -> dict:
    """
    Produit un résumé statistique du trafic réseau.

    Paramètres
    ----------
    packets : list[dict]
        Liste des paquets réseau déjà transformés
        en dictionnaires.

    Retour
    ------
    dict
        Résumé du trafic.
    """

    if not packets:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "protocols": {},
            "source_ips": {},
            "destination_ports": {},
        }


    total_packets = len(
        packets
    )

    total_bytes = sum(
        packet.get(
            "packet_size",
            0
        )
        or 0
        for packet in packets
    )


    protocols = Counter()

    source_ips = Counter()

    destination_ports = Counter()


    for packet in packets:

        protocol = packet.get(
            "protocol"
        )

        src_ip = packet.get(
            "src_ip"
        )

        dst_port = packet.get(
            "dst_port"
        )


        if protocol:
            protocols[
                str(protocol)
            ] += 1


        if src_ip:
            source_ips[
                str(src_ip)
            ] += 1


        if dst_port is not None:
            destination_ports[
                str(dst_port)
            ] += 1


    return {
        "total_packets": (
            total_packets
        ),

        "total_bytes": (
            total_bytes
        ),

        "protocols": dict(
            protocols
        ),

        "source_ips": dict(
            source_ips
        ),

        "destination_ports": dict(
            destination_ports
        ),
    }


# ============================================================
# ACTIVITÉ RÉSEAU ÉLEVÉE
# ============================================================

def detect_high_packet_activity(
    packets: list[dict],
    threshold: int = 50
) -> list[dict]:
    """
    Détecte les adresses IP ayant généré
    un nombre élevé de paquets.

    Paramètres
    ----------
    packets : list[dict]
        Paquets réseau collectés.

    threshold : int
        Nombre minimum de paquets nécessaires
        pour déclencher une détection.

    Retour
    ------
    list[dict]
        Liste des détections.
    """

    detections = []


    if not packets:
        return detections


    packet_counts = Counter()


    for packet in packets:

        src_ip = packet.get(
            "src_ip"
        )

        if src_ip:
            packet_counts[
                str(src_ip)
            ] += 1


    for ip_address, packet_count in packet_counts.items():

        if packet_count < threshold:
            continue


        detection = {
            "event_type": (
                "HIGH_PACKET_ACTIVITY"
            ),

            "source_type": (
                "TRAFFIC"
            ),

            "target": (
                ip_address
            ),

            "ip_address": (
                ip_address
            ),

            "src_ip": (
                ip_address
            ),

            "packet_count": (
                packet_count
            ),

            "message": (
                f"Activité réseau élevée "
                f"détectée depuis "
                f"{ip_address} : "
                f"{packet_count} paquets."
            ),

            "description": (
                "Un volume important de paquets "
                "réseau a été observé depuis "
                "la même adresse IP."
            ),

            "status": "OPEN",
        }


        detections.append(
            detection
        )


    return detections


# ============================================================
# DÉTECTION D'UN SCAN DE PORTS
# ============================================================

def detect_port_scan_activity(
    packets: list[dict],
    threshold: int = 10
) -> list[dict]:
    """
    Détecte lorsqu'une même adresse IP source
    contacte un nombre élevé de ports différents.

    Paramètres
    ----------
    packets : list[dict]
        Paquets réseau collectés.

    threshold : int
        Nombre minimum de ports distincts nécessaires
        pour générer une détection.

    Retour
    ------
    list[dict]
        Liste des détections.
    """

    detections = []


    if not packets:
        return detections


    source_ports = defaultdict(
        set
    )


    for packet in packets:

        src_ip = packet.get(
            "src_ip"
        )

        dst_port = packet.get(
            "dst_port"
        )


        if (
            src_ip
            and dst_port is not None
        ):

            source_ports[
                str(src_ip)
            ].add(
                dst_port
            )


    for ip_address, ports in source_ports.items():

        unique_ports = len(
            ports
        )


        if unique_ports < threshold:
            continue


        sorted_ports = sorted(
            ports
        )


        detection = {
            "event_type": (
                "PORT_SCAN_ACTIVITY"
            ),

            "source_type": (
                "TRAFFIC"
            ),

            "target": (
                ip_address
            ),

            "ip_address": (
                ip_address
            ),

            "src_ip": (
                ip_address
            ),

            "unique_ports": (
                unique_ports
            ),

            "ports": (
                sorted_ports
            ),

            "message": (
                f"Activité de scan de ports "
                f"détectée depuis "
                f"{ip_address} : "
                f"{unique_ports} ports "
                f"distincts contactés."
            ),

            "description": (
                "Une même adresse IP a contacté "
                "un nombre important de ports "
                "différents, ce qui peut "
                "correspondre à une activité "
                "de reconnaissance réseau."
            ),

            "status": "OPEN",
        }


        detections.append(
            detection
        )


    return detections


# ============================================================
# ANALYSE DU TRAFIC
# ============================================================

def analyze_traffic(
    packets: list[dict],
    packet_threshold: int = 50,
    port_threshold: int = 10
) -> dict:
    """
    Exécute l'analyse complète du trafic.

    Retourne :
    - le résumé du trafic ;
    - les détections produites.
    """

    summary = summarize_traffic(
        packets
    )


    high_activity = (
        detect_high_packet_activity(
            packets,
            threshold=packet_threshold
        )
    )


    port_scans = (
        detect_port_scan_activity(
            packets,
            threshold=port_threshold
        )
    )


    detections = (
        high_activity
        + port_scans
    )


    return {
        "summary": summary,
        "detections": detections,
    }


# ============================================================
# TRANSFORMATION EN ALERTES
# ============================================================

def process_traffic_detections(
    detections: list[dict]
) -> list[dict]:
    """
    Transforme les détections trafic
    en alertes normalisées puis les
    enregistre dans SQLite.
    """

    alerts = []


    for detection in detections:

        alert = build_security_alert(
            detection
        )


        alert_id = save_alert(
            alert
        )


        alert["id"] = alert_id


        alerts.append(
            alert
        )


    return alerts


# ============================================================
# PIPELINE COMPLET
# ============================================================

def run_traffic_analysis(
    packets: list[dict],
    packet_threshold: int = 50,
    port_threshold: int = 10
) -> dict:
    """
    Exécute le pipeline trafic complet :

    1. analyse statistique ;
    2. détection d'anomalies ;
    3. scoring ;
    4. création d'alertes ;
    5. sauvegarde dans SQLite.
    """

    analysis = analyze_traffic(
        packets=packets,
        packet_threshold=packet_threshold,
        port_threshold=port_threshold
    )


    alerts = process_traffic_detections(
        analysis["detections"]
    )


    return {
        "summary": (
            analysis["summary"]
        ),

        "detections": (
            analysis["detections"]
        ),

        "alerts": (
            alerts
        ),

        "alert_count": len(
            alerts
        ),
    }