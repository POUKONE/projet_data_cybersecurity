"""
Analyse des métadonnées réseau capturées avec Scapy.

Ce module permet :
- de compter les paquets par IP source ;
- de calculer le volume de trafic ;
- d'identifier les ports de destination sollicités ;
- de détecter des comportements simples potentiellement suspects.
"""

from collections import Counter
from app.scoring.risk_engine import build_security_alert
from app.database.db import save_alert

def summarize_traffic(
    packets: list[dict]
) -> dict:
    """
    Produit un résumé statistique du trafic réseau.

    Paramètres
    ----------
    packets : list[dict]
        Métadonnées issues du collecteur Scapy.

    Retour
    ------
    dict
        Statistiques principales du trafic.
    """

    if not packets:

        return {
            "total_packets": 0,
            "total_bytes": 0,
            "protocols": {},
            "source_ips": {},
            "destination_ports": {}
        }

    total_bytes = sum(
        packet.get("packet_size", 0)
        for packet in packets
    )

    protocols = Counter(
        packet.get("protocol")
        for packet in packets
    )

    source_ips = Counter(
        packet.get("src_ip")
        for packet in packets
    )

    destination_ports = Counter(
        packet.get("dst_port")
        for packet in packets
        if packet.get("dst_port") is not None
    )

    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "protocols": dict(protocols),
        "source_ips": dict(source_ips),
        "destination_ports": dict(
            destination_ports
        )
    }

def detect_high_packet_activity(
    packets: list[dict],
    threshold: int = 50
) -> list[dict]:
    """
    Détecte une IP source générant un grand nombre
    de paquets dans l'échantillon analysé.

    Paramètres
    ----------
    packets : list[dict]
        Métadonnées des paquets.

    threshold : int
        Nombre de paquets à partir duquel
        une activité est considérée comme élevée.

    Retour
    ------
    list[dict]
        Détections générées.
    """

    source_counts = Counter(
        packet.get("src_ip")
        for packet in packets
        if packet.get("src_ip")
    )

    detections = []

    for ip_address, packet_count in source_counts.items():

        if packet_count >= threshold:

            detections.append(
                {
                    "event_type": "HIGH_PACKET_ACTIVITY",
                    "ip_address": ip_address,
                    "packet_count": packet_count,
                    "message": (
                        "Un volume élevé de paquets "
                        "a été détecté depuis cette IP."
                    )
                }
            )

    return detections

def detect_port_scan_activity(
    packets: list[dict],
    threshold: int = 10
) -> list[dict]:
    """
    Détecte une IP source qui contacte
    de nombreux ports de destination différents.

    Cette logique constitue une première heuristique
    de détection d'un potentiel scan de ports.
    """

    ports_by_ip = {}

    for packet in packets:

        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")

        if (
            src_ip is None
            or dst_port is None
        ):
            continue

        if src_ip not in ports_by_ip:
            ports_by_ip[src_ip] = set()

        ports_by_ip[src_ip].add(
            dst_port
        )

    detections = []

    for ip_address, ports in ports_by_ip.items():

        if len(ports) >= threshold:

            detections.append(
                {
                    "event_type": "PORT_SCAN_ACTIVITY",
                    "ip_address": ip_address,
                    "unique_ports": len(ports),
                    "ports": sorted(ports),
                    "message": (
                        "Une même IP a contacté "
                        "de nombreux ports différents."
                    )
                }
            )

    return detections

def analyze_traffic(
    packets: list[dict]
) -> dict:
    """
    Lance l'analyse complète des métadonnées réseau.
    """

    summary = summarize_traffic(
        packets
    )

    detections = []

    detections.extend(
        detect_high_packet_activity(
            packets
        )
    )

    detections.extend(
        detect_port_scan_activity(
            packets
        )
    )

    return {
        "summary": summary,
        "detections": detections
    }

def process_traffic_detections(
    detections: list[dict]
) -> list[dict]:
    """
    Transforme les détections de trafic
    en alertes puis les stocke dans SQLite.
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

def run_traffic_analysis(
    packets: list[dict]
) -> dict:
    """
    Lance l'analyse complète du trafic réseau.

    Retour
    ------
    dict
        Résumé du trafic et alertes générées.
    """

    analysis = analyze_traffic(
        packets
    )

    alerts = process_traffic_detections(
        analysis["detections"]
    )

    return {
        "summary": analysis["summary"],
        "alerts": alerts
    }