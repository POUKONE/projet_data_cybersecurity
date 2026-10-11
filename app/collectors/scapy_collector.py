"""
Collecteur réseau basé sur Scapy.

Ce module permet :
- de capturer des paquets réseau ;
- d'extraire uniquement les métadonnées utiles ;
- de préparer les données pour l'analyse.

Important :
on évite de stocker le contenu brut des paquets.
"""

from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP


def packet_to_dict(packet) -> dict | None:
    """
    Transforme un paquet Scapy en dictionnaire.

    Seules les métadonnées utiles sont conservées.
    """

    # On ignore les paquets ne contenant pas IPv4.
    if IP not in packet:
        return None

    ip_layer = packet[IP]

    result = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "packet_size": len(packet),
    }

    # TCP
    if TCP in packet:

        tcp_layer = packet[TCP]

        result["protocol"] = "TCP"
        result["src_port"] = tcp_layer.sport
        result["dst_port"] = tcp_layer.dport

    # UDP
    elif UDP in packet:

        udp_layer = packet[UDP]

        result["protocol"] = "UDP"
        result["src_port"] = udp_layer.sport
        result["dst_port"] = udp_layer.dport

    else:
        result["protocol"] = str(
            ip_layer.proto
        )

    return result


def capture_packets(
    count: int = 10,
    timeout: int = 15
) -> list[dict]:
    """
    Capture un nombre limité de paquets réseau.

    Paramètres
    ----------
    count : int
        Nombre maximum de paquets.

    timeout : int
        Temps maximum de capture en secondes.

    Retour
    ------
    list[dict]
        Métadonnées des paquets capturés.
    """

    packets = sniff(
        count=count,
        timeout=timeout,
        store=True
    )

    results = []

    for packet in packets:

        packet_data = packet_to_dict(
            packet
        )

        if packet_data is not None:
            results.append(
                packet_data
            )

    return results


if __name__ == "__main__":

    print(
        "\n--- Capture réseau Scapy ---"
    )

    packets = capture_packets(
        count=10,
        timeout=15
    )

    if not packets:
        print(
            "Aucun paquet IPv4 capturé."
        )

    for packet in packets:

        print(
            f"{packet['protocol']} | "
            f"{packet['src_ip']}:{packet['src_port']} "
            f"→ "
            f"{packet['dst_ip']}:{packet['dst_port']} | "
            f"{packet['packet_size']} octets"
        )