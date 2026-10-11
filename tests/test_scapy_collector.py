from scapy.all import IP, TCP, UDP

from app.collectors.scapy_collector import (
    packet_to_dict
)


def test_tcp_packet_to_dict():
    """
    Vérifie l'extraction des métadonnées TCP.
    """

    packet = (
        IP(
            src="192.168.1.10",
            dst="192.168.1.20"
        )
        /
        TCP(
            sport=50000,
            dport=443
        )
    )

    result = packet_to_dict(
        packet
    )

    assert result is not None

    assert result["src_ip"] == "192.168.1.10"
    assert result["dst_ip"] == "192.168.1.20"
    assert result["protocol"] == "TCP"
    assert result["src_port"] == 50000
    assert result["dst_port"] == 443

    assert result["packet_size"] > 0


def test_udp_packet_to_dict():
    """
    Vérifie l'extraction des métadonnées UDP.
    """

    packet = (
        IP(
            src="10.0.0.1",
            dst="8.8.8.8"
        )
        /
        UDP(
            sport=53000,
            dport=53
        )
    )

    result = packet_to_dict(
        packet
    )

    assert result is not None

    assert result["protocol"] == "UDP"
    assert result["src_port"] == 53000
    assert result["dst_port"] == 53


def test_non_ip_packet_is_ignored():
    """
    Vérifie que les paquets sans couche IP
    sont ignorés.
    """

    packet = TCP(
        sport=1234,
        dport=80
    )

    result = packet_to_dict(
        packet
    )

    assert result is None