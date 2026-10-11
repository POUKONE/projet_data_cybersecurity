from unittest.mock import patch

from app.analyzers.traffic_analyzer import (
    summarize_traffic,
    detect_high_packet_activity,
    detect_port_scan_activity,
    analyze_traffic,
    process_traffic_detections,
    run_traffic_analysis
)

@patch(
    "app.analyzers.traffic_analyzer.save_alert"
)
def test_process_traffic_detections(
    mock_save_alert
):

    detections = [
        {
            "event_type": "HIGH_PACKET_ACTIVITY",
            "ip_address": "192.168.1.20",
            "packet_count": 50
        }
    ]

    alerts = process_traffic_detections(
        detections
    )

    assert len(alerts) == 1

    assert alerts[0]["risk_score"] == 30
    assert alerts[0]["risk_level"] == "MEDIUM"

    mock_save_alert.assert_called_once()


def test_summarize_traffic():

    packets = [
        {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "UDP",
            "src_port": 53000,
            "dst_port": 53,
            "packet_size": 100
        },
        {
            "src_ip": "192.168.1.10",
            "dst_ip": "1.1.1.1",
            "protocol": "UDP",
            "src_port": 53001,
            "dst_port": 53,
            "packet_size": 150
        }
    ]

    summary = summarize_traffic(
        packets
    )

    assert summary["total_packets"] == 2
    assert summary["total_bytes"] == 250
    assert summary["protocols"]["UDP"] == 2
    assert summary["source_ips"]["192.168.1.10"] == 2


def test_high_packet_activity():

    packets = [
        {
            "src_ip": "10.0.0.5",
            "dst_port": 80,
            "packet_size": 100
        }
        for _ in range(5)
    ]

    detections = detect_high_packet_activity(
        packets,
        threshold=5
    )

    assert len(detections) == 1

    assert (
        detections[0]["event_type"]
        == "HIGH_PACKET_ACTIVITY"
    )

    assert detections[0]["packet_count"] == 5


def test_port_scan_activity():

    packets = [
        {
            "src_ip": "10.0.0.50",
            "dst_port": port,
            "packet_size": 60
        }
        for port in [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            135,
            443,
            445
        ]
    ]

    detections = detect_port_scan_activity(
        packets,
        threshold=10
    )

    assert len(detections) == 1

    detection = detections[0]

    assert (
        detection["event_type"]
        == "PORT_SCAN_ACTIVITY"
    )

    assert detection["unique_ports"] == 10


def test_analyze_traffic():

    packets = [
        {
            "src_ip": "192.168.1.20",
            "dst_ip": "192.168.1.1",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 443,
            "packet_size": 200
        }
    ]

    result = analyze_traffic(
        packets
    )

    assert "summary" in result
    assert "detections" in result

    assert result["summary"]["total_packets"] == 1