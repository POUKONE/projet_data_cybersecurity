from unittest.mock import patch

from app.analyzers.network_analyzer import (
    detect_new_ports,
    process_network_detections
)

@patch(
    "app.analyzers.network_analyzer.save_alert"
)
def test_process_network_detection(
    mock_save_alert
):
    """
    Vérifie qu'une détection réseau :
    - devient une alerte ;
    - reçoit un score ;
    - est envoyée vers SQLite.
    """

    detection = {
        "event_type": "NEW_PORT_DETECTED",
        "host": "127.0.0.1",
        "ip_address": "127.0.0.1",
        "protocol": "tcp",
        "port": 1521,
        "state": "open",
        "service": "oracle-tns",
        "product": "Oracle TNS listener",
        "version": ""
    }

    detections = [
        detection
    ]

    alerts = process_network_detections(
        detections
    )

    # Une détection doit produire une alerte.
    assert len(alerts) == 1

    alert = alerts[0]

    assert (
        alert["event_type"]
        == "NEW_PORT_DETECTED"
    )

    assert alert["port"] == 1521

    # 1521 est défini comme port sensible.
    assert alert["risk_score"] == 40

    assert alert["risk_level"] == "MEDIUM"

    # Vérifie que l'enregistrement SQLite
    # a bien été demandé.
    mock_save_alert.assert_called_once()

@patch(
    "app.analyzers.network_analyzer.save_alert"
)
def test_process_multiple_network_detections(
    mock_save_alert
):
    """
    Vérifie que plusieurs détections
    produisent plusieurs alertes.
    """

    detections = [
        {
            "event_type": "NEW_PORT_DETECTED",
            "host": "127.0.0.1",
            "ip_address": "127.0.0.1",
            "protocol": "tcp",
            "port": 445,
            "state": "open",
            "service": "microsoft-ds",
            "product": "",
            "version": ""
        },
        {
            "event_type": "NEW_PORT_DETECTED",
            "host": "127.0.0.1",
            "ip_address": "127.0.0.1",
            "protocol": "tcp",
            "port": 8080,
            "state": "open",
            "service": "http-proxy",
            "product": "",
            "version": ""
        }
    ]

    alerts = process_network_detections(
        detections
    )

    assert len(alerts) == 2

    # save_alert doit être appelé
    # une fois par détection.
    assert mock_save_alert.call_count == 2

    assert alerts[0]["risk_score"] == 40
    assert alerts[1]["risk_score"] == 20

def test_no_new_port():
    previous_scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 135,
            "state": "open",
            "service": "msrpc",
            "product": "",
            "version": ""
        }
    ]

    current_scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 135,
            "state": "open",
            "service": "msrpc",
            "product": "",
            "version": ""
        }
    ]

    detections = detect_new_ports(
        previous_scan,
        current_scan
    )

    assert detections == []


def test_detect_one_new_port():
    previous_scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 135,
            "state": "open",
            "service": "msrpc",
            "product": "",
            "version": ""
        }
    ]

    current_scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 135,
            "state": "open",
            "service": "msrpc",
            "product": "",
            "version": ""
        },
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 445,
            "state": "open",
            "service": "microsoft-ds",
            "product": "",
            "version": ""
        }
    ]

    detections = detect_new_ports(
        previous_scan,
        current_scan
    )

    assert len(detections) == 1

    detection = detections[0]

    assert detection["event_type"] == "NEW_PORT_DETECTED"
    assert detection["port"] == 445
    assert detection["protocol"] == "tcp"
    assert detection["ip_address"] == "127.0.0.1"


def test_detect_multiple_new_ports():
    previous_scan = []

    current_scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 1521,
            "state": "open",
            "service": "oracle-tns",
            "product": "Oracle TNS listener",
            "version": ""
        },
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 7778,
            "state": "open",
            "service": "interwise",
            "product": "",
            "version": ""
        }
    ]

    detections = detect_new_ports(
        previous_scan,
        current_scan
    )

    assert len(detections) == 2

    ports = {
        detection["port"]
        for detection in detections
    }

    assert ports == {
        1521,
        7778
    }


def test_closed_port_is_not_detected():
    previous_scan = []

    current_scan = [
        {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": 9999,
            "state": "closed",
            "service": "",
            "product": "",
            "version": ""
        }
    ]

    detections = detect_new_ports(
        previous_scan,
        current_scan
    )

    assert detections == []