from unittest.mock import patch

from app.analyzers.network_analyzer import (
    detect_new_ports,
    process_network_detections,
    run_network_analysis
)

@patch(
    "app.analyzers.network_analyzer.process_network_detections"
)
@patch(
    "app.analyzers.network_analyzer.save_network_scan"
)
@patch(
    "app.analyzers.network_analyzer.scan_target"
)
@patch(
    "app.analyzers.network_analyzer.get_latest_network_scan"
)
def test_run_network_analysis(
    mock_get_latest_scan,
    mock_scan_target,
    mock_save_scan,
    mock_process_detections
):
    """
    Vérifie le pipeline réseau complet.
    """

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
            "port": 1521,
            "state": "open",
            "service": "oracle-tns",
            "product": "Oracle TNS listener",
            "version": ""
        }
    ]

    expected_alerts = [
        {
            "event_type": "NEW_PORT_DETECTED",
            "port": 1521,
            "risk_score": 40,
            "risk_level": "MEDIUM"
        }
    ]

    mock_get_latest_scan.return_value = (
        previous_scan
    )

    mock_scan_target.return_value = (
        current_scan
    )

    mock_process_detections.return_value = (
        expected_alerts
    )

    alerts = run_network_analysis(
        "127.0.0.1"
    )

    assert alerts == expected_alerts

    mock_get_latest_scan.assert_called_once()

    mock_scan_target.assert_called_once_with(
        "127.0.0.1"
    )

    mock_save_scan.assert_called_once_with(
        current_scan
    )

    mock_process_detections.assert_called_once()

@patch(
    "app.analyzers.network_analyzer.process_network_detections"
)
@patch(
    "app.analyzers.network_analyzer.save_network_scan"
)
@patch(
    "app.analyzers.network_analyzer.scan_target"
)
@patch(
    "app.analyzers.network_analyzer.get_latest_network_scan"
)
def test_first_network_scan_creates_baseline(
    mock_get_latest_scan,
    mock_scan_target,
    mock_save_scan,
    mock_process_detections
):
    """
    Le premier scan sert uniquement
    de référence initiale.
    """

    mock_get_latest_scan.return_value = []

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

    mock_scan_target.return_value = (
        current_scan
    )

    alerts = run_network_analysis(
        "127.0.0.1"
    )

    assert alerts == []

    mock_save_scan.assert_called_once_with(
        current_scan
    )

    mock_process_detections.assert_not_called()



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