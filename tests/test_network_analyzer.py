from app.analyzers.network_analyzer import detect_new_ports


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