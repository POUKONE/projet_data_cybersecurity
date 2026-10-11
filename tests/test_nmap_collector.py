from unittest.mock import patch

from app.collectors.nmap_collector import scan_target


# Faux résultat Nmap utilisé par les tests.
FAKE_SCAN_DATA = {
    "127.0.0.1": {
        "tcp": {
            135: {
                "state": "open",
                "name": "msrpc",
                "product": "Microsoft Windows RPC",
                "version": ""
            },
            445: {
                "state": "open",
                "name": "microsoft-ds",
                "product": "",
                "version": ""
            }
        }
    }
}


class FakeHost(dict):
    """
    Représente un hôte Nmap simulé.
    """

    def all_protocols(self):
        return list(self.keys())


class FakePortScanner:
    """
    Simule nmap.PortScanner sans effectuer
    de véritable scan réseau.
    """

    def __init__(self, *args, **kwargs):
        self.data = {}

    def scan(self, hosts, arguments):
        self.data = {
            host: FakeHost(protocols)
            for host, protocols in FAKE_SCAN_DATA.items()
        }

    def all_hosts(self):
        return list(self.data.keys())

    def __getitem__(self, host):
        return self.data[host]


@patch(
    "app.collectors.nmap_collector.nmap.PortScanner",
    FakePortScanner
)
def test_scan_target_returns_list():
    results = scan_target("127.0.0.1")

    assert isinstance(results, list)


@patch(
    "app.collectors.nmap_collector.nmap.PortScanner",
    FakePortScanner
)
def test_scan_result_structure():
    results = scan_target("127.0.0.1")

    assert len(results) > 0

    first_result = results[0]

    assert "host" in first_result
    assert "protocol" in first_result
    assert "port" in first_result
    assert "state" in first_result
    assert "service" in first_result
    assert "product" in first_result
    assert "version" in first_result


@patch(
    "app.collectors.nmap_collector.nmap.PortScanner",
    FakePortScanner
)
def test_detected_ports_are_integers():
    results = scan_target("127.0.0.1")

    for result in results:
        assert isinstance(
            result["port"],
            int
        )


@patch(
    "app.collectors.nmap_collector.nmap.PortScanner",
    FakePortScanner
)
def test_detected_ports_are_open():
    results = scan_target("127.0.0.1")

    for result in results:
        assert result["state"] == "open"