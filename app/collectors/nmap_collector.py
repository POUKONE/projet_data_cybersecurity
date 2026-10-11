"""
Collecteur réseau basé sur Nmap.

Ce module permet :
- de scanner une cible ;
- de récupérer les hôtes détectés ;
- d'extraire les ports ouverts ;
- d'identifier les services exposés.
"""

import nmap
import shutil
from pathlib import Path


def find_nmap() -> str:
    """
    Recherche l'exécutable Nmap sur le système.

    Retour
    ------
    str
        Chemin vers l'exécutable Nmap.

    Raises
    ------
    FileNotFoundError
        Si Nmap n'est pas installé ou introuvable.
    """

    # Première tentative :
    # recherche classique dans le PATH.
    nmap_path = shutil.which("nmap")

    if nmap_path:
        return nmap_path

    # Emplacements Windows courants.
    possible_paths = [
        Path(r"C:\Program Files\Nmap\nmap.exe"),
        Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
    ]

    for path in possible_paths:

        if path.exists():
            return str(path)

    raise FileNotFoundError(
        "Nmap est introuvable. "
        "Installez Nmap ou ajoutez-le au PATH."
    )

def scan_target(target: str) -> list[dict]:
    """
    Scanne une cible avec Nmap.

    Paramètres
    ----------
    target : str
        Adresse IP ou nom d'hôte à scanner.

    Retour
    ------
    list[dict]
        Liste des ports et services détectés.
    """

    nmap_path = find_nmap()

    scanner = nmap.PortScanner(
        nmap_search_path=(
            nmap_path,
    )
)

    # Scan TCP standard.
    #
    # -sT : TCP connect scan
    # -sV : détection des versions/services
    scanner.scan(
        hosts=target,
        arguments="-sT -sV"
    )

    results = []

    # Parcours des hôtes détectés.
    for host in scanner.all_hosts():

        # Parcours des protocoles disponibles.
        for protocol in scanner[host].all_protocols():

            ports = scanner[host][protocol].keys()

            for port in ports:

                port_info = scanner[host][protocol][port]

                result = {
                    "host": host,
                    "protocol": protocol,
                    "port": port,
                    "state": port_info.get("state"),
                    "service": port_info.get("name"),
                    "product": port_info.get("product"),
                    "version": port_info.get("version"),
                }

                results.append(result)

    return results

if __name__ == "__main__":

    target = "127.0.0.1"

    results = scan_target(
        target
    )

    print(
        f"\n--- Résultats du scan Nmap : {target} ---"
    )

    if not results:
        print(
            "Aucun port détecté."
        )

    for result in results:

        print(
            f"Port : {result['port']} | "
            f"État : {result['state']} | "
            f"Service : {result['service']} | "
            f"Produit : {result['product']} | "
            f"Version : {result['version']}"
        )