import re 
from typing import Optional

# Expression régulière utilisée pour reconnaître
# le format de nos logs.
#
# Exemple attendu :
#
# 2026-09-15 08:30:10 LOGIN
# username=admin
# status=FAILED
# ip=192.168.1.15

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"(?P<event_type>\w+) "
    r"username=(?P<username>[^\s]+) "
    r"status=(?P<status>[^\s]+) "
    r"ip=(?P<ip_address>[^\s]+)$"
)

def parse_log_line(line: str) -> Optional[dict]:
    """
    Transforme une ligne de log en dictionnaire Python.

    Paramètre
    ---------
    line : str
        Ligne brute provenant d'un fichier de logs.

    Retour
    ------
    dict | None
        Retourne un dictionnaire si la ligne correspond
        au format attendu.

        Retourne None si la ligne ne peut pas être parsée.
    """

    # strip() supprime les espaces et retours à la ligne
    # inutiles au début et à la fin.
    line = line.strip()

    # On applique notre expression régulière
    # sur la ligne complète.
    match = LOG_PATTERN.match(line)

    # Si aucune correspondance n'est trouvée,
    # la ligne n'est pas conforme au format attendu.
    if not match:
        return None

    # groupdict() transforme les groupes nommés Regex
    # directement en dictionnaire Python.
    parsed_data = match.groupdict()

    return parsed_data

def parse_log_lines(lines: list[str]) -> list[dict]:
    """
    Parse plusieurs lignes de logs.

    Les lignes invalides sont ignorées.

    Paramètre
    ---------
    lines : list[str]
        Liste des lignes récupérées depuis le fichier log.

    Retour
    ------
    list[dict]
        Liste contenant uniquement les événements valides.
    """

    # Liste dans laquelle seront stockés
    # les logs correctement parsés.
    parsed_logs = []

    # On parcourt chaque ligne.
    for line in lines:

        # Transformation de la ligne.
        parsed_line = parse_log_line(line)

        # On ajoute uniquement les lignes valides.
        if parsed_line is not None:
            parsed_logs.append(parsed_line)

    return parsed_logs

if __name__ == "__main__":
    from app.collectors.log_collector import read_log_file

    # Étape 1 : lire le fichier.
    lines = read_log_file("data/raw/sample.log")

    # Étape 2 : parser chaque ligne.
    parsed_logs = parse_log_lines(lines)

    # Étape 3 : afficher les résultats.
    for log in parsed_logs:
        print(log)