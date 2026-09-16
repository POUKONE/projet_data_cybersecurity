import pandas as pd 

import pandas as pd


def logs_to_dataframe(parsed_logs: list[dict]) -> pd.DataFrame:
    """
    Convertit une liste de logs parsés en DataFrame Pandas.

    Paramètre
    ---------
    parsed_logs : list[dict]
        Liste des événements déjà structurés par log_parser.py.

    Retour
    ------
    pd.DataFrame
        DataFrame contenant les événements.
    """

    # Création du DataFrame.
    df = pd.DataFrame(parsed_logs)

    # Si aucun log n'est présent, on retourne directement
    # le DataFrame vide.
    if df.empty:
        return df

    # Conversion du timestamp texte en vrai type datetime.
    # Cela nous permettra ensuite de faire des calculs temporels.
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    # Suppression éventuelle des lignes dont le timestamp
    # n'a pas pu être converti.
    df = df.dropna(subset=["timestamp"])

    return df

def get_failed_logins(df: pd.DataFrame) -> pd.DataFrame:
    """
    Retourne uniquement les tentatives de connexion échouées.

    Paramètre
    ---------
    df : pd.DataFrame
        DataFrame contenant les logs.

    Retour
    ------
    pd.DataFrame
        Sous-ensemble contenant uniquement status=FAILED.
    """

    # Si le DataFrame est vide, inutile de continuer.
    if df.empty:
        return df

    # Sélection des lignes où le statut vaut FAILED.
    failed_logins = df[
        df["status"].str.upper() == "FAILED"
    ].copy()

    return failed_logins

def count_failed_logins_by_ip(
    df: pd.DataFrame
) -> pd.DataFrame:
    """
    Compte le nombre de connexions échouées par adresse IP.

    Retour
    ------
    pd.DataFrame
        Tableau avec :
        ip_address
        failed_attempts
    """

    # On récupère uniquement les échecs.
    failed_logins = get_failed_logins(df)

    if failed_logins.empty:
        return pd.DataFrame(
            columns=["ip_address", "failed_attempts"]
        )

    # groupby() regroupe les événements par IP.
    #
    # size() compte le nombre de lignes dans chaque groupe.
    result = (
        failed_logins
        .groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
    )

    # Tri décroissant pour afficher les IP
    # les plus suspectes en premier.
    result = result.sort_values(
        by="failed_attempts",
        ascending=False
    )

    return result

def detect_suspicious_ips(
    df: pd.DataFrame,
    threshold: int = 3
) -> pd.DataFrame:
    """
    Détecte les adresses IP dépassant un seuil
    de tentatives de connexion échouées.

    Paramètres
    ----------
    df : pd.DataFrame
        Logs analysés.

    threshold : int
        Nombre minimal d'échecs pour considérer
        une IP comme suspecte.

    Retour
    ------
    pd.DataFrame
        IP suspectes et nombre d'échecs.
    """

    failed_by_ip = count_failed_logins_by_ip(df)

    if failed_by_ip.empty:
        return failed_by_ip

    # On conserve uniquement les IP dont le nombre
    # d'échecs est supérieur ou égal au seuil.
    suspicious_ips = failed_by_ip[
        failed_by_ip["failed_attempts"] >= threshold
    ].copy()

    return suspicious_ips

def get_log_statistics(df: pd.DataFrame) -> dict:
    """
    Calcule quelques statistiques générales
    sur les logs.

    Retour
    ------
    dict
        Statistiques utiles pour le dashboard.
    """

    if df.empty:
        return {
            "total_events": 0,
            "failed_logins": 0,
            "successful_logins": 0,
            "unique_ips": 0,
            "unique_users": 0
        }

    total_events = len(df)

    failed_logins = len(
        df[df["status"].str.upper() == "FAILED"]
    )

    successful_logins = len(
        df[df["status"].str.upper() == "SUCCESS"]
    )

    unique_ips = df["ip_address"].nunique()

    unique_users = df["username"].nunique()

    return {
        "total_events": total_events,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "unique_ips": unique_ips,
        "unique_users": unique_users
    }
if __name__ == "__main__":

    from app.collectors.log_collector import read_log_file
    from app.parsers.log_parser import parse_log_lines

    # 1. Lecture du fichier.
    lines = read_log_file(
        "data/raw/sample.log"
    )

    # 2. Parsing.
    parsed_logs = parse_log_lines(lines)

    # 3. Transformation en DataFrame.
    df = logs_to_dataframe(parsed_logs)

    print("\n--- DataFrame ---")
    print(df)

    # 4. Statistiques.
    stats = get_log_statistics(df)

    print("\n--- Statistiques ---")

    for key, value in stats.items():
        print(f"{key}: {value}")

    # 5. IP suspectes.
    suspicious_ips = detect_suspicious_ips(
        df,
        threshold=3
    )

    print("\n--- IP suspectes ---")
    print(suspicious_ips)