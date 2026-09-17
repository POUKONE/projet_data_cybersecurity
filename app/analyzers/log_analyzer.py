import pandas as pd
from app.scoring.risk_engine import build_security_alert

def logs_to_dataframe(
    parsed_logs: list[dict]
) -> pd.DataFrame:
    """
    Transforme une liste de logs parsés
    en DataFrame Pandas.

    Paramètres
    ----------
    parsed_logs : list[dict]
        Logs déjà transformés en dictionnaires.

    Retour
    ------
    pd.DataFrame
        DataFrame contenant les logs structurés.
    """

    # Création du DataFrame.
    df = pd.DataFrame(parsed_logs)

    # Si aucune donnée n'est disponible,
    # on retourne directement le DataFrame vide.
    if df.empty:
        return df

    # Conversion du timestamp en datetime.
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    # Suppression des lignes dont
    # le timestamp est invalide.
    df = df.dropna(
        subset=["timestamp"]
    )

    return df

def detect_failed_login_bursts(
    df: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 5
) -> list[dict]:
    """
    Détecte plusieurs tentatives de connexion échouées
    provenant d'une même adresse IP dans une courte période.

    Exemple :
        threshold = 5
        window_minutes = 5

    signifie :
        au moins 5 échecs depuis la même IP
        dans une fenêtre de 5 minutes.

    Paramètres
    ----------
    df : pd.DataFrame
        DataFrame contenant les logs structurés.

    threshold : int
        Nombre minimal d'échecs nécessaires
        pour considérer l'activité comme suspecte.

    window_minutes : int
        Durée maximale de la fenêtre temporelle.

    Retour
    ------
    list[dict]
        Liste des comportements suspects détectés.
    """

    # Si le DataFrame est vide, il n'y a rien à analyser.
    if df.empty:
        return []

    # Vérification de la présence des colonnes nécessaires.
    required_columns = {
        "timestamp",
        "status",
        "ip_address",
        "username"
    }

    # On calcule les colonnes manquantes.
    missing_columns = required_columns - set(df.columns)

    # Si certaines colonnes sont absentes,
    # l'analyse ne peut pas être effectuée correctement.
    if missing_columns:
        raise ValueError(
            f"Colonnes manquantes : {missing_columns}"
        )

    # On travaille sur une copie afin de ne pas modifier
    # le DataFrame original.
    working_df = df.copy()

    # Conversion de la colonne timestamp en datetime.
    # errors='coerce' transforme les dates invalides en NaT.
    working_df["timestamp"] = pd.to_datetime(
        working_df["timestamp"],
        errors="coerce"
    )

    # Suppression des lignes avec timestamp invalide.
    working_df = working_df.dropna(
        subset=["timestamp"]
    )

    # On ne garde que les événements dont
    # le statut correspond à FAILED.
    failed_logins = working_df[
        working_df["status"].str.upper() == "FAILED"
    ].copy()

    # S'il n'y a aucun échec, on retourne une liste vide.
    if failed_logins.empty:
        return []

    # On trie chronologiquement les logs.
    failed_logins = failed_logins.sort_values(
        by="timestamp"
    )

    # Cette liste contiendra les comportements suspects.
    detections = []

    # On analyse chaque adresse IP indépendamment.
    for ip_address, group in failed_logins.groupby("ip_address"):

        # Tri des événements de cette IP.
        group = group.sort_values(
            by="timestamp"
        ).reset_index(drop=True)

        # On parcourt chaque événement comme point
        # de départ potentiel d'une fenêtre temporelle.
        for start_index in range(len(group)):

            # Timestamp de départ.
            start_time = group.loc[
                start_index,
                "timestamp"
            ]

            # Timestamp de fin théorique.
            end_limit = start_time + pd.Timedelta(
                minutes=window_minutes
            )

            # On récupère les événements qui se trouvent
            # dans cette fenêtre temporelle.
            window = group[
                (group["timestamp"] >= start_time)
                &
                (group["timestamp"] <= end_limit)
            ]

            # Si le nombre d'échecs atteint le seuil,
            # on considère ce comportement comme suspect.
            if len(window) >= threshold:

                # Liste des utilisateurs ciblés.
                targeted_users = (
                    window["username"]
                    .dropna()
                    .unique()
                    .tolist()
                )

                # On construit une détection structurée.
                detection = {
                    "event_type": "FAILED_LOGIN_BURST",
                    "ip_address": ip_address,
                    "failed_attempts": len(window),
                    "start_time": start_time,
                    "end_time": window["timestamp"].max(),
                    "targeted_users": targeted_users
                }

                detections.append(detection)

                # On arrête après la première détection
                # pour éviter de générer plusieurs alertes
                # similaires pour la même IP.
                break

    return detections


if __name__ == "__main__":

    from app.collectors.log_collector import read_log_file
    from app.parsers.log_parser import parse_log_lines

    # Lecture.
    lines = read_log_file(
        "data/raw/sample.log"
    )

    # Parsing.
    parsed_logs = parse_log_lines(lines)

    # Transformation en DataFrame.
    df = logs_to_dataframe(
        parsed_logs
    )

    # Détection.
    burst_detections = detect_failed_login_bursts(
        df,
        threshold=5,
        window_minutes=5
    )

    print(
        "\n--- Tentatives suspectes détectées ---"
    )

    if not burst_detections:
        print(
            "Aucune activité suspecte détectée."
        )

    for detection in burst_detections:

        print(
            f"IP : {detection['ip_address']}"
        )

        print(
            f"Nombre d'échecs : "
            f"{detection['failed_attempts']}"
        )

        print(
            f"Début : {detection['start_time']}"
        )

        print(
            f"Fin : {detection['end_time']}"
        )

        print(
            f"Utilisateurs ciblés : "
            f"{detection['targeted_users']}"
        )

        print(
            f"Type : {detection['event_type']}"
        )

        print("-" * 40)

burst_detections = detect_failed_login_bursts(...)

print("\n--- Alertes de sécurité ---")

for detection in burst_detections:

    # Transformation de la détection
    # en alerte de sécurité.
    alert = build_security_alert(
        detection
    )

    print(
        f"Type : {alert['event_type']}"
    )

    print(
        f"IP : {alert['ip_address']}"
    )

    print(
        f"Score : {alert['risk_score']}/100"
    )

    print(
        f"Niveau : {alert['risk_level']}"
    )

    print(
        f"Description : "
        f"{alert['description']}"
    )

    print("-" * 50)