"""
Module de détection d'anomalies (Machine Learning).
Pipeline complet : Ingestion, Nettoyage, Feature Engineering, Entraînement et Évaluation.
Compatible avec les datasets Kaggle (CSV) pour les test et la base de données SQLite du projet.
"""

#Import des librairies necessaires
from pathlib import Path
import sqlite3
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

# ============================================================
# 1. GESTION DU CHIFFREMENT (COMPATIBILITÉ SQLITE)
# ============================================================
try:
    from app.security.crypto_utils import decrypt_sensitive_text

    def decrypt_value(val: str | None) -> str | None:
        if val is None or not str(val).startswith("ENC:"):
            return val
        return decrypt_sensitive_text(str(val)[4:])

except ImportError:
    # Mode fallback si exécuté hors du package app
    def decrypt_value(val: str | None) -> str | None:
        if val and str(val).startswith("ENC:"):
            return str(val)[4:]  # Conserve la chaîne sans bloquer
        return val


# ============================================================
# 2. INGESTION DES DONNÉES
# ============================================================
def load_data(
    source_type: str = "sqlite",
    path: str = "data/processed/security_project.db",
) -> pd.DataFrame:
    """Charge les données depuis SQLite ou un fichier CSV (Kaggle).

    Paramètres
    ----------
    source_type : 'sqlite' ou 'csv'
    path : chemin vers la base de données ou le fichier CSV
    """
    if source_type == "csv":
        print(f"[+] Chargement du dataset CSV depuis : {path}")
        df = pd.read_csv(path)
        return df

    elif source_type == "sqlite":
        print(f"[+] Connexion à la base SQLite : {path}")
        if not Path(path).exists():
            raise FileNotFoundError(
                f"La base {path} n'existe pas encore. veuillez créer la base."
            )

        conn = sqlite3.connect(path)

        # Extraction des événements de sécurité
        df_events = pd.read_sql_query("SELECT * FROM security_events", conn)
        # Extraction des scans réseau
        df_scans = pd.read_sql_query("SELECT * FROM network_scans", conn)
        # Extraction des alertes
        df_alerts = pd.read_sql_query("SELECT * FROM alerts", conn)

        conn.close()

        # Déchiffrement des adresses IP si nécessaire
        for df_target in [df_events, df_alerts]:
            if not df_target.empty and "ip_address" in df_target.columns:
                df_target["ip_address"] = df_target["ip_address"].apply(
                    decrypt_value
                )

        # Si les tables de logs/scans sont renseignées, on procède à l'agrégation
        if not df_events.empty or not df_scans.empty:
            return aggregate_sqlite_tables(df_events, df_scans, df_alerts)
        else:
            print(
                "[!] La base SQLite existe mais ne contient pas encore assez d'enregistrements."
            )
            return pd.DataFrame()
    else:
        raise ValueError(
            "source_type doit être soit 'sqlite' soit 'csv'."
        )


def aggregate_sqlite_tables(
    df_events: pd.DataFrame, df_scans: pd.DataFrame, df_alerts: pd.DataFrame
) -> pd.DataFrame:
    """Agrémente et combine les tables de sécurité par adresse IP / hôte pour le ML."""
    features_per_ip = {}

    # 1. Agrégation des scans réseau (ports scannés, diversité de services)
    if not df_scans.empty and "host" in df_scans.columns:
        scans_agg = (
            df_scans.groupby("host")
            .agg(
                nb_ports_scannes=("port", "count"),
                nb_ports_distincts=("port", "nunique"),
                nb_services_distincts=("service", "nunique"),
            )
            .reset_index()
            .rename(columns={"host": "entity_id"})
        )
        for _, row in scans_agg.iterrows():
            features_per_ip[row["entity_id"]] = row.to_dict()

    # 2. Agrégation des événements de sécurité
    if not df_events.empty and "ip_address" in df_events.columns:
        events_agg = (
            df_events.groupby("ip_address")
            .agg(
                nb_events_total=("id", "count"),
                nb_types_events=("event_type", "nunique"),
            )
            .reset_index()
            .rename(columns={"ip_address": "entity_id"})
        )
        for _, row in events_agg.iterrows():
            eid = row["entity_id"]
            if eid not in features_per_ip:
                features_per_ip[eid] = {
                    "entity_id": eid,
                    "nb_ports_scannes": 0,
                    "nb_ports_distincts": 0,
                    "nb_services_distincts": 0,
                }
            features_per_ip[eid].update(row.to_dict())

    # 3. Agrégation des alertes (échecs répétés, score moyen)
    if not df_alerts.empty and "ip_address" in df_alerts.columns:
        alerts_agg = (
            df_alerts.groupby("ip_address")
            .agg(
                nb_alertes=("id", "count"),
                total_failed_attempts=("failed_attempts", "sum"),
                risk_score_max=("risk_score", "max"),
            )
            .reset_index()
            .rename(columns={"ip_address": "entity_id"})
        )
        for _, row in alerts_agg.iterrows():
            eid = row["entity_id"]
            if eid not in features_per_ip:
                features_per_ip[eid] = {
                    "entity_id": eid,
                    "nb_ports_scannes": 0,
                    "nb_ports_distincts": 0,
                    "nb_services_distincts": 0,
                    "nb_events_total": 0,
                    "nb_types_events": 0,
                }
            features_per_ip[eid].update(row.to_dict())

    df_result = pd.DataFrame(list(features_per_ip.values()))
    return df_result


# ============================================================
# 3. NETTOYAGE ET SÉLECTION DES FEATURES
# ============================================================
def preprocess_features(
    df: pd.DataFrame, feature_cols: list[str] = None
) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    """Nettoie le DataFrame, gère les valeurs nulles et extrait la matrice X."""
    df_clean = df.copy()

    # Si aucune colonne spécifiée, on prend automatiquement toutes les colonnes numériques
    if feature_cols is None:
        numeric_cols = df_clean.select_dtypes(
            include=[np.number]
        ).columns.tolist()
        # On exclut les identifiants techniques
        feature_cols = [
            c
            for c in numeric_cols
            if c.lower() not in ["id", "scan_id", "label", "is_anomaly", "class"]
        ]

    print(f"[+] Variables sélectionnées pour le modèle : {feature_cols}")

    # Imputation des valeurs nulles par 0 (standard pour des compteurs et métriques réseau)
    df_clean[feature_cols] = df_clean[feature_cols].fillna(0)

    # Suppression des valeurs infinies éventuelles
    df_clean[feature_cols] = df_clean[feature_cols].replace(
        [np.inf, -np.inf], 0
    )

    X = df_clean[feature_cols]
    return df_clean, X, feature_cols


# ============================================================
# 4. ENTRAÎNEMENT DE L'ISOLATION FOREST
# ============================================================
def train_model(
    X: pd.DataFrame,
    contamination: float = 0.03,
    n_estimators: int = 150,
    random_state: int = 42,
) -> IsolationForest:
    """Entraîne l'Isolation Forest sur la matrice de caractéristiques."""
    print(
        f"[+] Entraînement de l'Isolation Forest (arbres={n_estimators}, contamination={contamination})..."
    )

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)
    return model


# ============================================================
# 5. ÉVALUATION ET TEST DU MODÈLE
# ============================================================
def evaluate_model(
    model: IsolationForest,
    X: pd.DataFrame,
    df_original: pd.DataFrame,
    ground_truth_col: str = None,
) -> pd.DataFrame:
    """Calcule les prédictions, les scores d'anomalie et évalue les performances."""
    df_results = df_original.copy()

    # Prédictions : 1 = normal, -1 = anomalie
    predictions = model.predict(X)
    df_results["is_anomaly"] = predictions

    # Score de décision brut (plus il est négatif, plus c'est une anomalie)
    raw_scores = model.decision_function(X)
    df_results["raw_anomaly_score"] = raw_scores

    # Normalisation du score de risque sur une échelle 0 - 100 pour le Risk Scoring
    # (Un score proche de 100 signifie une anomalie très critique)
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s != min_s:
        # Inversion : score brut faible -> risque élevé
        df_results["risk_score_ml"] = np.round(
            (1.0 - (raw_scores - min_s) / (max_s - min_s)) * 100, 2
        )
    else:
        df_results["risk_score_ml"] = 50.0

    nb_anomalies = (df_results["is_anomaly"] == -1).sum()
    nb_normaux = (df_results["is_anomaly"] == 1).sum()
    print(f"\n[+] Résultats de détection :")
    print(f"    - Événements normaux : {nb_normaux}")
    print(f"    - Anomalies détectées : {nb_anomalies}")

    # Si le dataset possède une vérité terrain (ex: Kaggle avec colonne 'label' ou 'attack')
    if ground_truth_col and ground_truth_col in df_original.columns:
        print(f"\n[+] Évaluation avec la vérité terrain ({ground_truth_col}) :")

        # Conversion du label Kaggle en format binaire (-1: attaque, 1: normal)
        y_true = df_original[ground_truth_col].apply(
            lambda x: (
                -1
                if str(x).lower()
                in ["1", "attack", "anomaly", "malicious", "true"]
                else 1
            )
        )

        print(
            confusion_matrix(
                y_true, predictions, labels=[1, -1]
            )
        )
        print(
            classification_report(
                y_true,
                predictions,
                labels=[1, -1],
                target_names=["Normal", "Anomalie"],
            )
        )

        # Calcul spécifique du taux de faux positifs (FPR)
        tn, fp, fn, tp = confusion_matrix(
            y_true == -1, predictions == -1
        ).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        print(f"    - Taux de Faux Positifs (FPR) : {fpr:.2%}")

    return df_results


# ============================================================
# 6. PIPELINE PRINCIPAL (RUNNER)
# ============================================================
def run_pipeline(
    source_type: str = "sqlite",
    data_path: str = "data/processed/security_project.db",
    ground_truth_col: str = None,
    export_model_path: str = "models/isolation_forest.joblib",
    contamination: float = 0.03,
):
    """Orchestre l'ensemble du workflow ML."""
    # 1. Chargement
    df = load_data(source_type=source_type, path=data_path)
    if df.empty:
        print("[!] Arrêt du pipeline : aucune donnée à traiter.")
        return None, None

    # 2. Prétraitement
    df_clean, X, feature_cols = preprocess_features(df)

    # 3. Entraînement
    model = train_model(X, contamination=contamination)

    # 4. Évaluation
    df_results = evaluate_model(
        model, X, df_clean, ground_truth_col=ground_truth_col
    )

    # 5. Sauvegarde du modèle et de la liste des features
    save_path = Path(export_model_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": model, "feature_names": feature_cols},
        save_path,
    )
    print(f"[+] Modèle et métadonnées sauvegardés sous : {save_path}")

    return model, df_results