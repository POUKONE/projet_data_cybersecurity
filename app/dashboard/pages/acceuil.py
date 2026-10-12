import pandas as pd
import requests
import streamlit as st

from api_client import (
    check_health,
    get_alerts,
    get_events,
)

API_URL = "http://127.0.0.1:8000"


st.title("Dashboard d'analyse de données et cybersécurité")

st.markdown(
    """
    Plateforme de supervision permettant de centraliser
    les événements de sécurité, les alertes, les analyses
    réseau, les audits Web et les résultats issus des
    modules de détection.
    """
)


# ============================================================
# API
# ============================================================

def check_api() -> bool:
    """
    Vérifie si l'API FastAPI est disponible.
    """

    try:
        response = requests.get(
            f"{API_URL}/health",
            timeout=3
        )

        response.raise_for_status()

        return (
            response.json().get("status")
            == "healthy"
        )

    except requests.RequestException:
        return False


def fetch_alerts() -> list[dict]:
    """
    Récupère les alertes de sécurité.
    """

    try:
        response = requests.get(
            f"{API_URL}/alerts",
            timeout=5
        )

        response.raise_for_status()

        return response.json().get(
            "alerts",
            []
        )

    except requests.RequestException:
        return []


def fetch_events() -> list[dict]:
    """
    Récupère les événements de sécurité.
    """

    try:
        response = requests.get(
            f"{API_URL}/events",
            timeout=5
        )

        response.raise_for_status()

        return response.json().get(
            "events",
            []
        )

    except requests.RequestException:
        return []


# ============================================================
# ÉTAT DU SYSTÈME
# ============================================================

api_available = check_api()

if api_available:

    st.success(
        "API opérationnelle"
    )

else:

    st.error(
        "API indisponible. Vérifiez que FastAPI est lancé."
    )


# ============================================================
# DONNÉES
# ============================================================

alerts = fetch_alerts()
events = fetch_events()

alerts_df = pd.DataFrame(
    alerts
)

events_df = pd.DataFrame(
    events
)


# ============================================================
# INDICATEURS PRINCIPAUX
# ============================================================

st.subheader(
    "Vue générale"
)

total_alerts = len(
    alerts_df
)

total_events = len(
    events_df
)

critical_alerts = 0

high_alerts = 0


if (
    not alerts_df.empty
    and "risk_level" in alerts_df.columns
):

    critical_alerts = (
        alerts_df[
            alerts_df["risk_level"]
            == "CRITICAL"
        ]
        .shape[0]
    )

    high_alerts = (
        alerts_df[
            alerts_df["risk_level"]
            == "HIGH"
        ]
        .shape[0]
    )


col1, col2, col3, col4 = st.columns(4)


with col1:
    st.metric(
        "Alertes",
        total_alerts
    )


with col2:
    st.metric(
        "Événements",
        total_events
    )


with col3:
    st.metric(
        "Alertes critiques",
        critical_alerts
    )


with col4:
    st.metric(
        "Alertes élevées",
        high_alerts
    )


# ============================================================
# MODULES
# ============================================================

st.divider()

st.subheader(
    "Modules disponibles"
)


module_data = [
    {
        "Module": "KPI",
        "Fonction": (
            "Vue synthétique des indicateurs "
            "et niveaux de risque"
        ),
    },
    {
        "Module": "Réseau",
        "Fonction": (
            "Analyse des ports, services "
            "et anomalies réseau"
        ),
    },
    {
        "Module": "Logs",
        "Fonction": (
            "Analyse des événements "
            "et activités enregistrées"
        ),
    },
    {
        "Module": "Web",
        "Fonction": (
            "Audit des principaux éléments "
            "de sécurité HTTP"
        ),
    },
    {
        "Module": "Alertes",
        "Fonction": (
            "Centralisation et filtrage "
            "des alertes de sécurité"
        ),
    },
    {
        "Module": "ML",
        "Fonction": (
            "Analyse des anomalies "
            "par apprentissage automatique"
        ),
    },
]


st.dataframe(
    pd.DataFrame(module_data),
    use_container_width=True,
    hide_index=True
)


# ============================================================
# ALERTES PRIORITAIRES
# ============================================================

st.divider()

st.subheader(
    "Alertes prioritaires"
)


if (
    not alerts_df.empty
    and "risk_score" in alerts_df.columns
):

    priority_df = alerts_df.copy()

    priority_df["risk_score"] = pd.to_numeric(
        priority_df["risk_score"],
        errors="coerce"
    )

    priority_df = (
        priority_df
        .sort_values(
            "risk_score",
            ascending=False
        )
        .head(5)
    )


    columns = [
        column
        for column in [
            "event_type",
            "ip_address",
            "risk_score",
            "risk_level",
            "description",
        ]
        if column in priority_df.columns
    ]


    st.dataframe(
        priority_df[
            columns
        ],
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "Aucune alerte prioritaire disponible."
    )