import pandas as pd
import requests
import streamlit as st


API_URL = "http://127.0.0.1:8000"


st.title("Alertes 🔔")

st.markdown(
    """
    Consultez les alertes de sécurité détectées
    par les différents modules du projet.
    """
)


def fetch_alerts() -> list[dict]:
    """
    Récupère les alertes depuis l'API FastAPI.
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

    except requests.RequestException as error:

        st.error(
            f"Impossible de récupérer les alertes : {error}"
        )

        return []


alerts = fetch_alerts()

if not alerts:

    st.info(
        "Aucune alerte disponible pour le moment."
    )

    st.stop()


df = pd.DataFrame(alerts)


# ============================================================
# FILTRES
# ============================================================

st.subheader("Filtres")

col1, col2, col3 = st.columns(3)


with col1:

    if "risk_level" in df.columns:

        risk_levels = sorted(
            df["risk_level"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_risk_levels = st.multiselect(
            "Niveau de risque",
            options=risk_levels,
            default=risk_levels
        )

    else:
        selected_risk_levels = []


with col2:

    if "event_type" in df.columns:

        event_types = sorted(
            df["event_type"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_event_types = st.multiselect(
            "Source / type d'alerte",
            options=event_types,
            default=event_types
        )

    else:
        selected_event_types = []


with col3:

    if "ip_address" in df.columns:

        ip_addresses = sorted(
            df["ip_address"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_ips = st.multiselect(
            "Machine / IP",
            options=ip_addresses,
            default=ip_addresses
        )

    else:
        selected_ips = []


# ============================================================
# APPLICATION DES FILTRES
# ============================================================

filtered_df = df.copy()


if (
    "risk_level" in filtered_df.columns
    and selected_risk_levels
):

    filtered_df = filtered_df[
        filtered_df["risk_level"].isin(
            selected_risk_levels
        )
    ]


if (
    "event_type" in filtered_df.columns
    and selected_event_types
):

    filtered_df = filtered_df[
        filtered_df["event_type"].isin(
            selected_event_types
        )
    ]


if (
    "ip_address" in filtered_df.columns
    and selected_ips
):

    filtered_df = filtered_df[
        filtered_df["ip_address"].isin(
            selected_ips
        )
    ]


# ============================================================
# KPI
# ============================================================

st.divider()

col1, col2, col3, col4 = st.columns(4)


total_alerts = len(filtered_df)

critical_alerts = 0
high_alerts = 0

average_score = 0


if "risk_level" in filtered_df.columns:

    critical_alerts = len(
        filtered_df[
            filtered_df["risk_level"]
            == "CRITICAL"
        ]
    )

    high_alerts = len(
        filtered_df[
            filtered_df["risk_level"]
            == "HIGH"
        ]
    )


if (
    "risk_score" in filtered_df.columns
    and not filtered_df.empty
):

    average_score = round(
        filtered_df["risk_score"].mean(),
        1
    )


with col1:
    st.metric(
        "Alertes",
        total_alerts
    )

with col2:
    st.metric(
        "Critiques",
        critical_alerts
    )

with col3:
    st.metric(
        "Élevées",
        high_alerts
    )

with col4:
    st.metric(
        "Score moyen",
        average_score
    )


# ============================================================
# TABLEAU
# ============================================================

st.divider()

st.subheader(
    "Tableau des alertes"
)


display_columns = [
    column
    for column in [
        "id",
        "event_type",
        "ip_address",
        "risk_score",
        "risk_level",
        "description",
        "created_at"
    ]
    if column in filtered_df.columns
]


st.dataframe(
    filtered_df[
        display_columns
    ],
    use_container_width=True,
    hide_index=True
)