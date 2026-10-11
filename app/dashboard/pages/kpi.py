import pandas as pd
import requests
import streamlit as st


API_URL = "http://127.0.0.1:8000"


st.title("Indicateurs de sécurité")

st.markdown(
    """
    Cette page présente une vue synthétique
    des principaux indicateurs de sécurité.
    """
)


def fetch_alerts() -> list[dict]:
    """
    Récupère les alertes depuis FastAPI.
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


def fetch_events() -> list[dict]:
    """
    Récupère les événements depuis FastAPI.
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

    except requests.RequestException as error:
        st.error(
            f"Impossible de récupérer les événements : {error}"
        )

        return []


alerts = fetch_alerts()
events = fetch_events()


alerts_df = pd.DataFrame(
    alerts
)

events_df = pd.DataFrame(
    events
)


# ============================================================
# KPI PRINCIPAUX
# ============================================================

total_alerts = len(
    alerts_df
)

total_events = len(
    events_df
)

critical_alerts = 0

high_alerts = 0

average_risk_score = 0


if not alerts_df.empty:

    if "risk_level" in alerts_df.columns:

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


    if "risk_score" in alerts_df.columns:

        average_risk_score = round(
            pd.to_numeric(
                alerts_df["risk_score"],
                errors="coerce"
            )
            .dropna()
            .mean(),
            1
        )

        if pd.isna(
            average_risk_score
        ):
            average_risk_score = 0


col1, col2, col3, col4, col5 = st.columns(5)


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
        "Critiques",
        critical_alerts
    )


with col4:
    st.metric(
        "Élevées",
        high_alerts
    )


with col5:
    st.metric(
        "Score moyen",
        average_risk_score
    )


# ============================================================
# NIVEAU GLOBAL DE RISQUE
# ============================================================

st.divider()

st.subheader(
    "Niveau global de risque"
)


if average_risk_score >= 70:

    global_risk = "CRITICAL"

elif average_risk_score >= 50:

    global_risk = "HIGH"

elif average_risk_score >= 30:

    global_risk = "MEDIUM"

else:

    global_risk = "LOW"


st.metric(
    "Niveau global",
    global_risk
)


# ============================================================
# RÉPARTITION DES NIVEAUX DE RISQUE
# ============================================================

st.divider()

st.subheader(
    "Répartition des niveaux de risque"
)


if (
    not alerts_df.empty
    and "risk_level" in alerts_df.columns
):

    risk_distribution = (
        alerts_df[
            "risk_level"
        ]
        .value_counts()
    )

    st.bar_chart(
        risk_distribution
    )

else:

    st.info(
        "Aucune donnée de risque disponible."
    )


# ============================================================
# TYPES D'ALERTES
# ============================================================

st.divider()

st.subheader(
    "Types d'alertes les plus fréquents"
)


if (
    not alerts_df.empty
    and "event_type" in alerts_df.columns
):

    alert_types = (
        alerts_df[
            "event_type"
        ]
        .value_counts()
        .head(10)
    )

    st.bar_chart(
        alert_types
    )

else:

    st.info(
        "Aucune alerte disponible."
    )


# ============================================================
# IP LES PLUS CONCERNÉES
# ============================================================

st.divider()

st.subheader(
    "Adresses IP les plus concernées"
)


if (
    not alerts_df.empty
    and "ip_address" in alerts_df.columns
):

    ip_counts = (
        alerts_df[
            "ip_address"
        ]
        .dropna()
        .value_counts()
        .head(10)
    )

    if not ip_counts.empty:

        st.bar_chart(
            ip_counts
        )

    else:

        st.info(
            "Aucune adresse IP disponible."
        )

else:

    st.info(
        "Aucune donnée IP disponible."
    )


# ============================================================
# ALERTES LES PLUS CRITIQUES
# ============================================================

st.divider()

st.subheader(
    "Alertes prioritaires"
)


if (
    not alerts_df.empty
    and "risk_score" in alerts_df.columns
):

    priority_df = (
        alerts_df
        .copy()
    )

    priority_df[
        "risk_score"
    ] = pd.to_numeric(
        priority_df[
            "risk_score"
        ],
        errors="coerce"
    )

    priority_df = (
        priority_df
        .sort_values(
            "risk_score",
            ascending=False
        )
        .head(10)
    )


    display_columns = [
        column
        for column in [
            "event_type",
            "ip_address",
            "risk_score",
            "risk_level",
            "description",
            "created_at",
        ]
        if column in priority_df.columns
    ]


    st.dataframe(
        priority_df[
            display_columns
        ],
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "Aucune alerte disponible."
    )