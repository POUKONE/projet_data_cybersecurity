import pandas as pd
import requests
import streamlit as st

from api_client import get_events
API_URL = "http://127.0.0.1:8000"


st.title("Analyse des Logs")

st.markdown(
    """
    Cette page permet d'explorer les événements
    de sécurité collectés et analysés par le système.
    """
)


def fetch_events() -> list[dict]:
    """
    Récupère les événements de sécurité
    depuis l'API FastAPI.
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


events = fetch_events()

if not events:
    st.info(
        "Aucun événement de sécurité disponible."
    )
    st.stop()


df = pd.DataFrame(events)


# ============================================================
# NORMALISATION DES DATES
# ============================================================

if "timestamp" in df.columns:
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )


# ============================================================
# KPI
# ============================================================

st.subheader("Vue générale")

col1, col2, col3, col4 = st.columns(4)


total_events = len(df)

failed_events = 0
successful_events = 0
unique_ips = 0


if "status" in df.columns:

    failed_events = len(
        df[
            df["status"]
            .astype(str)
            .str.upper()
            == "FAILED"
        ]
    )

    successful_events = len(
        df[
            df["status"]
            .astype(str)
            .str.upper()
            == "SUCCESS"
        ]
    )


if "ip_address" in df.columns:

    unique_ips = (
        df["ip_address"]
        .dropna()
        .nunique()
    )


with col1:
    st.metric(
        "Événements",
        total_events
    )

with col2:
    st.metric(
        "Connexions échouées",
        failed_events
    )

with col3:
    st.metric(
        "Connexions réussies",
        successful_events
    )

with col4:
    st.metric(
        "IP uniques",
        unique_ips
    )


# ============================================================
# FILTRES
# ============================================================

st.divider()

st.subheader("Filtres")

filter_col1, filter_col2 = st.columns(2)


with filter_col1:

    if "event_type" in df.columns:

        event_types = sorted(
            df["event_type"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_event_types = st.multiselect(
            "Type d'événement",
            options=event_types,
            default=event_types
        )

    else:
        selected_event_types = []


with filter_col2:

    if "ip_address" in df.columns:

        ip_addresses = sorted(
            df["ip_address"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_ips = st.multiselect(
            "Adresse IP",
            options=ip_addresses,
            default=ip_addresses
        )

    else:
        selected_ips = []


filtered_df = df.copy()


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
# ÉVÉNEMENTS DANS LE TEMPS
# ============================================================

st.divider()

st.subheader(
    "Volume d'événements dans le temps"
)


if (
    "timestamp" in filtered_df.columns
    and filtered_df["timestamp"]
    .notna()
    .any()
):

    timeline = (
        filtered_df
        .dropna(
            subset=["timestamp"]
        )
        .set_index("timestamp")
        .resample("h")
        .size()
        .rename("events")
    )

    st.line_chart(
        timeline
    )

else:

    st.info(
        "Aucune donnée temporelle exploitable."
    )


# ============================================================
# IP LES PLUS ACTIVES
# ============================================================

st.divider()

st.subheader(
    "IP les plus actives"
)


if (
    "ip_address" in filtered_df.columns
    and not filtered_df.empty
):

    top_ips = (
        filtered_df[
            "ip_address"
        ]
        .value_counts()
        .head(10)
    )

    st.bar_chart(
        top_ips
    )

else:

    st.info(
        "Aucune adresse IP disponible."
    )


# ============================================================
# TYPES D'ÉVÉNEMENTS
# ============================================================

st.divider()

st.subheader(
    "Répartition des événements"
)


if (
    "event_type" in filtered_df.columns
    and not filtered_df.empty
):

    event_distribution = (
        filtered_df[
            "event_type"
        ]
        .value_counts()
    )

    st.bar_chart(
        event_distribution
    )

else:

    st.info(
        "Aucun type d'événement disponible."
    )


# ============================================================
# TABLEAU COMPLET
# ============================================================

st.divider()

st.subheader(
    "Événements collectés"
)


display_columns = [
    column
    for column in [
        "id",
        "timestamp",
        "event_type",
        "ip_address",
        "message",
        "created_at",
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