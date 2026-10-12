import pandas as pd
import requests
import streamlit as st

from api_client import (
    get_network_scan,
    run_network_scan,
)


API_URL = "http://127.0.0.1:8000"


st.title("Analyse Réseau")

st.markdown(
    """
    Cette page permet de consulter le dernier scan réseau
    et de lancer une nouvelle analyse Nmap.
    """
)


def fetch_network_scan() -> list[dict]:
    """
    Récupère le dernier scan réseau enregistré.
    """

    try:
        response = requests.get(
            f"{API_URL}/network/scans",
            timeout=5
        )

        response.raise_for_status()

        return response.json().get(
            "scan",
            []
        )

    except requests.RequestException as error:
        st.error(
            f"Impossible de récupérer le scan réseau : {error}"
        )

        return []


def launch_network_scan(target: str) -> dict | None:
    """
    Lance une nouvelle analyse réseau
    via l'API FastAPI.
    """

    try:
        response = requests.post(
            f"{API_URL}/network/scan",
            json={
                "target": target
            },
            timeout=60
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as error:
        st.error(
            f"Impossible de lancer le scan réseau : {error}"
        )

        return None


# ============================================================
# LANCEMENT D'UN SCAN
# ============================================================

st.subheader("Lancer une analyse réseau")

target = st.text_input(
    "Cible",
    value="127.0.0.1",
    help=(
        "Utilisez uniquement une machine ou un réseau "
        "que vous êtes autorisé à analyser."
    )
)


if st.button("Lancer le scan"):

    if not target.strip():

        st.warning(
            "Veuillez renseigner une cible."
        )

    else:

        with st.spinner(
            "Analyse réseau en cours..."
        ):

            result = launch_network_scan(
                target.strip()
            )

        if result is not None:

            st.success(
                "Analyse réseau terminée."
            )

            alert_count = result.get(
                "alert_count",
                0
            )

            st.metric(
                "Alertes détectées",
                alert_count
            )

            alerts = result.get(
                "alerts",
                []
            )

            if alerts:

                st.subheader(
                    "Alertes détectées pendant le scan"
                )

                st.dataframe(
                    pd.DataFrame(alerts),
                    use_container_width=True,
                    hide_index=True
                )

            else:

                st.info(
                    "Aucune nouvelle anomalie détectée."
                )


# ============================================================
# DERNIER SCAN
# ============================================================

st.divider()

st.subheader("Dernier scan réseau")

scan = fetch_network_scan()

if not scan:

    st.info(
        "Aucun scan réseau disponible."
    )

    st.stop()


df = pd.DataFrame(scan)


# ============================================================
# KPI
# ============================================================

col1, col2, col3, col4 = st.columns(4)


total_entries = len(df)

unique_hosts = (
    df["host"].nunique()
    if "host" in df.columns
    else 0
)

open_ports = (
    df[
        df["state"]
        .astype(str)
        .str.lower()
        == "open"
    ].shape[0]
    if "state" in df.columns
    else 0
)

unique_services = (
    df["service"]
    .replace("", pd.NA)
    .dropna()
    .nunique()
    if "service" in df.columns
    else 0
)


with col1:
    st.metric(
        "Entrées réseau",
        total_entries
    )

with col2:
    st.metric(
        "Hôtes",
        unique_hosts
    )

with col3:
    st.metric(
        "Ports ouverts",
        open_ports
    )

with col4:
    st.metric(
        "Services détectés",
        unique_services
    )


# ============================================================
# FILTRES
# ============================================================

st.divider()

st.subheader("Filtres")

filter_col1, filter_col2 = st.columns(2)


with filter_col1:

    if "host" in df.columns:

        hosts = sorted(
            df["host"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_hosts = st.multiselect(
            "Hôtes",
            options=hosts,
            default=hosts
        )

    else:

        selected_hosts = []


with filter_col2:

    if "service" in df.columns:

        services = sorted(
            df["service"]
            .replace("", pd.NA)
            .dropna()
            .unique()
            .tolist()
        )

        selected_services = st.multiselect(
            "Services",
            options=services,
            default=services
        )

    else:

        selected_services = []


filtered_df = df.copy()


if (
    "host" in filtered_df.columns
    and selected_hosts
):

    filtered_df = filtered_df[
        filtered_df["host"].isin(
            selected_hosts
        )
    ]


if (
    "service" in filtered_df.columns
    and selected_services
):

    filtered_df = filtered_df[
        filtered_df["service"].isin(
            selected_services
        )
    ]


# ============================================================
# PORTS
# ============================================================

st.divider()

st.subheader("Ports détectés")

if (
    "port" in filtered_df.columns
    and not filtered_df.empty
):

    port_counts = (
        filtered_df["port"]
        .astype(str)
        .value_counts()
        .sort_index()
    )

    st.bar_chart(
        port_counts
    )


# ============================================================
# SERVICES
# ============================================================

st.divider()

st.subheader("Services réseau")

if (
    "service" in filtered_df.columns
    and not filtered_df.empty
):

    service_counts = (
        filtered_df["service"]
        .replace("", "Non identifié")
        .value_counts()
    )

    st.bar_chart(
        service_counts
    )


# ============================================================
# TABLEAU
# ============================================================

st.divider()

st.subheader("Détails du scan")


display_columns = [
    column
    for column in [
        "host",
        "protocol",
        "port",
        "state",
        "service",
        "product",
        "version",
        "scan_id",
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