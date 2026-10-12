import pandas as pd
import requests
import streamlit as st

from api_client import get_alerts


st.title("Alertes")

st.markdown(
    """
    Consultation et classification des observations
    de sécurité détectées par les différents modules.
    """
)


# ============================================================
# CHARGEMENT DES DONNÉES
# ============================================================

try:

    alerts = get_alerts()

except requests.RequestException as error:

    st.error(
        f"Impossible de récupérer les alertes : {error}"
    )

    st.stop()


if not alerts:

    st.info(
        "Aucune alerte disponible."
    )

    st.stop()


df = pd.DataFrame(
    alerts
)


# ============================================================
# NORMALISATION
# ============================================================

if "created_at" in df.columns:

    df["created_at"] = pd.to_datetime(
        df["created_at"],
        errors="coerce"
    )


for column in [
    "source_type",
    "target",
    "ip_address",
    "host",
    "url",
    "event_type",
    "risk_level",
    "status",
]:

    if column not in df.columns:
        df[column] = None


# ============================================================
# TITRE DE LA ZONE DE FILTRES
# ============================================================

st.subheader(
    "Classification des observations"
)


# ============================================================
# PREMIÈRE LIGNE DE FILTRES
# ============================================================

col1, col2, col3 = st.columns(3)


# ------------------------------------------------------------
# SOURCE
# ------------------------------------------------------------

with col1:

    sources = sorted(
        df["source_type"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_sources = st.multiselect(
        "Source",
        sources
    )


# ------------------------------------------------------------
# NIVEAU DE RISQUE
# ------------------------------------------------------------

with col2:

    risk_levels = sorted(
        df["risk_level"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_risks = st.multiselect(
        "Niveau de risque",
        risk_levels
    )


# ------------------------------------------------------------
# STATUT
# ------------------------------------------------------------

with col3:

    statuses = sorted(
        df["status"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_statuses = st.multiselect(
        "Statut",
        statuses
    )


# ============================================================
# DEUXIÈME LIGNE DE FILTRES
# ============================================================

col4, col5, col6 = st.columns(3)


# ------------------------------------------------------------
# CIBLE
# ------------------------------------------------------------

with col4:

    targets = sorted(
        df["target"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_targets = st.multiselect(
        "Cible",
        targets
    )


# ------------------------------------------------------------
# ADRESSE IP
# ------------------------------------------------------------

with col5:

    ip_addresses = sorted(
        df["ip_address"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_ips = st.multiselect(
        "Adresse IP",
        ip_addresses
    )


# ------------------------------------------------------------
# TYPE D'OBSERVATION
# ------------------------------------------------------------

with col6:

    event_types = sorted(
        df["event_type"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_events = st.multiselect(
        "Type d'observation",
        event_types
    )


# ============================================================
# FILTRAGE
# ============================================================

filtered_df = df.copy()


if selected_sources:

    filtered_df = filtered_df[
        filtered_df[
            "source_type"
        ].isin(
            selected_sources
        )
    ]


if selected_risks:

    filtered_df = filtered_df[
        filtered_df[
            "risk_level"
        ].isin(
            selected_risks
        )
    ]


if selected_statuses:

    filtered_df = filtered_df[
        filtered_df[
            "status"
        ].isin(
            selected_statuses
        )
    ]


if selected_targets:

    filtered_df = filtered_df[
        filtered_df[
            "target"
        ].isin(
            selected_targets
        )
    ]


if selected_ips:

    filtered_df = filtered_df[
        filtered_df[
            "ip_address"
        ].isin(
            selected_ips
        )
    ]


if selected_events:

    filtered_df = filtered_df[
        filtered_df[
            "event_type"
        ].isin(
            selected_events
        )
    ]


# ============================================================
# KPI
# ============================================================

st.divider()

total = len(
    filtered_df
)

critical = (
    filtered_df[
        filtered_df["risk_level"]
        == "CRITICAL"
    ].shape[0]
)

high = (
    filtered_df[
        filtered_df["risk_level"]
        == "HIGH"
    ].shape[0]
)

open_alerts = (
    filtered_df[
        filtered_df["status"]
        == "OPEN"
    ].shape[0]
)


score = pd.to_numeric(
    filtered_df.get(
        "risk_score"
    ),
    errors="coerce"
)


average_score = (
    round(
        score.mean(),
        1
    )
    if not score.empty
    else 0
)


kpi1, kpi2, kpi3, kpi4, kpi5 = (
    st.columns(5)
)


kpi1.metric(
    "Observations",
    total
)

kpi2.metric(
    "Critiques",
    critical
)

kpi3.metric(
    "Élevées",
    high
)

kpi4.metric(
    "Ouvertes",
    open_alerts
)

kpi5.metric(
    "Score moyen",
    average_score
)


# ============================================================
# VUE PAR CIBLE
# ============================================================

st.divider()

st.subheader(
    "Analyse par cible"
)


if filtered_df.empty:

    st.info(
        "Aucune observation ne correspond aux filtres sélectionnés."
    )

else:

    # On retire les cibles absentes
    target_df = filtered_df.dropna(
        subset=["target"]
    ).copy()


    if target_df.empty:

        st.info(
            "Aucune cible identifiable dans les observations."
        )

    else:

        # ----------------------------------------------------
        # AGRÉGATION PAR CIBLE
        # ----------------------------------------------------

        target_summary = (
            target_df
            .groupby("target")
            .agg(
                observations=(
                    "event_type",
                    "count"
                ),
                score_max=(
                    "risk_score",
                    "max"
                ),
                score_moyen=(
                    "risk_score",
                    "mean"
                ),
                source=(
                    "source_type",
                    lambda values: ", ".join(
                        sorted(
                            set(
                                values
                                .dropna()
                                .astype(str)
                            )
                        )
                    )
                ),
            )
            .reset_index()
        )


        target_summary[
            "score_moyen"
        ] = (
            target_summary[
                "score_moyen"
            ]
            .round(1)
        )


        # ----------------------------------------------------
        # CALCUL DU NIVEAU MAXIMAL
        # ----------------------------------------------------

        def get_level_from_score(
            score
        ):

            if pd.isna(score):
                return "UNKNOWN"

            if score >= 70:
                return "CRITICAL"

            if score >= 50:
                return "HIGH"

            if score >= 30:
                return "MEDIUM"

            return "LOW"


        target_summary[
            "niveau_max"
        ] = (
            target_summary[
                "score_max"
            ]
            .apply(
                get_level_from_score
            )
        )


        # ----------------------------------------------------
        # CLASSEMENT
        # ----------------------------------------------------

        target_summary = (
            target_summary
            .sort_values(
                [
                    "score_max",
                    "observations",
                ],
                ascending=[
                    False,
                    False,
                ],
            )
        )


        st.dataframe(
            target_summary.rename(
                columns={
                    "target": "Cible",
                    "source": "Source",
                    "observations": "Observations",
                    "score_max": "Score maximal",
                    "score_moyen": "Score moyen",
                    "niveau_max": "Niveau maximal",
                }
            ),
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# SÉLECTION D'UNE CIBLE
# ============================================================

st.divider()

st.subheader(
    "Détails d'une cible"
)


available_targets = (
    filtered_df[
        "target"
    ]
    .dropna()
    .astype(str)
    .unique()
    .tolist()
)


available_targets = sorted(
    available_targets
)


if not available_targets:

    st.info(
        "Aucune cible disponible."
    )

else:

    selected_target = st.selectbox(
        "Sélectionner une cible",
        available_targets
    )


    selected_target_df = (
        filtered_df[
            filtered_df[
                "target"
            ].astype(str)
            == selected_target
        ]
        .copy()
    )


    # ========================================================
    # KPI DE LA CIBLE
    # ========================================================

    target_total = len(
        selected_target_df
    )


    target_max_score = (
        pd.to_numeric(
            selected_target_df[
                "risk_score"
            ],
            errors="coerce"
        )
        .max()
    )


    if pd.isna(
        target_max_score
    ):
        target_max_score = 0


    target_level = (
        get_level_from_score(
            target_max_score
        )
    )


    target_sources = (
        selected_target_df[
            "source_type"
        ]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )


    target_ips = (
        selected_target_df[
            "ip_address"
        ]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )


    c1, c2, c3, c4 = (
        st.columns(4)
    )


    c1.metric(
        "Observations",
        target_total
    )

    c2.metric(
        "Score maximal",
        target_max_score
    )

    c3.metric(
        "Niveau",
        target_level
    )

    c4.metric(
        "Sources",
        len(
            target_sources
        )
    )


    # ========================================================
    # INFORMATIONS SUR LA CIBLE
    # ========================================================

    st.markdown(
        f"**Cible :** {selected_target}"
    )


    if target_sources:

        st.markdown(
            "**Source(s) :** "
            + ", ".join(
                target_sources
            )
        )


    if target_ips:

        st.markdown(
            "**Adresse(s) IP :** "
            + ", ".join(
                target_ips
            )
        )


    # ========================================================
    # OBSERVATIONS DE LA CIBLE
    # ========================================================

    st.subheader(
        "Observations associées"
    )


    target_columns = [
        column
        for column in [
            "event_type",
            "message",
            "risk_score",
            "risk_level",
            "status",
            "created_at",
        ]
        if column
        in selected_target_df.columns
    ]


    st.dataframe(
        selected_target_df[
            target_columns
        ]
        .sort_values(
            "risk_score",
            ascending=False
        ),
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# TABLEAU GLOBAL
# ============================================================

st.divider()

st.subheader(
    "Toutes les observations"
)


display_columns = [
    column
    for column in [
        "source_type",
        "target",
        "ip_address",
        "host",
        "url",
        "event_type",
        "message",
        "risk_score",
        "risk_level",
        "status",
        "created_at",
    ]
    if column
    in filtered_df.columns
]


st.dataframe(
    filtered_df[
        display_columns
    ],
    use_container_width=True,
    hide_index=True
)