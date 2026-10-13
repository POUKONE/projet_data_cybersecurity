import pandas as pd
import streamlit as st

from api_client import get_alerts


# ============================================================
# PAGE
# ============================================================


st.title(
    "Alertes de sécurité"
)

st.caption(
    (
        "Consultation, filtrage et analyse "
        "des alertes générées par la plateforme."
    )
)


# ============================================================
# CHARGEMENT DES DONNÉES
# ============================================================


try:

    alerts = get_alerts()

except Exception as error:

    st.error(
        (
            "Impossible de récupérer les alertes : "
            f"{error}"
        )
    )

    st.stop()


# ============================================================
# VALIDATION
# ============================================================


if alerts is None:

    alerts = []


if isinstance(
    alerts,
    dict,
):

    if "alerts" in alerts:

        alerts = alerts[
            "alerts"
        ]

    else:

        alerts = [
            alerts
        ]


if not alerts:

    st.info(
        "Aucune alerte disponible."
    )

    st.stop()


# ============================================================
# DATAFRAME
# ============================================================


df = pd.DataFrame(
    alerts
)


if df.empty:

    st.info(
        "Aucune alerte disponible."
    )

    st.stop()


# ============================================================
# NORMALISATION DES COLONNES
# ============================================================


expected_columns = [
    "id",
    "event_type",
    "source_type",
    "risk_score",
    "risk_level",
    "target",
    "ip_address",
    "host",
    "url",
    "message",
    "description",
    "status",
    "classification",
    "severity",
    "confidence",
    "created_at",
]


for column in expected_columns:

    if column not in df.columns:

        df[
            column
        ] = None


# ============================================================
# SCORE
# ============================================================


df[
    "risk_score"
] = pd.to_numeric(
    df[
        "risk_score"
    ],
    errors="coerce",
)


# ============================================================
# NORMALISATION TEXTE
# ============================================================


text_columns = [
    "event_type",
    "source_type",
    "risk_level",
    "status",
    "classification",
    "severity",
    "confidence",
]


for column in text_columns:

    df[
        column
    ] = (
        df[
            column
        ]
        .fillna(
            "UNKNOWN"
        )
        .astype(
            str
        )
    )


# ============================================================
# CIBLE UNIFIÉE
# ============================================================


def resolve_target(
    row,
):
    """
    Détermine la cible principale d'une alerte.
    """

    candidates = [
        row.get(
            "target"
        ),
        row.get(
            "url"
        ),
        row.get(
            "host"
        ),
        row.get(
            "ip_address"
        ),
    ]


    for value in candidates:

        if (
            value is not None
            and not pd.isna(
                value
            )
            and str(
                value
            ).strip()
        ):

            return str(
                value
            )


    return (
        "Cible inconnue"
    )


df[
    "display_target"
] = df.apply(
    resolve_target,
    axis=1,
)


# ============================================================
# EN-TÊTE KPI
# ============================================================


st.subheader(
    "Vue d'ensemble"
)


total_alerts = len(
    df
)


open_alerts = len(
    df[
        df[
            "status"
        ].str.upper()
        == "OPEN"
    ]
)


critical_alerts = len(
    df[
        df[
            "risk_level"
        ].str.upper()
        == "CRITICAL"
    ]
)


high_alerts = len(
    df[
        df[
            "risk_level"
        ].str.upper()
        == "HIGH"
    ]
)


kpi_col1, kpi_col2, kpi_col3, kpi_col4 = (
    st.columns(
        4
    )
)


with kpi_col1:

    st.metric(
        "Alertes totales",
        total_alerts,
    )


with kpi_col2:

    st.metric(
        "Alertes ouvertes",
        open_alerts,
    )


with kpi_col3:

    st.metric(
        "Critiques",
        critical_alerts,
    )


with kpi_col4:

    st.metric(
        "Élevées",
        high_alerts,
    )


# ============================================================
# SCORE GLOBAL
# ============================================================


st.subheader(
    "Niveau de risque"
)


valid_scores = (
    df[
        "risk_score"
    ]
    .dropna()
)


if not valid_scores.empty:

    max_score = (
        valid_scores.max()
    )

    average_score = (
        valid_scores.mean()
    )


    score_col1, score_col2 = (
        st.columns(
            2
        )
    )


    with score_col1:

        if (
            max_score is not None
            and not pd.isna(
                max_score
            )
        ):

            st.metric(
                "Score maximal",
                f"{float(max_score):.0f}/100",
            )


    with score_col2:

        if (
            average_score is not None
            and not pd.isna(
                average_score
            )
        ):

            st.metric(
                "Score moyen",
                f"{float(average_score):.1f}/100",
            )


else:

    st.info(
        (
            "Aucun score de risque "
            "n'est disponible."
        )
    )


# ============================================================
# FILTRES
# ============================================================


st.subheader(
    "Filtres"
)


filter_col1, filter_col2, filter_col3 = (
    st.columns(
        3
    )
)


source_types = sorted(
    df[
        "source_type"
    ]
    .dropna()
    .unique()
    .tolist()
)


risk_levels = sorted(
    df[
        "risk_level"
    ]
    .dropna()
    .unique()
    .tolist()
)


statuses = sorted(
    df[
        "status"
    ]
    .dropna()
    .unique()
    .tolist()
)


with filter_col1:

    selected_sources = (
        st.multiselect(
            "Source",
            options=source_types,
            default=source_types,
            key=(
                "alerts_source_filter"
            ),
        )
    )


with filter_col2:

    selected_levels = (
        st.multiselect(
            "Niveau de risque",
            options=risk_levels,
            default=risk_levels,
            key=(
                "alerts_risk_filter"
            ),
        )
    )


with filter_col3:

    selected_statuses = (
        st.multiselect(
            "Statut",
            options=statuses,
            default=statuses,
            key=(
                "alerts_status_filter"
            ),
        )
    )


# ============================================================
# FILTRE PAR TYPE
# ============================================================


event_types = sorted(
    df[
        "event_type"
    ]
    .dropna()
    .unique()
    .tolist()
)


selected_event_types = (
    st.multiselect(
        "Type d'événement",
        options=event_types,
        default=event_types,
        key=(
            "alerts_event_filter"
        ),
    )
)


# ============================================================
# FILTRE PAR CIBLE
# ============================================================


targets = sorted(
    df[
        "display_target"
    ]
    .dropna()
    .unique()
    .tolist()
)


selected_targets = (
    st.multiselect(
        "Cible",
        options=targets,
        default=targets,
        key=(
            "alerts_target_filter"
        ),
    )
)


# ============================================================
# APPLICATION DES FILTRES
# ============================================================


filtered_df = df[
    df[
        "source_type"
    ].isin(
        selected_sources
    )
    & df[
        "risk_level"
    ].isin(
        selected_levels
    )
    & df[
        "status"
    ].isin(
        selected_statuses
    )
    & df[
        "event_type"
    ].isin(
        selected_event_types
    )
    & df[
        "display_target"
    ].isin(
        selected_targets
    )
].copy()


# ============================================================
# RÉSULTATS
# ============================================================


st.subheader(
    "Alertes"
)


st.write(
    (
        f"{len(filtered_df)} alerte(s) "
        "correspondent aux filtres."
    )
)


if filtered_df.empty:

    st.info(
        (
            "Aucune alerte ne correspond "
            "aux filtres sélectionnés."
        )
    )

else:

    display_columns = [
        "id",
        "event_type",
        "source_type",
        "risk_score",
        "risk_level",
        "display_target",
        "status",
    ]


    available_columns = [
        column
        for column
        in display_columns
        if column
        in filtered_df.columns
    ]


    table_df = filtered_df[
        available_columns
    ].copy()


    table_df = table_df.rename(
        columns={
            "id": "ID",
            "event_type": (
                "Type"
            ),
            "source_type": (
                "Source"
            ),
            "risk_score": (
                "Score"
            ),
            "risk_level": (
                "Niveau"
            ),
            "display_target": (
                "Cible"
            ),
            "status": (
                "Statut"
            ),
        }
    )


    st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# RÉPARTITION PAR NIVEAU
# ============================================================


st.subheader(
    "Répartition par niveau de risque"
)


if not filtered_df.empty:

    risk_distribution = (
        filtered_df[
            "risk_level"
        ]
        .value_counts()
        .rename_axis(
            "Niveau"
        )
        .reset_index(
            name="Nombre"
        )
    )


    st.bar_chart(
        risk_distribution,
        x="Niveau",
        y="Nombre",
    )


# ============================================================
# RÉPARTITION PAR SOURCE
# ============================================================


st.subheader(
    "Répartition par source"
)


if not filtered_df.empty:

    source_distribution = (
        filtered_df[
            "source_type"
        ]
        .value_counts()
        .rename_axis(
            "Source"
        )
        .reset_index(
            name="Nombre"
        )
    )


    st.bar_chart(
        source_distribution,
        x="Source",
        y="Nombre",
    )


# ============================================================
# DÉTAIL DES ALERTES
# ============================================================


st.subheader(
    "Détail des alertes"
)


if filtered_df.empty:

    st.info(
        "Aucune alerte à afficher."
    )


else:

    for _, row in filtered_df.iterrows():

        alert_id = row.get(
            "id"
        )


        event_type = row.get(
            "event_type",
            "UNKNOWN",
        )


        risk_level = row.get(
            "risk_level",
            "UNKNOWN",
        )


        target = row.get(
            "display_target",
            "Cible inconnue",
        )


        title = (
            f"{event_type} - "
            f"{risk_level} - "
            f"{target}"
        )


        with st.expander(
            title
        ):

            detail_col1, detail_col2 = (
                st.columns(
                    2
                )
            )


            with detail_col1:

                st.write(
                    "ID :",
                    alert_id,
                )


                st.write(
                    "Source :",
                    row.get(
                        "source_type"
                    ),
                )


                st.write(
                    "Type :",
                    event_type,
                )


                st.write(
                    "Niveau :",
                    risk_level,
                )


                score = row.get(
                    "risk_score"
                )


                if (
                    score is not None
                    and not pd.isna(
                        score
                    )
                ):

                    st.write(
                        "Score :",
                        f"{float(score):.0f}/100",
                    )

                else:

                    st.write(
                        "Score :",
                        "Non disponible",
                    )


            with detail_col2:

                st.write(
                    "Statut :",
                    row.get(
                        "status"
                    ),
                )


                st.write(
                    "Cible :",
                    target,
                )


                if (
                    row.get(
                        "classification"
                    )
                    not in [
                        None,
                        "UNKNOWN",
                    ]
                ):

                    st.write(
                        "Classification :",
                        row.get(
                            "classification"
                        ),
                    )


                if (
                    row.get(
                        "severity"
                    )
                    not in [
                        None,
                        "UNKNOWN",
                    ]
                ):

                    st.write(
                        "Sévérité :",
                        row.get(
                            "severity"
                        ),
                    )


                if (
                    row.get(
                        "confidence"
                    )
                    not in [
                        None,
                        "UNKNOWN",
                    ]
                ):

                    st.write(
                        "Confiance :",
                        row.get(
                            "confidence"
                        ),
                    )


            message = row.get(
                "message"
            )


            description = row.get(
                "description"
            )


            if (
                message is not None
                and not pd.isna(
                    message
                )
                and str(
                    message
                ).strip()
            ):

                st.markdown(
                    "##### Message"
                )

                st.write(
                    message
                )


            if (
                description is not None
                and not pd.isna(
                    description
                )
                and str(
                    description
                ).strip()
            ):

                st.markdown(
                    "##### Description"
                )

                st.write(
                    description
                )


            url_value = row.get(
                "url"
            )


            if (
                url_value is not None
                and not pd.isna(
                    url_value
                )
                and str(
                    url_value
                ).strip()
            ):

                st.write(
                    "URL :",
                    url_value,
                )


            ip_address = row.get(
                "ip_address"
            )


            if (
                ip_address is not None
                and not pd.isna(
                    ip_address
                )
                and str(
                    ip_address
                ).strip()
            ):

                st.write(
                    "Adresse IP :",
                    ip_address,
                )


            host = row.get(
                "host"
            )


            if (
                host is not None
                and not pd.isna(
                    host
                )
                and str(
                    host
                ).strip()
            ):

                st.write(
                    "Hôte :",
                    host,
                )


# ============================================================
# TOP ALERTES
# ============================================================


st.subheader(
    "Alertes les plus risquées"
)


scored_alerts = (
    filtered_df.dropna(
        subset=[
            "risk_score"
        ]
    )
    .sort_values(
        by="risk_score",
        ascending=False,
    )
    .head(
        10
    )
)


if scored_alerts.empty:

    st.info(
        (
            "Aucune alerte avec un score "
            "de risque disponible."
        )
    )


else:

    top_rows = scored_alerts[
        [
            "event_type",
            "source_type",
            "risk_score",
            "risk_level",
            "display_target",
        ]
    ].copy()


    top_rows = top_rows.rename(
        columns={
            "event_type": (
                "Type"
            ),
            "source_type": (
                "Source"
            ),
            "risk_score": (
                "Score"
            ),
            "risk_level": (
                "Niveau"
            ),
            "display_target": (
                "Cible"
            ),
        }
    )


    st.dataframe(
        top_rows,
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# EXPORT
# ============================================================


st.subheader(
    "Export"
)


if not filtered_df.empty:

    export_df = filtered_df.drop(
        columns=[
            "display_target"
        ],
        errors="ignore",
    )


    csv_data = export_df.to_csv(
        index=False
    )


    st.download_button(
        label=(
            "Exporter les alertes en CSV"
        ),
        data=csv_data,
        file_name=(
            "security_alerts.csv"
        ),
        mime="text/csv",
        key="alerts_export_csv",
    )