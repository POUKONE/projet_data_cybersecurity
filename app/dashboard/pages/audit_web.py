"""
Page Streamlit dédiée à l'audit Web passif.
"""

import json

import pandas as pd
import requests
import streamlit as st

from api_client import (
    run_web_audit,
)


# ============================================================
# PAGE
# ============================================================

st.title(
    "Audit Web"
)

st.markdown(
    """
    Analyse passive de la configuration de sécurité
    d'une application Web.
    """
)

st.caption(
    "L'absence de résultat ne garantit pas "
    "l'absence de vulnérabilités."
)


# ============================================================
# FORMULAIRE
# ============================================================

url = st.text_input(
    "URL à analyser",
    placeholder=(
        "https://example.com"
    )
)


launch = st.button(
    "Lancer l'audit"
)


# ============================================================
# LANCEMENT
# ============================================================

if launch:

    if not url.strip():

        st.warning(
            "Veuillez renseigner une URL."
        )

        st.stop()


    try:

        with st.spinner(
            "Audit Web en cours..."
        ):

            report = run_web_audit(
                url.strip()
            )


    except requests.RequestException as error:

        st.error(
            "Impossible de communiquer "
            "avec l'API."
        )

        st.code(
            str(error)
        )

        st.stop()


    # ========================================================
    # STATUT DE L'AUDIT
    # ========================================================

    audit_status = report.get(
        "audit_status",
        "UNKNOWN"
    )


    st.divider()

    st.subheader(
        "État de l'audit"
    )


    if audit_status == "COMPLETED":

        st.success(
            "Audit terminé."
        )

    elif audit_status == "PARTIAL":

        st.warning(
            "Audit partiellement terminé."
        )

    elif audit_status == "FAILED":

        st.error(
            "L'audit n'a pas pu être réalisé correctement."
        )

    else:

        st.info(
            f"Statut : {audit_status}"
        )


    # ========================================================
    # INFORMATIONS CIBLE
    # ========================================================

    requested_url = report.get(
        "requested_url"
    )

    final_url = report.get(
        "final_url"
    )

    http_status = report.get(
        "http_status"
    )


    info1, info2, info3 = (
        st.columns(3)
    )


    info1.metric(
        "URL demandée",
        requested_url or "-"
    )

    info2.metric(
        "URL finale",
        final_url or "-"
    )

    info3.metric(
        "Statut HTTP",
        http_status
        if http_status is not None
        else "-"
    )


    # ========================================================
    # COUVERTURE
    # ========================================================

    st.divider()

    st.subheader(
        "Couverture de l'audit"
    )


    coverage = report.get(
        "coverage",
        {}
    )


    c1, c2, c3, c4, c5 = (
        st.columns(5)
    )


    c1.metric(
        "Exécutés",
        coverage.get(
            "executed",
            0
        )
    )

    c2.metric(
        "Réussis",
        coverage.get(
            "passed",
            0
        )
    )

    c3.metric(
        "Échoués",
        coverage.get(
            "failed",
            0
        )
    )

    c4.metric(
        "Ignorés",
        coverage.get(
            "skipped",
            0
        )
    )

    c5.metric(
        "Indéterminés",
        coverage.get(
            "indeterminate",
            0
        )
    )


    st.metric(
        "Requêtes HTTP effectuées",
        report.get(
            "request_count",
            0
        )
    )


    # ========================================================
    # ERREURS D'ANALYSE
    # ========================================================

    errors = report.get(
        "errors",
        []
    )


    if errors:

        st.divider()

        st.subheader(
            "Erreurs d'analyse"
        )


        for error in errors:

            st.error(
                (
                    f"{error.get('type', 'ERROR')} : "
                    f"{error.get('message', '')}"
                )
            )


    # ========================================================
    # REDIRECTIONS
    # ========================================================

    redirects = report.get(
        "redirects",
        []
    )


    st.divider()

    st.subheader(
        "Redirections"
    )


    if redirects:

        redirect_df = pd.DataFrame(
            redirects
        )

        st.dataframe(
            redirect_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "Aucune redirection observée."
        )


    # ========================================================
    # CONTRÔLES
    # ========================================================

    st.divider()

    st.subheader(
        "Contrôles exécutés"
    )


    checks = report.get(
        "checks",
        []
    )


    if checks:

        checks_df = pd.DataFrame(
            checks
        )

        check_statuses = sorted(
            checks_df[
                "status"
            ]
            .dropna()
            .unique()
            .tolist()
        )


        selected_check_status = (
            st.multiselect(
                "Statut du contrôle",
                options=check_statuses,
                default=check_statuses
            )
        )


        if selected_check_status:

            checks_df = checks_df[
                checks_df[
                    "status"
                ].isin(
                    selected_check_status
                )
            ]


        st.dataframe(
            checks_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "Aucun contrôle enregistré."
        )


    # ========================================================
    # RÉSULTATS
    # ========================================================

    st.divider()

    st.subheader(
        "Résultats de sécurité"
    )


    detections = report.get(
        "detections",
        []
    )


    if not detections:

        st.info(
            "Aucune vulnérabilité détectée par les "
            "contrôles exécutés. Ce résultat ne garantit "
            "pas l'absence de vulnérabilités."
        )

    else:

        findings_df = pd.DataFrame(
            detections
        )


        # ----------------------------------------------------
        # FILTRES
        # ----------------------------------------------------

        f1, f2, f3 = (
            st.columns(3)
        )


        with f1:

            categories = sorted(
                findings_df.get(
                    "classification",
                    pd.Series(
                        dtype=str
                    )
                )
                .dropna()
                .unique()
                .tolist()
            )

            selected_categories = (
                st.multiselect(
                    "Classification",
                    options=categories,
                    default=categories
                )
            )


        with f2:

            event_types = sorted(
                findings_df.get(
                    "event_type",
                    pd.Series(
                        dtype=str
                    )
                )
                .dropna()
                .unique()
                .tolist()
            )

            selected_types = (
                st.multiselect(
                    "Type",
                    options=event_types,
                    default=event_types
                )
            )


        with f3:

            confidences = sorted(
                findings_df.get(
                    "confidence",
                    pd.Series(
                        dtype=str
                    )
                )
                .dropna()
                .unique()
                .tolist()
            )

            selected_confidences = (
                st.multiselect(
                    "Confiance",
                    options=confidences,
                    default=confidences
                )
            )


        filtered_findings = (
            findings_df.copy()
        )


        if selected_categories:

            filtered_findings = (
                filtered_findings[
                    filtered_findings[
                        "classification"
                    ].isin(
                        selected_categories
                    )
                ]
            )


        if selected_types:

            filtered_findings = (
                filtered_findings[
                    filtered_findings[
                        "event_type"
                    ].isin(
                        selected_types
                    )
                ]
            )


        if selected_confidences:

            filtered_findings = (
                filtered_findings[
                    filtered_findings[
                        "confidence"
                    ].isin(
                        selected_confidences
                    )
                ]
            )


        display_columns = [
            column
            for column in [
                "event_type",
                "classification",
                "confidence",
                "target",
                "status_code",
                "message",
                "description",
            ]
            if column
            in filtered_findings.columns
        ]


        st.dataframe(
            filtered_findings[
                display_columns
            ],
            use_container_width=True,
            hide_index=True
        )


    # ========================================================
    # EXPORT
    # ========================================================

    st.divider()

    st.subheader(
        "Export"
    )


    json_data = json.dumps(
        report,
        ensure_ascii=False,
        indent=2,
        default=str
    )


    st.download_button(
        label="Exporter le rapport JSON",
        data=json_data,
        file_name="web_audit.json",
        mime="application/json"
    )


    if detections:

        csv_data = (
            pd.DataFrame(
                detections
            )
            .to_csv(
                index=False
            )
        )


        st.download_button(
            label="Exporter les résultats CSV",
            data=csv_data,
            file_name="web_audit_findings.csv",
            mime="text/csv"
        )