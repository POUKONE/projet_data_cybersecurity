import json

import pandas as pd
import requests
import streamlit as st

from api_client import run_web_audit


# ============================================================
# PAGE
# ============================================================


st.title(
    "Audit Web"
)

st.caption(
    (
        "Analyse passive de la configuration de sécurité "
        "d'une application Web."
    )
)


# ============================================================
# SESSION
# ============================================================


if "web_audit_report" not in st.session_state:

    st.session_state[
        "web_audit_report"
    ] = None


# ============================================================
# URL
# ============================================================


url = st.text_input(
    "URL à analyser",
    placeholder="https://example.com",
    key="web_audit_url",
)


# ============================================================
# PARAMÈTRES DU CRAWLER
# ============================================================


st.subheader(
    "Paramètres de l'exploration"
)


col1, col2 = st.columns(
    2
)


with col1:

    max_depth = st.number_input(
        "Profondeur maximale",
        min_value=0,
        max_value=5,
        value=2,
        step=1,
        key="web_audit_max_depth",
    )


with col2:

    max_pages = st.number_input(
        "Nombre maximal de pages",
        min_value=1,
        max_value=100,
        value=20,
        step=1,
        key="web_audit_max_pages",
    )


col3, col4 = st.columns(
    2
)


with col3:

    max_duration_seconds = st.number_input(
        "Durée maximale du crawl (secondes)",
        min_value=5,
        max_value=120,
        value=30,
        step=5,
        key="web_audit_max_duration",
    )


with col4:

    delay_seconds = st.number_input(
        "Délai entre les requêtes (secondes)",
        min_value=0.0,
        max_value=5.0,
        value=0.2,
        step=0.1,
        key="web_audit_delay",
    )


# ============================================================
# BOUTON
# ============================================================


launch_audit = st.button(
    "Lancer l'audit",
    key="web_audit_launch",
)


# ============================================================
# EXÉCUTION
# ============================================================


if launch_audit:

    if not url.strip():

        st.error(
            "Veuillez saisir une URL."
        )

    else:

        try:

            with st.spinner(
                "Audit en cours..."
            ):

                report = run_web_audit(
                    url=url.strip(),

                    max_depth=int(
                        max_depth
                    ),

                    max_pages=int(
                        max_pages
                    ),

                    max_duration_seconds=int(
                        max_duration_seconds
                    ),

                    delay_seconds=float(
                        delay_seconds
                    ),
                )


            st.session_state[
                "web_audit_report"
            ] = report


        except requests.RequestException as error:

            st.error(
                (
                    "Impossible de contacter l'API : "
                    f"{error}"
                )
            )


        except Exception as error:

            st.error(
                (
                    "Erreur pendant l'audit : "
                    f"{error}"
                )
            )


# ============================================================
# RAPPORT
# ============================================================


report = st.session_state.get(
    "web_audit_report"
)


if not report:

    st.info(
        (
            "Saisissez une URL puis lancez "
            "l'audit pour afficher les résultats."
        )
    )

    st.stop()


# ============================================================
# ÉTAT GLOBAL
# ============================================================


st.divider()

st.subheader(
    "État de l'audit"
)


status = report.get(
    "audit_status",
    "UNKNOWN",
)


mode = report.get(
    "mode",
    "PASSIVE",
)


status_col1, status_col2 = (
    st.columns(
        2
    )
)


with status_col1:

    st.metric(
        "Statut",
        status,
    )


with status_col2:

    st.metric(
        "Mode",
        mode,
    )


if status == "FAILED":

    st.error(
        (
            "L'audit n'a pas pu être "
            "exécuté correctement."
        )
    )


elif status == "PARTIAL":

    st.warning(
        (
            "L'audit a été exécuté partiellement. "
            "Certaines pages ou vérifications "
            "ont échoué."
        )
    )


elif status == "COMPLETED":

    st.success(
        "L'audit passif est terminé."
    )


# ============================================================
# CIBLE
# ============================================================


st.subheader(
    "Cible"
)


target_data = {
    "URL demandée": (
        report.get(
            "requested_url"
        )
    ),

    "URL finale": (
        report.get(
            "final_url"
        )
    ),

    "Code HTTP": (
        report.get(
            "http_status"
        )
    ),

    "Requêtes HTTP": (
        report.get(
            "request_count",
            0,
        )
    ),
}


st.dataframe(
    pd.DataFrame(
        [
            target_data
        ]
    ),
    use_container_width=True,
    hide_index=True,
)


# ============================================================
# PÉRIMÈTRE
# ============================================================


st.subheader(
    "Périmètre autorisé"
)


metadata = report.get(
    "metadata",
    {},
)


allowed_domains = metadata.get(
    "allowed_domains",
    [],
)


if allowed_domains:

    st.write(
        ", ".join(
            allowed_domains
        )
    )

else:

    st.info(
        "Aucun domaine autorisé disponible."
    )


# ============================================================
# EXPLORATION
# ============================================================


st.subheader(
    "Exploration du site"
)


crawl = report.get(
    "crawl",
    {},
)


crawl_col1, crawl_col2, crawl_col3, crawl_col4 = (
    st.columns(
        4
    )
)


with crawl_col1:

    st.metric(
        "Pages visitées",
        crawl.get(
            "visited_count",
            0,
        ),
    )


with crawl_col2:

    st.metric(
        "URLs découvertes",
        crawl.get(
            "discovered_count",
            0,
        ),
    )


with crawl_col3:

    st.metric(
        "Profondeur max",
        crawl.get(
            "max_depth",
            0,
        ),
    )


with crawl_col4:

    st.metric(
        "Durée du crawl",
        (
            f"{crawl.get('duration_seconds', 0)} s"
        ),
    )


# ============================================================
# RÉSUMÉ SÉCURITÉ
# ============================================================


st.subheader(
    "Résumé sécurité"
)


findings = report.get(
    "findings",
    report.get(
        "detections",
        [],
    ),
)


alerts = report.get(
    "alerts",
    [],
)


pages = report.get(
    "pages",
    [],
)


forms = report.get(
    "forms",
    [],
)


summary_col1, summary_col2, summary_col3, summary_col4 = (
    st.columns(
        4
    )
)


with summary_col1:

    st.metric(
        "Findings",
        len(
            findings
        ),
    )


with summary_col2:

    st.metric(
        "Alertes",
        len(
            alerts
        ),
    )


with summary_col3:

    st.metric(
        "Pages",
        len(
            pages
        ),
    )


with summary_col4:

    st.metric(
        "Formulaires",
        len(
            forms
        ),
    )


# ============================================================
# RISQUE GLOBAL DU SITE
# ============================================================


st.subheader(
    "Risque global du site"
)


site_risk = report.get(
    "site_risk",
    {},
)


risk_score = site_risk.get(
    "score",
    0,
)


risk_level = site_risk.get(
    "level",
    "LOW",
)


risk_col1, risk_col2 = (
    st.columns(
        2
    )
)


with risk_col1:

    st.metric(
        "Score de risque",
        f"{risk_score}/100",
    )


with risk_col2:

    st.metric(
        "Niveau",
        risk_level,
    )


contributors = site_risk.get(
    "contributors",
    [],
)


if contributors:

    contributor_rows = []


    for contributor in contributors:

        contributor_rows.append(
            {
                "Type": (
                    contributor.get(
                        "event_type"
                    )
                ),

                "Score de base": (
                    contributor.get(
                        "base_score"
                    )
                ),

                "Bonus propagation": (
                    contributor.get(
                        "propagation_bonus"
                    )
                ),

                "Contribution": (
                    contributor.get(
                        "score"
                    )
                ),

                "Pages touchées": (
                    contributor.get(
                        "affected_page_count"
                    )
                ),

                "Pages analysées": (
                    contributor.get(
                        "total_pages"
                    )
                ),

                "Couverture (%)": (
                    contributor.get(
                        "coverage_percentage"
                    )
                ),
            }
        )


    with st.expander(
        "Détail du calcul du risque"
    ):

        st.dataframe(
            pd.DataFrame(
                contributor_rows
            ),
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# COUVERTURE
# ============================================================


st.subheader(
    "Couverture des contrôles"
)


coverage = report.get(
    "coverage",
    {},
)


coverage_columns = st.columns(
    6
)


coverage_values = [
    (
        "Total",
        coverage.get(
            "total",
            0,
        ),
    ),
    (
        "Exécutés",
        coverage.get(
            "executed",
            0,
        ),
    ),
    (
        "Réussis",
        coverage.get(
            "passed",
            0,
        ),
    ),
    (
        "Échecs",
        coverage.get(
            "failed",
            0,
        ),
    ),
    (
        "Ignorés",
        coverage.get(
            "skipped",
            0,
        ),
    ),
    (
        "Indéterminés",
        coverage.get(
            "indeterminate",
            0,
        ),
    ),
]


for column, (
    label,
    value,
) in zip(
    coverage_columns,
    coverage_values,
):

    with column:

        st.metric(
            label,
            value,
        )


# ============================================================
# PAGES VISITÉES
# ============================================================


st.subheader(
    "Pages visitées"
)


if pages:

    pages_df = pd.DataFrame(
        pages
    )


    preferred_columns = [
        "depth",
        "status_code",
        "url",
        "final_url",
        "content_type",
    ]


    existing_columns = [
        column
        for column in preferred_columns
        if column in pages_df.columns
    ]


    if existing_columns:

        pages_df = pages_df[
            existing_columns
        ]


    st.dataframe(
        pages_df,
        use_container_width=True,
        hide_index=True,
    )


else:

    st.info(
        "Aucune page visitée."
    )


# ============================================================
# URLS IGNORÉES
# ============================================================


st.subheader(
    "URLs ignorées"
)


skipped_urls = report.get(
    "skipped_urls",
    [],
)


if skipped_urls:

    st.dataframe(
        pd.DataFrame(
            skipped_urls
        ),
        use_container_width=True,
        hide_index=True,
    )


else:

    st.info(
        "Aucune URL ignorée."
    )


# ============================================================
# REDIRECTIONS
# ============================================================


st.subheader(
    "Redirections"
)


redirects = report.get(
    "redirects",
    [],
)


if redirects:

    st.dataframe(
        pd.DataFrame(
            redirects
        ),
        use_container_width=True,
        hide_index=True,
    )


else:

    st.info(
        "Aucune redirection détectée."
    )


# ============================================================
# FORMULAIRES
# ============================================================


st.subheader(
    "Formulaires détectés"
)


if forms:

    for index, form in enumerate(
        forms,
        start=1,
    ):

        method = form.get(
            "method",
            "GET",
        )


        action = form.get(
            "action",
            "Action inconnue",
        )


        title = (
            f"Formulaire {index} - "
            f"{method} - "
            f"{action}"
        )


        with st.expander(
            title
        ):

            st.write(
                "Page :",
                form.get(
                    "page_url",
                    "Non disponible",
                ),
            )


            st.write(
                "Méthode :",
                method,
            )


            st.write(
                "Action :",
                action,
            )


            fields = form.get(
                "fields",
                [],
            )


            if fields:

                st.dataframe(
                    pd.DataFrame(
                        fields
                    ),
                    use_container_width=True,
                    hide_index=True,
                )

            else:

                st.info(
                    "Aucun champ identifié."
                )


else:

    st.info(
        "Aucun formulaire détecté."
    )


# ============================================================
# SYNTHÈSE DES FINDINGS
# ============================================================


st.subheader(
    "Synthèse des findings"
)


finding_summary = report.get(
    "finding_summary",
    [],
)


if finding_summary:

    finding_summary_rows = []


    for item in finding_summary:

        finding_summary_rows.append(
            {
                "Type": (
                    item.get(
                        "event_type"
                    )
                ),

                "Classification": (
                    item.get(
                        "classification"
                    )
                ),

                "Sévérité": (
                    item.get(
                        "severity"
                    )
                ),

                "Confiance": (
                    item.get(
                        "confidence"
                    )
                ),

                "Occurrences": (
                    item.get(
                        "occurrence_count",
                        0,
                    )
                ),

                "Pages concernées": (
                    item.get(
                        "affected_page_count",
                        0,
                    )
                ),

                "Pages analysées": (
                    item.get(
                        "total_pages",
                        0,
                    )
                ),

                "Couverture (%)": (
                    item.get(
                        "coverage_percentage",
                        0,
                    )
                ),
            }
        )


    st.dataframe(
        pd.DataFrame(
            finding_summary_rows
        ),
        use_container_width=True,
        hide_index=True,
    )


else:

    st.info(
        "Aucune synthèse disponible."
    )


# ============================================================
# CONTRÔLES
# ============================================================


st.subheader(
    "Contrôles exécutés"
)


checks = report.get(
    "checks",
    [],
)


if checks:

    check_statuses = sorted(
        {
            str(
                check.get(
                    "status",
                    "UNKNOWN",
                )
            )
            for check in checks
        }
    )


    selected_check_status = (
        st.multiselect(
            "Filtrer par statut de contrôle",
            options=check_statuses,
            default=check_statuses,
            key="web_audit_check_status_filter",
        )
    )


    filtered_checks = [
        check
        for check in checks
        if str(
            check.get(
                "status",
                "UNKNOWN",
            )
        )
        in selected_check_status
    ]


    if filtered_checks:

        st.dataframe(
            pd.DataFrame(
                filtered_checks
            ),
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            (
                "Aucun contrôle ne correspond "
                "au filtre sélectionné."
            )
        )


else:

    st.info(
        "Aucun contrôle enregistré."
    )


# ============================================================
# FINDINGS DÉTAILLÉS
# ============================================================


st.subheader(
    "Résultats de sécurité"
)


if findings:

    classifications = sorted(
        {
            str(
                finding.get(
                    "classification",
                    "UNKNOWN",
                )
            )
            for finding in findings
        }
    )


    severities = sorted(
        {
            str(
                finding.get(
                    "severity",
                    "UNKNOWN",
                )
            )
            for finding in findings
        }
    )


    confidences = sorted(
        {
            str(
                finding.get(
                    "confidence",
                    "UNKNOWN",
                )
            )
            for finding in findings
        }
    )


    filter_col1, filter_col2, filter_col3 = (
        st.columns(
            3
        )
    )


    with filter_col1:

        selected_classifications = (
            st.multiselect(
                "Classification",
                options=classifications,
                default=classifications,
                key=(
                    "web_audit_classification_filter"
                ),
            )
        )


    with filter_col2:

        selected_severities = (
            st.multiselect(
                "Sévérité",
                options=severities,
                default=severities,
                key=(
                    "web_audit_severity_filter"
                ),
            )
        )


    with filter_col3:

        selected_confidences = (
            st.multiselect(
                "Confiance",
                options=confidences,
                default=confidences,
                key=(
                    "web_audit_confidence_filter"
                ),
            )
        )


    filtered_findings = [
        finding
        for finding in findings
        if str(
            finding.get(
                "classification",
                "UNKNOWN",
            )
        )
        in selected_classifications

        and str(
            finding.get(
                "severity",
                "UNKNOWN",
            )
        )
        in selected_severities

        and str(
            finding.get(
                "confidence",
                "UNKNOWN",
            )
        )
        in selected_confidences
    ]


    if filtered_findings:

        table_rows = []


        for finding in filtered_findings:

            table_rows.append(
                {
                    "Type": (
                        finding.get(
                            "event_type"
                        )
                    ),

                    "Classification": (
                        finding.get(
                            "classification"
                        )
                    ),

                    "Sévérité": (
                        finding.get(
                            "severity"
                        )
                    ),

                    "Confiance": (
                        finding.get(
                            "confidence"
                        )
                    ),

                    "URL": (
                        finding.get(
                            "url"
                        )
                        or finding.get(
                            "target"
                        )
                    ),

                    "Paramètre": (
                        finding.get(
                            "parameter"
                        )
                    ),

                    "Message": (
                        finding.get(
                            "message"
                        )
                    ),
                }
            )


        st.dataframe(
            pd.DataFrame(
                table_rows
            ),
            use_container_width=True,
            hide_index=True,
        )


        st.markdown(
            "#### Détails"
        )


        for index, finding in enumerate(
            filtered_findings,
            start=1,
        ):

            event_type = finding.get(
                "event_type",
                "Finding",
            )


            target = (
                finding.get(
                    "url"
                )
                or finding.get(
                    "target"
                )
                or "Cible inconnue"
            )


            with st.expander(
                (
                    f"{index}. "
                    f"{event_type} - "
                    f"{target}"
                )
            ):

                st.write(
                    "Classification :",
                    finding.get(
                        "classification"
                    ),
                )


                st.write(
                    "Sévérité :",
                    finding.get(
                        "severity"
                    ),
                )


                st.write(
                    "Confiance :",
                    finding.get(
                        "confidence"
                    ),
                )


                st.write(
                    "URL :",
                    target,
                )


                st.write(
                    "Paramètre :",
                    finding.get(
                        "parameter"
                    ),
                )


                st.write(
                    "Message :",
                    finding.get(
                        "message"
                    ),
                )


                st.write(
                    "Évidence :",
                    finding.get(
                        "evidence"
                    ),
                )


                st.write(
                    "Risque :",
                    finding.get(
                        "risk"
                    ),
                )


                st.write(
                    "Recommandation :",
                    finding.get(
                        "recommendation"
                    ),
                )


                st.write(
                    "Validation :",
                    finding.get(
                        "validation_method"
                    ),
                )


    else:

        st.info(
            (
                "Aucun finding ne correspond "
                "aux filtres sélectionnés."
            )
        )


else:

    st.success(
        (
            "Aucune vulnérabilité détectée par les "
            "contrôles exécutés. Ce résultat ne garantit "
            "pas l’absence de vulnérabilités."
        )
    )


# ============================================================
# ALERTES
# ============================================================


st.subheader(
    "Alertes générées"
)


if alerts:

    alert_rows = []


    for alert in alerts:

        alert_rows.append(
            {
                "Type": (
                    alert.get(
                        "event_type"
                    )
                ),

                "Niveau": (
                    alert.get(
                        "risk_level"
                    )
                ),

                "Score": (
                    alert.get(
                        "risk_score"
                    )
                ),

                "Cible": (
                    alert.get(
                        "target"
                    )
                    or alert.get(
                        "url"
                    )
                ),

                "Statut": (
                    alert.get(
                        "status"
                    )
                ),
            }
        )


    st.dataframe(
        pd.DataFrame(
            alert_rows
        ),
        use_container_width=True,
        hide_index=True,
    )


else:

    st.info(
        "Aucune alerte générée."
    )


# ============================================================
# ERREURS
# ============================================================


st.subheader(
    "Erreurs et analyses incomplètes"
)


errors = report.get(
    "errors",
    [],
)


if errors:

    st.dataframe(
        pd.DataFrame(
            errors
        ),
        use_container_width=True,
        hide_index=True,
    )


else:

    st.info(
        "Aucune erreur de collecte."
    )


# ============================================================
# LIMITATIONS
# ============================================================


st.subheader(
    "Limites de l'analyse"
)


limitations = report.get(
    "limitations",
    [],
)


if limitations:

    for limitation in limitations:

        st.write(
            f"- {limitation}"
        )


else:

    st.info(
        "Aucune limitation renseignée."
    )


# ============================================================
# EXPORT
# ============================================================


st.subheader(
    "Export"
)


json_data = json.dumps(
    report,
    indent=2,
    ensure_ascii=False,
    default=str,
)


export_col1, export_col2 = (
    st.columns(
        2
    )
)


with export_col1:

    st.download_button(
        label="Exporter le rapport JSON",
        data=json_data,
        file_name=(
            "web_audit_report.json"
        ),
        mime="application/json",
        key="web_audit_export_json",
    )


with export_col2:

    if findings:

        findings_df = pd.DataFrame(
            findings
        )


        csv_data = (
            findings_df.to_csv(
                index=False
            )
        )


        st.download_button(
            label="Exporter les findings CSV",
            data=csv_data,
            file_name=(
                "web_audit_findings.csv"
            ),
            mime="text/csv",
            key="web_audit_export_csv",
        )