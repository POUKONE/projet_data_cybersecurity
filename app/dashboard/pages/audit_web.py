"""
Dashboard Streamlit de l'audit Web.

Cette page affiche les résultats de l'audit passif
renvoyés par FastAPI.
"""

import json

import pandas as pd
import requests
import streamlit as st

from api_client import (
    run_web_audit,
)


# ============================================================
# TITRE
# ============================================================

st.title(
    "Audit Web"
)

st.markdown(
    """
    Analyse passive de la configuration et de plusieurs
    mécanismes de sécurité d'une application Web.
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
    ),
)


launch = st.button(
    "Lancer l'audit",
)


# ============================================================
# SESSION
# ============================================================

if "web_audit_report" not in st.session_state:

    st.session_state[
        "web_audit_report"
    ] = None


# ============================================================
# LANCEMENT DE L'AUDIT
# ============================================================

if launch:

    clean_url = (
        url.strip()
    )


    if not clean_url:

        st.warning(
            "Veuillez renseigner une URL."
        )

        st.stop()


    try:

        with st.spinner(
            "Audit Web en cours..."
        ):

            report = (
                run_web_audit(
                    clean_url
                )
            )


        st.session_state[
            "web_audit_report"
        ] = report


    except requests.RequestException as error:

        st.error(
            "Impossible de communiquer avec l'API."
        )

        st.code(
            str(
                error
            )
        )

        st.stop()


# ============================================================
# RAPPORT
# ============================================================

report = st.session_state.get(
    "web_audit_report"
)


if not report:

    st.info(
        "Renseignez une URL puis lancez un audit."
    )

    st.stop()


# ============================================================
# ÉTAT DE L'AUDIT
# ============================================================

st.divider()

st.subheader(
    "État de l'audit"
)


audit_status = report.get(
    "audit_status",
    "UNKNOWN",
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


mode = report.get(
    "mode",
    "PASSIVE",
)


st.write(
    f"Mode : {mode}"
)


# ============================================================
# INFORMATIONS SUR LA CIBLE
# ============================================================

st.divider()

st.subheader(
    "Cible"
)


requested_url = report.get(
    "requested_url"
)

final_url = report.get(
    "final_url"
)

http_status = report.get(
    "http_status"
)

request_count = report.get(
    "request_count",
    0,
)


c1, c2 = st.columns(2)

c1.metric(
    "URL demandée",
    requested_url or "-",
)

c2.metric(
    "URL finale",
    final_url or "-",
)


c3, c4 = st.columns(2)

c3.metric(
    "Statut HTTP",
    (
        http_status
        if http_status is not None
        else "-"
    ),
)

c4.metric(
    "Requêtes effectuées",
    request_count,
)


# ============================================================
# PÉRIMÈTRE
# ============================================================

metadata = report.get(
    "metadata",
    {},
)

allowed_domains = metadata.get(
    "allowed_domains",
    [],
)


st.write(
    "Domaines autorisés :",
    (
        ", ".join(
            allowed_domains
        )
        if allowed_domains
        else "-"
    ),
)


# ============================================================
# COUVERTURE
# ============================================================

st.divider()

st.subheader(
    "Couverture de l'audit"
)


coverage = report.get(
    "coverage",
    {},
)


c1, c2, c3, c4, c5 = (
    st.columns(5)
)


c1.metric(
    "Exécutés",
    coverage.get(
        "executed",
        0,
    ),
)

c2.metric(
    "Réussis",
    coverage.get(
        "passed",
        0,
    ),
)

c3.metric(
    "Échoués",
    coverage.get(
        "failed",
        0,
    ),
)

c4.metric(
    "Ignorés",
    coverage.get(
        "skipped",
        0,
    ),
)

c5.metric(
    "Indéterminés",
    coverage.get(
        "indeterminate",
        0,
    ),
)


# ============================================================
# SYNTHÈSE DES RÉSULTATS
# ============================================================

findings = report.get(
    "findings",
    report.get(
        "detections",
        [],
    ),
)


finding_count = len(
    findings
)


alerts = report.get(
    "alerts",
    [],
)


s1, s2, s3 = st.columns(
    3
)


s1.metric(
    "Résultats détectés",
    finding_count,
)

s2.metric(
    "Alertes enregistrées",
    len(
        alerts
    ),
)

s3.metric(
    "Pages analysées",
    len(
        report.get(
            "pages",
            [],
        )
    ),
)


# ============================================================
# ERREURS
# ============================================================

errors = report.get(
    "errors",
    [],
)


if errors:

    st.divider()

    st.subheader(
        "Erreurs d'analyse"
    )


    for error in errors:

        error_type = error.get(
            "type",
            "ERROR",
        )

        error_message = error.get(
            "message",
            "",
        )

        st.error(
            (
                f"{error_type} : "
                f"{error_message}"
            )
        )


# ============================================================
# REDIRECTIONS
# ============================================================

st.divider()

st.subheader(
    "Redirections"
)


redirects = report.get(
    "redirects",
    [],
)


if redirects:

    redirects_df = (
        pd.DataFrame(
            redirects
        )
    )


    st.dataframe(
        redirects_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info(
        "Aucune redirection observée."
    )


# ============================================================
# PAGES ANALYSÉES
# ============================================================

st.divider()

st.subheader(
    "Pages analysées"
)


pages = report.get(
    "pages",
    [],
)


if pages:

    pages_df = (
        pd.DataFrame(
            pages
        )
    )


    st.dataframe(
        pages_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info(
        "Aucune page analysée."
    )


# ============================================================
# FORMULAIRES
# ============================================================

st.divider()

st.subheader(
    "Formulaires détectés"
)


forms = report.get(
    "forms",
    [],
)


if not forms:

    st.info(
        "Aucun formulaire détecté."
    )

else:

    st.metric(
        "Nombre de formulaires",
        len(
            forms
        ),
    )


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
            "-",
        )


        with st.expander(
            (
                f"Formulaire {index} - "
                f"{method} {action}"
            )
        ):

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
                    "Aucun champ détecté."
                )


# ============================================================
# CONTRÔLES
# ============================================================

st.divider()

st.subheader(
    "Contrôles exécutés"
)


checks = report.get(
    "checks",
    [],
)


if not checks:

    st.info(
        "Aucun contrôle enregistré."
    )

else:

    checks_df = (
        pd.DataFrame(
            checks
        )
    )


    check_statuses = sorted(
        checks_df.get(
            "status",
            pd.Series(
                dtype=str
            ),
        )
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )


    selected_check_statuses = (
        st.multiselect(
            "Statut des contrôles",
            options=check_statuses,
            default=check_statuses,
        )
    )


    filtered_checks_df = (
        checks_df.copy()
    )


    if selected_check_statuses:

        filtered_checks_df = (
            filtered_checks_df[
                filtered_checks_df[
                    "status"
                ].isin(
                    selected_check_statuses
                )
            ]
        )


    st.dataframe(
        filtered_checks_df,
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# RÉSULTATS DE SÉCURITÉ
# ============================================================

st.divider()

st.subheader(
    "Résultats de sécurité"
)


if not findings:

    st.info(
        "Aucune vulnérabilité détectée par les "
        "contrôles exécutés. Ce résultat ne garantit "
        "pas l'absence de vulnérabilités."
    )

else:

    findings_df = (
        pd.DataFrame(
            findings
        )
    )


    # ========================================================
    # FILTRES
    # ========================================================

    f1, f2, f3 = (
        st.columns(3)
    )


    classifications = sorted(
        findings_df.get(
            "classification",
            pd.Series(
                dtype=str
            ),
        )
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )


    severities = sorted(
        findings_df.get(
            "severity",
            pd.Series(
                dtype=str
            ),
        )
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )


    confidences = sorted(
        findings_df.get(
            "confidence",
            pd.Series(
                dtype=str
            ),
        )
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )


    with f1:

        selected_classifications = (
            st.multiselect(
                "Classification",
                options=classifications,
                default=classifications,
            )
        )


    with f2:

        selected_severities = (
            st.multiselect(
                "Sévérité",
                options=severities,
                default=severities,
            )
        )


    with f3:

        selected_confidences = (
            st.multiselect(
                "Confiance",
                options=confidences,
                default=confidences,
            )
        )


    filtered_findings = (
        findings_df.copy()
    )


    if (
        selected_classifications
        and "classification"
        in filtered_findings.columns
    ):

        filtered_findings = (
            filtered_findings[
                filtered_findings[
                    "classification"
                ].isin(
                    selected_classifications
                )
            ]
        )


    if (
        selected_severities
        and "severity"
        in filtered_findings.columns
    ):

        filtered_findings = (
            filtered_findings[
                filtered_findings[
                    "severity"
                ].isin(
                    selected_severities
                )
            ]
        )


    if (
        selected_confidences
        and "confidence"
        in filtered_findings.columns
    ):

        filtered_findings = (
            filtered_findings[
                filtered_findings[
                    "confidence"
                ].isin(
                    selected_confidences
                )
            ]
        )


    # ========================================================
    # TABLEAU
    # ========================================================

    display_columns = [
        column
        for column in [
            "event_type",
            "classification",
            "severity",
            "confidence",
            "target",
            "parameter",
            "message",
            "evidence",
            "recommendation",
            "validation_method",
        ]
        if column
        in filtered_findings.columns
    ]


    st.dataframe(
        filtered_findings[
            display_columns
        ],
        use_container_width=True,
        hide_index=True,
    )


    # ========================================================
    # DÉTAIL D'UN FINDING
    # ========================================================

    st.subheader(
        "Détail des résultats"
    )


    for index, finding in enumerate(
        filtered_findings.to_dict(
            orient="records"
        ),
        start=1,
    ):

        event_type = finding.get(
            "event_type",
            "RESULT",
        )

        severity = finding.get(
            "severity",
            "-",
        )


        with st.expander(
            (
                f"{index}. "
                f"{event_type} - "
                f"{severity}"
            )
        ):

            st.write(
                "Classification :",
                finding.get(
                    "classification",
                    "-",
                ),
            )

            st.write(
                "Sévérité :",
                severity,
            )

            st.write(
                "Confiance :",
                finding.get(
                    "confidence",
                    "-",
                ),
            )

            st.write(
                "URL :",
                finding.get(
                    "url",
                    finding.get(
                        "target",
                        "-",
                    ),
                ),
            )


            parameter = finding.get(
                "parameter"
            )

            if (
                parameter
                and str(
                    parameter
                ).lower()
                != "nan"
            ):

                st.write(
                    "Paramètre :",
                    parameter,
                )


            st.write(
                "Observation :",
                finding.get(
                    "message",
                    "-",
                ),
            )

            st.write(
                "Risque :",
                finding.get(
                    "description",
                    "-",
                ),
            )


            evidence = finding.get(
                "evidence"
            )

            if (
                evidence
                and str(
                    evidence
                ).lower()
                != "nan"
            ):

                st.write(
                    "Preuve :",
                    evidence,
                )


            recommendation = (
                finding.get(
                    "recommendation"
                )
            )

            if (
                recommendation
                and str(
                    recommendation
                ).lower()
                != "nan"
            ):

                st.write(
                    "Recommandation :",
                    recommendation,
                )


            validation_method = (
                finding.get(
                    "validation_method"
                )
            )

            if (
                validation_method
                and str(
                    validation_method
                ).lower()
                != "nan"
            ):

                st.write(
                    "Méthode de validation :",
                    validation_method,
                )


# ============================================================
# LIMITATIONS
# ============================================================

st.divider()

st.subheader(
    "Limites de l'audit"
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
        "Aucune limitation déclarée."
    )


# ============================================================
# EXPORT JSON
# ============================================================

st.divider()

st.subheader(
    "Export"
)


json_data = json.dumps(
    report,
    ensure_ascii=False,
    indent=2,
    default=str,
)


st.download_button(
    label="Exporter le rapport JSON",
    data=json_data,
    file_name=(
        "web_audit_report.json"
    ),
    mime="application/json",
)


# ============================================================
# EXPORT CSV
# ============================================================

if findings:

    csv_data = (
        pd.DataFrame(
            findings
        )
        .to_csv(
            index=False
        )
    )


    st.download_button(
        label="Exporter les résultats CSV",
        data=csv_data,
        file_name=(
            "web_audit_findings.csv"
        ),
        mime="text/csv",
    )