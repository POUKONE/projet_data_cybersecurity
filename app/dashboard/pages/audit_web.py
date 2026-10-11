import pandas as pd
import requests
import streamlit as st


API_URL = "http://127.0.0.1:8000"


st.title("Audit Web")

st.markdown(
    """
    Cette page permet de lancer un audit de sécurité
    sur une application ou un site Web.
    """
)


def launch_web_audit(url: str) -> dict | None:
    """
    Lance un audit Web via l'API FastAPI.
    """

    try:
        response = requests.post(
            f"{API_URL}/web/audit",
            json={
                "url": url
            },
            timeout=30
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as error:
        st.error(
            f"Impossible de lancer l'audit Web : {error}"
        )

        return None


# ============================================================
# FORMULAIRE
# ============================================================

st.subheader("Lancer un audit")

url = st.text_input(
    "URL à analyser",
    value="https://example.com",
    placeholder="https://example.com"
)


if st.button("Lancer l'audit"):

    if not url.strip():

        st.warning(
            "Veuillez renseigner une URL."
        )

    else:

        with st.spinner(
            "Audit Web en cours..."
        ):

            result = launch_web_audit(
                url.strip()
            )

        if result is not None:

            st.success(
                "Audit terminé."
            )

            alerts = result.get(
                "alerts",
                []
            )

            alert_count = result.get(
                "alert_count",
                len(alerts)
            )

            # ====================================================
            # KPI
            # ====================================================

            col1, col2, col3, col4 = st.columns(4)

            critical_count = 0
            high_count = 0
            medium_count = 0

            if alerts:

                alerts_df = pd.DataFrame(alerts)

                if "risk_level" in alerts_df.columns:

                    critical_count = (
                        alerts_df[
                            alerts_df["risk_level"]
                            == "CRITICAL"
                        ].shape[0]
                    )

                    high_count = (
                        alerts_df[
                            alerts_df["risk_level"]
                            == "HIGH"
                        ].shape[0]
                    )

                    medium_count = (
                        alerts_df[
                            alerts_df["risk_level"]
                            == "MEDIUM"
                        ].shape[0]
                    )

            with col1:
                st.metric(
                    "Alertes détectées",
                    alert_count
                )

            with col2:
                st.metric(
                    "Critiques",
                    critical_count
                )

            with col3:
                st.metric(
                    "Élevées",
                    high_count
                )

            with col4:
                st.metric(
                    "Moyennes",
                    medium_count
                )


            # ====================================================
            # RÉSULTATS
            # ====================================================

            st.divider()

            st.subheader(
                "Résultats de l'audit"
            )

            if not alerts:

                st.success(
                    "Aucune anomalie détectée."
                )

            else:

                alerts_df = pd.DataFrame(
                    alerts
                )

                display_columns = [
                    column
                    for column in [
                        "event_type",
                        "risk_score",
                        "risk_level",
                        "description",
                        "message",
                        "url",
                        "status_code",
                    ]
                    if column in alerts_df.columns
                ]

                st.dataframe(
                    alerts_df[
                        display_columns
                    ],
                    use_container_width=True,
                    hide_index=True
                )


                # ================================================
                # RÉPARTITION DES RISQUES
                # ================================================

                if "risk_level" in alerts_df.columns:

                    st.divider()

                    st.subheader(
                        "Répartition des niveaux de risque"
                    )

                    risk_distribution = (
                        alerts_df[
                            "risk_level"
                        ]
                        .value_counts()
                    )

                    st.bar_chart(
                        risk_distribution
                    )