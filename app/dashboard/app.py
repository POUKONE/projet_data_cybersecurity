import streamlit as st


# ============================================================
# CONFIGURATION GLOBALE
# ============================================================

st.set_page_config(
    page_title=(
        "Dashboard d'analyse de données "
        "et Cybersécurité"
    ),
    layout="wide"
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title(
    "Dashboard"
)

st.sidebar.markdown(
    "---"
)


# ============================================================
# PAGES
# ============================================================

page_accueil = st.Page(
    "pages/acceuil.py",
    title="Accueil",

)

page_kpi = st.Page(
    "pages/kpi.py",
    title="KPI",

)

page_network = st.Page(
    "pages/network.py",
    title="Réseau",
)

page_logs = st.Page(
    "pages/logs.py",
    title="Logs",
)

page_web = st.Page(
    "pages/audit_web.py",
    title="Web",
)

page_alertes = st.Page(
    "pages/alertes.py",
    title="Alertes",
)

page_ml = st.Page(
    "pages/ml.py",
    title="ML",
)


# ============================================================
# NAVIGATION
# ============================================================

pg_manager = st.navigation(
    [
        page_accueil,
        page_kpi,
        page_network,
        page_logs,
        page_web,
        page_alertes,
        page_ml,
    ]
)


# ============================================================
# EXÉCUTION
# ============================================================

pg_manager.run()