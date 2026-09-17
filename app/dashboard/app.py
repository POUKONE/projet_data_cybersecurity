from PIL import GimpGradientFile
import streamlit as st

# Configuration globale de l'application
st.set_page_config(page_title="Dashboard d'analyse de données et Cybersécurité", layout="wide")

# affichage d'un en-tête dans la sidebar
st.sidebar.title(" Dashboard")
st.sidebar.markdown("---")

# Définitions des pages pour la barre de navigation
page_acceuil = st.Page("pages/acceuil.py", title="Acceuil", icon="🏠")
page_kpi = st.Page("pages/kpi.py", title="KPI", icon="📊")
page_network = st.Page("pages/network.py", title="Réseau", icon="🌐")
page_logs = st.Page("pages/logs.py", title="Logs", icon="📝")
page_web = st.Page("pages/audit_web.py", title="Web", icon="💻")
page_alertes = st.Page("pages/alertes.py", title="Alertes", icon="🔔")
page_ml = st.Page("pages/ml.py", title="ML", icon="🧠")

# Création de la barre de navigation
pg_manager = st.navigation([
    page_acceuil,
    page_kpi,
    page_network,
    page_logs,
    page_web,
    page_alertes,
    page_ml
])


# execution de la navigation 
pg_manager.run()