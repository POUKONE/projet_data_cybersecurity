import streamlit as st
from metrics import get_overview_kpis

st.title("Vue d'ensemble & KPI")

# 1 recuperation des données
kpis = get_overview_kpis()

# 2 affichage du score global de sécurité
st.metric("score global de sécurité ", f" {kpis["Score_securite"]}/100")

# affichage des autres indicateurs
col1,col2,col3,col4=st.columns(4)
col1.metric("Nombre de machines surveillées ",kpis["nombre_machine_surveillé"])
col2.metric("Alertes critiques ",kpis["alertes_critiques"])
col3.metric("Machines compromises ",kpis["machines_compromises"])
col4.metric("Anomalies détectées ",kpis["anomalies_détecté"])

st.markdown("---")
