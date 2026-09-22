import streamlit as st
from metrics import get_alertes_metrics

st.title("Alertes")

# Récupération des métriques
alertes=get_alertes_metrics()

# Affichage des indicateurs
st.metric("Nombre de machines surveiller", alertes['nombre_machine_surveillé'])

col1, col2,col3 = st.columns(3)
col1.metric("Alertes critiques", alertes["alertes_critiques"])
col2.metric("Alertes importantes", alertes["alertes_importantes"])
col3.metric("Alertes mineures", alertes["alertes_mineures"])
st.markdown("---")