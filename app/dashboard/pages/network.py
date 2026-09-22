import streamlit as st
from metrics import get_network_metrics

st.title("Analyse Réseau")

# Récupérations des métriques 
network = get_network_metrics()

# Affichage des indicateurs 
st.metric("Total connexions ", network["total_connexions"])
col1, col2 =st.columns(2)
with col1: 
    st.write("Ports ouverts ")
    st.dataframe(network["top_ports_exposes"])
with col2:
    st.write("IP suspectes")
    st.dataframe(network["ip_suspectes"])
st.markdown("---")
