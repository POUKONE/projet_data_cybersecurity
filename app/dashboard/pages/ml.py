import streamlit as st
from metrics import get_ml_metrics

st.title("Machine Learning & detection d'anomalies")

# Récupérations des métriques 
ml = get_ml_metrics()

# Affichage des indicateurs 
st.metric("Anomalies détectées ", ml["anomalies_detectees"])
col1, col2 =st.columns(2)
col1.metric("Taux de faux positifs ", ml["taux_faux_positifs_estime"])
col2.metric("Score de détection ", ml["precision_modele"])

st.markdown("---")