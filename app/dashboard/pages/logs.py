import streamlit as st
from metrics import get_logs_metrics

st.title("Analyse des Logs")

# Récupérations des métriques 
logs = get_logs_metrics()

# Affichage des indicateurs 
st.metric("nombre total de logs", logs["total_logs"])

col1,col2 = st.columns(2)
col1.metric("Echecs de connexion", logs["echecs_connexion"])

with col2 :
    st.write("Classement des erreurs par type d'utilisateur")
    st.dataframe(logs["top_users_erreurs"])
st.markdown("---")