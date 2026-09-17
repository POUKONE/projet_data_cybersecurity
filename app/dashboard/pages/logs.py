import streamlit as st

st.title("Analyse des Logs 📝")
st.markdown(
    """
    ### Ici on va afficher : 
    - Volume d’événements.
    - Connexions réussies et échouées.
    - Événements par heure ou par jour.
    - Utilisateurs et IP les plus actifs.
    - Événements suspects et répétitions.
    """
    )