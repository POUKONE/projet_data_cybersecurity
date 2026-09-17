import streamlit as st

st.title("Analyse Réseau")
st.markdown(
    """
    ### Ici on va afficher : 
    - Liste des machines, IP et statut.
    - Ports et services ouverts.
    - Date du dernier scan.
    - Score de risque par machine.
    - Changements entre deux scans.
    """
    )
