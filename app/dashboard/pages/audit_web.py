import streamlit as st

st.title("Audit Web 💻")
st.markdown(
    """
    ### Ici on va afficher : 
    - URL analysée et disponibilité.
    - HTTPS et temps de réponse.
    - HSTS, CSP, X-Frame-Options et cookies.
    - Score de sécurité web.
    - Recommandations associées
    """
    )