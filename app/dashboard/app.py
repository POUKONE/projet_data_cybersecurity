from PIL import GimpGradientFile
import streamlit as st

# Configuration globale de l'application
st.set_page_config(page_title="Dashboard d'analyse de données et Cybersécurité", layout="wide")

# Menu de navigation 
st.sidebar.title("Menu de Navigation")

# Définitions des pages pour la barre de navigation
pages = [
    "1. Acceuil",
    "2. Vue d'ensemble & KPI",
    "3. Analyse Réseau",
    "4. Analyse des Logs",
    "5. Audit Web",
    "6. Alertes",
    "7. Machine Learning & detection d'anomalies"
]

# Choix de la page affiché
choix_page = st.sidebar.selectbox("Choisissez une page", pages)

# =========================== PAGE 1 : Page d'accueil ===========================
if choix_page == "1. Acceuil":
    st.title("Page d'accueil")
    st.markdown(
        """
        TODO: Ajouter toute les information liées au projet de tels sorte que la page d'acceuil
        soit comme une page explicative et d'introduction pour l'utilisateur.
        """
    )

# =========================== PAGE 2: Vue d'ensemble & KPI ===========================
elif choix_page == "2. Vue d'ensemble & KPI":
    st.title("Vue d'ensemble & KPI")
    st.markdown(
        """
    ### Ici on va afficher : 
    - Score global de sécurité.
    - Nombre de machines surveillées.
    - Nombre d’événements analysés.
    - Nombre d’alertes actives et critiques.
    - Nombre d’anomalies détectées.
    Évolution temporelle des alertes.
    Top des alertes et des machines à risque.
    """
    )


# =========================== PAGE 3: Analyse Réseau ===========================
elif choix_page == "3. Analyse Réseau":
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


# =========================== PAGE 4: Analyse des logs ===========================
elif choix_page == "4. Analyse des Logs":
    st.title("Analyse des Logs")
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


# =========================== PAGE 5: Audit Web ===========================
elif choix_page == "5. Audit Web":
    st.title("Audit Web")
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


# =========================== PAGE 6: Alertes ===========================
elif choix_page == "6. Alertes":
    st.title("Alertes")
    st.markdown(
        """
    ### Ici on va afficher : 
    Le tableau des alertes, avec une possibilité de filtrer les alertes par période, source, machine, niveau de risque et statut.
    """
    )


# =========================== PAGE 7: Machine Learning & detection d'anomalies ===========================
elif choix_page == "7. Machine Learning & detection d'anomalies":
    st.title("Machine Learning & detection d'anomalies")
    st.markdown(
        """
    ### Ici on va afficher : 
    -  Anomalies détectées.
    - Score d'anomalie.
    - Variables ayant contribué à la détection.
    - Historique des anomalies.
    """
    )