# Roadmap — Mise en place de l'environnement

Étapes à suivre par chaque membre (Ibrahima et Amsa) pour disposer d'un environnement de développement identique.

## 1. Prérequis système

- [ ] Git installé (`git --version`)
- [ ] Python 3.11+ installé (`python3 --version`)
- [ ] Nmap installé sur la machine (`nmap --version`) — nécessaire pour `app/collectors/nmap_collector.py`
- [ ] Compte GitHub avec accès au dépôt `POUKONE/projet-data-cybersecurite`
- [ ] (Optionnel) VS Code + extensions Python, Pylance, GitLens

## 2. Récupérer le dépôt

```bash
git clone https://github.com/POUKONE/projet-data-cybersecurite.git
cd projet-data-cybersecurite
git checkout develop
```

Tout le développement part de `develop`, jamais de `main`.

## 3. Créer l'environnement virtuel Python

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
```

## 4. Installer les dépendances

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## 5. Configurer les variables d'environnement

```bash
cp .env.example .env
```

Remplir `.env` si besoin (`DATABASE_URL`, `FERNET_KEY`, `RSA_PRIVATE_KEY_PATH`, `API_HOST`, `API_PORT`). Ne jamais committer `.env` (déjà dans `.gitignore`).

## 6. Vérifier que tout fonctionne

```bash
python -c "import fastapi, streamlit, pandas, sklearn, scapy, cryptography, sqlalchemy; print('OK')"
pytest
```

## 7. Lancer les briques applicatives (vérification manuelle)

```bash
# API FastAPI
uvicorn app.api.main:app --reload

# Dashboard Streamlit (dans un autre terminal)
streamlit run app/dashboard/app.py
```

## 8. Créer sa branche de travail

Chaque tâche correspond à une Issue GitHub et à une branche `feature/<nom>` créée depuis `develop` :

```bash
git checkout develop
git pull
git checkout -b feature/<nom-de-la-fonctionnalite>
```

## 9. Workflow quotidien

1. Développer et tester localement.
2. Commits explicites, push vers GitHub.
3. Ouvrir une Pull Request vers `develop` (jamais vers `main`).
4. Attendre la relecture croisée (Ibrahima ↔ Amsa) avant merge.

## 10. Bonnes pratiques

- Ne jamais commiter de secrets, clés ou données sensibles.
- Garder `requirements.txt` à jour si une dépendance est ajoutée.
- Documenter les choix non évidents directement dans le code ou le README.
