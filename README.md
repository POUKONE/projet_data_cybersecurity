# Projet d'analyse de données et cybersécurité

Projet collaboratif combinant collecte et analyse de données réseau/logs de sécurité, scoring de risque, et un modèle de Machine Learning (détection d'anomalies), exposés via une API et un dashboard.

## Membres du projet

- **Ibrahima** — Cybersécurité, backend et intégration (55 %)
- **Amsa** — Data Science et Intelligence Artificielle (45 %)

Voir la répartition complète des tâches et l'organisation GitHub dans le document de travail collaboratif partagé entre les deux membres.

## Stack technique

- **Backend / API** : FastAPI
- **Collecte** : Nmap (`python-nmap`), Scapy, Requests/BeautifulSoup (audit web)
- **Stockage** : SQLite (SQLAlchemy)
- **Sécurité** : cryptography (AES/Fernet, RSA)
- **Data Science / ML** : pandas, numpy, scikit-learn (Isolation Forest)
- **Dashboard** : Streamlit, Plotly (+ dashboard analytique complémentaire sous Power BI)
- **Tests** : pytest

## Arborescence

```
app/
  collectors/     Collecte Nmap et Scapy
  parsers/        Parsing des fichiers logs
  analyzers/      Analyse logs, réseau, web, trafic
  scoring/        Règles et moteur de Risk Scoring
  security/       Cryptographie (AES/Fernet, RSA)
  database/       Modèles et accès SQLite
  ml/             Modèle Isolation Forest
  api/            API FastAPI
  dashboard/      Dashboard Streamlit (app, charts, metrics)
notebooks/        Exploration et expérimentation Data Science
tests/            Tests unitaires et d'intégration
data/
  raw/            Données brutes (non versionnées)
  processed/      Données traitées (non versionnées)
```

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Lancer l'API

```bash
uvicorn app.api.main:app --reload
```

## Lancer le dashboard

```bash
streamlit run app/dashboard/app.py
```

## Lancer les tests

```bash
pytest
```

## Workflow Git

- `main` : version stable et présentable uniquement.
- `develop` : intégration des fonctionnalités en cours.
- `feature/<nom>` : une branche par fonctionnalité, créée depuis `develop`.

Chaque fonctionnalité importante correspond à une Issue GitHub. Les Pull Requests vers `develop` doivent être relues par l'autre membre avant merge :

- Ibrahima relit les PR Data Science / IA d'Amsa sous l'angle intégration et qualité logicielle.
- Amsa relit les PR d'Ibrahima sous l'angle qualité des données, cohérence analytique et exploitabilité.

Aucune donnée sensible, secret ou clé ne doit être publié dans le dépôt.

## Milestones

| Milestone | Contenu principal |
|---|---|
| M1 - Foundation | Architecture, GitHub, SQLite, logs |
| M2 - Cybersecurity Core | Nmap, audit web, règles de risque, changements réseau |
| M3 - MVP | Dashboard, alertes, Risk Score, intégration |
| M4 - AI | Features, Isolation Forest, évaluation, intégration ML |
| M5 - Final Release | Scapy, FastAPI, Docker, tests, documentation, Power BI |
