# Learn-Protect - Moniteur de Sécurité en Temps Réel

Outil de surveillance et d'analyse des processus système avec heuristiques de sécurité intégrées.

**This project is a desktop application based on windows which analyses suspicious process in the computer and dispatches alert to the user with an  description of the alert so the user learn about cybersecurity concepts while protecting his computer.**

## 🎯 Fonctionnalités

- ✅ **Analyse continue des processus** : Détection et scoring automatiques
- ✅ **Interface web en temps réel** : Dashboard avec CPU, mémoire, disque, processus
- ✅ **API REST** : Endpoints JSON pour intégration tierce
- ✅ **Heuristiques de sécurité** : Règles basées sur chemins, réseau, signatures, ressources
- ✅ **Scoring intelligent** : Classification SAFE / SUSPICIOUS / DANGEROUS
- ✅ **Messages pédagogiques** : Explications et bonnes pratiques pour chaque alerte

## 🚀 Démarrage Rapide

### Mode Batch (Analyse unique)
```bash
# Analyser les 5 premiers processus
python3 main.py --limit 5

# Mode stream (un JSON par ligne)
python3 main.py --limit 10 --json-lines

# Avec droits élevés
sudo python3 main.py --limit 20
```

### Mode Serveur Continu (Recommandé)
```bash
# Activer l'environnement virtuel
source .venv/bin/activate

# Démarrer le serveur HTTP (port 5000 par défaut, 20 processus par analyse, intervalle 2s)
python3 backend_server.py --port 5000 --limit 20 --interval 2

# Avec port personnalisé
python3 backend_server.py --port 5001 --limit 10

# En background
nohup python3 backend_server.py --port 5000 --limit 20 > /tmp/learn-protect.log 2>&1 &
```

Ouvrir dans le navigateur :
- 🌐 **Dashboard** : [http://localhost:5000](http://localhost:5000)
- 🌐 **Réseau** : [http://localhost:5000/network](http://localhost:5000/network)
- 📚 **Learning** : [http://localhost:5000/learning](http://localhost:5000/learning)
- ℹ️ **Infos** : [http://localhost:5000/infos](http://localhost:5000/infos)
- 📊 **API** : http://localhost:5000/api/system, `/api/processes`, `/api/analysis`, `/api/alerts`, `/api/learning/resources`

## 📋 Structure du Projet

```
Learn-Protect/
├── main.py                           # Orchestrateur pour analyse unique/batch
├── backend_server.py                 # Serveur HTTP continu (Flask) ⭐ MODULARISÉ
│                                      # - Imports vues depuis vue/
│                                      # - Moteur d'analyse minimal (wrapper)
│                                      # - Routes API /api/* (analysis, system, processes, alerts, learning)
├── learning_module.py                # Module d'apprentissage pédagogique (15+ ressources)
├── infos_view.py                     # Template HTML Infos (legacy)
│
├── vue/                              # 📦 NOUVEAU: Package de vues modulaires
│   ├── __init__.py
│   ├── dashboard.py                  # Dashboard principal (vues tous processus)
│   ├── network.py                    # Vue réseau (connexions TCP/UDP)
│   ├── learning.py                   # Vue apprentissage (ressources pédagogiques, thème vert)
│   └── infos.py                      # Vue infos (wrapper autour infos_view.py)
│
├── moteur_analyse/                   # Moteur d'analyse heuristique
│   ├── __init__.py
│   ├── regles_heuristiques.py        # Moteur heuristique (10+ règles)
│   ├── score_de_risque.py            # Calcul du score
│   ├── generateur_messages.py        # Messages pédagogiques
│   └── classification.py             # Classification (SAFE/SUSPICIOUS/DANGEROUS)
│
├── scanner_processus/                # Collecteur de données système
│   ├── __init__.py
│   ├── liste_processus.py            # Énumération des processus
│   ├── analyseur_reseau.py           # Connexions réseau par PID
│   ├── calcul_hash.py                # SHA-256 des binaires
│   ├── controle_integrite.py         # Signatures Windows
│   ├── collecteur_systeme.py         # Infos CPU, mémoire, disque ⭐
│   └── moniteur_ressource.py         # Suivi ressources CPU/Memory
│
└── integrite_fichier/                # Surveillance d'intégrité
    ├── __init__.py
    └── check_binaire_fichier.py      # Surveillance d'intégrité (Windows)
```

### Architecture Logicielle (Modularisée)

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (HTML/CSS/JS)                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Dashboard   │  │  Network     │  │  Learning    │ Infos│
│  │ (vue/*)      │  │  (vue/*)     │  │  (vue/*,vert)│(info)│
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            ▲
                   GET /, /network, /learning, /infos
                            │
┌─────────────────────────────────────────────────────────────┐
│              Flask Backend (backend_server.py)              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Routes HTML  │  │  Routes API  │  │  AnalysisEng │      │
│  │ (vue calls)  │  │  (/api/*)    │  │  (wrapper)   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            ▲
          /api/analysis, /api/system, /api/processes, /api/alerts, /api/learning/*
                            │
┌─────────────────────────────────────────────────────────────┐
│         Moteur d'Analyse (moteur_analyse, scanner_processus)│
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ ProcessLister│  │SystemCollect │  │LearningMod   │      │
│  │ (list_proc)  │  │ (sys info)   │  │(resources&   │      │
│  │              │  │              │  │ alerts)      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Heuristiques (10+ rules) → Score → Classification   │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Avantages de l'architecture actuelle :**
- ✅ **Séparation des responsabilités** : Vues en modules indépendants (vue/)
- ✅ **Maintenabilité** : backend_server.py léger, appelle seulement les wrappers de vues
- ✅ **Scalabilité** : API REST découpée, ajout facile de nouveaux endpoints
- ✅ **Pédagogique** : Learning module intégré avec 15+ ressources interactives
- ✅ **Consistance UI** : Thème vert unifié (Dashboard, Network, Learning)


## 📊 Niveaux de Risque

| Niveau | Plage | Signification |
|--------|-------|---------------|
| 🟢 **SAFE** | 0-30 pts | Aucun comportement suspect |
| 🟡 **SUSPICIOUS** | 31-70 pts | Attention requise |
| 🔴 **DANGEROUS** | 71+ pts | Action recommandée |

## 🔍 Règles Heuristiques

- `PATH_TMP` (20 pts) : Exécution depuis /tmp
- `HIDDEN_FILE` (15 pts) : Fichier exécutable caché
- `NETWORK_MANY_CONN` (25 pts) : Plus de 20 connexions
- `NETWORK_SUSPICIOUS_IP` (30 pts) : IP zone sensible
- `UNSIGNED_BINARY` (10 pts) : Fichier non signé
- `ADMIN_PRIVILEGE` (20 pts) : Exécution admin sans raison
- `HIGH_CPU` (20 pts) : CPU > 80%
- `HIGH_MEMORY` (15 pts) : Mémoire > 500 MB
- `SUSPICIOUS_PARENT` (25 pts) : Parent-enfant anormal
- `INTEGRITY_FAIL` (40 pts) : Hash modifié

## 💻 API REST Endpoints

### Routes HTML (servent les vues modulaires)
```bash
# Dashboard principal (tous les processus)
curl http://localhost:5000/

# Vue réseau (connexions TCP/UDP par processus)
curl http://localhost:5000/network

# Vue apprentissage (ressources cybersécurité pédagogiques, thème vert)
curl http://localhost:5000/learning

# Vue infos (glossaire et documentation)
curl http://localhost:5000/infos
```

### Routes API (JSON)
```bash
# Infos système complètes (CPU, RAM, disque, réseau)
curl http://localhost:5000/api/system

# Processus avec scores heuristiques
curl http://localhost:5000/api/processes?limit=20

# Analyse complète (système + processus)
curl http://localhost:5000/api/analysis

# Alertes de sécurité récentes
curl http://localhost:5000/api/alerts?limit=10

# Détails d'une alerte spécifique
curl http://localhost:5000/api/alerts/<alert_id>

# Ressources d'apprentissage (tous)
curl http://localhost:5000/api/learning/resources

# Ressources filtrées par catégorie
curl 'http://localhost:5000/api/learning/resources?category=malware'

# Ressources filtrées par difficulté
curl 'http://localhost:5000/api/learning/resources?difficulty=beginner'

# Détails d'une ressource
curl http://localhost:5000/api/learning/resources/<resource_id>

# Health check
curl http://localhost:5000/health
```

## 🔧 Installation des Dépendances

```bash
# Dépendances principales
pip install psutil flask flask-cors

# Optionnel (Windows uniquement, pour signatures)
pip install pefile cryptography pywin32 watchdog
```

## 📝 Exemple Requête API + Réponse

### Requête
```bash
curl -s http://localhost:5000/api/processes?limit=2 | jq .[0]
```

### Réponse JSON
```json
{
  "pid": 1234,
  "name": "python3",
  "exe": "/usr/bin/python3",
  "username": "axlnx",
  "ppid": 1234,
  "status": "running",
  "create_time": "2025-11-28T11:00:00+00:00",
  "cmdline": ["python3", "backend_server.py"]
}
```

### Requête alertes
```bash
curl -s http://localhost:5000/api/alerts?limit=1 | jq .[0]
```

### Réponse alerte avec ressources liées
```json
{
  "id": "alert_0_5678_1732781234",
  "timestamp": "2025-11-28T11:23:45.123456",
  "process_id": 5678,
  "process_name": "unknown.exe",
  "severity": "critical",
  "title": "Processus suspect détecté",
  "message": "Exécution depuis /tmp avec connexion à IP malveillante",
  "triggered_rules": ["PATH_TMP", "NETWORK_SUSPICIOUS_IP"],
  "learning_resources": [
    "malware_tmp_execution",
    "network_suspicious_ip"
  ]
}
```

## 🎨 Vues Modulaires (Package `vue/`)

Chaque vue HTML est maintenant un module Python indépendant avec template embarqué :

| Module | Route | Fonction | Description |
|--------|-------|----------|-------------|
| `vue/dashboard.py` | `/` | `get_dashboard_view()` | Tableau de bord principal : tous les processus, scores, alertes en temps réel |
| `vue/network.py` | `/network` | `get_network_view()` | Connexions réseau : TCP/UDP par processus, adresses locales/distantes, avertissements externes |
| `vue/learning.py` | `/learning` | `get_learning_view()` | Apprentissage pédagogique : 15+ ressources interactives cybersécurité (thème vert 🟢) |
| `vue/infos.py` | `/infos` | `get_infos_view()` | Infos et glossaire : documentation Learn-Protect |

**Bénéfices de cette architecture :**
- ✅ Chaque vue est **modulaire et réutilisable**
- ✅ Facile d'ajouter nouvelles vues (créer `vue/nouvelle.py` + importer dans `backend_server.py`)
- ✅ Templates HTML + CSS + JS encapsulés dans chaque module
- ✅ `backend_server.py` reste **léger** (appelle seulement les wrappers)

## 📚 Module d'Apprentissage Pédagogique

`learning_module.py` fournit **15+ ressources cybersécurité** :

- 🛡️ **Malware & Exécution** : Pourquoi /tmp est dangereux, signatures binaires
- 🌐 **Réseau & C&C** : Détecter connexions malveillantes, serveurs de commande
- 🔑 **Privilèges** : Escalade de privilèges, exploitation du noyau
- 🔐 **Chiffrement** : Concepts de cryptographie, TLS, asymétrique
- 🛑 **Incidents** : Plan de réponse à incident cybersécurité
- Et plus... (Phishing, Firewalls, Zero Trust, Injection, etc.)

**Chaque alerte heuristique est liée à des ressources pertinentes :**
```python
# Exemple : Alerte "exécution depuis /tmp"
→ Suggère ressource "malware_tmp_execution" (beginner, 5 min)
```

## 🛠️ Commandes Utiles

```bash
# Mode batch avec output JSON joli
python3 main.py --limit 5 | jq .

# Serveur avec logs
python3 backend_server.py --port 5000 --limit 20 2>&1 | tee /tmp/learn-protect.log

# Arrêter tous les serveurs
pkill -f backend_server.py

# Consulter les alertes générées
curl -s http://localhost:5000/api/alerts | jq .

# Filtrer par catégorie d'apprentissage
curl -s 'http://localhost:5000/api/learning/resources?category=malware' | jq .
```

## 📌 Pipeline d'Analyse

```
Énumération → Heuristiques → Scoring → Classification → Alertes → Ressources
  Processus    (10+ règles)   (SAFE/SUS)  (pédagogique)  API        Pédagogiques
    ↓              ↓             ↓            ↓           ↓             ↓
scanner_processus → moteur_analyse → learning_module → backend_server → vue/
```

