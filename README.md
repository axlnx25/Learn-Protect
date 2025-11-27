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
# Démarrer le serveur HTTP (port 5001, 10 processus par analyse, intervalle 2s)
python3 backend_server.py --port 5001 --limit 10 --interval 2

# En background
nohup python3 backend_server.py --port 5001 --limit 10 > /tmp/server.log 2>&1 &
```

Ouvrir dans le navigateur :
- 🌐 **Interface web** : [http://localhost:5001](http://localhost:5001)
- 📊 **API** : http://localhost:5001/api/system, `/api/processes`, `/api/analysis`

## 📋 Structure du Projet

```
Learn-Protect/
├── main.py                           # Orchestrateur pour analyse unique/batch
├── backend_server.py                 # Serveur HTTP continu (Flask) ⭐
├── moteur_analyse/
│   ├── regles_heuristiques.py        # Moteur heuristique (10+ règles)
│   ├── score_de_risque.py            # Calcul du score
│   ├── generateur_messages.py        # Messages pédagogiques
│   └── classification.py             # Classification (SAFE/SUSPICIOUS/DANGEROUS)
├── scanner_processus/
│   ├── liste_processus.py            # Énumération des processus
│   ├── analyseur_reseau.py           # Connexions réseau par PID
│   ├── calcul_hash.py                # SHA-256 des binaires
│   ├── controle_integrite.py         # Signatures Windows
│   └── collecteur_systeme.py         # Infos CPU, mémoire, disque ⭐
└── integrite_fichier/
    └── check_binaire_fichier.py      # Surveillance d'intégrité (Windows)
```

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

## 💻 API REST

```bash
# Infos système
curl http://localhost:5001/api/system

# Processus avec scores
curl http://localhost:5001/api/processes

# Données complètes
curl http://localhost:5001/api/analysis

# Health check
curl http://localhost:5001/health
```

## 🔧 Installation des Dépendances

```bash
pip install psutil flask flask-cors

# Optionnel (Windows uniquement)
pip install pefile cryptography pywin32 watchdog
```

## 📝 Examples Résultat JSON

```json
{
  "pid": 1234,
  "name": "python",
  "exe": "/usr/bin/python3",
  "user": "axlnx",
  "cpu_percent": 5.5,
  "memory_mb": 150.3,
  "network_connections": 2,
  "score": 35,
  "level": "SAFE",
  "triggered_rules": ["HIGH_MEMORY"]
}
```

## 🛠️ Commandes Utiles

```bash
# Mode batch avec output JSON joli
python3 main.py --limit 5 | jq .

# Serveur avec logs
python3 backend_server.py --port 5001 --limit 10 2>&1 | tee /tmp/learn-protect.log

# Arrêter tous les serveurs
pkill -f backend_server.py
```

## 📌 Architecture

Pipeline d'analyse :
```
Processus → Heuristiques → Score → Message → Classification → API/UI
```
