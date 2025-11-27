# 📚 Module Learning - Sensibilisation Cybersécurité

## Vue d'ensemble

Le module **Learning** est un système complet de sensibilisation et d'apprentissage en cybersécurité intégré directement dans Learn-Protect. Il génère des **alertes de sécurité** automatiquement quand des processus suspects sont détectés, et les associe à des **ressources éducatives** pour que l'utilisateur comprenne le risque.

---

## 🎯 Fonctionnalités Principales

### 1. **Alertes de Sécurité Automatiques**
- Génération automatique d'alertes lors de la détection de processus **SUSPICIOUS** ou **DANGEROUS**
- Classification par sévérité : `info`, `warning`, `critical`
- Association automatique à des ressources d'apprentissage pertinentes
- Affichage en temps réel sur le Dashboard avec notification 🔔

### 2. **Système de Notifications**
- **Bell icon** (🔔) sur le Dashboard avec badge compteur d'alertes
- **Notification panel** affichant les dernières alertes
- Clic sur une alerte → accès direct à la ressource d'apprentissage

### 3. **Ressources d'Apprentissage**
5 catégories principales :
- **🦠 Malware** : Exécution depuis /tmp, fichiers cachés
- **🌐 Réseau** : Connexions C&C, serveurs malveillants
- **🔐 Privilèges** : Escalade de privilèges, sudo misconfigurations
- **📁 Fichiers** : Binaires non signés, intégrité des fichiers
- **⚙️ Processus** : Monitoring, détection d'anomalies

Chaque ressource contient :
- **Titre** : Problème spécifique
- **Description** : Résumé du contenu
- **Contenu HTML riche** : Explications détaillées, exemples, cas réels
- **Difficulté** : beginner, intermediate, advanced
- **Durée** : Temps de lecture estimé
- **Tags** : Mots-clés pour classification

### 4. **Page Learning Dédiée**
Accès à : `http://localhost:5001/learning`
- 📊 **Alertes Récentes** : Les 10 dernières alertes avec détails
- 📖 **Ressources Filtrées** : Par catégorie (Malware, Réseau, Privilèges, etc.)
- 🎓 **Modal d'Apprentissage** : Contenu pédagogique complet en modal

---

## 🔌 Intégration Avec le Backend

### Génération d'Alertes

Lors de l'analyse d'un processus :
```python
# Si processus SUSPICIOUS ou DANGEROUS
if result["level"] in ["SUSPICIOUS", "DANGEROUS"]:
    alert = learning.create_alert(
        process_id=pid,
        process_name=name,
        severity="warning" ou "critical",
        title="Processus dangerous: malware.exe",
        message="Score: 72/100. Règles: PATH_TMP, NETWORK_SUSPICIOUS_IP",
        triggered_rules=["PATH_TMP", "NETWORK_SUSPICIOUS_IP"]
    )
```

### Mappage Automatique Règles → Ressources

```
PATH_TMP                    → malware_tmp_execution
NETWORK_SUSPICIOUS_IP       → network_suspicious_ip
PRIV_ESCALATION             → privilege_escalation
UNSIGNED_BINARY             → unsigned_binary
HIGH_CPU / HIGH_MEMORY      → process_monitoring
... et plus
```

---

## 🌐 Routes API

### Alertes

**GET** `/api/alerts` - Récupère les dernières alertes
```json
Query param: ?limit=20 (défaut)
Response: [
  {
    "id": "alert_0_1234_1701098715",
    "timestamp": "2025-11-27T21:00:15.771385",
    "process_id": 1234,
    "process_name": "malware.exe",
    "severity": "critical",
    "title": "Processus dangereux",
    "message": "Score: 85/100",
    "triggered_rules": ["PATH_TMP", "NETWORK_SUSPICIOUS_IP"],
    "learning_resources": ["malware_tmp_execution", "network_suspicious_ip"]
  }
]
```

**GET** `/api/alerts/<alert_id>` - Détail d'une alerte spécifique

### Ressources d'Apprentissage

**GET** `/api/learning/resources` - Toutes les ressources
```
Query params:
  ?category=malware       (filter par catégorie)
  ?difficulty=beginner    (filter par difficulté)
```

**GET** `/api/learning/resources/<resource_id>` - Détail d'une ressource

---

## 🎨 Interface Utilisateur

### Dashboard (/)
- **🔔 Bell icon** avec compteur d'alertes
- **Notification panel** : Affiche les 5 dernières alertes
- Clic sur alerte → va à `/learning`
- Mise à jour toutes les 2 secondes

### Learning Page (/learning)
```
┌─────────────────────────────────────┐
│  📚 Sensibilisation Cybersécurité   │
│  Alertes de sécurité + Ressources   │
└─────────────────────────────────────┘

🚨 ALERTES RÉCENTES
├─ 🔴 Processus dangereux: malware.exe
├─ 🟡 Connexion réseau suspecte
└─ 🟠 Escalade de privilèges détectée

📖 RESSOURCES D'APPRENTISSAGE
[Toutes] [🦠 Malware] [🌐 Réseau] [🔐 Priv] [⚙️ Proc]

📚 Pourquoi /tmp est dangereux
   Beginner | 5min | Tags: malware, permissions
   Description: ...

[Cliquer pour ouvrir le contenu complet en modal]
```

---

## 📋 Ressources d'Apprentissage Disponibles

1. **Pourquoi les exécutables dans /tmp sont dangereux**
   - Catégorie : Malware
   - Difficulté : Beginner
   - Durée : 5 min
   - Couvre : Répertoire /tmp, permissions, cas WannaCry

2. **Détecter les connexions vers des serveurs malveillants**
   - Catégorie : Réseau
   - Difficulté : Intermediate
   - Durée : 8 min
   - Couvre : C&C, botnet, détection

3. **L'escalade de privilèges : Comment les attaquants deviennent admin**
   - Catégorie : Privilèges
   - Difficulté : Advanced
   - Durée : 10 min
   - Couvre : Kernel exploits, sudo, SUID, weak permissions

4. **Binaires non signés : Vérifier l'authenticité**
   - Catégorie : Fichiers
   - Difficulté : Beginner
   - Durée : 6 min
   - Couvre : Signatures numériques, code signing

5. **Monitoring des processus : Votre première ligne de défense**
   - Catégorie : Processus
   - Difficulté : Intermediate
   - Durée : 9 min
   - Couvre : Monitoring, signaux d'alerte, outils

---

## 🚀 Démarrage

```bash
# Lancer le serveur avec tous les processus analysés
/home/axlnx/PycharmProjects/Learn-Protect/.venv/bin/python backend_server.py --port 5001 --limit 0

# Ouvrir dans le navigateur
# Dashboard: http://localhost:5001
# Learning:  http://localhost:5001/learning
```

---

## 💡 Cas d'Usage : Flux Complet

1. **Utilisateur lance le Dashboard** (`http://localhost:5001`)
   - Voit tous les processus en temps réel
   - Bell icon 🔔 montre le nombre d'alertes

2. **Un processus suspect est détecté**
   - Ligne rouge "DANGEROUS" dans le tableau
   - Alert créée automatiquement
   - Notification affichée

3. **Utilisateur clique sur la bell** 🔔
   - Voir la notification panel
   - Clique sur une alerte

4. **Va à la page Learning** (/learning)
   - Voit l'alerte en détail
   - Les ressources d'apprentissage liées sont proposées
   - Clique sur "Pourquoi /tmp est dangereux"

5. **Lecture du contenu pédagogique**
   - Comprend le risque
   - Apprend comment se protéger
   - Ressort éduqué sur ce vecteur d'attaque

---

## 🔐 Sécurité & Confidentialité

- **Pas de données externalisées** : Tout reste local
- **Pas d'authentification requise** : C'est un outil local
- **Données stockées en mémoire** : Alertes perdues au redémarrage (normal)
- **Pas de trackers** : Aucune telemetry

---

## 📊 Statistiques

- **5 catégories** de ressources
- **5 ressources** d'apprentissage (extensible)
- **10+ règles** heuristiques mappées
- **Auto-alerting** sur SUSPICIOUS/DANGEROUS
- **Real-time notifications** toutes les 2-5 secondes

---

## 🛠️ Extension Futur

Pour ajouter une ressource d'apprentissage :

```python
# Dans learning_module.py, dans _initialize_resources()
"id_unique": LearningResource(
    id="id_unique",
    title="Titre du problème",
    category="malware|network|privilege|file|process",
    description="Description courte",
    content="""<h3>Contenu HTML riche...</h3>""",
    difficulty="beginner|intermediate|advanced",
    duration_minutes=10,
    tags=["tag1", "tag2"],
    created_at=datetime.now().isoformat()
),
```

Puis mapper la règle heuristique :
```python
resource_mapping = {
    "YOUR_NEW_RULE": "id_unique",
    ...
}
```

---

## 📞 Support

En cas d'erreur :
1. Vérifier les logs : `tail -f /tmp/server.log`
2. Vérifier que Flask/CORS sont installés
3. Vérifier que le port 5001 n'est pas occupé

---

**Learn-Protect** © 2025 - Module Learning v1.0
