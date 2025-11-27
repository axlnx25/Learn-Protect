"""
Agent de Surveillance de Sécurité pour Windows
Surveille les fichiers système critiques et les journaux d'événements
pour détecter des activités suspectes et des anomalies de sécurité.
"""

import os
import sys
import time
import logging
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import threading

# Bibliothèques pour la surveillance des fichiers
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("ERREUR: Module 'watchdog' requis. Installez-le avec: pip install watchdog")
    sys.exit(1)

# Bibliothèques pour les journaux d'événements Windows
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
except ImportError:
    print("ERREUR: Module 'pywin32' requis. Installez-le avec: pip install pywin32")
    sys.exit(1)

# Configuration globale
CONFIG = {
    'monitored_dirs': [
        r'C:\Windows\System32',
        os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup')
    ],
    'suspicious_extensions': ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr'],
    'log_file': 'agent_alerts.log',
    'check_interval': 60,  # Intervalle d'analyse des event logs (secondes)
    'file_change_threshold': 10,  # Nombre de modifications considérées comme anormales
    'time_window': 300,  # Fenêtre temporelle pour compter les modifications (secondes)

    # Configuration pour la vérification d'intégrité
    'critical_files': [
        r'C:\Windows\System32\cmd.exe',
        r'C:\Windows\System32\powershell.exe',
        r'C:\Windows\System32\regedit.exe',
        r'C:\Windows\System32\taskmgr.exe',
        r'C:\Windows\System32\notepad.exe',
        r'C:\Windows\System32\services.exe',
        r'C:\Windows\System32\lsass.exe',
        r'C:\Windows\System32\svchost.exe',
        r'C:\Windows\System32\winlogon.exe',
        r'C:\Windows\System32\csrss.exe',
        r'C:\Windows\System32\explorer.exe',
        r'C:\Windows\System32\kernel32.dll',
        r'C:\Windows\System32\ntdll.dll',
        r'C:\Windows\System32\user32.dll',
    ],
    'hash_db_file': 'file_integrity_baseline.json',
    'integrity_check_interval': 300,  # Vérification d'intégrité toutes les 5 minutes
}

# Compteurs globaux pour la détection d'anomalies
file_modifications = defaultdict(list)
modification_lock = threading.Lock()


def initialize_agent():
    """
    Initialise l'agent de surveillance : configuration du logging,
    vérification des permissions, des répertoires surveillés et
    création de la baseline d'intégrité des fichiers.
    """
    # Configuration du système de logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(CONFIG['log_file'], encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

    logging.info("=" * 70)
    logging.info("Initialisation de l'Agent de Surveillance de Sécurité Windows")
    logging.info("=" * 70)

    # Vérification des permissions administrateur
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin:
        logging.warning("⚠️  L'agent ne s'exécute pas avec des privilèges administrateur.")
        logging.warning("   Certaines fonctionnalités peuvent être limitées.")

    # Vérification de l'existence des répertoires surveillés
    for directory in CONFIG['monitored_dirs']:
        if os.path.exists(directory):
            logging.info(f"✓ Répertoire surveillé validé: {directory}")
        else:
            logging.warning(f"✗ Répertoire non trouvé: {directory}")

    # Initialisation du module de vérification d'intégrité
    initialize_file_integrity()

    logging.info("Initialisation terminée avec succès.\n")
    return True


class FileMonitor(FileSystemEventHandler):
    """
    Gestionnaire d'événements pour la surveillance des modifications de fichiers.
    Hérite de FileSystemEventHandler de watchdog pour intercepter les événements.
    """

    def __init__(self):
        super().__init__()
        self.suspicious_files = []

    def on_created(self, event):
        """Déclenché lors de la création d'un fichier ou répertoire."""
        if not event.is_directory:
            self._handle_file_event("CRÉATION", event.src_path)

    def on_modified(self, event):
        """Déclenché lors de la modification d'un fichier."""
        if not event.is_directory:
            self._handle_file_event("MODIFICATION", event.src_path)

    def on_deleted(self, event):
        """Déclenché lors de la suppression d'un fichier ou répertoire."""
        if not event.is_directory:
            self._handle_file_event("SUPPRESSION", event.src_path)

    def _handle_file_event(self, event_type, file_path):
        """
        Traite les événements de fichiers et détecte les anomalies.

        Args:
            event_type: Type d'événement (CRÉATION, MODIFICATION, SUPPRESSION)
            file_path: Chemin complet du fichier concerné
        """
        current_time = time.time()
        file_ext = Path(file_path).suffix.lower()

        # Enregistrement de la modification avec timestamp
        with modification_lock:
            file_modifications[file_path].append(current_time)

            # Nettoyage des anciennes entrées (hors fenêtre temporelle)
            file_modifications[file_path] = [
                t for t in file_modifications[file_path]
                if current_time - t < CONFIG['time_window']
            ]

        # Détection 1: Fichiers exécutables suspects dans des emplacements non standard
        if file_ext in CONFIG['suspicious_extensions']:
            if event_type == "CRÉATION":
                severity = "HAUTE"
                message = (
                    f"🚨 ALERTE SÉCURITÉ - Fichier exécutable créé dans un emplacement surveillé\n"
                    f"   Type: {event_type}\n"
                    f"   Fichier: {file_path}\n"
                    f"   Extension: {file_ext}\n"
                    f"   Gravité: {severity}"
                )
                logging.warning(message)
                self._log_alert(event_type, file_path, severity, "Création de fichier exécutable")

        # Détection 2: Taux de modification anormalement élevé
        modification_count = len(file_modifications[file_path])
        if modification_count >= CONFIG['file_change_threshold']:
            severity = "MOYENNE"
            message = (
                f"⚠️  ANOMALIE DÉTECTÉE - Taux de modification élevé\n"
                f"   Fichier: {file_path}\n"
                f"   Modifications: {modification_count} en {CONFIG['time_window']}s\n"
                f"   Gravité: {severity}"
            )
            logging.warning(message)
            self._log_alert("ANOMALIE_MODIFICATION", file_path, severity,
                            f"Taux de modification élevé ({modification_count} fois)")

            # Réinitialisation du compteur après alerte
            with modification_lock:
                file_modifications[file_path] = []

    def _log_alert(self, alert_type, file_path, severity, description):
        """
        Enregistre une alerte détaillée dans le fichier de log.

        Args:
            alert_type: Type d'alerte (ex: CRÉATION, ANOMALIE_MODIFICATION)
            file_path: Chemin du fichier concerné
            severity: Niveau de gravité (BASSE, MOYENNE, HAUTE)
            description: Description détaillée de l'anomalie
        """
        alert_entry = (
            f"\n{'=' * 70}\n"
            f"ALERTE DE SÉCURITÉ\n"
            f"Horodatage: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Type: {alert_type}\n"
            f"Fichier: {file_path}\n"
            f"Gravité: {severity}\n"
            f"Description: {description}\n"
            f"{'=' * 70}\n"
        )

        # Écriture dans un fichier d'alertes dédié
        with open(CONFIG['log_file'], 'a', encoding='utf-8') as f:
            f.write(alert_entry)


def analyze_event_logs():
    """
    Analyse les journaux d'événements Windows (Sécurité et Application)
    pour détecter des activités suspectes.
    """
    logs_to_check = ['Security', 'Application', 'System']

    for log_type in logs_to_check:
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            # Lecture des événements récents (dernière heure)
            events = []
            total = 0

            while True:
                events_batch = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events_batch:
                    break

                for event in events_batch:
                    # Filtrage par temps (dernière heure)
                    if event.TimeGenerated:
                        event_time = event.TimeGenerated
                        if datetime.now() - event_time > timedelta(hours=1):
                            break

                    events.append(event)
                    total += 1

                    if total >= 100:  # Limite pour éviter une surcharge
                        break

                if total >= 100:
                    break

            win32evtlog.CloseEventLog(hand)

            # Analyse des événements collectés
            _analyze_security_events(events, log_type)

        except Exception as e:
            logging.error(f"Erreur lors de l'analyse du journal {log_type}: {str(e)}")


def _analyze_security_events(events, log_type):
    """
    Analyse les événements de sécurité pour détecter des patterns suspects.

    Args:
        events: Liste des événements Windows
        log_type: Type de journal (Security, Application, System)
    """
    # Compteurs pour détecter des patterns suspects
    failed_logins = 0
    access_denied = 0
    new_services = 0

    for event in events:
        event_id = event.EventID & 0xFFFF  # Masque pour obtenir l'ID réel

        # Détection 1: Tentatives de connexion échouées (Event ID 4625)
        if event_id == 4625 and log_type == 'Security':
            failed_logins += 1

        # Détection 2: Accès refusés répétés (Event ID 4656)
        if event_id == 4656 and log_type == 'Security':
            access_denied += 1

        # Détection 3: Création de nouveaux services (Event ID 7045)
        if event_id == 7045 and log_type == 'System':
            new_services += 1
            try:
                event_data = win32evtlogutil.SafeFormatMessage(event, log_type)
                logging.warning(
                    f"⚠️  Nouveau service détecté:\n"
                    f"   Event ID: {event_id}\n"
                    f"   Données: {event_data[:200]}"
                )
            except:
                pass

    # Alertes basées sur les seuils
    if failed_logins > 5:
        severity = "HAUTE"
        message = (
            f"🚨 ALERTE SÉCURITÉ - Tentatives de connexion échouées multiples\n"
            f"   Journal: {log_type}\n"
            f"   Nombre: {failed_logins} dans la dernière heure\n"
            f"   Gravité: {severity}\n"
            f"   Recommandation: Vérifier les tentatives d'accès non autorisé"
        )
        logging.warning(message)

    if access_denied > 10:
        severity = "MOYENNE"
        message = (
            f"⚠️  ANOMALIE - Accès refusés répétés\n"
            f"   Journal: {log_type}\n"
            f"   Nombre: {access_denied} dans la dernière heure\n"
            f"   Gravité: {severity}"
        )
        logging.warning(message)

    if new_services > 0:
        severity = "HAUTE"
        message = (
            f"🚨 ALERTE SÉCURITÉ - Création de nouveaux services\n"
            f"   Journal: {log_type}\n"
            f"   Nombre: {new_services}\n"
            f"   Gravité: {severity}\n"
            f"   Recommandation: Vérifier la légitimité des nouveaux services"
        )
        logging.warning(message)


# ============================================================================
# MODULE DE VÉRIFICATION D'INTÉGRITÉ DES FICHIERS CRITIQUES
# ============================================================================

def calculate_file_hash(file_path, algorithm='sha256'):
    """
    Calcule le hash d'un fichier en utilisant l'algorithme spécifié.

    Args:
        file_path: Chemin complet du fichier
        algorithm: Algorithme de hash (sha256 par défaut)

    Returns:
        Hash hexadécimal du fichier ou None en cas d'erreur
    """
    try:
        hash_obj = hashlib.new(algorithm)

        with open(file_path, 'rb') as f:
            # Lecture par blocs pour gérer les gros fichiers
            while chunk := f.read(8192):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    except FileNotFoundError:
        logging.error(f"Fichier introuvable pour le calcul de hash: {file_path}")
        return None
    except PermissionError:
        logging.error(f"Permission refusée pour accéder au fichier: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Erreur lors du calcul du hash de {file_path}: {str(e)}")
        return None


def initialize_file_integrity():
    """
    Initialise la baseline d'intégrité des fichiers critiques.
    Si la baseline existe déjà, elle est chargée. Sinon, elle est créée.
    """
    logging.info("\n🔐 Initialisation du module de vérification d'intégrité...")

    baseline_file = CONFIG['hash_db_file']

    # Si la baseline existe, la charger
    if os.path.exists(baseline_file):
        logging.info(f"✓ Baseline d'intégrité existante trouvée: {baseline_file}")
        try:
            with open(baseline_file, 'r', encoding='utf-8') as f:
                baseline = json.load(f)
            logging.info(f"✓ {len(baseline)} fichiers chargés depuis la baseline")
            return baseline
        except Exception as e:
            logging.error(f"Erreur lors du chargement de la baseline: {str(e)}")
            logging.info("Création d'une nouvelle baseline...")

    # Créer une nouvelle baseline
    logging.info("📝 Création de la baseline d'intégrité initiale...")
    baseline = {}

    for file_path in CONFIG['critical_files']:
        if os.path.exists(file_path):
            file_hash = calculate_file_hash(file_path)
            if file_hash:
                file_size = os.path.getsize(file_path)
                baseline[file_path] = {
                    'hash': file_hash,
                    'size': file_size,
                    'timestamp': datetime.now().isoformat(),
                    'algorithm': 'sha256'
                }
                logging.info(f"  ✓ {os.path.basename(file_path)}: {file_hash[:16]}...")
        else:
            logging.warning(f"  ✗ Fichier critique introuvable: {file_path}")

    # Sauvegarder la baseline
    try:
        with open(baseline_file, 'w', encoding='utf-8') as f:
            json.dump(baseline, f, indent=2, ensure_ascii=False)
        logging.info(f"✓ Baseline sauvegardée: {len(baseline)} fichiers\n")
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde de la baseline: {str(e)}")

    return baseline


def verify_file_integrity():
    """
    Vérifie l'intégrité de tous les fichiers critiques en comparant
    leurs hash actuels avec la baseline de référence.
    """
    logging.info("🔍 Vérification de l'intégrité des fichiers critiques...")

    # Charger la baseline
    baseline_file = CONFIG['hash_db_file']
    if not os.path.exists(baseline_file):
        logging.warning("⚠️  Baseline d'intégrité non trouvée. Création en cours...")
        initialize_file_integrity()
        return

    try:
        with open(baseline_file, 'r', encoding='utf-8') as f:
            baseline = json.load(f)
    except Exception as e:
        logging.error(f"Erreur lors du chargement de la baseline: {str(e)}")
        return

    # Compteurs
    verified = 0
    modified = 0
    missing = 0

    # Vérifier chaque fichier de la baseline
    for file_path, baseline_info in baseline.items():
        # Vérifier l'existence du fichier
        if not os.path.exists(file_path):
            missing += 1
            severity = "CRITIQUE"
            message = (
                f"🚨🚨 ALERTE CRITIQUE - Fichier système critique manquant!\n"
                f"   Fichier: {file_path}\n"
                f"   Hash baseline: {baseline_info['hash'][:16]}...\n"
                f"   Gravité: {severity}\n"
                f"   Action: Le fichier a été supprimé ou déplacé!"
            )
            logging.critical(message)
            _log_integrity_alert(file_path, "FICHIER_MANQUANT", severity,
                                 "Fichier système critique supprimé ou déplacé")
            continue

        # Calculer le hash actuel
        current_hash = calculate_file_hash(file_path)
        if not current_hash:
            continue

        # Comparer avec la baseline
        if current_hash != baseline_info['hash']:
            modified += 1

            # Vérifier également la taille du fichier
            current_size = os.path.getsize(file_path)
            size_changed = current_size != baseline_info.get('size', 0)

            severity = "CRITIQUE"
            message = (
                f"🚨🚨 ALERTE CRITIQUE - Modification d'un fichier système!\n"
                f"   Fichier: {file_path}\n"
                f"   Hash baseline: {baseline_info['hash'][:32]}\n"
                f"   Hash actuel:   {current_hash[:32]}\n"
                f"   Taille baseline: {baseline_info.get('size', 'N/A')} octets\n"
                f"   Taille actuelle: {current_size} octets\n"
                f"   Gravité: {severity}\n"
                f"   Action: VÉRIFICATION IMMÉDIATE REQUISE - Possible compromission!"
            )
            logging.critical(message)

            description = f"Hash modifié (baseline: {baseline_info['hash'][:16]}..., actuel: {current_hash[:16]}...)"
            if size_changed:
                description += f" | Taille modifiée ({baseline_info.get('size')} -> {current_size} octets)"

            _log_integrity_alert(file_path, "MODIFICATION_FICHIER", severity, description)
        else:
            verified += 1

    # Rapport de vérification
    total = len(baseline)
    logging.info(
        f"✓ Vérification terminée: {verified}/{total} fichiers intacts, "
        f"{modified} modifiés, {missing} manquants"
    )

    if modified > 0 or missing > 0:
        logging.warning(
            f"\n⚠️  ATTENTION: Des anomalies d'intégrité ont été détectées!\n"
            f"   Fichiers modifiés: {modified}\n"
            f"   Fichiers manquants: {missing}\n"
            f"   Consultez {CONFIG['log_file']} pour les détails.\n"
        )


def _log_integrity_alert(file_path, alert_type, severity, description):
    """
    Enregistre une alerte d'intégrité dans le fichier de log.

    Args:
        file_path: Chemin du fichier concerné
        alert_type: Type d'alerte (MODIFICATION_FICHIER, FICHIER_MANQUANT)
        severity: Niveau de gravité (CRITIQUE, HAUTE, MOYENNE)
        description: Description détaillée de l'anomalie
    """
    alert_entry = (
        f"\n{'=' * 70}\n"
        f"ALERTE D'INTÉGRITÉ - FICHIER SYSTÈME\n"
        f"Horodatage: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Type: {alert_type}\n"
        f"Fichier: {file_path}\n"
        f"Gravité: {severity}\n"
        f"Description: {description}\n"
        f"Recommandation: Vérifier immédiatement l'intégrité du système\n"
        f"{'=' * 70}\n"
    )

    with open(CONFIG['log_file'], 'a', encoding='utf-8') as f:
        f.write(alert_entry)


def main_loop():
    """
    Boucle principale orchestrant la surveillance des fichiers, l'analyse des logs
    et la vérification d'intégrité des fichiers critiques.
    """
    # Initialisation de l'agent
    if not initialize_agent():
        logging.error("Échec de l'initialisation de l'agent. Arrêt.")
        return

    # Configuration de la surveillance des fichiers
    event_handler = FileMonitor()
    observer = Observer()

    # Ajout des répertoires à surveiller
    for directory in CONFIG['monitored_dirs']:
        if os.path.exists(directory):
            observer.schedule(event_handler, directory, recursive=False)
            logging.info(f"📁 Surveillance active sur: {directory}")

    # Démarrage de l'observateur
    observer.start()
    logging.info("\n🔍 Agent de surveillance démarré. Appuyez sur Ctrl+C pour arrêter.\n")

    # Compteur pour la vérification d'intégrité périodique
    last_integrity_check = time.time()

    try:
        while True:
            # Analyse périodique des journaux d'événements
            logging.info("🔎 Analyse des journaux d'événements Windows...")
            analyze_event_logs()

            # Vérification d'intégrité des fichiers critiques (toutes les X secondes)
            current_time = time.time()
            if current_time - last_integrity_check >= CONFIG['integrity_check_interval']:
                verify_file_integrity()
                last_integrity_check = current_time

            # Attente avant la prochaine analyse
            time.sleep(CONFIG['check_interval'])

    except KeyboardInterrupt:
        logging.info("\n\n⛔ Arrêt de l'agent de surveillance demandé...")
        observer.stop()

    observer.join()
    logging.info("✓ Agent de surveillance arrêté proprement.")


if __name__ == "__main__":
    try:
        main_loop()
    except Exception as e:
        logging.critical(f"ERREUR CRITIQUE: {str(e)}", exc_info=True)
        sys.exit(1)