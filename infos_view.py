"""
Vue Infos - Page d'information et glossaire Learn-Protect
Contient le template HTML pour la page /infos
"""

INFOS_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Learn-Protect - Infos & Guide</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
            color: #e0e0e0;
        }
        nav {
            background: #0a0e1a;
            padding: 12px 20px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            display: flex;
            gap: 24px;
            align-items: center;
        }
        nav div:first-child { color: #7ee787; font-weight: bold; font-size: 1.1em; }
        nav a { color: #9fb0c8; text-decoration: none; padding: 6px 12px; border-radius: 4px; transition: all 0.2s; }
        nav a:hover { color: #7ee787; background: rgba(0, 255, 136, 0.1); }
        nav a.active { background: rgba(0, 255, 136, 0.1); color: #7ee787; }
        .container { max-width: 1200px; margin: 0 auto; padding: 30px 20px; }
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding: 30px;
            background: linear-gradient(135deg, rgba(0,255,136,0.1) 0%, rgba(0,255,136,0.05) 100%);
            border-radius: 12px;
            border: 1px solid rgba(0, 255, 136, 0.2);
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; color: #00ff88; }
        .header p { font-size: 1.1em; color: #9fb0c8; }
        .section {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(0,255,136,0.15);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
        }
        .section h2 { color: #00ff88; font-size: 1.8em; margin-bottom: 15px; border-bottom: 2px solid rgba(0,255,136,0.2); padding-bottom: 10px; }
        .section p { line-height: 1.7; margin-bottom: 12px; color: #cfd8df; }
        .term-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 15px; }
        .term-card {
            background: rgba(0,0,0,0.2);
            border-left: 4px solid #00ff88;
            padding: 20px;
            border-radius: 8px;
            transition: all 0.3s;
        }
        .term-card:hover { background: rgba(0,255,136,0.08); border-left-color: #7ee787; }
        .term-card h3 { color: #7ee787; margin-bottom: 10px; font-size: 1.2em; }
        .term-card .definition { color: #bbb; line-height: 1.6; }
        .term-card .example { margin-top: 10px; padding-top: 10px; border-top: 1px solid rgba(0,255,136,0.1); font-size: 0.9em; color: #999; font-style: italic; }
        .feature-list { list-style: none; margin: 15px 0; }
        .feature-list li { padding: 10px 0; padding-left: 30px; position: relative; color: #cfd8df; }
        .feature-list li:before { content: "→"; position: absolute; left: 0; color: #00ff88; font-weight: bold; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 6px; font-size: 0.85em; font-weight: 600; margin: 3px; }
        .badge.level-safe { background: rgba(0,200,100,0.3); color: #00ff88; }
        .badge.level-suspicious { background: rgba(255,180,0,0.3); color: #ffb400; }
        .badge.level-dangerous { background: rgba(255,60,60,0.3); color: #ff3c3c; }
        .icon-box { display: inline-flex; width: 50px; height: 50px; background: rgba(0,255,136,0.1); border-radius: 8px; align-items: center; justify-content: center; font-size: 1.5em; margin-right: 15px; }
        .sidebar-note {
            background: rgba(255,200,0,0.05);
            border-left: 4px solid #ffc800;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
            color: #e8d8a0;
        }
    </style>
</head>
<body>
    <nav>
        <div>🛡️ Learn-Protect</div>
        <a href="/">Dashboard</a>
        <a href="/network">Réseau</a>
        <a href="/learning">📚 Learning</a>
        <a href="/infos" class="active">ℹ️ Infos</a>
    </nav>

    <div class="container">
        <div class="header">
            <h1>📖 À propos de Learn-Protect</h1>
            <p>Plateforme de sensibilisation et d'analyse des processus pour la cybersécurité</p>
        </div>

        <!-- Présentation générale -->
        <div class="section">
            <h2>🎯 Qu'est-ce que Learn-Protect ?</h2>
            <p>
                Learn-Protect est une application de monitoring et d'analyse des processus système. Elle combine :
            </p>
            <ul class="feature-list">
                <li><strong>Analyse en temps réel</strong> — surveillance continue des processus actifs</li>
                <li><strong>Scoring intelligent</strong> — évaluation automatique du risque de chaque processus</li>
                <li><strong>Alertes de sécurité</strong> — notifications lorsqu'un comportement suspect est détecté</li>
                <li><strong>Ressources pédagogiques</strong> — documentation pour comprendre et se protéger</li>
                <li><strong>Analyse réseau</strong> — inspection des connexions sortantes par processus</li>
            </ul>
            <p style="margin-top: 20px; font-style: italic; color: #888;">
                L'objectif principal est de <strong>sensibiliser</strong> les utilisateurs aux risques de sécurité et de fournir des outils pédagogiques pour améliorer leur hygiène numérique.
            </p>
        </div>

        <!-- Navigation des vues -->
        <div class="section">
            <h2>🗂️ Pages principales</h2>
            <div class="term-grid">
                <div class="term-card">
                    <div style="display:flex; align-items:center; margin-bottom:10px;">
                        <div class="icon-box">📊</div>
                        <h3 style="margin:0;">Dashboard</h3>
                    </div>
                    <div class="definition">
                        Vue d'ensemble avec infos système (CPU, mémoire, disque) et tableau des processus analysés en temps réel. Voir scores, niveaux de risque et règles déclenchées.
                    </div>
                </div>
                <div class="term-card">
                    <div style="display:flex; align-items:center; margin-bottom:10px;">
                        <div class="icon-box">🌐</div>
                        <h3 style="margin:0;">Réseau</h3>
                    </div>
                    <div class="definition">
                        Détail des connexions réseau actives par processus. Affiche adresses locales/distantes, protocoles, et adresses externes suspectes.
                    </div>
                </div>
                <div class="term-card">
                    <div style="display:flex; align-items:center; margin-bottom:10px;">
                        <div class="icon-box">📚</div>
                        <h3 style="margin:0;">Learning</h3>
                    </div>
                    <div class="definition">
                        Ressources pédagogiques et alertes générées. Consultez les documentations sur malware, réseau, privilèges, incidents, et bien plus.
                    </div>
                </div>
            </div>
        </div>

        <!-- Glossaire des termes clés -->
        <div class="section">
            <h2>📚 Glossaire des termes clés</h2>
            <div class="term-grid">
                <div class="term-card">
                    <h3>Score de risque</h3>
                    <div class="definition">
                        Valeur numérique entre 0 et 100 calculée pour chaque processus. Plus la valeur est élevée, plus le processus présente de signaux d'alerte.
                    </div>
                    <div class="example">
                        Exemple : Score 42 = risque modéré | Score 78 = risque élevé
                    </div>
                </div>

                <div class="term-card">
                    <h3>Niveau de classification</h3>
                    <div class="definition">
                        Catégorie dérivée du score de risque :
                    </div>
                    <div style="margin-top:8px;">
                        <span class="badge level-safe">SAFE</span> Risque faible, processus fiable
                    </div>
                    <div style="margin-top:4px;">
                        <span class="badge level-suspicious">SUSPICIOUS</span> Comportement inhabituel, surveiller
                    </div>
                    <div style="margin-top:4px;">
                        <span class="badge level-dangerous">DANGEROUS</span> Risque confirmé, action recommandée
                    </div>
                </div>

                <div class="term-card">
                    <h3>Règles heuristiques</h3>
                    <div class="definition">
                        Ensemble de critères automatisés qui analysent les attributs d'un processus (exécutable, localisation, réseau, ressources). Chaque règle peut augmenter ou valider le score de risque.
                    </div>
                    <div class="example">
                        Ex : NETWORK_SUSPICIOUS, TMP_EXEC, PRIVILEGE_ESCALATION
                    </div>
                </div>

                <div class="term-card">
                    <h3>Triggers (déclenchements)</h3>
                    <div class="definition">
                        Nombre de règles heuristiques qui se sont «déclenchées» pour ce processus. Un nombre élevé indique plusieurs signaux d'alerte.
                    </div>
                    <div class="example">
                        Ex : 3 triggers = 3 règles d'alerte détectées
                    </div>
                </div>

                <div class="term-card">
                    <h3>Alertes de sécurité</h3>
                    <div class="definition">
                        Notifications créées automatiquement lorsqu'un processus atteint un niveau SUSPICIOUS ou DANGEROUS. Chaque alerte inclut des ressources pédagogiques pour comprendre et réagir.
                    </div>
                    <div class="example">
                        Accessible depuis la cloche (🔔) ou la page Learning
                    </div>
                </div>

                <div class="term-card">
                    <h3>Connexions réseau</h3>
                    <div class="definition">
                        Ensemble des connexions TCP/UDP établies par un processus vers d'autres machines. Comprend adresses locales, distantes, protocole et état (ESTABLISHED, LISTEN, etc.).
                    </div>
                    <div class="example">
                        Ex : curl → 192.168.1.1:80 ESTABLISHED (connexion HTTP)
                    </div>
                </div>

                <div class="term-card">
                    <h3>CPU et Mémoire</h3>
                    <div class="definition">
                        Ressources système utilisées par le processus. Un usage anormal peut indiquer une infection ou comportement malveillant (mines de crypto, botnet, etc.).
                    </div>
                    <div class="example">
                        Ex : CPU 98% pendant longtemps = alerte | Mémoire 2048 MB = usage suspect
                    </div>
                </div>

                <div class="term-card">
                    <h3>Ressources d'apprentissage</h3>
                    <div class="definition">
                        Contenus pédagogiques couvrant les menaces, protections et bonnes pratiques en cybersécurité. Associées aux alertes pour sensibilisation contextuelle.
                    </div>
                    <div class="example">
                        Catégories : Malware, Réseau, Privilèges, Processus, Incident Response, etc.
                    </div>
                </div>
            </div>
        </div>

        <!-- Guide de bonnes pratiques -->
        <div class="section">
            <h2>✅ Bonnes pratiques de sécurité</h2>
            <ul class="feature-list">
                <li>Consultez régulièrement le Dashboard pour identifier les processus suspects</li>
                <li>Lorsqu'une alerte est générée (cloche 🔔), lisez les ressources associées</li>
                <li>Vérifiez les connexions réseau (page Réseau) pour identifier les communications non autorisées</li>
                <li>Suivez les ressources Learning pour améliorer vos connaissances en sécurité</li>
                <li>Gardez votre système à jour et lancez des scans réguliers</li>
                <li>En cas de processus DANGEROUS, enquêtez avant de le terminer</li>
            </ul>
        </div>

        <!-- Sidebar note -->
        <div class="sidebar-note">
            <strong>⚠️ Note importante :</strong> Learn-Protect est un outil de sensibilisation et de monitoring. Il ne remplace pas une solution antivirus ou firewall complète. Utilisez-le en complément de vos mesures de sécurité existantes.
        </div>
        <!-- Sidebar note -->
    </div>
    <footer style="background: rgba(0,0,0,0.18); border-top:1px solid rgba(0,255,136,0.06); padding:12px 20px; color:#9fb0c8; text-align:center; font-size:0.9em;">
        © 2025 Learn&Protect — Tous droits réservés. Pour la documentation, voir <a href="/infos" style="color:#7ee787; text-decoration:none;">Infos</a>.
    </footer>
</body>
</html>
"""
