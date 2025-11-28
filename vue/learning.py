"""
Vue Learning - Module d'éducation sur la cybersécurité.
Contient alertes de sécurité et ressources pédagogiques avec filtrage par catégorie.
"""

LEARNING_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Learn-Protect - Learning</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
            color: #e0e0e0;
            padding: 0;
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
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: rgba(255, 255, 255, 0.05); border-radius: 10px; border-left: 4px solid #00ff88; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; color: #00ff88; }
        .header p { color: #9fb0c8; font-size: 1.05em; }
        .sections { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .section { background: rgba(255, 255, 255, 0.05); padding: 20px; border-radius: 10px; border: 1px solid rgba(0, 255, 136, 0.2); }
        .section h2 { color: #00ff88; margin-bottom: 15px; font-size: 1.3em; }
        .alert-item { background: linear-gradient(135deg, rgba(255, 100, 100, 0.1) 0%, rgba(100, 0, 0, 0.1) 100%); border-left: 4px solid #ff6464; padding: 12px; margin-bottom: 10px; border-radius: 6px; cursor: pointer; transition: all 0.2s; }
        .alert-item:hover { background: linear-gradient(135deg, rgba(255, 100, 100, 0.15) 0%, rgba(100, 0, 0, 0.15) 100%); }
        .alert-title { font-weight: 600; color: #ff8888; }
        .alert-details { font-size: 0.9em; color: #bbb; margin-top: 4px; }
        .resource-filters { display: flex; gap: 8px; margin-bottom: 15px; flex-wrap: wrap; }
        .filter-btn { padding: 8px 12px; background: rgba(0, 255, 136, 0.18); border: 1px solid rgba(0, 255, 136, 0.35); color: #00ff88; border-radius: 6px; cursor: pointer; transition: all 0.2s; }
        .filter-btn.active { background: rgba(0, 255, 136, 0.5); color: #07120b; }
        .filter-btn:hover { background: rgba(0, 255, 136, 0.35); }
        .resource-card { background: rgba(0, 255, 136, 0.06); border-left: 3px solid #00ff88; padding: 12px; margin-bottom: 10px; border-radius: 6px; cursor: pointer; transition: all 0.2s; }
        .resource-card:hover { background: rgba(0, 255, 136, 0.12); transform: translateX(4px); }
        .resource-title { font-weight: 600; color: #00ff88; }
        .resource-category { display: inline-block; background: rgba(0, 255, 136, 0.3); color: #00ff88; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; margin-top: 4px; }
        .resource-desc { font-size: 0.9em; color: #bbb; margin-top: 4px; }
        .no-alerts { text-align: center; padding: 20px; color: #666; }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.6);
            animation: fadeIn 0.2s;
        }
        .modal.active { display: flex; align-items: center; justify-content: center; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .modal-content {
            background: #1e1e2e;
            padding: 30px;
            border-radius: 10px;
            max-width: 600px;
            width: 90%;
            border: 1px solid rgba(0, 255, 136, 0.2);
            max-height: 80vh;
            overflow-y: auto;
            animation: slideUp 0.3s;
        }
        @keyframes slideUp { from { transform: translateY(30px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-header h2 { color: #00ff88; }
        .close-btn { background: none; border: none; color: #9fb0c8; font-size: 1.5em; cursor: pointer; }
        .close-btn:hover { color: #00ff88; }
        .modal-body { color: #e0e0e0; line-height: 1.6; }
        .modal-body h3 { color: #00ff88; margin-top: 15px; margin-bottom: 8px; }
        .modal-body ul { margin-left: 20px; margin-bottom: 10px; }
        .modal-body li { margin-bottom: 6px; }
        footer { background: rgba(0,0,0,0.18); border-top:1px solid rgba(0,255,136,0.06); padding:12px 20px; color:#9fb0c8; text-align:center; font-size:0.9em; }
        footer a { color:#7ee787; text-decoration:none; }
    </style>
</head>
<body>
    <nav>
        <div>🛡️ Learn-Protect</div>
        <a href="/">Dashboard</a>
        <a href="/network">Réseau</a>
        <a href="/learning" class="active">📚 Learning</a>
        <a href="/infos">ℹ️ Infos</a>
    </nav>

    <div class="container">
        <div class="header">
            <h1>📚 Ressources de Cybersécurité</h1>
            <p>Apprenez les concepts clés pour protéger votre système</p>
        </div>

        <div class="sections">
            <div class="section">
                <h2>🚨 Alertes Récentes</h2>
                <div id="alertsContainer">
                    <div class="no-alerts">Chargement des alertes...</div>
                </div>
            </div>

            <div class="section">
                <h2>📖 Centre d'Apprentissage</h2>
                <div class="resource-filters">
                    <button class="filter-btn active" data-category="all">Toutes</button>
                    <button class="filter-btn" data-category="malware">Malware</button>
                    <button class="filter-btn" data-category="network">Réseau</button>
                    <button class="filter-btn" data-category="privileges">Privilèges</button>
                    <button class="filter-btn" data-category="process">Processus</button>
                </div>
                <div id="resourcesContainer">
                    <div class="no-alerts">Chargement des ressources...</div>
                </div>
            </div>
        </div>
    </div>

    <div id="modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle"></h2>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="modalBody"></div>
        </div>
    </div>

    <footer>
        © 2025 Learn&Protect — Tous droits réservés. Pour la documentation, voir <a href="/infos">Infos</a>.
    </footer>

    <script>
        let allResources = [];

        function loadAlerts() {
            fetch("/api/alerts")
                .then(r => r.json())
                .then(alerts => displayAlerts(alerts))
                .catch(e => console.error("Erreur:", e));
        }

        function displayAlerts(alerts) {
            const container = document.getElementById("alertsContainer");
            if (!alerts || alerts.length === 0) {
                container.innerHTML = '<div class="no-alerts">✅ Aucune alerte pour le moment</div>';
                return;
            }
            container.innerHTML = alerts.map(a => `
                <div class="alert-item" onclick="loadAndShowResource('alert', '${a.id || a.rule_id}')">
                    <div class="alert-title">⚠️ ${a.process_name || 'Processus'}</div>
                    <div class="alert-details">${a.reason || 'Activité suspecte détectée'}</div>
                </div>
            `).join("");
        }

        function loadResources() {
            fetch("/api/learning/resources")
                .then(r => r.json())
                .then(resources => {
                    allResources = resources;
                    displayResources(resources);
                })
                .catch(e => console.error("Erreur:", e));
        }

        function displayResources(resources) {
            const container = document.getElementById("resourcesContainer");
            if (!resources || resources.length === 0) {
                container.innerHTML = '<div class="no-alerts">Aucune ressource disponible</div>';
                return;
            }
            container.innerHTML = resources.map(r => `
                <div class="resource-card" onclick="loadAndShowResource('resource', '${r.id}')">
                    <div class="resource-title">${r.title}</div>
                    <div class="resource-category">${r.category}</div>
                    <div class="resource-desc">${r.description}</div>
                </div>
            `).join("");
        }

        function filterResources(category) {
            document.querySelectorAll(".filter-btn").forEach(btn => btn.classList.remove("active"));
            event.target.classList.add("active");

            if (category === "all") {
                displayResources(allResources);
            } else {
                displayResources(allResources.filter(r => r.category.toLowerCase() === category));
            }
        }

        function loadAndShowResource(type, id) {
            let resource;
            if (type === "resource") {
                resource = allResources.find(r => r.id === id);
            } else {
                resource = allResources.find(r => r.id === id);
            }

            if (resource) {
                document.getElementById("modalTitle").textContent = resource.title || "Détail";
                document.getElementById("modalBody").innerHTML = `
                    <h3>Description</h3>
                    <p>${resource.content || resource.description}</p>
                    <h3>Catégorie</h3>
                    <p>${resource.category}</p>
                    <h3>Recommandations</h3>
                    <ul>
                        <li>${(resource.recommendations || ["Consultez la documentation officielle"])[0]}</li>
                    </ul>
                `;
                document.getElementById("modal").classList.add("active");
            }
        }

        function closeModal() {
            document.getElementById("modal").classList.remove("active");
        }

        document.querySelectorAll(".filter-btn").forEach(btn => {
            btn.addEventListener("click", () => filterResources(btn.dataset.category));
        });

        document.getElementById("modal").addEventListener("click", (e) => {
            if (e.target === document.getElementById("modal")) closeModal();
        });

        loadAlerts();
        loadResources();
        setInterval(loadAlerts, 5000);
    </script>
</body>
</html>
"""

def get_learning_view():
    """Retourne le template de la vue learning."""
    from flask import render_template_string
    return render_template_string(LEARNING_HTML)
