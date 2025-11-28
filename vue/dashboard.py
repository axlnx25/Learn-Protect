"""
Vue Dashboard - Affichage principal avec table de processus et infos système.
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Learn-Protect Dashboard</title>
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
        nav div:first-child {
            color: #7ee787;
            font-weight: bold;
            font-size: 1.1em;
        }
        nav a {
            color: #9fb0c8;
            text-decoration: none;
            padding: 6px 12px;
            border-radius: 4px;
            transition: all 0.2s;
        }
        nav a:hover {
            color: #7ee787;
            background: rgba(0, 255, 136, 0.1);
        }
        nav a.active {
            background: rgba(0, 255, 136, 0.1);
            color: #7ee787;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            border-left: 4px solid #00ff88;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: #00ff88;
        }
        .system-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .info-card {
            background: rgba(255, 255, 255, 0.08);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 136, 0.3);
        }
        .info-card h3 {
            color: #00ff88;
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        .info-card .value {
            font-size: 1.8em;
            font-weight: bold;
            color: #fff;
        }
        .info-card .subtext {
            font-size: 0.85em;
            color: #999;
            margin-top: 5px;
        }
        .bar {
            height: 6px;
            background: rgba(0, 255, 136, 0.2);
            border-radius: 3px;
            margin-top: 8px;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff88, #00cc66);
            border-radius: 3px;
            transition: width 0.3s ease;
        }
        .processes-section {
            background: rgba(255, 255, 255, 0.05);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid rgba(0, 255, 136, 0.2);
        }
        .processes-section h2 {
            color: #00ff88;
            margin-bottom: 15px;
            font-size: 1.5em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }
        th {
            background: rgba(0, 255, 136, 0.1);
            color: #00ff88;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid rgba(0, 255, 136, 0.3);
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        tr:hover {
            background: rgba(0, 255, 136, 0.08);
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
        }
        .badge.safe {
            background: rgba(0, 200, 100, 0.3);
            color: #00ff88;
        }
        .badge.suspicious {
            background: rgba(255, 180, 0, 0.3);
            color: #ffb400;
        }
        .badge.dangerous {
            background: rgba(255, 60, 60, 0.3);
            color: #ff3c3c;
        }
        .rules {
            font-size: 0.8em;
            color: #bbb;
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: #999;
        }
        .refresh-time {
            text-align: right;
            color: #666;
            font-size: 0.85em;
            margin-top: 15px;
        }
        .table-scroll {
            max-height: 60vh;
            overflow-y: auto;
            border-radius: 8px;
        }
        .notification-panel {
            position: fixed;
            right: 20px;
            top: 70px;
            width: 350px;
            max-height: 500px;
            background: rgba(10, 14, 26, 0.98);
            border: 2px solid rgba(0, 255, 136, 0.3);
            border-radius: 8px;
            overflow-y: auto;
            z-index: 500;
            display: none;
        }
        .notification-panel.show {
            display: block;
        }
        .notification-header {
            background: rgba(0, 255, 136, 0.1);
            padding: 12px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            font-weight: bold;
            color: #00ff88;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .notification-item {
            padding: 12px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.1);
            cursor: pointer;
            transition: background 0.2s;
        }
        .notification-item:hover {
            background: rgba(0, 255, 136, 0.05);
        }
        .notification-severity-critical {
            border-left: 4px solid #ff3c3c;
        }
        .notification-severity-warning {
            border-left: 4px solid #ffc800;
        }
        .notification-severity-info {
            border-left: 4px solid #6496ff;
        }
        .notification-title {
            font-weight: bold;
            color: #fff;
            font-size: 0.95em;
            margin-bottom: 4px;
        }
        .notification-meta {
            font-size: 0.8em;
            color: #999;
        }
        footer {
            background: rgba(0,0,0,0.18);
            border-top:1px solid rgba(0,255,136,0.06);
            padding:12px 20px;
            color:#9fb0c8;
            text-align:center;
            font-size:0.9em;
        }
        footer a {
            color:#7ee787;
            text-decoration:none;
        }
    </style>
</head>
<body>
    <nav>
        <div>🛡️ Learn-Protect</div>
        <a href="/" class="active">Dashboard</a>
        <a href="/network">Réseau</a>
        <a href="/learning">📚 Learning</a>
        <a href="/infos">ℹ️ Infos</a>
        <div style="margin-left: auto;">
            <a href="/learning" id="alertBell" style="font-size: 1.5em; cursor: pointer;">🔔</a>
        </div>
    </nav>

    <div class="container">
        <div class="header">
            <h1>🛡️ Dashboard</h1>
            <p>Analyse en temps réel des processus et du système</p>
        </div>

        <div class="notification-panel" id="notificationPanel">
            <div class="notification-header">
                🚨 Alertes de Sécurité
                <span style="cursor: pointer; font-size: 1.2em;" onclick="closeNotifications()">×</span>
            </div>
            <div id="notificationsList"></div>
        </div>

        <div class="system-info" id="systemInfo">
            <div class="loading">Chargement des données...</div>
        </div>

        <div class="processes-section">
            <h2>Tous les Processus Actifs</h2>
            <div class="table-scroll">
                <table id="procTable">
                    <thead>
                        <tr>
                            <th>PID</th>
                            <th>Nom</th>
                            <th>CPU %</th>
                            <th>Mémoire</th>
                            <th>Conn.</th>
                            <th>Score</th>
                            <th>Niveau / Règles</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="7" class="loading">Chargement...</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="refresh-time">Mise à jour: <span id="lastUpdate">--:--:--</span></div>
        </div>
    </div>

    <footer>
        © 2025 Learn&Protect — Tous droits réservés. Pour la documentation, voir <a href="/infos">Infos</a>.
    </footer>

    <script>
        let lastAlertCount = 0;

        function updateData() {
            fetch("/api/analysis")
                .then(r => r.json())
                .then(data => {
                    displaySystemInfo(data.system);
                    displayProcesses(data.processes);
                    document.getElementById("lastUpdate").textContent = new Date().toLocaleTimeString();
                })
                .catch(e => console.error("Erreur:", e));
            
            loadAlerts();
        }

        function loadAlerts() {
            fetch("/api/alerts?limit=5")
                .then(r => r.json())
                .then(alerts => {
                    displayNotifications(alerts);
                })
                .catch(e => console.error("Erreur alertes:", e));
        }

        function displayNotifications(alerts) {
            const panel = document.getElementById("notificationPanel");
            const list = document.getElementById("notificationsList");
            const bell = document.getElementById("alertBell");

            if (!alerts || alerts.length === 0) {
                list.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">✓ Aucune alerte</div>';
                bell.textContent = '🔔';
                lastAlertCount = 0;
                return;
            }

            if (alerts.length > 0) {
                bell.innerHTML = `🔔<span style="position: absolute; background: #ff3c3c; color: white; border-radius: 50%; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; font-size: 0.7em; margin-left: -15px; margin-top: -10px;">${alerts.length}</span>`;
            }

            list.innerHTML = alerts.map(alert => `
                <div class="notification-item notification-severity-${alert.severity}" onclick="goToLearning('${alert.id}')">
                    <div class="notification-title">${alert.title}</div>
                    <div class="notification-meta">
                        ${alert.process_name} (PID ${alert.process_id})
                        <br>${alert.severity.toUpperCase()}
                    </div>
                </div>
            `).join('');

            lastAlertCount = alerts.length;
        }

        function toggleNotifications() {
            const panel = document.getElementById("notificationPanel");
            panel.classList.toggle("show");
        }

        function closeNotifications() {
            document.getElementById("notificationPanel").classList.remove("show");
        }

        function goToLearning(alertId) {
            window.location.href = "/learning#alert-" + alertId;
        }

        document.getElementById("alertBell").addEventListener("click", (e) => {
            e.preventDefault();
            toggleNotifications();
        });

        function displaySystemInfo(sys) {
            if (sys.error) return;

            const cpu = sys.cpu_percent || 0;
            const mem = sys.memory || {};
            const disk = sys.disk || {};

            const html = `
                <div class="info-card">
                    <h3>CPU</h3>
                    <div class="value">${cpu.toFixed(1)}%</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: ${Math.min(cpu, 100)}%"></div>
                    </div>
                </div>
                <div class="info-card">
                    <h3>Mémoire</h3>
                    <div class="value">${(mem.percent || 0).toFixed(1)}%</div>
                    <div class="subtext">${((mem.used || 0) / 1024 / 1024 / 1024).toFixed(2)} GB / ${((mem.total || 0) / 1024 / 1024 / 1024).toFixed(2)} GB</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: ${Math.min(mem.percent || 0, 100)}%"></div>
                    </div>
                </div>
                <div class="info-card">
                    <h3>Disque</h3>
                    <div class="value">${(disk.percent || 0).toFixed(1)}%</div>
                    <div class="subtext">${((disk.used || 0) / 1024 / 1024 / 1024).toFixed(2)} GB / ${((disk.total || 0) / 1024 / 1024 / 1024).toFixed(2)} GB</div>
                    <div class="bar">
                        <div class="bar-fill" style="width: ${Math.min(disk.percent || 0, 100)}%"></div>
                    </div>
                </div>
                <div class="info-card">
                    <h3>Processus</h3>
                    <div class="value">${sys.process_count || 0}</div>
                    <div class="subtext">processus actifs</div>
                </div>
            `;
            document.getElementById("systemInfo").innerHTML = html;
        }

        function displayProcesses(procs) {
            if (!procs || procs.length === 0) {
                document.getElementById("procTable").querySelector("tbody").innerHTML = '<tr><td colspan="7" class="loading">Aucun processus trouvé</td></tr>';
                return;
            }

            const rows = procs.map(p => {
                const level = (p.level || "SAFE").toUpperCase();
                const levelBadge = `<span class="badge ${level.toLowerCase()}">${level}</span>`;
                const rules = p.triggered_rules && p.triggered_rules.length > 0
                    ? `<div class="rules">${p.triggered_rules.join(", ")}</div>`
                    : "";

                return `
                    <tr>
                        <td>${p.pid}</td>
                        <td><strong>${p.name}</strong></td>
                        <td>${(p.cpu_percent || 0).toFixed(1)}%</td>
                        <td>${(p.memory_mb || 0).toFixed(1)} MB</td>
                        <td>${p.network_connections || 0}</td>
                        <td><strong>${p.score || 0}</strong></td>
                        <td>${levelBadge}${rules}</td>
                    </tr>
                `;
            }).join("");

            document.getElementById("procTable").querySelector("tbody").innerHTML = rows;
        }

        updateData();
        setInterval(updateData, 2000);
    </script>
</body>
</html>
"""

def get_dashboard_view():
    """Retourne le template du dashboard."""
    from flask import render_template_string
    return render_template_string(DASHBOARD_HTML)
