"""
Vue Network - Affichage des connexions réseau par processus.
Contient le template HTML et la fonction de rendu pour la route /network.
"""

NETWORK_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Learn-Protect - Réseau</title>
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
        .network-section { background: rgba(255, 255, 255, 0.05); padding: 20px; border-radius: 10px; border: 1px solid rgba(0, 255, 136, 0.2); }
        .network-section h2 { color: #00ff88; margin-bottom: 15px; font-size: 1.5em; }
        .process-card { background: linear-gradient(135deg, rgba(0,255,136,0.05) 0%, rgba(0,0,0,0.2) 100%); border: 1px solid rgba(0, 255, 136, 0.15); border-radius: 10px; padding: 20px; margin-bottom: 15px; overflow: hidden; }
        .process-header { font-weight: bold; color: #00ff88; margin-bottom: 12px; font-size: 1.2em; display: flex; align-items: center; gap: 10px; }
        .process-header::before { content: "▶"; font-size: 0.8em; }
        .process-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 15px; font-size: 0.9em; color: #bbb; padding: 10px; background: rgba(0,0,0,0.2); border-radius: 6px; }
        .process-meta div { display: flex; gap: 6px; align-items: center; }
        .meta-label { color: #7ee787; font-weight: 600; min-width: 90px; }
        .connection-group { margin-bottom: 12px; }
        .connection-group-title { color: #ffb400; font-weight: 600; margin-bottom: 8px; font-size: 0.95em; display: flex; align-items: center; gap: 6px; }
        .connection-item { background: rgba(0, 255, 136, 0.08); border-left: 3px solid #00ff88; padding: 12px; margin-bottom: 8px; border-radius: 6px; font-size: 0.9em; }
        .connection-detail { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 8px; }
        .address-pair { display: flex; flex-direction: column; gap: 4px; }
        .address-label { font-size: 0.8em; color: #888; text-transform: uppercase; letter-spacing: 0.5px; }
        .address-value { font-family: 'Courier New', monospace; color: #7ee787; font-weight: 500; word-break: break-all; }
        .protocol-badge { display: inline-block; background: rgba(0,255,136,0.2); color: #00ff88; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; margin-right: 8px; text-transform: uppercase; }
        .status-badge { display: inline-block; background: rgba(100,200,255,0.2); color: #64c8ff; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; }
        .external-warning { background: rgba(255, 180, 0, 0.15); border-left: 3px solid #ffb400; padding: 10px; margin-top: 10px; border-radius: 4px; color: #ffb400; font-size: 0.9em; display: flex; align-items: center; gap: 8px; }
        .no-conn { color: #666; font-style: italic; padding: 10px; text-align: center; }
        .scroll-area { max-height: 65vh; overflow-y: auto; border-radius: 8px; }
        .loading { text-align: center; padding: 40px; color: #999; }
        .refresh-time { text-align: right; color: #666; font-size: 0.85em; margin-top: 15px; }
        footer { background: rgba(0,0,0,0.18); border-top:1px solid rgba(0,255,136,0.06); padding:12px 20px; color:#9fb0c8; text-align:center; font-size:0.9em; }
        footer a { color:#7ee787; text-decoration:none; }
    </style>
</head>
<body>
    <nav>
        <div>🛡️ Learn-Protect</div>
        <a href="/">Dashboard</a>
        <a href="/network" class="active">Réseau</a>
        <a href="/learning">📚 Learning</a>
        <a href="/infos">ℹ️ Infos</a>
    </nav>

    <div class="container">
        <div class="header">
            <h1>🌐 Connexions Réseau en Temps Réel</h1>
            <p>Découvrez quels programmes se connectent à Internet et vers où</p>
        </div>

        <div class="network-section">
            <h2>📡 Détail des Connexions par Programme</h2>
            <div class="scroll-area" id="networkContent">
                <div class="loading">Chargement des données réseau...</div>
            </div>
            <div class="refresh-time">Mise à jour: <span id="lastUpdate">--:--:--</span></div>
        </div>
    </div>

    <footer>
        © 2025 Learn&Protect — Tous droits réservés. Pour la documentation, voir <a href="/infos">Infos</a>.
    </footer>

    <script>
        function updateNetwork() {
            fetch("/api/analysis")
                .then(r => r.json())
                .then(data => {
                    displayNetworkInfo(data.processes);
                    document.getElementById("lastUpdate").textContent = new Date().toLocaleTimeString();
                })
                .catch(e => console.error("Erreur:", e));
        }

        function formatAddress(ip, port) {
            if (!ip || ip === '?') return 'Adresse locale';
            if (port && port !== '?') return ip + ':' + port;
            return ip;
        }

        function displayNetworkInfo(processes) {
            const content = document.getElementById("networkContent");
            content.innerHTML = "";

            const withNetwork = processes.filter(p => p.network && p.network.length > 0);

            if (withNetwork.length === 0) {
                content.innerHTML = '<div class="loading">Aucun processus avec connexions réseau actives (pas de trafic détecté)</div>';
                return;
            }

            withNetwork.forEach(proc => {
                const card = document.createElement("div");
                card.className = "process-card";

                let html = `
                    <div class="process-header">${proc.name}</div>
                    <div class="process-meta">
                        <div><span class="meta-label">👤 Utilisateur:</span> <span>${proc.user || 'N/A'}</span></div>
                        <div><span class="meta-label">🔢 ID:</span> <span>${proc.pid}</span></div>
                        <div><span class="meta-label">📂 Chemin:</span> <span>${proc.exe ? proc.exe.substring(proc.exe.lastIndexOf('/')+1) : 'N/A'}</span></div>
                        <div><span class="meta-label">💾 Mémoire:</span> <span>${proc.memory ? Math.round(proc.memory/1024/1024) + ' MB' : 'N/A'}</span></div>
                    </div>
                `;

                if (proc.network && proc.network.length > 0) {
                    const tcpConns = proc.network.filter(c => (c.protocol || '').toUpperCase() === 'TCP');
                    const udpConns = proc.network.filter(c => (c.protocol || '').toUpperCase() === 'UDP');

                    if (tcpConns.length > 0) {
                        html += '<div class="connection-group"><div class="connection-group-title">🔗 Connexions TCP (fiables)</div>';
                        tcpConns.forEach(conn => {
                            const local = formatAddress(conn.laddr_ip, conn.laddr_port);
                            const remote = formatAddress(conn.raddr_ip, conn.raddr_port);
                            const isExternal = conn.is_external ? '⚠️' : '';
                            html += `
                                <div class="connection-item">
                                    <div>
                                        <span class="protocol-badge">TCP</span>
                                        <span class="status-badge">${conn.status || 'CONNECTÉ'}</span>
                                        ${isExternal}
                                    </div>
                                    <div class="connection-detail">
                                        <div class="address-pair">
                                            <div class="address-label">De (Local):</div>
                                            <div class="address-value">${local}</div>
                                        </div>
                                        <div class="address-pair">
                                            <div class="address-label">Vers (Distant):</div>
                                            <div class="address-value">${remote}</div>
                                        </div>
                                    </div>
                                    ${conn.is_external ? '<div class="external-warning">⚠️ Connexion vers une adresse externe</div>' : ''}
                                </div>
                            `;
                        });
                        html += '</div>';
                    }

                    if (udpConns.length > 0) {
                        html += '<div class="connection-group"><div class="connection-group-title">📦 Connexions UDP (rapides)</div>';
                        udpConns.forEach(conn => {
                            const local = formatAddress(conn.laddr_ip, conn.laddr_port);
                            const remote = formatAddress(conn.raddr_ip, conn.raddr_port);
                            html += `
                                <div class="connection-item">
                                    <div>
                                        <span class="protocol-badge">UDP</span>
                                        <span class="status-badge">${conn.status || 'ACTIF'}</span>
                                    </div>
                                    <div class="connection-detail">
                                        <div class="address-pair">
                                            <div class="address-label">De (Local):</div>
                                            <div class="address-value">${local}</div>
                                        </div>
                                        <div class="address-pair">
                                            <div class="address-label">Vers (Distant):</div>
                                            <div class="address-value">${remote}</div>
                                        </div>
                                    </div>
                                </div>
                            `;
                        });
                        html += '</div>';
                    }
                } else {
                    html += '<div class="no-conn">Aucune connexion réseau active pour ce processus</div>';
                }

                card.innerHTML = html;
                content.appendChild(card);
            });
        }

        updateNetwork();
        setInterval(updateNetwork, 3000);
    </script>
</body>
</html>
"""

def get_network_view():
    """Retourne le template de la vue réseau."""
    from flask import render_template_string
    return render_template_string(NETWORK_HTML)
