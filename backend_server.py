#!/usr/bin/env python3
"""
Serveur HTTP pour Learn-Protect - Dashboard avec Navigation
Expose les analyses de processus en temps réel via REST API et vues HTML.

Usage:
  python3 backend_server.py --port 5001 --limit 10
  Puis ouvrez http://localhost:5001 dans votre navigateur
"""

import argparse
import json
import sys
import threading
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Dict, List

try:
    from flask import Flask, render_template_string, jsonify, request
    from flask_cors import CORS
except ImportError:
    print("ERROR: Flask et flask-cors requis. Installez: pip install flask flask-cors")
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("ERROR: psutil requis. Installez: pip install psutil")
    sys.exit(1)

try:
    from infos_view import INFOS_HTML
except ImportError:
    INFOS_HTML = None


def _to_serializable(obj: Any) -> Any:
    """Convertit les objets dataclass et complexes en JSON-compatible."""
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    try:
        return str(obj)
    except Exception:
        return None


class AnalysisEngine:
    """Moteur d'analyse continu des processus."""

    def __init__(self, limit: int = 20):
        self.limit = limit
        self.last_analysis = None
        self.lock = threading.Lock()

        # Import des modules d'analyse
        try:
            from moteur_analyse.regles_heuristiques import HeuristicEngine
            from moteur_analyse.score_de_risque import ScoringEngine
            from moteur_analyse.generateur_messages import MessageGenerator
            from moteur_analyse.classification import Classifier
            from scanner_processus.liste_processus import ProcessLister
            from scanner_processus.analyseur_reseau import NetworkAnalyzer
            from scanner_processus.calcul_hash import HashCalculator
            from learning_module import LearningModule

            self.heuristic = HeuristicEngine()
            self.scorer = ScoringEngine()
            self.msg_gen = MessageGenerator()
            self.classifier = Classifier()
            self.proc_lister = ProcessLister()
            self.NetworkAnalyzer = NetworkAnalyzer
            self.HashCalculator = HashCalculator
            self.learning = LearningModule()
        except Exception as e:
            print(f"Erreur import modules: {e}")
            self.heuristic = None
            self.scorer = None
            self.msg_gen = None
            self.classifier = None
            self.proc_lister = None
            self.NetworkAnalyzer = None
            self.HashCalculator = None
            self.learning = None

    def get_system_info(self) -> Dict[str, Any]:
        """Récupère infos système (CPU, mémoire, disque)."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            proc_count = len(psutil.pids())

            return {
                "cpu_percent": float(cpu_percent),
                "memory": {
                    "total": int(mem.total),
                    "used": int(mem.used),
                    "available": int(mem.available),
                    "percent": float(mem.percent),
                },
                "disk": {
                    "total": int(disk.total),
                    "used": int(disk.used),
                    "free": int(disk.free),
                    "percent": float(disk.percent),
                },
                "process_count": proc_count,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {"error": str(e)}

    def analyze_processes(self, limit: int | None = None) -> List[Dict[str, Any]]:
        """Analyse les processus actifs."""
        results = []

        # Récupère processus
        processes = []
        try:
            if self.proc_lister:
                processes = self.proc_lister.list_processes()
            else:
                # Fallback psutil
                for p in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline", "username"]):
                    processes.append(p.info)
        except Exception:
            processes = []

        # Determine effective limit: None -> use self.limit; 0 -> all
        if limit is None:
            eff_limit = self.limit
        else:
            eff_limit = limit

        targets = processes if eff_limit == 0 else processes[: eff_limit]

        for proc in targets:
            try:
                # Normalize process data
                if is_dataclass(proc):
                    pdict = asdict(proc)
                elif isinstance(proc, dict):
                    pdict = proc
                else:
                    pdict = {k: getattr(proc, k, None) for k in dir(proc) if not k.startswith("_")}

                pid = pdict.get("pid")
                exe_path = pdict.get("exe") or pdict.get("exe_path")
                name = pdict.get("name") or ""

                # Données de base
                result = {
                    "pid": pid,
                    "name": name,
                    "exe": exe_path,
                    "user": pdict.get("username") or pdict.get("user"),
                    "status": "RUNNING",
                }

                # Enrichissement psutil (CPU, mémoire, parent)
                try:
                    proc_obj = psutil.Process(pid)
                    result["cpu_percent"] = float(proc_obj.cpu_percent(interval=0.05))
                    result["memory_mb"] = float(proc_obj.memory_info().rss / 1024 / 1024)
                    try:
                        parent = proc_obj.parent()
                        result["parent_name"] = parent.name() if parent else None
                    except Exception:
                        result["parent_name"] = None
                except Exception:
                    result["cpu_percent"] = 0.0
                    result["memory_mb"] = 0.0
                    result["parent_name"] = None

                # Réseau
                network = []
                if self.NetworkAnalyzer and pid:
                    try:
                        na = self.NetworkAnalyzer(pid)
                        conns = na.list_connections()
                        network = _to_serializable(conns)
                    except Exception:
                        network = []
                result["network_connections"] = len(network)
                result["network"] = network  # Include full network data

                # Heuristiques
                if self.heuristic and self.scorer:
                    process_data = {
                        "pid": pid,
                        "name": name,
                        "exe_path": exe_path or "",
                        "user": result.get("user") or "",
                        "parent_name": result.get("parent_name"),
                        "cpu_percent": result.get("cpu_percent", 0),
                        "memory_rss": int(result.get("memory_mb", 0) * 1024 * 1024),
                        "network": network,
                        "signature": None,
                        "integrity": None,
                    }

                    try:
                        heur_out = self.heuristic.analyze(process_data)
                        score_result = self.scorer.score_from_heuristic_output(heur_out)
                        result["score"] = int(score_result.total_score)
                        result["level"] = score_result.level
                        result["triggers"] = len(score_result.triggers)
                        result["triggered_rules"] = [t.get("rule_id") for t in score_result.triggers]
                        
                        # Créer une alerte si processus suspect/dangereux
                        if result["level"] in ["SUSPICIOUS", "DANGEROUS"] and self.learning:
                            severity_map = {"SUSPICIOUS": "warning", "DANGEROUS": "critical"}
                            alert = self.learning.create_alert(
                                process_id=pid,
                                process_name=name,
                                severity=severity_map.get(result["level"], "info"),
                                title=f"Processus {result['level'].lower()}: {name}",
                                message=f"Score de risque: {result['score']}/100. Règles déclenchées: {', '.join(result['triggered_rules'])}",
                                triggered_rules=result["triggered_rules"],
                            )
                            result["alert_id"] = alert.id
                        
                    except Exception:
                        result["score"] = 0
                        result["level"] = "SAFE"
                        result["triggers"] = 0
                        result["triggered_rules"] = []
                else:
                    result["score"] = 0
                    result["level"] = "SAFE"
                    result["triggers"] = 0
                    result["triggered_rules"] = []

                results.append(result)

            except Exception as e:
                results.append({
                    "error": str(e),
                    "pid": pdict.get("pid") if isinstance(pdict, dict) else None
                })

        return results

    def get_analysis(self) -> Dict[str, Any]:
        """Retourne l'analyse complète (système + processus)."""
        with self.lock:
            self.last_analysis = {
                "timestamp": datetime.now().isoformat(),
                "system": self.get_system_info(),
                "processes": self.analyze_processes(),
            }
            return self.last_analysis


# Flask app
app = Flask(__name__)
CORS(app)

# Engine global
engine = None


@app.route("/", methods=["GET"])
def index():
    """Dashboard principal - tous les processus avec table scrollable."""
    html = """
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
                
                // Charger les alertes
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

                // Badge avec nombre
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

            // Mise à jour initiale et périodique
            updateData();
            setInterval(updateData, 2000);
        </script>
        <footer style="background: rgba(0,0,0,0.18); border-top:1px solid rgba(0,255,136,0.06); padding:12px 20px; color:#9fb0c8; text-align:center; font-size:0.9em;">
            © 2025 Learn&Protect — Tous droits réservés. Pour la documentation, voir <a href="/infos" style="color:#7ee787; text-decoration:none;">Infos</a>.
        </footer>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/network", methods=["GET"])
def network_view():
    """Affichage des infos réseau par processus - scrollable."""
    html = """
    <!DOCTYPE html>
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
            .header p {
                color: #9fb0c8;
                font-size: 1.05em;
            }
            .network-section {
                background: rgba(255, 255, 255, 0.05);
                padding: 20px;
                border-radius: 10px;
                border: 1px solid rgba(0, 255, 136, 0.2);
            }
            .network-section h2 {
                color: #00ff88;
                margin-bottom: 15px;
                font-size: 1.5em;
            }
            .process-card {
                background: linear-gradient(135deg, rgba(0,255,136,0.05) 0%, rgba(0,0,0,0.2) 100%);
                border: 1px solid rgba(0, 255, 136, 0.15);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 15px;
                overflow: hidden;
            }
            .process-header {
                font-weight: bold;
                color: #00ff88;
                margin-bottom: 12px;
                font-size: 1.2em;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .process-header::before {
                content: "▶";
                font-size: 0.8em;
            }
            .process-meta {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
                margin-bottom: 15px;
                font-size: 0.9em;
                color: #bbb;
                padding: 10px;
                background: rgba(0,0,0,0.2);
                border-radius: 6px;
            }
            .process-meta div {
                display: flex;
                gap: 6px;
                align-items: center;
            }
            .meta-label {
                color: #7ee787;
                font-weight: 600;
                min-width: 90px;
            }
            .connection-group {
                margin-bottom: 12px;
            }
            .connection-group-title {
                color: #ffb400;
                font-weight: 600;
                margin-bottom: 8px;
                font-size: 0.95em;
                display: flex;
                align-items: center;
                gap: 6px;
            }
            .connection-item {
                background: rgba(0, 255, 136, 0.08);
                border-left: 3px solid #00ff88;
                padding: 12px;
                margin-bottom: 8px;
                border-radius: 6px;
                font-size: 0.9em;
            }
            .connection-detail {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
                margin-top: 8px;
            }
            .address-pair {
                display: flex;
                flex-direction: column;
                gap: 4px;
            }
            .address-label {
                font-size: 0.8em;
                color: #888;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .address-value {
                font-family: 'Courier New', monospace;
                color: #7ee787;
                font-weight: 500;
                word-break: break-all;
            }
            .protocol-badge {
                display: inline-block;
                background: rgba(0,255,136,0.2);
                color: #00ff88;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                font-weight: 600;
                margin-right: 8px;
                text-transform: uppercase;
            }
            .status-badge {
                display: inline-block;
                background: rgba(100,200,255,0.2);
                color: #64c8ff;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.8em;
            }
            .external-warning {
                background: rgba(255, 180, 0, 0.15);
                border-left: 3px solid #ffb400;
                padding: 10px;
                margin-top: 10px;
                border-radius: 4px;
                color: #ffb400;
                font-size: 0.9em;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .no-conn {
                color: #666;
                font-style: italic;
                padding: 10px;
                text-align: center;
            }
            .scroll-area {
                max-height: 65vh;
                overflow-y: auto;
                border-radius: 8px;
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
            .info-tooltip {
                display: inline-block;
                width: 16px;
                height: 16px;
                background: rgba(0,255,136,0.3);
                border: 1px solid rgba(0,255,136,0.5);
                border-radius: 50%;
                text-align: center;
                line-height: 14px;
                font-size: 0.8em;
                color: #00ff88;
                cursor: help;
                title: "Plus d'informations";
            }
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

            function getProtocolEmoji(protocol) {
                const p = (protocol || '').toUpperCase();
                if (p === 'TCP') return '🔗';
                if (p === 'UDP') return '📦';
                return '📡';
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

            // Mise à jour initiale et périodique
            updateNetwork();
            setInterval(updateNetwork, 3000);
        </script>
        <footer style="background: rgba(0,0,0,0.18); border-top:1px solid rgba(0,255,136,0.06); padding:12px 20px; color:#9fb0c8; text-align:center; font-size:0.9em;">
            © 2025 Learn&Protect — Tous droits réservés. Pour la documentation, voir <a href="/infos" style="color:#7ee787; text-decoration:none;">Infos</a>.
        </footer>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/api/analysis", methods=["GET"])
def api_analysis():
    """Retourne l'analyse JSON."""
    if engine:
        analysis = engine.get_analysis()
        return jsonify(analysis)
    return jsonify({"error": "Engine not initialized"}), 500


@app.route("/api/system", methods=["GET"])
def api_system():
    """Infos système uniquement."""
    if engine:
        return jsonify(engine.get_system_info())
    return jsonify({"error": "Engine not initialized"}), 500


@app.route("/api/processes", methods=["GET"])
def api_processes():
    """Processus uniquement."""
    if engine:
        try:
            q = request.args.get("limit")
            if q is not None:
                lim = int(q)
            else:
                lim = None
        except Exception:
            lim = None

        return jsonify(engine.analyze_processes(limit=0 if lim == 0 else lim))
    return jsonify({"error": "Engine not initialized"}), 500


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """Récupère les alertes de sécurité récentes."""
    if engine and engine.learning:
        limit = request.args.get("limit", default=20, type=int)
        alerts = engine.learning.get_recent_alerts(limit)
        return jsonify(_to_serializable(alerts))
    return jsonify({"error": "Learning module not initialized"}), 500


@app.route("/api/alerts/<alert_id>", methods=["GET"])
def api_alert_detail(alert_id):
    """Récupère les détails d'une alerte spécifique."""
    if engine and engine.learning:
        alert = engine.learning.get_alert(alert_id)
        if alert:
            return jsonify(_to_serializable(alert))
        return jsonify({"error": "Alert not found"}), 404
    return jsonify({"error": "Learning module not initialized"}), 500


@app.route("/api/learning/resources", methods=["GET"])
def api_learning_resources():
    """Récupère toutes les ressources d'apprentissage."""
    if engine and engine.learning:
        category = request.args.get("category")
        difficulty = request.args.get("difficulty")
        
        if category:
            resources = engine.learning.get_learning_resources_by_category(category)
        elif difficulty:
            resources = engine.learning.get_learning_resources_by_difficulty(difficulty)
        else:
            resources = engine.learning.get_all_learning_resources()
        
        return jsonify(_to_serializable(resources))
    return jsonify({"error": "Learning module not initialized"}), 500


@app.route("/api/learning/resources/<resource_id>", methods=["GET"])
def api_learning_resource_detail(resource_id):
    """Récupère les détails d'une ressource d'apprentissage."""
    if engine and engine.learning:
        resource = engine.learning.get_learning_resource(resource_id)
        if resource:
            return jsonify(_to_serializable(resource))
        return jsonify({"error": "Resource not found"}), 404
    return jsonify({"error": "Learning module not initialized"}), 500


@app.route("/learning", methods=["GET"])
def learning_page():
    """Page principale de sensibilisation cybersécurité."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Learn-Protect - Sensibilisation Cybersécurité</title>
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
            .alerts-section {
                margin-bottom: 40px;
            }
            .alerts-section h2 {
                color: #00ff88;
                margin-bottom: 15px;
                font-size: 1.8em;
            }
            .alert-box {
                background: rgba(255, 255, 255, 0.08);
                border: 2px solid rgba(0, 255, 136, 0.3);
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 12px;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .alert-box:hover {
                background: rgba(0, 255, 136, 0.15);
                border-color: #00ff88;
            }
            .alert-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .alert-title {
                font-weight: bold;
                font-size: 1.1em;
                color: #fff;
            }
            .alert-badge {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 0.75em;
                font-weight: 600;
            }
            .alert-badge.info {
                background: rgba(100, 150, 255, 0.3);
                color: #6496ff;
            }
            .alert-badge.warning {
                background: rgba(255, 200, 0, 0.3);
                color: #ffc800;
            }
            .alert-badge.critical {
                background: rgba(255, 60, 60, 0.3);
                color: #ff3c3c;
            }
            .alert-details {
                display: none;
                background: rgba(0, 0, 0, 0.3);
                margin-top: 10px;
                padding: 12px;
                border-radius: 6px;
                font-size: 0.9em;
            }
            .alert-details.open {
                display: block;
            }
            .alert-process {
                color: #7ee787;
                font-weight: bold;
                margin-top: 5px;
            }
            .learning-section {
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(0, 255, 136, 0.2);
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 30px;
            }
            .learning-section h3 {
                color: #00ff88;
                margin-bottom: 15px;
                font-size: 1.4em;
            }
            .resource-card {
                background: rgba(0, 0, 0, 0.2);
                border-left: 4px solid #00ff88;
                padding: 15px;
                margin-bottom: 12px;
                border-radius: 6px;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            .resource-card:hover {
                background: rgba(0, 255, 136, 0.1);
            }
            .resource-header {
                font-weight: bold;
                color: #00ff88;
                margin-bottom: 8px;
                font-size: 1.05em;
            }
            .resource-meta {
                font-size: 0.85em;
                color: #9fb0c8;
                margin-bottom: 8px;
            }
            .resource-desc {
                color: #ccc;
                font-size: 0.95em;
            }
            .modal {
                display: none;
                position: fixed;
                z-index: 1000;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0, 0, 0, 0.8);
                overflow: auto;
            }
            .modal.show {
                display: block;
            }
            .modal-content {
                background: #2d2d44;
                margin: 5% auto;
                padding: 30px;
                border: 1px solid rgba(0, 255, 136, 0.3);
                border-radius: 10px;
                width: 90%;
                max-width: 800px;
                max-height: 80vh;
                overflow-y: auto;
            }
            .modal-header {
                color: #00ff88;
                font-size: 1.8em;
                margin-bottom: 20px;
                border-bottom: 2px solid rgba(0, 255, 136, 0.3);
                padding-bottom: 10px;
            }
            .modal-body {
                color: #e0e0e0;
                line-height: 1.6;
            }
            .modal-body h3 {
                color: #00ff88;
                margin-top: 20px;
                margin-bottom: 10px;
            }
            .modal-body h4 {
                color: #7ee787;
                margin-top: 15px;
                margin-bottom: 8px;
            }
            .modal-body ul {
                margin-left: 20px;
                margin-bottom: 10px;
            }
            .modal-body li {
                margin-bottom: 5px;
            }
            .modal-body pre {
                background: rgba(0, 0, 0, 0.4);
                padding: 12px;
                border-radius: 6px;
                overflow-x: auto;
                margin-bottom: 10px;
            }
            .modal-body table {
                border-collapse: collapse;
                margin-bottom: 10px;
            }
            .modal-body th, .modal-body td {
                border: 1px solid rgba(0, 255, 136, 0.2);
                padding: 8px;
                text-align: left;
            }
            .modal-body th {
                background: rgba(0, 255, 136, 0.1);
                color: #00ff88;
            }
            .close-btn {
                background: #ff3c3c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
                margin-top: 20px;
            }
            .close-btn:hover {
                background: #ff5555;
            }
            .refresh-time {
                text-align: right;
                color: #666;
                font-size: 0.85em;
                margin-top: 15px;
            }
            .tabs {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            }
            .tab-btn {
                padding: 10px 20px;
                background: transparent;
                border: none;
                color: #9fb0c8;
                cursor: pointer;
                font-size: 1em;
                border-bottom: 2px solid transparent;
                transition: all 0.3s;
            }
            .tab-btn.active {
                color: #00ff88;
                border-bottom-color: #00ff88;
            }
            .tab-content {
                display: none;
            }
            .tab-content.active {
                display: block;
            }
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
                <h1>📚 Sensibilisation Cybersécurité</h1>
                <p>Alertes de sécurité et ressources d'apprentissage</p>
            </div>

            <div class="alerts-section">
                <h2>🚨 Alertes Récentes</h2>
                <div id="alertsContainer">
                    <div style="text-align: center; color: #666;">Chargement des alertes...</div>
                </div>
                <div class="refresh-time">Mise à jour: <span id="alertsUpdate">--:--:--</span></div>
            </div>

            <div style="display: flex; gap: 20px; margin-bottom: 20px;">
                <button class="tab-btn active" onclick="filterResources('all')">📖 Toutes</button>
                <button class="tab-btn" onclick="filterResources('malware')">🦠 Malware</button>
                <button class="tab-btn" onclick="filterResources('network')">🌐 Réseau</button>
                <button class="tab-btn" onclick="filterResources('privilege')">🔐 Privilèges</button>
                <button class="tab-btn" onclick="filterResources('process')">⚙️ Processus</button>
            </div>

            <div id="resourcesContainer" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 20px;">
                <div style="text-align: center; color: #666;">Chargement des ressources...</div>
            </div>
        </div>

        <div id="resourceModal" class="modal">
            <div class="modal-content">
                <div class="modal-header" id="modalTitle"></div>
                <div class="modal-body" id="modalBody"></div>
                <button class="close-btn" onclick="closeModal()">Fermer</button>
            </div>
        </div>

        <script>
            let currentFilter = 'all';
            let allResources = [];

            function loadAlerts() {
                fetch('/api/alerts?limit=10')
                    .then(r => r.json())
                    .then(alerts => {
                        displayAlerts(alerts);
                        document.getElementById('alertsUpdate').textContent = new Date().toLocaleTimeString();
                    })
                    .catch(e => console.error('Erreur alertes:', e));
            }

            function displayAlerts(alerts) {
                const container = document.getElementById('alertsContainer');
                
                if (!alerts || alerts.length === 0) {
                    container.innerHTML = '<div style="text-align: center; color: #7ee787;">✓ Aucune alerte - Système sain</div>';
                    return;
                }

                container.innerHTML = alerts.map(alert => `
                    <div class="alert-box" onclick="toggleAlertDetails(this)">
                        <div class="alert-header">
                            <div>
                                <div class="alert-title">${alert.title}</div>
                                <div class="alert-process">PID ${alert.process_id} - ${alert.process_name}</div>
                            </div>
                            <span class="alert-badge ${alert.severity}">${alert.severity.toUpperCase()}</span>
                        </div>
                        <div class="alert-details">
                            <div><strong>Message:</strong> ${alert.message}</div>
                            <div><strong>Règles:</strong> ${alert.triggered_rules.join(', ')}</div>
                            <div><strong>Ressources d'apprentissage:</strong></div>
                            <ul style="margin-left: 20px;">
                                ${alert.learning_resources.map(rid => `<li><a href="#" onclick="loadAndShowResource('${rid}'); return false;" style="color: #7ee787; text-decoration: none;">📚 ${rid}</a></li>`).join('')}
                            </ul>
                        </div>
                    </div>
                `).join('');
            }

            function toggleAlertDetails(elem) {
                elem.querySelector('.alert-details').classList.toggle('open');
            }

            function loadResources() {
                fetch('/api/learning/resources')
                    .then(r => r.json())
                    .then(resources => {
                        allResources = resources;
                        filterResources('all');
                    })
                    .catch(e => console.error('Erreur ressources:', e));
            }

            function filterResources(category) {
                currentFilter = category;
                document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
                event.target?.classList.add('active');

                let filtered = allResources;
                if (category !== 'all') {
                    filtered = allResources.filter(r => r.category === category);
                }

                const container = document.getElementById('resourcesContainer');
                container.innerHTML = filtered.map(res => `
                    <div class="resource-card" onclick="loadAndShowResource('${res.id}')">
                        <div class="resource-header">${res.title}</div>
                        <div class="resource-meta">
                            <span>${res.difficulty.toUpperCase()}</span> | 
                            <span>⏱️ ${res.duration_minutes}min</span> | 
                            <span>${res.category}</span>
                        </div>
                        <div class="resource-desc">${res.description}</div>
                        <div style="margin-top: 8px; color: #666; font-size: 0.85em;">
                            Tags: ${res.tags.join(', ')}
                        </div>
                    </div>
                `).join('');
            }

            function loadAndShowResource(resourceId) {
                fetch(`/api/learning/resources/${resourceId}`)
                    .then(r => r.json())
                    .then(resource => {
                        document.getElementById('modalTitle').textContent = resource.title;
                        document.getElementById('modalBody').innerHTML = resource.content;
                        document.getElementById('resourceModal').classList.add('show');
                    })
                    .catch(e => console.error('Erreur chargement ressource:', e));
            }

            function closeModal() {
                document.getElementById('resourceModal').classList.remove('show');
            }

            // Charger les données
            loadAlerts();
            loadResources();
            
            // Mise à jour périodique des alertes
            setInterval(loadAlerts, 5000);
        </script>
        <footer style="background: rgba(0,0,0,0.18); border-top:1px solid rgba(0,255,136,0.06); padding:12px 20px; color:#9fb0c8; text-align:center; font-size:0.9em;">
            © 2025 Learn&Protect — Tous droits réservés. Pour la documentation, voir <a href="/infos" style="color:#7ee787; text-decoration:none;">Infos</a>.
        </footer>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/infos", methods=["GET"])
def infos():
    """Page d'information et glossaire Learn-Protect."""
    if INFOS_HTML:
        return render_template_string(INFOS_HTML)
    return "<h1>Page Infos indisponible</h1>", 404


@app.route("/health", methods=["GET"])
def health():
    """Health check."""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


def main():
    parser = argparse.ArgumentParser(description="Backend Learn-Protect")
    parser.add_argument("--port", type=int, default=5000, help="Port (défaut: 5000)")
    parser.add_argument("--interval", type=int, default=2, help="Intervalle analyse en secondes (défaut: 2)")
    parser.add_argument("--limit", type=int, default=20, help="Nombre processus à analyser (défaut: 20)")
    parser.add_argument("--host", default="0.0.0.0", help="Host (défaut: 0.0.0.0)")
    args = parser.parse_args()

    global engine
    engine = AnalysisEngine(limit=args.limit)

    print(f"\n{'='*60}")
    print(f"🚀 Learn-Protect Backend Server")
    print(f"{'='*60}")
    print(f"📡 URL: http://localhost:{args.port}")
    print(f"⏱️  Intervalle: {args.interval}s")
    print(f"📊 Max processus par scan: {args.limit}")
    print(f"{'='*60}\n")

    # Démarrer Flask
    try:
        app.run(host=args.host, port=args.port, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n\n⛔ Serveur arrêté.")
    except Exception as e:
        print(f"Erreur: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
