#!/usr/bin/env python3
"""
Serveur HTTP en arrière-plan pour Learn-Protect.
Expose les analyses de processus en temps réel via REST API et WebSocket.

Usage:
  python3 backend_server.py --port 5000 --interval 2
  Puis ouvrez http://localhost:5000 dans votre navigateur

Options:
  --port PORT           Port d'écoute (défaut: 5000)
  --interval SECONDS    Intervalle d'analyse (défaut: 2)
  --limit PROCESSES     Nombre de processus à analyser (défaut: 20)
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
    """
    Moteur d'analyse continu des processus.
    Collecte données système et processus, applique heuristiques, scoring et classification.
    """

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

            self.heuristic = HeuristicEngine()
            self.scorer = ScoringEngine()
            self.msg_gen = MessageGenerator()
            self.classifier = Classifier()
            self.proc_lister = ProcessLister()
            self.NetworkAnalyzer = NetworkAnalyzer
            self.HashCalculator = HashCalculator
        except Exception as e:
            print(f"Erreur import modules: {e}")
            self.heuristic = None
            self.scorer = None
            self.msg_gen = None
            self.classifier = None
            self.proc_lister = None
            self.NetworkAnalyzer = None
            self.HashCalculator = None

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
                # Log erreur mais continue
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
    """Page web d'affichage."""
    # Keep index as analysis view
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Learn-Protect Monitoring</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
                color: #e0e0e0;
                padding: 20px;
            }
            .container {
                max-width: 1400px;
                margin: 0 auto;
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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Learn-Protect Monitoring</h1>
                <p>Analyse en temps réel des processus et du système</p>
            </div>

            <div class="system-info" id="systemInfo">
                <div class="loading">Chargement des données...</div>
            </div>

            <div class="processes-section">
                <h2>Processus Actifs</h2>
                <div id="processesList">
                    <div class="loading">Chargement des processus...</div>
                </div>
                <div class="refresh-time">Mise à jour: <span id="lastUpdate">--:--:--</span></div>
            </div>
        </div>

        <script>
            function updateData() {
                fetch("/api/analysis")
                    .then(r => r.json())
                    .then(data => {
                        displaySystemInfo(data.system);
                        displayProcesses(data.processes);
                        document.getElementById("lastUpdate").textContent = new Date().toLocaleTimeString();
                    })
                    .catch(e => console.error("Erreur:", e));
            }

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
                    document.getElementById("processesList").innerHTML = '<div class="loading">Aucun processus trouvé</div>';
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

                const html = `
                    <table>
                        <thead>
                            <tr>
                                <th>PID</th>
                                <th>Nom</th>
                                <th>CPU %</th>
                                <th>Mémoire</th>
                                <th>Réseau</th>
                                <th>Score</th>
                                <th>Niveau</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows}
                        </tbody>
                    </table>
                `;
                document.getElementById("processesList").innerHTML = html;
            }

            // Mise à jour initiale et périodique
            updateData();
            setInterval(updateData, 2000);  // Refresh toutes les 2 secondes
        </script>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/system", methods=["GET"])
def system_view():
        """HTML view for system info (consumes /api/system)."""
        html = """
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><title>System Info - Learn-Protect</title>
        <style>
            body{font-family:Inter,Arial;margin:20px;background:#0f1724;color:#e6eef8}
            .card{background:#0b1220;border-radius:8px;padding:18px;border:1px solid rgba(255,255,255,0.03);max-width:1100px;margin:auto}
            h1{color:#7ee787}
            pre{background:#071019;padding:12px;border-radius:6px;overflow:auto}
        </style></head><body>
        <div class="card">
            <h1>System Overview</h1>
            <div id="content"><em>Loading...</em></div>
            <p style="text-align:right;color:#88a">Updated: <span id="t">--</span></p>
        </div>
        <script>
            function upd(){fetch('/api/system').then(r=>r.json()).then(d=>{
                if(d.error){document.getElementById('content').innerHTML='<pre>'+JSON.stringify(d,null,2)+'</pre>';return}
                const html = `
                    <h3>CPU: ${d.cpu_percent.toFixed(1)}%</h3>
                    <div style="display:flex;gap:12px;flex-wrap:wrap">
                        <div style="min-width:220px"><strong>Memory</strong><pre>${(d.memory.used/1024/1024/1024).toFixed(2)} GB / ${(d.memory.total/1024/1024/1024).toFixed(2)} GB\n${d.memory.percent}%</pre></div>
                        <div style="min-width:220px"><strong>Disk</strong><pre>${(d.disk.used/1024/1024/1024).toFixed(2)} GB / ${(d.disk.total/1024/1024/1024).toFixed(2)} GB\n${d.disk.percent}%</pre></div>
                        <div style="min-width:220px"><strong>Processes</strong><pre>${d.process_count}</pre></div>
                    </div>
                `;
                document.getElementById('content').innerHTML = html;
                document.getElementById('t').textContent = new Date().toLocaleTimeString();
            }).catch(e=>document.getElementById('content').innerText = e)}
            upd(); setInterval(upd,3000);
        </script>
        </body></html>
        """
        return render_template_string(html)


@app.route("/processes", methods=["GET"])
def processes_view():
        """HTML view for processes (consumes /api/processes?limit=0 to get all)."""
        html = """
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><title>Processes - Learn-Protect</title>
        <style>
            body{font-family:Inter,Arial;margin:16px;background:#081021;color:#e7eef8}
            .wrap{max-width:1400px;margin:auto}
            h1{color:#7ee787}
            .table-wrap{background:#071019;border-radius:8px;padding:12px;border:1px solid rgba(255,255,255,0.03)}
            table{width:100%;border-collapse:collapse;color:#dbe9f7}
            th,td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,0.03);text-align:left}
            thead th{background:rgba(124,255,142,0.06);color:#9fffc0;position:sticky;top:0}
            .scroll{max-height:65vh;overflow:auto;border-radius:6px}
            .badge{padding:4px 8px;border-radius:10px;font-weight:600}
            .safe{background:#082b14;color:#7ee787}
            .susp{background:#332100;color:#ffc36b}
            .danger{background:#3a1515;color:#ff8f8f}
            .small{font-size:0.85em;color:#9fb0c8}
        </style></head><body>
        <div class="wrap">
            <h1>Tous les Processus</h1>
            <div class="table-wrap">
                <div style="margin-bottom:8px"><button onclick="refresh()">Rafraîchir</button> <span class="small">(Chargement en continu)</span></div>
                <div class="scroll" id="tablec"><table id="ptable"><thead><tr><th>PID</th><th>Nom</th><th>CPU %</th><th>Mémoire MB</th><th>Conn.</th><th>Score</th><th>Niveau / Règles</th></tr></thead><tbody></tbody></table></div>
            </div>
            <p class="small">Mise à jour: <span id="t">--</span></p>
        </div>
        <script>
            async function load(limit=0){
                const resp = await fetch('/api/processes?limit=0');
                const procs = await resp.json();
                const tbody = document.querySelector('#ptable tbody'); tbody.innerHTML='';
                for(const p of procs){
                    const level = (p.level||'SAFE').toUpperCase();
                    const badgeClass = level==='SAFE'? 'safe': (level==='SUSPICIOUS'?'susp':'danger');
                    const rules = (p.triggered_rules && p.triggered_rules.length)? p.triggered_rules.join(', '): '';
                    const tr = document.createElement('tr');
                    tr.innerHTML = `<td>${p.pid||''}</td><td>${p.name||''}</td><td>${(p.cpu_percent||0).toFixed(1)}</td><td>${(p.memory_mb||0).toFixed(1)}</td><td>${p.network_connections||0}</td><td><strong>${p.score||0}</strong></td><td><span class='badge ${badgeClass}'>${level}</span><div class='small'>${rules}</div></td>`;
                    tbody.appendChild(tr);
                }
                document.getElementById('t').textContent = new Date().toLocaleTimeString();
            }
            function refresh(){ load(); }
            load(); setInterval(load,2000);
        </script>
        </body></html>
        """
        return render_template_string(html)


@app.route("/analysis", methods=["GET"])
def analysis_view():
        """HTML view for combined analysis (consumes /api/analysis)."""
        # reuse index style but make it more focused on detailed messages
        html = """
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><title>Analysis - Learn-Protect</title>
        <style>
            body{font-family:Arial,Helvetica,sans-serif;background:#08101a;color:#ecf6ff;margin:18px}
            .wrap{max-width:1200px;margin:auto}
            h1{color:#7ee787}
            .card{background:#071019;padding:14px;border-radius:8px;border:1px solid rgba(255,255,255,0.03)}
            .proc{border-bottom:1px dashed rgba(255,255,255,0.03);padding:10px}
            .meta{font-size:0.85em;color:#9fb0c8}
            .danger{color:#ff8f8f}
        </style></head><body>
            <div class='wrap'><h1>Analyse complète</h1><div id='content' class='card'><em>Chargement...</em></div></div>
            <script>
                async function upd(){
                    const r = await fetch('/api/analysis'); const d = await r.json();
                    const el = document.getElementById('content'); el.innerHTML='';
                    const sys = document.createElement('div'); sys.className='meta'; sys.innerHTML=`<strong>CPU</strong>: ${d.system.cpu_percent}% &nbsp; <strong>Processus</strong>: ${d.system.process_count} &nbsp; <strong>Updated</strong>: ${new Date(d.timestamp).toLocaleTimeString()}`;
                    el.appendChild(sys);
                    for(const p of d.processes){
                        const pdiv = document.createElement('div'); pdiv.className='proc';
                        const rules = p.triggered_rules && p.triggered_rules.length? '<em>'+p.triggered_rules.join(', ')+'</em>' : '<span class="small">aucune</span>';
                        pdiv.innerHTML = `<div><strong>${p.name}</strong> (PID ${p.pid}) — <span class='meta'>CPU ${p.cpu_percent}% · ${p.memory_mb.toFixed(1)} MB</span></div><div class='meta'>Score: <strong>${p.score}</strong> · Niveau: ${p.level} · Règles: ${rules}</div>`;
                        el.appendChild(pdiv);
                    }
                }
                upd(); setInterval(upd,3000);
            </script>
        </body></html>
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
        # allow query param ?limit=0 for all processes
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


@app.route("/health", methods=["GET"])
def health():
    """Health check."""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


def main():
    parser = argparse.ArgumentParser(description="Backend continu Learn-Protect")
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
