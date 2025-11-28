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

# Import modular views moved to `vue/` package
try:
    from vue.dashboard import get_dashboard_view
    from vue.network import get_network_view
    from vue.learning import get_learning_view
    from vue.infos import get_infos_view
except Exception:
    # If views package isn't available yet, set placeholders
    get_dashboard_view = None
    get_network_view = None
    get_learning_view = None
    get_infos_view = None

try:
    from flask import Flask, render_template_string, jsonify, request
    from flask_cors import CORS
except ImportError:
    print("ERROR: Flask et flask-cors requis. Installez: pip install flask flask-cors")
    sys.exit(1)

# Flask app initialization
app = Flask(__name__)
CORS(app)

# Global engine placeholder
engine = None

# Lightweight analysis engine wrapper (minimal for API endpoints)
try:
    from scanner_processus.liste_processus import ProcessLister
    from scanner_processus.collecteur_systeme import SystemInfoCollector
    from learning_module import LearningModule
except Exception:
    ProcessLister = None
    SystemInfoCollector = None
    LearningModule = None


def _to_serializable(obj: Any):
    """Convertit dataclasses / nested structures en objets sérialisables JSON."""
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(x) for x in obj]
    return obj


class AnalysisEngine:
    """Simple engine that aggregates system info, processes and learning module."""

    def __init__(self, limit: int = 20):
        self.limit = limit
        self.process_lister = ProcessLister() if ProcessLister else None
        self.system_collector = SystemInfoCollector() if SystemInfoCollector else None
        self.learning = LearningModule() if LearningModule else None

    def get_system_info(self) -> Dict[str, Any]:
        if self.system_collector:
            return self.system_collector.collect()
        return {"error": "system collector not available"}

    def analyze_processes(self, limit: int | None = None) -> List[Dict[str, Any]]:
        if not self.process_lister:
            return []
        procs = self.process_lister.list_processes()
        if limit and limit > 0:
            procs = procs[:limit]
        # Convert dataclass objects to serializable dicts
        result = []
        for p in procs:
            try:
                result.append(_to_serializable(p))
            except Exception:
                result.append({"pid": getattr(p, 'pid', None), "name": getattr(p, 'name', None)})
        return result

    def get_analysis(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.now().isoformat(),
            "system": self.get_system_info(),
            "processes": self.analyze_processes(limit=self.limit),
        }


try:
    from flask import Flask, render_template_string, jsonify, request
    from flask_cors import CORS
except ImportError:
    print("ERROR: Flask et flask-cors requis. Installez: pip install flask flask-cors")
    sys.exit(1)

try:
    import psutil
except ImportError:
    psutil = None

@app.route("/", methods=["GET"])
def index():
    """Dashboard principal - tous les processus avec table scrollable."""
    if get_dashboard_view:
        return get_dashboard_view()
    return "<h1>Dashboard indisponible</h1>", 500


@app.route("/network", methods=["GET"])
def network_view():
    """Affichage des infos réseau par processus - scrollable."""
    if get_network_view:
        return get_network_view()
    return "<h1>Network indisponible</h1>", 500


@app.route("/__old_network__", methods=["GET"])
def network_view_old():
    """Old network view removed."""
    return "<h1>Old network view removed</h1>", 410


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
    if get_learning_view:
        return get_learning_view()
    return "<h1>Learning indisponible</h1>", 500


@app.route("/infos", methods=["GET"])
def infos():
    """Page d'information et glossaire Learn-Protect."""
    if get_infos_view:
        return get_infos_view()
    return "<h1>Page Infos indisponible</h1>", 404


@app.route("/health", methods=["GET"])
def health():
    """Health check."""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})





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
