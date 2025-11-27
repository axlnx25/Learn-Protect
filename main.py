#!/usr/bin/env python3
"""
Orchestrateur principal du backend Learn-Protect.
Rassemble les modules du scanner et du moteur d'analyse et affiche
leurs sorties au format JSON pour consommation par une UI.

Usage:
  python main.py --limit 5

Le script évite d'importer les modules Windows-only lorsque exécuté
sur un système non-Windows.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional


def _to_serializable(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    # fallback
    try:
        return str(obj)
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="Orchestrateur Learn-Protect (console)")
    parser.add_argument("--limit", type=int, default=5, help="Nombre de processus à analyser (par défaut: 5)")
    parser.add_argument("--json-lines", action="store_true", help="Imprime un JSON par ligne (streamable)")
    args = parser.parse_args()

    # Imports dynamiques (certains modules sont Windows-only)
    try:
        from scanner_processus.liste_processus import ProcessLister
    except Exception:
        ProcessLister = None

    try:
        from scanner_processus.analyseur_reseau import NetworkAnalyzer
    except Exception:
        NetworkAnalyzer = None

    try:
        from scanner_processus.calcul_hash import HashCalculator
    except Exception:
        HashCalculator = None

    # Heuristic + scoring + message + classification (pure python, safe to import)
    try:
        from moteur_analyse.regles_heuristiques import HeuristicEngine
        from moteur_analyse.score_de_risque import ScoringEngine
        from moteur_analyse.generateur_messages import MessageGenerator
        from moteur_analyse.classification import Classifier
    except Exception as e:
        print(json.dumps({"error": "Failed to import analysis modules", "detail": str(e)}))
        sys.exit(1)

    # Windows-only signature/agent modules: import only on Windows
    sig_inspector = None
    if sys.platform.startswith("win"):
        try:
            from scanner_processus.controle_integrite import inspect_signature
            sig_inspector = inspect_signature
        except Exception:
            sig_inspector = None

    # Instantiate utilities
    proc_lister = ProcessLister() if ProcessLister else None
    hash_calc = HashCalculator() if HashCalculator else None
    heuristic = HeuristicEngine()
    scorer = ScoringEngine()
    msg_gen = MessageGenerator()
    classifier = Classifier()

    # Collect processes
    processes = []
    if proc_lister:
        try:
            processes = proc_lister.list_processes()
        except Exception:
            processes = []
    else:
        # best-effort fallback using psutil if available
        try:
            import psutil

            procs = []
            for p in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline", "username", "ppid"]):
                info = p.info
                processes.append(info)
        except Exception:
            processes = []

    # Limit processes
    targets = processes[: args.limit]

    results = []

    for proc in targets:
        # normalize process information
        try:
            # If proc is a dataclass (ProcessInfo), convert to dict
            if is_dataclass(proc):
                pdict = asdict(proc)
            elif isinstance(proc, dict):
                pdict = proc
            else:
                # attempt attribute access
                pdict = {k: getattr(proc, k) for k in dir(proc) if not k.startswith("_")}
        except Exception:
            pdict = {"repr": str(proc)}

        pid = pdict.get("pid")
        name = pdict.get("name") or pdict.get("exe") or ""
        exe_path = pdict.get("exe") or pdict.get("exe_path") or None

        # Network
        network_list = []
        if NetworkAnalyzer and pid:
            try:
                na = NetworkAnalyzer(pid)
                conns = na.list_connections()
                network_list = _to_serializable(conns)
            except Exception:
                network_list = []

        # Hash of binary (best-effort)
        hash_result = None
        if hash_calc and exe_path:
            try:
                hash_result = hash_calc.compute_sha256(exe_path)
                hash_result = _to_serializable(hash_result)
            except Exception:
                hash_result = {"error": "hash failed"}

        # Signature inspection (Windows only)
        signature = None
        if sig_inspector and exe_path:
            try:
                signature = sig_inspector(exe_path)
                signature = _to_serializable(signature)
            except Exception:
                signature = {"error": "signature inspection failed"}

        # Build heuristic input expected keys
        process_data = {
            "pid": pid,
            "name": pdict.get("name") or "",
            "exe_path": exe_path or "",
            "cmdline": pdict.get("cmdline") or [],
            "user": pdict.get("username") or pdict.get("user") or "",
            "parent_name": None,
            "cpu_percent": 0,
            "memory_rss": 0,
            "network": network_list,
            "signature": signature,
            "integrity": None,
        }

        # try to enrich with parent name / cpu / mem using psutil
        try:
            import psutil
            proc_obj = None
            try:
                proc_obj = psutil.Process(pid)
            except Exception:
                proc_obj = None

            if proc_obj:
                try:
                    parent = proc_obj.parent()
                    process_data["parent_name"] = parent.name() if parent else None
                except Exception:
                    process_data["parent_name"] = None

                try:
                    process_data["cpu_percent"] = float(proc_obj.cpu_percent(interval=0.1))
                except Exception:
                    process_data["cpu_percent"] = 0

                try:
                    mem = proc_obj.memory_info().rss
                    process_data["memory_rss"] = int(mem)
                except Exception:
                    process_data["memory_rss"] = 0
        except Exception:
            pass

        # Run heuristic engine
        try:
            heuristic_output = heuristic.analyze(process_data)
        except Exception as e:
            heuristic_output = {"error": "heuristic failed", "detail": str(e)}

        # Score
        try:
            score_result = scorer.score_from_heuristic_output(heuristic_output) if isinstance(heuristic_output, dict) else scorer.score_from_triggers([])
            # allow serialization
            score_ser = _to_serializable(score_result)
        except Exception as e:
            score_ser = {"error": "scoring failed", "detail": str(e)}

        # Message generation
        try:
            if isinstance(score_result, object):
                message = msg_gen.generate(score_result)
                message_ser = _to_serializable(message)
            else:
                message_ser = None
        except Exception as e:
            message_ser = {"error": "message generation failed", "detail": str(e)}

        # Classification
        try:
            classification = classifier.classify(score_result)
            classification_ser = _to_serializable(classification)
        except Exception as e:
            classification_ser = {"error": "classification failed", "detail": str(e)}

        result = {
            "process": _to_serializable(pdict),
            "network": network_list,
            "hash": hash_result,
            "signature": signature,
            "heuristic": heuristic_output,
            "score": score_ser,
            "message": message_ser,
            "classification": classification_ser,
        }

        results.append(result)

        # Output streaming option
        if args.json_lines:
            print(json.dumps(_to_serializable(result), ensure_ascii=False))

    # Final output
    if not args.json_lines:
        print(json.dumps(_to_serializable(results), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
