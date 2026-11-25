"""REST API v1 — automation-friendly JSON endpoints + OpenAPI spec."""

from __future__ import annotations

import csv
import io

from flask import Blueprint, jsonify, request

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


def _store():
    from flask import current_app

    return current_app.extensions["wicrack_store"]


def _mgr():
    from flask import current_app

    return current_app.extensions["wicrack_manager"]


# ------------------------------------------------------------------ status
@api_bp.get("/status")
def status():
    """Live worker status snapshot (also used by the dashboard JS)."""
    return jsonify(_mgr().snapshot())


# ------------------------------------------------------------------- jobs
@api_bp.route("/jobs", methods=["GET", "POST"])
def jobs():
    """GET: recent runs + queue info. POST: {"action": "start"|"stop"}."""
    if request.method == "GET":
        return jsonify(
            {
                "snapshot": _mgr().snapshot(),
                "runs": [dict(r) for r in _store().recent_runs(25)],
            }
        )
    action = (request.get_json(silent=True) or {}).get("action", "")
    if action == "start":
        from wicrack.capture.parser import list_capture_files

        files = list_capture_files(_mgr().settings.uploads_dir)
        if not files:
            return jsonify({"ok": False, "error": "no captures uploaded"}), 400
        _mgr().resume()
        count = _mgr().submit(files)
        return jsonify({"ok": True, "queued": count})
    if action == "stop":
        _mgr().stop()
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "action must be start|stop"}), 400


# ----------------------------------------------------------------- results
@api_bp.get("/results")
def results():
    """All cracked credentials recorded so far."""
    return jsonify({"results": [dict(r) for r in _store().all_results()]})


@api_bp.get("/results.csv")
def results_csv():
    """Results as CSV (automation export)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["time", "essid", "bssid", "mode", "key", "key_len", "has_space", "only_digits", "stage"]
    )
    for r in _store().all_results():
        writer.writerow(
            [
                r["ts"],
                r["essid"],
                r["bssid"],
                r["mode"],
                r["key"],
                r["key_len"],
                r["has_space"],
                r["only_digits"],
                r["stage"],
            ]
        )
    return jsonify({"csv": buffer.getvalue()})
