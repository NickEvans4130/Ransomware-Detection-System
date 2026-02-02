"""API route handlers for the dashboard.

Implements the exact endpoints from the Phase 6 docs:

    GET  /api/status          - Current system status
    GET  /api/events          - Recent file events (paginated)
    GET  /api/threats         - Threat history
    POST /api/quarantine      - Manual quarantine process
    GET  /api/backups         - List available backups
    POST /api/restore         - Restore files
    GET  /api/config          - Get configuration
    PUT  /api/config          - Update configuration
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

api = Blueprint("api", __name__, url_prefix="/api")

# These are set by app.py at init time via init_routes()
_event_logger = None
_backup_manager = None
_response_engine = None
_behavior_analyzer = None
_config = None
_config_path = None
_ws_handler = None


def init_routes(
    event_logger,
    backup_manager,
    response_engine,
    behavior_analyzer,
    config: dict,
    config_path: str,
    ws_handler,
):
    """Wire up shared application state into the route handlers."""
    global _event_logger, _backup_manager, _response_engine
    global _behavior_analyzer, _config, _config_path, _ws_handler
    _event_logger = event_logger
    _backup_manager = backup_manager
    _response_engine = response_engine
    _behavior_analyzer = behavior_analyzer
    _config = config
    _config_path = config_path
    _ws_handler = ws_handler


# ------------------------------------------------------------------
# GET /api/status
# ------------------------------------------------------------------

@api.route("/status", methods=["GET"])
def get_status():
    """Current system status: health, threat level, monitored processes."""
    scores = {}
    threat_level = "NORMAL"
    if _behavior_analyzer:
        scores = {
            str(pid): {
                "score": ts.score,
                "level": ts.level,
                "process_name": ts.process_name,
            }
            for pid, ts in _behavior_analyzer.get_all_scores().items()
        }
        crits = _behavior_analyzer.get_critical_processes()
        if crits:
            threat_level = "CRITICAL"
        elif any(s["level"] in ("LIKELY", "SUSPICIOUS") for s in scores.values()):
            threat_level = "ELEVATED"

    ws_clients = _ws_handler.client_count if _ws_handler else 0

    return jsonify({
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "threat_level": threat_level,
        "active_processes": scores,
        "websocket_clients": ws_clients,
    })


# ------------------------------------------------------------------
# GET /api/events
# ------------------------------------------------------------------

@api.route("/events", methods=["GET"])
def get_events():
    """Recent file events, paginated."""
    event_type = request.args.get("type")
    since = request.args.get("since")
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)

    if not _event_logger:
        return jsonify({"events": [], "total": 0})

    try:
        events = _event_logger.get_events(
            event_type=event_type,
            since=since,
            limit=limit + offset,
        )
    except Exception as exc:
        logger.exception("Database error fetching events")
        return jsonify({"error": f"Database error: {exc}"}), 500

    paginated = events[offset: offset + limit]
    return jsonify({
        "events": paginated,
        "total": len(events),
        "limit": limit,
        "offset": offset,
    })


# ------------------------------------------------------------------
# GET /api/threats
# ------------------------------------------------------------------

@api.route("/threats", methods=["GET"])
def get_threats():
    """Threat history from the response engine log."""
    severity = request.args.get("severity")
    since = request.args.get("since")
    limit = request.args.get("limit", 50, type=int)

    threats = []
    if _response_engine:
        for r in reversed(_response_engine.response_log):
            if r.escalation_level == 0:
                continue
            entry = {
                "timestamp": r.timestamp,
                "process_id": r.threat_score.process_id,
                "process_name": r.threat_score.process_name,
                "score": r.threat_score.score,
                "level": r.threat_score.level,
                "escalation_level": r.escalation_level,
                "actions_taken": r.actions_taken,
                "triggered_indicators": r.threat_score.triggered_indicators,
            }
            if r.incident_report:
                entry["incident_report"] = r.incident_report.to_dict()

            if severity and str(r.escalation_level) != severity:
                continue
            if since and r.timestamp < since:
                continue
            threats.append(entry)
            if len(threats) >= limit:
                break

    return jsonify({"threats": threats, "total": len(threats)})


# ------------------------------------------------------------------
# POST /api/quarantine
# ------------------------------------------------------------------

@api.route("/quarantine", methods=["POST"])
def quarantine_process():
    """Manually quarantine (suspend) a process by PID."""
    data = request.get_json(silent=True) or {}
    pid = data.get("pid")
    if pid is None:
        return jsonify({"error": "pid is required"}), 400

    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return jsonify({"error": "pid must be an integer"}), 400

    if not _response_engine:
        return jsonify({"error": "Response engine not available"}), 503

    action = _response_engine.process_ctrl.suspend(pid)

    if _ws_handler:
        _ws_handler.broadcast("quarantine", {
            "pid": pid,
            "success": action.success,
            "error": action.error,
        })

    return jsonify({
        "pid": pid,
        "action": "suspend",
        "success": action.success,
        "error": action.error,
    }), 200 if action.success else 500


# ------------------------------------------------------------------
# GET /api/backups
# ------------------------------------------------------------------

@api.route("/backups", methods=["GET"])
def get_backups():
    """List available backups with optional filters."""
    original_path = request.args.get("path")
    process_name = request.args.get("process")
    since = request.args.get("since")
    limit = request.args.get("limit", 50, type=int)

    if not _backup_manager:
        return jsonify({"backups": [], "total": 0})

    try:
        backups = _backup_manager.snapshot.get_backups(
            original_path=original_path,
            process_name=process_name,
            since=since,
            limit=limit,
        )
    except Exception as exc:
        logger.exception("Database error fetching backups")
        return jsonify({"error": f"Database error: {exc}"}), 500

    return jsonify({"backups": backups, "total": len(backups)})


# ------------------------------------------------------------------
# POST /api/restore
# ------------------------------------------------------------------

@api.route("/restore", methods=["POST"])
def restore_files():
    """Restore files from backup.

    Accepts either:
        {"backup_id": int}           - restore single file
        {"backup_ids": [int, ...]}   - batch restore
        {"process_name": str}        - restore all for a process
    """
    data = request.get_json(silent=True) or {}

    if not _backup_manager:
        return jsonify({"error": "Backup manager not available"}), 503

    results = []

    try:
        if "backup_id" in data:
            try:
                bid = int(data["backup_id"])
            except (TypeError, ValueError):
                return jsonify({"error": "backup_id must be an integer"}), 400
            r = _backup_manager.recovery.restore_file(bid)
            results = [_restore_to_dict(r)]

        elif "backup_ids" in data:
            if not isinstance(data["backup_ids"], list):
                return jsonify({"error": "backup_ids must be a list"}), 400
            for bid in data["backup_ids"]:
                try:
                    bid = int(bid)
                except (TypeError, ValueError):
                    return jsonify({"error": f"Invalid backup_id: {bid}"}), 400
                r = _backup_manager.recovery.restore_file(bid)
                results.append(_restore_to_dict(r))

        elif "process_name" in data:
            rs = _backup_manager.recovery.restore_by_process(data["process_name"])
            results = [_restore_to_dict(r) for r in rs]

        else:
            return jsonify({"error": "Provide backup_id, backup_ids, or process_name"}), 400

    except Exception as exc:
        logger.exception("Error during file restore")
        return jsonify({"error": f"Restore failed: {exc}"}), 500

    if _ws_handler:
        _ws_handler.broadcast("restore", {"results": results})

    succeeded = sum(1 for r in results if r["success"])
    return jsonify({
        "results": results,
        "total": len(results),
        "succeeded": succeeded,
    })


def _restore_to_dict(r) -> dict:
    return {
        "original_path": r.original_path,
        "backup_path": r.backup_path,
        "success": r.success,
        "integrity_ok": r.integrity_ok,
        "error": r.error,
    }


# ------------------------------------------------------------------
# GET /api/config
# ------------------------------------------------------------------

@api.route("/config", methods=["GET"])
def get_config():
    """Return current configuration."""
    return jsonify(_config or {})


# ------------------------------------------------------------------
# PUT /api/config
# ------------------------------------------------------------------

@api.route("/config", methods=["PUT"])
def update_config():
    """Update configuration. Merges provided keys into existing config."""
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "No data provided"}), 400

    if _config is None:
        return jsonify({"error": "Configuration not loaded"}), 503

    _deep_merge(_config, data)

    # Persist to disk
    if _config_path:
        try:
            Path(_config_path).write_text(json.dumps(_config, indent=4))
        except OSError as exc:
            return jsonify({"error": f"Failed to save: {exc}"}), 500

    if _ws_handler:
        _ws_handler.broadcast("config_updated", _config)

    return jsonify(_config)


def _deep_merge(base: dict, override: dict):
    """Recursively merge override into base in-place."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
