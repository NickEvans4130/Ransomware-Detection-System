"""Flask application for the ransomware detection dashboard.

Serves the REST API and WebSocket endpoint:

    GET  /api/status
    GET  /api/events
    GET  /api/threats
    POST /api/quarantine
    GET  /api/backups
    POST /api/restore
    GET  /api/config
    PUT  /api/config
    WS   /ws/live
"""

import json
import logging
import os
from pathlib import Path

from flask import Flask
from flask_sock import Sock

from src.dashboard.api.routes import api, init_routes
from src.dashboard.websocket_handler import WebSocketHandler
from src.database.event_logger import EventLogger
from src.response.backup_manager import BackupManager
from src.response.response_engine import ResponseEngine
from src.analysis.behavior_analyzer import BehaviorAnalyzer

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = str(PROJECT_ROOT / "config" / "config.json")


def create_app(
    config_path: str = None,
    event_logger: EventLogger = None,
    backup_manager: BackupManager = None,
    response_engine: ResponseEngine = None,
    behavior_analyzer: BehaviorAnalyzer = None,
) -> Flask:
    """Application factory.

    Accepts pre-built service instances (for testing) or constructs
    defaults from config.
    """
    cfg_path = config_path or DEFAULT_CONFIG_PATH
    config = {}
    if os.path.isfile(cfg_path):
        with open(cfg_path) as f:
            config = json.load(f)

    # Defaults for services not provided
    if event_logger is None:
        db_path = config.get("database", {}).get("path", "data/events.db")
        event_logger = EventLogger(db_path)

    if backup_manager is None:
        vault = config.get("backup", {}).get("vault_path")
        backup_manager = BackupManager(vault_path=vault)

    if response_engine is None:
        response_engine = ResponseEngine(
            backup_manager=backup_manager,
            safe_mode=config.get("response", {}).get("safe_mode", False),
            enable_desktop_alerts=False,
        )

    ws_handler = WebSocketHandler()

    # Build Flask app
    app = Flask(__name__)
    sock = Sock(app)

    # Wire routes
    init_routes(
        event_logger=event_logger,
        backup_manager=backup_manager,
        response_engine=response_engine,
        behavior_analyzer=behavior_analyzer,
        config=config,
        config_path=cfg_path,
        ws_handler=ws_handler,
    )
    app.register_blueprint(api)

    # WebSocket: /ws/live
    @sock.route("/ws/live")
    def ws_live(ws):
        ws_handler.register(ws)
        try:
            while True:
                # Keep connection alive; client can send pings
                data = ws.receive(timeout=60)
                if data is None:
                    break
        except Exception:
            pass
        finally:
            ws_handler.unregister(ws)

    # Store references for test access
    app.event_logger = event_logger
    app.backup_manager = backup_manager
    app.response_engine = response_engine
    app.behavior_analyzer = behavior_analyzer
    app.ws_handler = ws_handler

    return app
