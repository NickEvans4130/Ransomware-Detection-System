"""Backup system configuration and retention policies."""

import os
from pathlib import Path

# Default vault location (hidden directory)
DEFAULT_VAULT_PATH = os.path.join(
    os.path.expanduser("~"), ".ransomware_detection", "backup_vault"
)

# Retention: backups older than this are purged
RETENTION_HOURS = 48

# Permissions: owner-only read/write/execute on vault and snapshot dirs
VAULT_DIR_MODE = 0o700
VAULT_FILE_MODE = 0o600

# Timestamp format used for snapshot directory names
SNAPSHOT_DIR_FORMAT = "%Y-%m-%d_%H-%M-%S"
