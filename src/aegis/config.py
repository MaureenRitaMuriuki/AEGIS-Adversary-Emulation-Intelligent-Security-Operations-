"""Application configuration with conservative local defaults."""
import os
from pathlib import Path

DB_PATH = Path(os.getenv("AEGIS_DB_PATH", "data/aegis.db"))
APP_NAME = "AEGIS"
APP_VERSION = "0.1.0"
