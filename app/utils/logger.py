import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs log records as JSON lines.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "filename": record.filename,
            "line_no": record.lineno,
        }
        
        # Merge extra fields if present
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict): # type: ignore
            log_data.update(record.extra_fields)
            
        # Exception handling
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_data)

def setup_logger(name: str = "firewall", log_file: str = "logs/firewall.json.log") -> logging.Logger:
    """
    Set up structured JSON logging for the application.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # Clean previous handlers
    if logger.hasHandlers():
        logger.handlers.clear()
        
    # Prevent propagation to root logger
    logger.propagate = False
    
    # Formatter
    formatter = JSONFormatter()
    
    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File Handler
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
        
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

# Shared logger instance
logger = setup_logger()
