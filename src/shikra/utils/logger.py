import logging
import sys
from typing import Optional

# To prevent duplicate handlers if setup_logger is called multiple times
loggers = {}

def setup_logger(name: str, log_file: Optional[str] = None, level=logging.INFO):
    """
    Set up a logger with file and console handlers.
    Avoids adding duplicate handlers to the same logger.
    """
    if loggers.get(name):
        return loggers.get(name)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Prevents propagation to the root logger, which might have its own handlers
    logger.propagate = False
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    
    # File handler if specified
    if log_file and not any(isinstance(h, logging.FileHandler) and h.baseFilename == log_file for h in logger.handlers):
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    
    loggers[name] = logger
    return logger
