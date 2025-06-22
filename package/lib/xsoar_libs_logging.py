#!/usr/bin/env python
# coding=utf-8

__author__ = "TrackMe Limited"
__copyright__ = "Copyright 2023-2025, TrackMe Limited, U.K."
__credits__ = "TrackMe Limited, U.K."
__license__ = "TrackMe Limited, all rights reserved"
__version__ = "0.1.0"
__maintainer__ = "TrackMe Limited, U.K."
__email__ = "support@trackme-solutions.com"
__status__ = "PRODUCTION"

# Standard library imports
import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# append lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-trackme-xsoar", "lib"))


def setup_logger(
    name: str, logfile: str, level=logging.INFO, redirect_root: bool = False
) -> logging.Logger:
    """
    Set up a dedicated logger.

    :param name: Unique name for the logger (e.g. 'myapp.rest.config')
    :param logfile: Name of the log file (relative to $SPLUNK_HOME/var/log/splunk)
    :param level: Logging level, defaults to logging.INFO
    :param redirect_root: If True, attach the same handler to the root logger (not recommended for shared apps)
    :return: Configured logger instance
    """

    splunkhome = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    log_path = os.path.join(splunkhome, "var", "log", "splunk", logfile)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False  # Prevent bubbling

    # Check if this handler is already attached
    if not any(
        isinstance(h, RotatingFileHandler)
        and getattr(h, "baseFilename", None) == log_path
        for h in logger.handlers
    ):
        handler = RotatingFileHandler(
            log_path, mode="a", maxBytes=10 * 1024 * 1024, backupCount=1
        )
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(filename)s %(funcName)s %(lineno)d %(message)s"
        )
        logging.Formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Optional: redirect root logger
        if redirect_root:
            root_logger = logging.getLogger()
            root_logger.setLevel(level)
            root_logger.propagate = False
            if not any(
                isinstance(h, RotatingFileHandler)
                and getattr(h, "baseFilename", None) == log_path
                for h in root_logger.handlers
            ):
                root_logger.addHandler(handler)

    return logger
