#!/usr/bin/env python
import getopt
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, TypedDict

import typer
from structlog import get_logger
from structlog.stdlib import BoundLogger

from pytacs.config import read_config_file
from pytacs.plugins import load_plugins
from pytacs.structures.exceptions import ConfigurationError
from pytacs.structures.models.configuration import Configuration
from pytacs.util import configure_structlog, get_log_level_from_string


class Config(TypedDict):
    pidfile: Path
    configfile: Path
    configdir: Path
    kill: bool
    fork: bool


DEFAULT_CONFIG: Config = {
    "pidfile": Path("/var/run/pytacs.pid"),
    "configfile": Path("./etc/pytacs.json"),
    "configdir": Path("./etc/pytacs.d"),
    "kill": False,
    "fork": True,
}


optshort = "?hfesdqP:k"
optlong: List[str] = [
    "help",
    "forground",
    "stderr",
    "syslog",
    "debug",
    "quiet",
    "pidfile=",
    "kill",
]

app = typer.Typer()


@app.command()
def start_server(
    config_file_location: Path = DEFAULT_CONFIG["configfile"],
    pidfile: Path = DEFAULT_CONFIG["pidfile"],
    kill: bool = DEFAULT_CONFIG["kill"],
    fork: bool = DEFAULT_CONFIG["fork"],
):
    config: Configuration = read_config_file(config_file_location)
    log_level: int = get_log_level_from_string(str(config.options.log_level))
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    configure_structlog()
    logger: BoundLogger = get_logger("PyTacs")

    logger.info("Starting server")

    if pidfile.exists():
        pid = int(pidfile.read_text())
        if kill:
            # Force Kill
            try:
                os.kill(pid, 1)
                logger.info(f"Running copy (pid {pid}) killed")
                sys.exit(0)
            except Exception:
                logger.exception(f"Failed to stop PID {pid}")

        # Graceful kill
        os.kill(pid, 0)
        logger.error(f"Server already running as pid {pid}")
        sys.exit(1)

    if kill:
        # If kill is passed but PIDFile doesnt exist
        logger.error("No running server to kill")

    if fork:
        # Fork things out
        pid = os.fork()
        if pid:
            # Record the pid in the pid-file and then exit
            open(pidfile, "w").write(f"{pid}")
            sys.exit(0)
        # Close tty(s)
        si = open("/dev/null", "a+")
        os.dup2(si.fileno(), 0)
        os.dup2(si.fileno(), 1)
        os.dup2(si.fileno(), 2)
        si.close()

    # Load plugins from config file(s)
    loaded_plugins: Dict[str, Any] = load_plugins(config.modules, logger)

    logger.info(f"Loaded Plugins: {loaded_plugins}")


if __name__ == "__main__":
    app()
