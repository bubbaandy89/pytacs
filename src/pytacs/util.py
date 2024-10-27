import logging

import structlog


def get_log_level_from_string(loglevel: str) -> int:
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: %s" % loglevel)

    return numeric_level


def configure_structlog() -> None:
    structlog.configure_once(
        # Don't mess up the order of this!
        # Note this https://www.structlog.org/en/stable/standard-library.html
        # On the structlog side, the processor chain must be configured to end with
        # structlog.stdlib.ProcessorFormatter.wrap_for_formatter as the renderer.
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
