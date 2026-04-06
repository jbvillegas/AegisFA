import logging
import os
import structlog

def setup_logging(service_name: str = "ingestion") -> None:
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    logging.basicConfig(
        level=log_level,
        format = "%(message)s",
    )

    structlog.configure(
        processors = [
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],

        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),

        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, log_level, logging.INFO)),
        cache_logger_on_first_use=True,
    )