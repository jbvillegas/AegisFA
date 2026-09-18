"""HTTP routes for the ingestion service."""

import sys
import types

from flask import Blueprint

from .. import supabase_client as _supabase_client

main = Blueprint("main", __name__)
import structlog
logger = structlog.get_logger(__name__)

supabase_client = _supabase_client


class _RoutesModule(types.ModuleType):
    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if name == "supabase_client":
            for module_name in (
                "constants", "utils", "auth", "health", "ingest",
                "analysis", "analysis_jobs", "upload_sessions", "rf_models",
                "incidents", "tasks", "feedback",
            ):
                module = sys.modules.get(f"{__name__}.{module_name}")
                if module is not None:
                    setattr(module, name, value)


sys.modules[__name__].__class__ = _RoutesModule

from . import utils
from . import auth
from ..timeline_routes import register_timeline_routes

register_timeline_routes(
    main,
    request_logger=utils._request_logger,
    require_roles=utils._require_roles,
    is_uuid=utils._is_uuid,
    error_response=utils._error_response,
    enforce_file_scope=utils._enforce_file_scope,
    enforce_org_scope=utils._enforce_org_scope,
    get_request_id=utils._get_request_id,
)

from . import analysis, analysis_jobs, feedback, health, incidents, ingest
from . import rf_models, tasks, upload_sessions

__all__ = ["main"]
