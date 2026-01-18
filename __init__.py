# kimura/__init__.py - Expose public API
from .session.worker import PQCWorker as worker
from .session.master import PQCMaster as master  
from .session.manager import SessionManager

__version__ = "0.1.0"
__all__ = ["worker", "master", "SessionManager"]
