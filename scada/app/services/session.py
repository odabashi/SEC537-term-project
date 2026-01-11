import time
from starlette.requests import Request


def create_session(request: Request, username: str) -> str:
    # Use Starlette/FastAPI cookie-backed sessions (SessionMiddleware) instead of in-memory dict (sessions = {}).
    # VULNERABILITY: Predictable Session ID, Very weak session handling, no expiration, no signing.
    # In this example we use time-based session ID (But also sequential IDs could be used as they are not bound to User
    # or IP).
    session_id = f"session-{int(time.time())}"
    request.session['session_id'] = session_id
    request.session['username'] = username
    return session_id


def require_session(request: Request):
    # TODO: MONITORING - VULNERABILITY: PREDICTABLE SESSION ID, ATTACK: SESSION HIJACK
    session_id = request.headers.get("X-Session-ID")
    if not session_id:
        return None
    if request.session.get("session_id") == session_id:
        return request.session.get("username")
    return None



