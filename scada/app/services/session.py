from fastapi import Request, HTTPException, status
from datetime import datetime
import time
import logging


logger = logging.getLogger("SEC537_SCADA")

SESSIONS = {}


def generate_session_id():
    return f"session-{int(time.time())}"


def create_session(session_id: str, user: str, ip: str, user_agent: str):
    # VULNERABILITY: Predictable Session ID, Very weak session handling, no expiration, no signing.
    # In this example we use time-based session ID (But also sequential IDs could be used as they are not bound to User
    # or IP).
    SESSIONS[session_id] = {
        "user": user,
        "ip": ip,
        "user_agent": user_agent,
        "created_at": datetime.now(),
        "last_seen": datetime.now()
    }


def get_session(session_id: str):
    return SESSIONS.get(session_id)


def update_session(session_id: str):
    session = SESSIONS.get(session_id)
    if session:
        session["last_seen"] = datetime.now()
        return session
    return None


def require_user(request: Request):
    session_id = request.cookies.get("session_id")

    logger.warning("Session ID is not found. Try to Login!")
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is not found. Try to Login!"
        )
    session = get_session(session_id)

    logger.warning("Invalid Session ID is used. There is no session with such ID!")
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Session ID is used. There is no session with such ID!"
        )
    return session["user"]
