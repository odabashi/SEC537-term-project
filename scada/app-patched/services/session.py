from fastapi import Request, HTTPException, status
import time
import secrets
import logging


logger = logging.getLogger("SEC537_SCADA")

SESSIONS = {}
# PATCHED: Session Expiration added
SESSION_TTL = 1800  # 30 minutes


def generate_session_id():
    # PREVIOUS VULNERABILITY: Predictable Session ID
    # return f"session-{int(time.time())}"
    # PATCHED: Strong unpredictable Session ID
    return secrets.token_urlsafe(32)


def create_session(session_id: str, user: str, ip: str, user_agent: str):
    # PREVIOUS VULNERABILITY: Predictable Session ID, Very weak session handling, no expiration.
    # In this example we use time-based session ID (But also sequential IDs could be used as they are not bound to User
    # or IP).
    # PATCHED: Strong Session ID, Session Expiration added
    SESSIONS[session_id] = {
        "user": user,
        "ip": ip,
        "user_agent": user_agent,
        "created_at": time.time(),
        "last_seen": time.time()
    }


def get_session(session_id: str):
    # PREVIOUS VULNERABILITY: No session expiration
    # PATCHED: Session Expiration added
    session = SESSIONS.get(session_id)
    if time.time() - session["created_at"] > SESSION_TTL:
        del SESSIONS[session_id]
        return None
    return session


def update_session(session_id: str):
    session = SESSIONS.get(session_id)
    if session:
        session["last_seen"] = time.time()
        return session
    return None


def require_session(request: Request):
    session_id = request.cookies.get("session_id")

    if not session_id:
        logger.warning("Session ID is not found. Try to Login!")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is not found. Try to Login!"
        )
    session = get_session(session_id)

    if not session:
        logger.warning("Invalid Session ID is used. There is no session with such ID! Try to Login!")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Session ID is used. There is no session with such ID! Try to Login!"
        )
    return session
