from fastapi import Request, APIRouter
from fastapi.responses import JSONResponse
import logging
from ..models.schemas import LoginRequest
from ..services.session import create_session, generate_session_id


logger = logging.getLogger("SEC537_SCADA")
router = APIRouter()


# VULNERABILITY: Hardcoded credentials
USERS = {
    "operator": "operator123",
    "admin": "admin123",
    "odabasi": "king123",
    "berkay": "can123",
    "sec537": "boring"
}

# Login attempts counter (no real rate limiting)
login_attempts = {}

# For CAPTCHA (We are asking what is 2 + 3 =?)
WEAK_CAPTCHA_ANSWER = "5"  # static, predictable


@router.post("/login")
def login(data: LoginRequest, request: Request):
    # VULNERABILITY: Weak CAPTCHA: It is static, reusable, client-known and does NOT block automation
    if data.captcha != WEAK_CAPTCHA_ANSWER:
        logger.warning("Invalid CAPTCHA attempt")
        return {"error": "Invalid CAPTCHA"}

    # extract client IP, prefer X-Forwarded-For if behind proxy
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = request.client.host
    if ip not in login_attempts:
        login_attempts[ip] = 0

    # increment attempts for this IP
    login_attempts[ip] += 1

    # VULNERABILITY: No rate limiting
    # For monitoring purposes, log after 10 failed attempts
    if login_attempts[ip] > 10:
        # TODO: MONITORING - VULNERABILITY: NO RATE LIMIT, ATTACK: BRUTE-FORCE
        logger.warning(f"Brute force detected from {ip} (attempt #{login_attempts[ip]})")

    if login_attempts[ip] > 1000:
        # TODO: MONITORING - VULNERABILITY: PASSWORD LEAK, ATTACK: BRUTE-FORCE
        logger.critical(f"Password compromised via brute force from {ip}")

    # TODO: MONITORING - VULNERABILITY: WEAK PASSWORD, ATTACK: CREDENTIAL LEAK
    if data.username in USERS and USERS[data.username] == data.password:
        # reset attempts on successful login
        # TODO: MONITORING - VULNERABILITY: NO/WEAK CAPTCHA
        login_attempts[ip] = 0
        # TODO: MONITORING - VULNERABILITY: PREDICTABLE SESSION ID, ATTACK: SESSION HIJACK
        session_id = generate_session_id()
        create_session(
            session_id=session_id,
            user=data.username,
            ip=ip,
            user_agent=request.headers.get("user-agent", "unknown")
        )
        logger.info(f"User logged in: {data.username}")
        resp = JSONResponse(content={"session_id": session_id})
        resp.set_cookie("session_id", session_id, httponly=True)
        return resp

    logger.warning(f"Failed login for {data.username}")
    return {"error": "Invalid credentials"}
