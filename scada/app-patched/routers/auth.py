from fastapi import Request, APIRouter, HTTPException
from fastapi.responses import JSONResponse
import logging
import secrets
import time
from models.schemas import LoginRequest
from services.session import create_session, generate_session_id, get_session
from services.monitoring import log_attack


logger = logging.getLogger("SEC537_SCADA_Patched")


router = APIRouter(tags=["Authentication Handlers"])


# VULNERABILITY: Hardcoded credentials
USERS = {
    "operator": "operator123",
    "admin": "admin123",
    "odabasi": "king123",
    "berkay": "can123",
    "sec537": "boring"
}

# PATCHED: RATE LIMITING
login_attempts_per_ip = {}
login_attempts_per_username = {}
MAX_ATTEMPTS = 10
BLOCK_TIME = 300


def is_account_blocked(username: str):
    entry = login_attempts_per_username.get(username)
    if not entry:
        return False

    if entry.get("last_attempt") and time.time() - entry["last_attempt"] < BLOCK_TIME:
        return True

    # Auto-unblock after time passes
    if entry.get("last_attempt") and time.time() - entry["last_attempt"] >= BLOCK_TIME:
        login_attempts_per_username[username] = {"count": 0, "last_attempt": None}

    return False


# PATCHED: STRONG CAPTCHA
CAPTCHA_STORE = {}


@router.get("/captcha")
def get_captcha(username: str):
    first_term = secrets.randbelow(10)
    second_term = secrets.randbelow(10)
    total = first_term + second_term
    CAPTCHA_STORE[username] = {"1": first_term, "2": second_term, "total": str(total)}
    return {"Captcha": f"{first_term} + {second_term}"}


@router.post("/login")
def login(data: LoginRequest, request: Request):
    # Extract client IP, prefer X-Forwarded-For if behind proxy
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = request.client.host
    
    user_agent = request.headers.get("user-agent", "unknown")

    # PREVIOUS VULNERABILITY: Brute Force No rate limiting
    # PATCHED: Account Locking
    if is_account_blocked(data.username):
        log_attack(
            attack_type='BRUTE_FORCE',
            target_url='/auth/login',
            payload=f'Blocked login attempt for locked account: {data.username}',
            source_ip=ip,
            user_agent=user_agent,
            success=False,
            details={
                'username': data.username,
                'remaining_block_time': BLOCK_TIME - int(time.time() -
                                                         login_attempts_per_username[data.username]["last_attempt"]),
                'policy': f'{MAX_ATTEMPTS} attempts / {BLOCK_TIME}s',
                "detail": "Account temporarily locked due to multiple failed login attempts"
            }
        )
        raise HTTPException(
            status_code=403,
            detail="Account temporarily locked due to multiple failed login attempts"
        )
    else:
        login_attempts_per_username[data.username] = {"count": 1, "last_attempt": time.time()}

    # PREVIOUS VULNERABILITY: Weak CAPTCHA (2+3 = 5): It is static, reusable, client-known and does NOT block automation
    # PATCHING: Strong Random CAPTCHA
    if data.captcha_answer != CAPTCHA_STORE.get(data.username):
        logger.warning("Invalid CAPTCHA attempt")
        
        # MONITORING: Log weak CAPTCHA attempt
        log_attack(
            attack_type='WEAK_CAPTCHA',
            target_url='/auth/login',
            payload=f'Invalid CAPTCHA: {data.captcha_answer}',
            source_ip=ip,
            user_agent=user_agent,
            success=False,
            details={'username': data.username, 'captcha_attempt': data.captcha_answer}
        )
        return {"error": "Invalid CAPTCHA"}

    if ip not in login_attempts_per_ip:
        login_attempts_per_ip[ip] = {
            "count": 0,
            "last_attempt": None
        }

    # PREVIOUS VULNERABILITY: No rate limiting
    # PATCHING: Rate Limiting by IP
    # Before Incrementing, check if the IP has exceeded the maximum attempts
    if login_attempts_per_ip[ip]["count"] >= MAX_ATTEMPTS:
        if time.time() - login_attempts_per_ip[ip]["last_attempt"] < BLOCK_TIME:
            log_attack(
                attack_type='BRUTE_FORCE',
                target_url='/auth/login',
                payload=f'Attempt #{login_attempts_per_ip[ip]['count']} - Username: {data.username}',
                source_ip=ip,
                user_agent=user_agent,
                success=False,
                details={
                    'attempts': login_attempts_per_ip[ip]['count'],
                    'username': data.username
                }
            )
            logger.warning(f"Brute force detected from {ip} (attempt #{login_attempts_per_ip[ip]['count']})")
            raise HTTPException(status_code=429, detail="Too many attempts")
        else:
            login_attempts_per_ip[ip]["count"] = 1
            login_attempts_per_ip[ip]["last_attempt"] = time.time()
    else:
        login_attempts_per_ip[ip]["count"] += 1
        login_attempts_per_ip[ip]["last_attempt"] = time.time()

    # Check credentials
    if data.username in USERS and USERS[data.username] == data.password:
        # reset attempts on successful login
        login_attempts_per_ip[ip] = {"count": 0, "last_attempt": None}
        login_attempts_per_username[data.username] = {"count": 0, "last_attempt": None}
        
        # Generate predictable session ID
        session_id = generate_session_id()
        
        create_session(
            session_id=session_id,
            user=data.username,
            ip=ip,
            user_agent=user_agent
        )

        logger.info(f"Session Info: {get_session(session_id)}")
        
        # MONITORING: Log successful login with weak credentials
        log_attack(
            attack_type='WEAK_PASSWORD',
            target_url='/auth/login',
            payload=f'Successful login with weak credentials',
            source_ip=ip,
            user_agent=user_agent,
            success=True,
            details={
                'username': data.username,
                'password_strength': 'weak',
                'vulnerability': 'WEAK_PASSWORD',
                'session_id': session_id
            }
        )

        logger.info(f"User logged in: {data.username}")
        resp = JSONResponse(content={"session_id": session_id})
        resp.set_cookie("session_id", session_id, httponly=True)
        return resp

    logger.warning(f"Failed login for {data.username}")
    return {"error": "Invalid credentials"}
