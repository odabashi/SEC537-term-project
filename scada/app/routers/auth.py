from fastapi import Request, APIRouter
from fastapi.responses import JSONResponse
import logging
from scada.app.models.schemas import LoginRequest
from scada.app.services.session import create_session, generate_session_id 
from services.monitoring import log_attack 


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
    # Extract client IP, prefer X-Forwarded-For if behind proxy
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = request.client.host
    
    user_agent = request.headers.get("user-agent", "unknown")
    
    # VULNERABILITY: Weak CAPTCHA: It is static, reusable, client-known and does NOT block automation
    if data.captcha_answer != WEAK_CAPTCHA_ANSWER:
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

    if ip not in login_attempts:
        login_attempts[ip] = 0

    # increment attempts for this IP
    login_attempts[ip] += 1

    # VULNERABILITY: No rate limiting
    # For monitoring purposes, log after 10 failed attempts
    if login_attempts[ip] > 10:
        # MONITORING: Log brute force attack
        log_attack(
            attack_type='BRUTE_FORCE',
            target_url='/auth/login',
            payload=f'Attempt #{login_attempts[ip]} - Username: {data.username}',
            source_ip=ip,
            user_agent=user_agent,
            success=False,
            details={
                'attempts': login_attempts[ip],
                'username': data.username,
                'vulnerability': 'NO_RATE_LIMIT'
            }
        )
        logger.warning(f"Brute force detected from {ip} (attempt #{login_attempts[ip]})")

    if login_attempts[ip] > 1000:
        # MONITORING: Log critical password leak
        log_attack(
            attack_type='PASSWORD_LEAK',
            target_url='/auth/login',
            payload=f'CRITICAL: Credentials leaked after {login_attempts[ip]} attempts',
            source_ip=ip,
            user_agent=user_agent,
            success=True,
            details={
                'leaked_credentials': {
                    'operator': 'operator123',
                    'admin': 'admin123',
                    'odabasi': 'king123',
                    'berkay': 'can123',
                    'sec537': 'boring'
                },
                'attempts': login_attempts[ip],
                'vulnerability': 'System exhaustion leads to credential disclosure'
            }
        )
        logger.critical(f"Password compromised via brute force from {ip}")

    # Check credentials
    if data.username in USERS and USERS[data.username] == data.password:
        # reset attempts on successful login
        login_attempts[ip] = 0
        
        # Generate predictable session ID
        session_id = generate_session_id()
        
        create_session(
            session_id=session_id,
            user=data.username,
            ip=ip,
            user_agent=user_agent
        )
        
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
        
        # MONITORING: Log predictable session ID
        log_attack(
            attack_type='PREDICTABLE_SESSION',
            target_url='/auth/login',
            payload=f'Predictable session ID generated: {session_id}',
            source_ip=ip,
            user_agent=user_agent,
            success=True,
            details={
                'username': data.username,
                'session_id': session_id,
                'vulnerability': 'Session ID can be predicted/hijacked',
                'session_pattern': 'Deterministic generation'
            }
        )
        
        logger.info(f"User logged in: {data.username}")
        resp = JSONResponse(content={"session_id": session_id})
        resp.set_cookie("session_id", session_id, httponly=True)
        return resp

    logger.warning(f"Failed login for {data.username}")
    return {"error": "Invalid credentials"}