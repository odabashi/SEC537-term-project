from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import logging
from scada.app.services.session import get_session, update_session
from services.monitoring import log_attack 

logger = logging.getLogger("SEC537_SCADA")


class SessionMonitorMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        session_id = request.cookies.get("session_id")

        if session_id:
            # extract client IP, prefer X-Forwarded-For if behind proxy
            xff = request.headers.get("x-forwarded-for")
            if xff:
                ip = xff.split(",")[0].strip()
            else:
                ip = request.client.host
            user_agent = request.headers.get("user-agent", "unknown")

            session = get_session(session_id)
            logger.info(f"Session Info: {session}")

            if session:
                if session["ip"] != ip or session["user_agent"] != user_agent:
                    # MONITORING: Log session hijack attempt
                    log_attack(
                        attack_type='SESSION_HIJACK',
                        target_url=str(request.url.path),
                        payload=f'Session hijack suspected',
                        source_ip=ip,
                        user_agent=user_agent,
                        success=True,
                        details={
                            'session_id': session_id,
                            'original_ip': session['ip'],
                            'current_ip': ip,
                            'original_user_agent': session['user_agent'],
                            'current_user_agent': user_agent,
                            'vulnerability': 'PREDICTABLE_SESSION_ID',
                            'user': session.get('user', 'unknown')
                        }
                    )
                    
                    logger.warning(
                        f"Session hijack suspected | "
                        f"Session ID: {session_id} | "
                        f"IP: {session['ip']} (Original) → {ip} (Current) | "
                        f"User-Agent: {session['user_agent']} (Original) → {user_agent} (Current) "
                    )
                update_session(session_id)

        response = await call_next(request)
        return response