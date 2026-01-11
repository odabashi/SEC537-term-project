from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import logging
from scada.app.services.session import get_session, update_session


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
                    # TODO: MONITORING - VULNERABILITY: PREDICTABLE SESSION ID, ATTACK: SESSION HIJACK
                    logger.warning(
                        f"Session hijack suspected | "
                        f"Session ID: {session_id} | "
                        f"IP: {session['ip']} (Original) → {ip} (Current) | "
                        f"User-Agent: {session['user_agent']} (Original) → {user_agent} (Current) "
                    )
                update_session(session_id)

        response = await call_next(request)
        return response
