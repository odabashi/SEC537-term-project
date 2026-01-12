from fastapi import Depends, APIRouter
import os
import logging
import re
from scada.app.models.schemas import DiagnosticRequest
from scada.app.services.session import require_session


logger = logging.getLogger("SEC537_SCADA")

COMMAND_INJECTION_PATTERNS = [
    r";",
    r"&&",
    r"\|\|",
    r"\|",
    r"\$\(",
    r"`",
]

router = APIRouter()


@router.post("/ping")
def ping(data: DiagnosticRequest, session: str = Depends(require_session)):
    """
    System will execute ping command by sending 4 packets to the host to check if the host is up.

    VULNERABILITY: Command injection.
    """
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, data.host):
            # TODO: MONITORING - COMMAND INJECTION
            logger.critical("Command Injection attempt!!!")

    cmd = f"ping -c 1 {data.host}"
    os.system(cmd)
    return {"executed": cmd}


@router.post("/traceroute")
def traceroute(data: DiagnosticRequest, session: str = Depends(require_session)):
    """
    System will execute traceroute command to the host and show every single "hop" (router) the data passes through
    along the way.

    VULNERABILITY: Command injection.
    """
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, data.host):
            # TODO: MONITORING - COMMAND INJECTION
            logger.critical("Command Injection attempt!!!")
    cmd = f"traceroute {data.host}"
    os.system(cmd)
    return {"executed": cmd}
