"""
Monitoring Router for SCADA Honeypot
Provides endpoints for attack monitoring and statistics
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from services.monitoring import (
    get_all_attacks,
    get_attack_stats,
    clear_logs,
    get_recent_attacks,
    get_attacks_by_severity
)

router = APIRouter()


@router.get("/attacks")
def get_attacks():
    """
    Get all logged attacks
    Returns list of all attacks with details
    """
    attacks = get_all_attacks()
    return JSONResponse(content={
        'success': True,
        'total': len(attacks),
        'attacks': attacks
    })


@router.get("/stats")
def get_stats():
    """
    Get attack statistics
    Returns aggregated statistics by severity and type
    """
    stats = get_attack_stats()
    return JSONResponse(content={
        'success': True,
        'stats': stats
    })


@router.get("/recent")
def get_recent(limit: int = 10):
    """
    Get recent attacks
    Query param: limit (default 10)
    """
    attacks = get_recent_attacks(limit)
    return JSONResponse(content={
        'success': True,
        'total': len(attacks),
        'attacks': attacks
    })


@router.get("/severity/{severity}")
def get_by_severity(severity: str):
    """
    Get attacks by severity level
    Path param: severity (critical, high, medium, low)
    """
    attacks = get_attacks_by_severity(severity)
    return JSONResponse(content={
        'success': True,
        'severity': severity,
        'total': len(attacks),
        'attacks': attacks
    })


@router.post("/clear")
def clear_attack_logs():
    """
    Clear all attack logs
    Used for testing/demo purposes
    """
    clear_logs()
    return JSONResponse(content={
        'success': True,
        'message': 'Attack logs cleared'
    })