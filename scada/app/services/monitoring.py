"""
Monitoring Service for SCADA Honeypot
Tracks and logs all security attacks and vulnerabilities
Adapted from Flask version to FastAPI
"""

from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger("SEC537_SCADA")

# In-memory attack log storage
attack_log: List[Dict] = []
MAX_LOG_SIZE = 1000  # Prevent memory overflow

# Attack severity classification
ATTACK_SEVERITY = {
    'BRUTE_FORCE': 'medium',
    'CREDENTIAL_LEAK': 'critical',
    'PASSWORD_LEAK': 'critical',
    'WEAK_PASSWORD': 'high',
    'WEAK_CAPTCHA': 'medium',
    'NO_RATE_LIMIT': 'high',
    'SESSION_HIJACK': 'critical',
    'PREDICTABLE_SESSION': 'high',
    'PATH_TRAVERSAL': 'critical',
    'SSRF': 'critical',
    'CMD_INJECTION': 'critical',
    'UNSAFE_DEVICE_ADD': 'medium',
    'PATH_INJECTION': 'high',
    'MODBUS_UNAUTHORIZED': 'critical'
}


def log_attack(
    attack_type: str,
    target_url: str,
    payload: str,
    source_ip: str,
    user_agent: str = "Unknown",
    success: bool = True,
    details: Optional[Dict] = None
) -> Dict:
    """
    Log an attack to the monitoring system
    
    Args:
        attack_type: Type of attack (e.g., 'BRUTE_FORCE', 'SSRF')
        target_url: Target endpoint/URL
        payload: Attack payload/content
        source_ip: Attacker's IP address
        user_agent: User agent string
        success: Whether the attack was successful
        details: Additional attack details
    
    Returns:
        Dict containing the logged attack data
    """
    attack_data = {
        'id': len(attack_log) + 1,
        'timestamp': datetime.now().isoformat(),
        'type': attack_type,
        'severity': ATTACK_SEVERITY.get(attack_type, 'medium'),
        'source_ip': source_ip,
        'target_url': target_url,
        'payload': str(payload)[:500],  # Limit payload size
        'success': success,
        'details': details or {},
        'user_agent': user_agent
    }
    
    # Add to in-memory log
    attack_log.insert(0, attack_data)  # Most recent first
    
    # Prevent memory overflow
    if len(attack_log) > MAX_LOG_SIZE:
        attack_log.pop()
    
    # Log to file
    logger.warning(
        f"[{attack_type}] {target_url} | "
        f"Payload: {str(payload)[:50]}... | "
        f"Source: {source_ip} | "
        f"Success: {success}"
    )
    
    return attack_data


def get_all_attacks() -> List[Dict]:
    """Get all logged attacks"""
    return attack_log


def get_attack_stats() -> Dict:
    """Get attack statistics"""
    stats = {
        'total': len(attack_log),
        'by_severity': {
            'critical': sum(1 for a in attack_log if a['severity'] == 'critical'),
            'high': sum(1 for a in attack_log if a['severity'] == 'high'),
            'medium': sum(1 for a in attack_log if a['severity'] == 'medium'),
            'low': sum(1 for a in attack_log if a['severity'] == 'low')
        },
        'by_type': {}
    }
    
    # Count by attack type
    for attack in attack_log:
        attack_type = attack['type']
        stats['by_type'][attack_type] = stats['by_type'].get(attack_type, 0) + 1
    
    return stats


def clear_logs():
    """Clear all attack logs (for testing/demo purposes)"""
    global attack_log
    attack_log = []
    logger.info("Attack logs cleared")


def get_recent_attacks(limit: int = 10) -> List[Dict]:
    """Get most recent attacks"""
    return attack_log[:limit]


def get_attacks_by_severity(severity: str) -> List[Dict]:
    """Get attacks filtered by severity"""
    return [a for a in attack_log if a['severity'] == severity]


def get_attacks_by_ip(ip: str) -> List[Dict]:
    """Get all attacks from a specific IP"""
    return [a for a in attack_log if a['source_ip'] == ip]