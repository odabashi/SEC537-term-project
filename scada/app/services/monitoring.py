"""
Monitoring Service for SCADA Honeypot
Tracks and logs all security attacks and vulnerabilities
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
    'PASSWORD_LEAK': 'critical',
    'WEAK_PASSWORD': 'high',
    'WEAK_CAPTCHA': 'medium',
    'SESSION_HIJACK': 'critical',
    'PATH_TRAVERSAL': 'critical',
    'SSRF': 'critical',
    'STORED_SSRF': 'critical',
    'CMD_INJECTION': 'critical',
    'UNSAFE_DEVICE_ADD': 'high',
    'PATH_INJECTION': 'high',
    'MODBUS_UNAUTHORIZED': 'critical'
}

# Mitigation recommendations for each attack type
ATTACK_MITIGATION = {
    'BRUTE_FORCE': 'Implement rate limiting (e.g., max 5 attempts per minute per IP), account lockout after failed attempts, and strong CAPTCHA verification',
    'PASSWORD_LEAK': 'Never expose credentials under any circumstance. Implement proper error handling that does not reveal system internals',
    'WEAK_PASSWORD': 'Enforce strong password policies (minimum 12 characters, complexity requirements), implement password strength meters, and use multi-factor authentication (MFA)',
    'WEAK_CAPTCHA': 'Use robust CAPTCHA solutions (e.g., reCAPTCHA v3, hCaptcha), implement time-based token validation, and add entropy to challenge generation',
    'SESSION_HIJACK': 'Use cryptographically secure session tokens, bind sessions to IP and User-Agent, implement session rotation, set HTTPOnly and Secure flags on cookies',
    'PATH_TRAVERSAL': 'Implement strict input validation, use whitelisting for allowed files, sanitize file paths, employ chroot jails, and never construct paths from user input directly',
    'SSRF': 'Validate and whitelist allowed destination IPs/domains, block requests to private IP ranges (RFC 1918), use DNS resolution checks, implement request timeouts',
    'STORED_SSRF': 'Same as SSRF, plus: validate data before storage, implement additional checks before making requests using stored data, use separate networks for internal services',
    'CMD_INJECTION': 'Never pass user input directly to shell commands, use parameterized APIs instead of shell execution, implement strict input sanitization with whitelisting, use command execution libraries with built-in escaping',
    'UNSAFE_DEVICE_ADD': 'Implement IP validation and whitelisting, use predefined device templates, require administrative approval for new devices, validate device configurations',
    'PATH_INJECTION': 'Use whitelisting for allowed log types, implement path sanitization, store logs in separate directories with restricted access, use predefined file mappings',
    'MODBUS_UNAUTHORIZED': 'Implement authentication and authorization for Modbus connections, use VPN or encrypted tunnels, employ network segmentation, enable Modbus security extensions (if available)'
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
        'user_agent': user_agent,
        'mitigation': ATTACK_MITIGATION.get(attack_type, 'Implement proper input validation and security controls')
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
