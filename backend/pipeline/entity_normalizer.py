import ipaddress
import re
from typing import Tuple, Optional

class EntityNormalizer:
    @staticmethod
    def normalize_ip(ip_str: str) -> Tuple[Optional[str], Optional[str]]:
        """Returns (canonical_value, display_value)"""
        if not ip_str:
            return None, None
        try:
            ip = ipaddress.ip_address(ip_str)
            return str(ip.exploded), str(ip)
        except ValueError:
            return None, None

    @staticmethod
    def normalize_domain(domain_str: str) -> Tuple[Optional[str], Optional[str]]:
        if not domain_str:
            return None, None
        canonical = domain_str.strip().lower()
        if canonical.endswith('.'):
            canonical = canonical[:-1]
        try:
            canonical = canonical.encode('idna').decode('ascii')
        except Exception:
            pass
        return canonical, domain_str

    @staticmethod
    def normalize_hash(hash_str: str) -> Tuple[Optional[str], Optional[str]]:
        if not hash_str:
            return None, None
        canonical = hash_str.strip().lower()
        if not re.match(r'^[a-f0-9]+$', canonical):
            return None, None
        return canonical, hash_str

    @staticmethod
    def normalize_username(username: str) -> Tuple[Optional[str], Optional[str]]:
        if not username:
            return None, None
        canonical = username.strip().lower()
        if '\\' in canonical:
            canonical = canonical.split('\\')[-1]
        if '@' in canonical:
            canonical = canonical.split('@')[0]
        return canonical, username

    @staticmethod
    def normalize_hostname(hostname: str) -> Tuple[Optional[str], Optional[str]]:
        if not hostname:
            return None, None
        canonical = hostname.strip().lower()
        if '.' in canonical:
            canonical = canonical.split('.')[0]
        return canonical, hostname
        
    @staticmethod
    def normalize_process(process: str) -> Tuple[Optional[str], Optional[str]]:
        if not process:
            return None, None
        canonical = process.strip()
        if '\\' in canonical:
            canonical = canonical.split('\\')[-1]
        if '/' in canonical:
            canonical = canonical.split('/')[-1]
        return canonical.lower(), process
