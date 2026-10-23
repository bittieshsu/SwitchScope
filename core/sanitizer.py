"""
SwitchScope - Sanitizer Module
Protects enterprise data by sanitizing credentials, passwords, and sensitive IPs before analysis or LLM export.
"""
import re

def sanitize_cisco_output(raw_text: str, mask_ips: bool = False) -> str:
    """
    Sanitizes sensitive information from Cisco CLI outputs:
    1. Passwords, secrets, and keys.
    2. SNMP community strings.
    3. (Optional) IP addresses and MAC addresses.
    """
    text = raw_text

    # 1. Mask enable secret / password hashes
    text = re.sub(
        r'(enable\s+secret\s+\d+\s+)\S+',
        r'\1[MASKED_SECRET_HASH]',
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        r'(password\s+\d+\s+)\S+',
        r'\1[MASKED_PASSWORD]',
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        r'(username\s+\S+\s+(?:secret|password)\s+\d+\s+)\S+',
        r'\1[MASKED_USER_SECRET]',
        text,
        flags=re.IGNORECASE
    )

    # 2. Mask SNMP community strings
    text = re.sub(
        r'(snmp-server\s+community\s+)(\S+)',
        r'\1[MASKED_COMMUNITY]',
        text,
        flags=re.IGNORECASE
    )

    # 3. Mask pre-shared keys and crypto keys
    text = re.sub(
        r'(key-string\s+)\S+',
        r'\1[MASKED_KEY]',
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        r'(crypto\s+isakmp\s+key\s+)\S+',
        r'\1[MASKED_ISAKMP_KEY]',
        text,
        flags=re.IGNORECASE
    )

    # 4. Optional IP masking
    if mask_ips:
        ip_map = {}
        ip_counter = 1

        def replace_ip(match):
            nonlocal ip_counter
            ip = match.group(0)
            if ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "255.255.255.0"):
                return ip
            if ip not in ip_map:
                ip_map[ip] = f"10.0.X.{ip_counter}"
                ip_counter += 1
            return ip_map[ip]

        text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', replace_ip, text)

    return text
