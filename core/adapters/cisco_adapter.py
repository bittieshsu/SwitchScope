# -*- coding: utf-8 -*-
"""
Cisco IOS / IOS-XE / NX-OS Adapter
包裝既有 CiscoParser，無縫接入多廠牌轉接層
"""
import re
from typing import Dict, Any
from core.adapters.base_adapter import BaseVendorAdapter
from core.parser import CiscoParser

class CiscoAdapter(BaseVendorAdapter):
    vendor_id = "cisco"
    vendor_name = "Cisco IOS / IOS-XE / NX-OS"

    def __init__(self):
        self.parser = CiscoParser()

    def sniff(self, text: str) -> float:
        score = 0.0
        patterns = [
            (r"Cisco IOS Software", 0.6),
            (r"C9\d{3}|WS-C\d{4}|ISR\d{4}|Nexus", 0.4),
            (r"show\s+(?:version|interfaces\s+status|etherchannel|switch)", 0.5),
            (r"GigabitEthernet\d+|TenGigabitEthernet\d+|FastEthernet\d+", 0.4),
            (r"switchport\s+(?:mode\s+trunk|access\s+vlan)", 0.4),
            (r"Port-channel\d+", 0.3)
        ]
        for pat, weight in patterns:
            if re.search(pat, text, re.IGNORECASE):
                score += weight
        return min(1.0, score)

    def parse(self, text: str) -> Dict[str, Any]:
        data = self.parser.parse_all(text)
        if "device_info" in data and isinstance(data["device_info"], dict):
            data["device_info"]["vendor"] = "Cisco"
        return data

    def generate_fix(self, issue_type: str, port: str, params: Dict[str, Any]) -> Dict[str, str]:
        vlan = params.get("vlan", "10")
        group = params.get("group", "1")
        if issue_type == "LACP_MISCONFIG":
            return {
                "apply_script": f"configure terminal\ninterface {port}\n channel-group {group} mode active\n no shutdown\nend\nwrite memory",
                "rollback_script": f"configure terminal\ninterface {port}\n no channel-group {group}\n shutdown\nend\nwrite memory"
            }
        elif issue_type == "ERR_DISABLED":
            return {
                "apply_script": f"configure terminal\ninterface {port}\n shutdown\n no shutdown\nend",
                "rollback_script": f"configure terminal\ninterface {port}\n shutdown\nend"
            }
        elif issue_type == "TRUNK_VLAN_MISSING":
            return {
                "apply_script": f"configure terminal\ninterface {port}\n switchport trunk allowed vlan add {vlan}\nend",
                "rollback_script": f"configure terminal\ninterface {port}\n switchport trunk allowed vlan remove {vlan}\nend"
            }
        return super().generate_fix(issue_type, port, params)
