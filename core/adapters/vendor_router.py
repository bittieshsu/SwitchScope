# -*- coding: utf-8 -*-
"""
SwitchScope Multi-Vendor Router
自動特徵嗅探、適配器路由與多廠牌統一介面
"""
from typing import Dict, Any, Tuple
from core.adapters.base_adapter import BaseVendorAdapter
from core.adapters.cisco_adapter import CiscoAdapter
from core.adapters.aruba_adapter import ArubaAdapter
from core.adapters.juniper_adapter import JuniperAdapter
from core.adapters.fortiswitch_adapter import FortiSwitchAdapter

class VendorRouter:
    """多廠牌適配器路由器"""

    def __init__(self):
        self.adapters: Dict[str, BaseVendorAdapter] = {
            "cisco": CiscoAdapter(),
            "aruba": ArubaAdapter(),
            "juniper": JuniperAdapter(),
            "fortiswitch": FortiSwitchAdapter()
        }

    def detect_vendor(self, text: str) -> Tuple[str, float]:
        """
        自動嗅探輸入文本的設備廠牌，回傳 (vendor_id, confidence)
        """
        best_vendor = "cisco"
        best_score = 0.0

        for vid, adapter in self.adapters.items():
            score = adapter.sniff(text)
            if score > best_score:
                best_score = score
                best_vendor = vid

        # Default fallback to cisco if all scores are low
        if best_score < 0.2:
            return "cisco", 0.5
        return best_vendor, best_score

    def parse(self, text: str, vendor: str = "auto") -> Tuple[Dict[str, Any], str, float]:
        """
        依指定或自動探測的廠牌解析文本
        回傳: (parsed_data, detected_vendor, confidence)
        """
        if vendor != "auto" and vendor in self.adapters:
            chosen_vendor = vendor
            conf = 1.0
        else:
            chosen_vendor, conf = self.detect_vendor(text)

        adapter = self.adapters.get(chosen_vendor, self.adapters["cisco"])
        parsed_data = adapter.parse(text)
        
        # Inject vendor metadata
        if "device_info" in parsed_data:
            parsed_data["device_info"]["detected_vendor"] = chosen_vendor
            parsed_data["device_info"]["vendor_name"] = adapter.vendor_name
            parsed_data["device_info"]["vendor_confidence"] = round(conf, 2)

        return parsed_data, chosen_vendor, conf

    def generate_fix(self, vendor: str, issue_type: str, port: str, params: Dict[str, Any]) -> Dict[str, str]:
        adapter = self.adapters.get(vendor, self.adapters["cisco"])
        return adapter.generate_fix(issue_type, port, params)
