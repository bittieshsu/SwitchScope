# -*- coding: utf-8 -*-
"""
SwitchScope Multi-Vendor Base Adapter
定義異質網通設備轉接器抽象基類，將各廠牌 CLI 輸出規範化為統一數據模型
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseVendorAdapter(ABC):
    """多廠牌設備解析器抽象基類"""
    
    vendor_id: str = "generic"
    vendor_name: str = "Generic Network Device"
    default_prompt_symbol: str = "#"

    @abstractmethod
    def sniff(self, text: str) -> float:
        """
        嗅探輸入文字是否屬於本廠牌特徵
        回傳 0.0 ~ 1.0 的信心度評分
        """
        pass

    @abstractmethod
    def parse(self, text: str) -> Dict[str, Any]:
        """
        將本廠牌 CLI 原始輸出解析為 SwitchScope 標準結構
        必須包含:
        - device_info: dict (hostname, model, version, vendor, uptime, serial)
        - ports_table: list (port, description, status, vlan, duplex, speed, crc_errors, in_errors, out_errors, collisions, in_drops, out_drops)
        - etherchannel: list (group, port_channel, protocol, ports)
        - vlans: list (vlan_id, name, status, ports)
        - lldp_neighbors: list (local_port, chassis_id, port_id, system_name)
        - raw_sections_found: list
        """
        pass

    def generate_fix(self, issue_type: str, port: str, params: Dict[str, Any]) -> Dict[str, str]:
        """
        產生該廠牌專屬的修復指令與緊急回滾 (Rollback) 指令
        回傳: {"apply_script": "...", "rollback_script": "..."}
        """
        return {
            "apply_script": f"# {self.vendor_name}: Manual intervention required for {port}",
            "rollback_script": f"# {self.vendor_name}: No rollback defined"
        }
