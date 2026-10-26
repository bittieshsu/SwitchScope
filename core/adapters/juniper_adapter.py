# -*- coding: utf-8 -*-
"""
Juniper Junos OS Switch Adapter
將 Juniper EX/QFX 交換機 CLI 輸出規範化為 SwitchScope 標準數據模型
"""
import re
from typing import Dict, Any, List
from core.adapters.base_adapter import BaseVendorAdapter

class JuniperAdapter(BaseVendorAdapter):
    vendor_id = "juniper"
    vendor_name = "Juniper Networks Junos OS (EX / QFX)"
    default_prompt_symbol = ">"

    def sniff(self, text: str) -> float:
        score = 0.0
        patterns = [
            (r"Junos:\s*\d+\.\d+|JUNOS\s+Software", 0.6),
            (r"ex\d{4}|qfx\d{4}|srx\d{3}|mx\d{3}", 0.4),
            (r"show\s+interfaces\s+terse|show\s+lacp\s+interfaces|show\s+vlans", 0.5),
            (r"\b(?:ge|xe|et|ae)-\d+\/\d+\/\d+\b", 0.4),
            (r"eth-switch|Collecting\s+distributing", 0.3),
            (r"set\s+interfaces\s+\S+\s+unit", 0.4)
        ]
        for pat, weight in patterns:
            if re.search(pat, text, re.IGNORECASE):
                score += weight
        return min(1.0, score)

    def parse(self, text: str) -> Dict[str, Any]:
        device_info = self._parse_version(text)
        ports_status = self._parse_interfaces_terse(text)
        ports_counters = self._parse_interfaces_extensive(text)
        etherchannel = self._parse_lacp(text)
        vlans = self._parse_vlans(text)
        lldp = self._parse_lldp(text)

        ports_table = []
        all_ports = set(ports_status.keys()) | set(ports_counters.keys())
        sorted_ports = sorted(list(all_ports), key=self._port_sort_key)

        for p in sorted_ports:
            stat = ports_status.get(p, {})
            cnt = ports_counters.get(p, {})
            
            p_record = {
                "port": p,
                "description": stat.get("description", ""),
                "status": stat.get("status", cnt.get("status", "down")),
                "vlan": stat.get("vlan", "1"),
                "duplex": "full",
                "speed": stat.get("speed", "1000"),
                "input_rate_bps": cnt.get("input_rate_bps", 0),
                "output_rate_bps": cnt.get("output_rate_bps", 0),
                "in_errors": cnt.get("in_errors", 0),
                "crc_errors": cnt.get("crc_errors", 0),
                "out_errors": cnt.get("out_errors", 0),
                "collisions": cnt.get("collisions", 0),
                "in_drops": cnt.get("in_drops", 0),
                "out_drops": cnt.get("out_drops", 0),
                "lldp_neighbors": [n for n in lldp if n.get("local_port") == p],
                "cdp_neighbors": [],
                "mac_addresses": [],
                "ip_addresses": [],
                "is_flapping": False
            }
            ports_table.append(p_record)

        return {
            "device_info": device_info,
            "ports_table": ports_table,
            "etherchannel": etherchannel,
            "vlans": vlans,
            "stack": [],
            "routing": {},
            "cdp_neighbors": [],
            "lldp_neighbors": lldp,
            "mac_table": [],
            "arp_table": [],
            "syslog": [],
            "timeline": {},
            "raw_sections_found": ["version", "interfaces_terse", "interfaces_extensive", "lacp", "vlans", "lldp"]
        }

    def _port_sort_key(self, p: str):
        nums = re.findall(r"\d+", p)
        if nums:
            return (0, [int(n) for n in nums])
        return (1, p)

    def _parse_version(self, text: str) -> Dict[str, Any]:
        info = {
            "hostname": "Juniper-Switch",
            "model": "EX/QFX Series",
            "version": "Junos",
            "vendor": "Juniper Networks",
            "serial": "Unknown",
            "uptime": "Unknown"
        }
        m_host = re.search(r"Hostname:\s*(\S+)", text, re.I)
        if m_host:
            info["hostname"] = m_host.group(1)

        m_mod = re.search(r"Model:\s*(\S+)", text, re.I)
        if m_mod:
            info["model"] = m_mod.group(1).upper()

        m_ver = re.search(r"Junos:\s*(\S+)", text, re.I)
        if m_ver:
            info["version"] = m_ver.group(1)

        m_up = re.search(r"System\s+booted:\s*(.+?)$", text, re.M | re.I)
        if m_up:
            info["uptime"] = m_up.group(1).strip()

        return info

    def _parse_interfaces_terse(self, text: str) -> Dict[str, Dict[str, Any]]:
        """
        Parses `show interfaces terse`
        Interface               Admin Link Proto    Local                 Remote
        ge-0/0/0                up    up
        ge-0/0/0.0              up    up   eth-switch
        ge-0/0/1                up    down
        ae0                     up    up
        ae0.0                   up    up   eth-switch
        """
        ports = {}
        for line in text.splitlines():
            line_s = line.strip()
            # Match physical port lines (ignoring unit subinterfaces .0)
            m = re.match(r"^((?:ge|xe|et|ae|me)-\d+\/\d+\/\d+|ae\d+)\s+(up|down)\s+(up|down)", line_s, re.I)
            if m:
                port = m.group(1)
                admin = m.group(2).lower()
                link = m.group(3).lower()
                status = "connected" if (admin == "up" and link == "up") else ("disabled" if admin == "down" else "notconnect")
                
                ports[port] = {
                    "port": port,
                    "status": status,
                    "vlan": "trunk" if "ae" in port else "1",
                    "speed": "10000" if "xe" in port else "1000"
                }
        return ports

    def _parse_interfaces_extensive(self, text: str) -> Dict[str, Dict[str, Any]]:
        """
        Parses `show interfaces extensive`
        """
        counters = {}
        blocks = re.split(r"(?:^|\n)Physical\s+interface:\s*(\S+),\s+Enabled,\s+Physical\s+link\s+is\s+(\S+)", text, flags=re.I)
        if len(blocks) > 1:
            for i in range(1, len(blocks), 3):
                p_name = blocks[i]
                p_link = blocks[i+1]
                body = blocks[i+2] if (i+2 < len(blocks)) else ""

                crc = 0
                in_err = 0
                out_err = 0
                in_drop = 0
                out_drop = 0

                m_crc = re.search(r"CRC\s*(?:errors)?\s*[:=]?\s*(\d+)", body, re.I)
                if m_crc:
                    crc = int(m_crc.group(1))

                m_in_err = re.search(r"Input\s+errors:\s*Errors:\s*(\d+)", body, re.I)
                if m_in_err:
                    in_err = int(m_in_err.group(1))

                m_drop = re.search(r"Drops:\s*(\d+)", body, re.I)
                if m_drop:
                    in_drop = int(m_drop.group(1))

                counters[p_name] = {
                    "status": "connected" if p_link.lower() == "up" else "down",
                    "crc_errors": crc,
                    "in_errors": in_err,
                    "out_errors": out_err,
                    "in_drops": in_drop,
                    "out_drops": out_drop,
                    "collisions": 0,
                    "input_rate_bps": 0,
                    "output_rate_bps": 0
                }
        return counters

    def _parse_lacp(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show lacp interfaces`
        Aggregated interface: ae0
        LACP state:       Role   Exp   Def  Dist  Col  Syn  Aggr  Timeout  Activity
          ge-0/0/0       Actor    No    No   Yes  Yes  Yes   Yes     Fast    Active
          ge-0/0/1       Actor    No    No    No   No   No   Yes     Fast    Active
        """
        lags = {}
        curr_ae = "ae0"
        for line in text.splitlines():
            line_s = line.strip()
            m_ae = re.search(r"Aggregated\s+interface:\s*(\S+)", line_s, re.I)
            if m_ae:
                curr_ae = m_ae.group(1)
                if curr_ae not in lags:
                    lags[curr_ae] = {
                        "group": re.sub(r"\D", "", curr_ae) or "0",
                        "bundle": curr_ae,
                        "port_channel": curr_ae,
                        "protocol": "LACP",
                        "status": "UP",
                        "members": [],
                        "ports": []
                    }
                continue

            # Match member port line
            m_p = re.match(r"^((?:ge|xe|et)-\d+\/\d+\/\d+)\s+Actor\s+\S+\s+\S+\s+(\S+)\s+(\S+)", line_s, re.I)
            if m_p:
                p_name = m_p.group(1)
                dist = m_p.group(2).lower()  # Distributing
                col = m_p.group(3).lower()   # Collecting
                
                is_suspended = (dist != "yes" or col != "yes")
                state = "suspended" if is_suspended else "bundled"

                if curr_ae not in lags:
                    lags[curr_ae] = {
                        "group": re.sub(r"\D", "", curr_ae) or "0",
                        "bundle": curr_ae,
                        "port_channel": curr_ae,
                        "protocol": "LACP",
                        "status": "UP",
                        "members": [],
                        "ports": []
                    }
                lags[curr_ae]["members"].append({
                    "port": p_name,
                    "is_bundled": not is_suspended,
                    "is_suspended": is_suspended,
                    "is_down": False
                })
                lags[curr_ae]["ports"].append({
                    "port": p_name,
                    "state": state
                })
                lags[curr_ae]["has_suspended"] = any(m["is_suspended"] for m in lags[curr_ae]["members"])
                lags[curr_ae]["has_down"] = any(m["is_down"] for m in lags[curr_ae]["members"])

        return list(lags.values())

    def _parse_vlans(self, text: str) -> List[Dict[str, Any]]:
        vlans = []
        for line in text.splitlines():
            m = re.match(r"^([A-Za-z0-9_\-]+)\s+(\d+)\s+(.+)$", line.strip())
            if m:
                vlans.append({
                    "name": m.group(1),
                    "vlan_id": m.group(2),
                    "ports": m.group(3).strip(),
                    "status": "up"
                })
        return vlans

    def _parse_lldp(self, text: str) -> List[Dict[str, Any]]:
        neighbors = []
        for line in text.splitlines():
            m = re.match(r"^((?:ge|xe|et)-\d+\/\d+\/\d+)\s+\S+\s+([0-9a-fA-F\:\-]+)\s+(\S+)\s+(.+)$", line.strip())
            if m:
                neighbors.append({
                    "local_port": m.group(1),
                    "chassis_id": m.group(2),
                    "port_id": m.group(3),
                    "system_name": m.group(4).strip()
                })
        return neighbors

    def generate_fix(self, issue_type: str, port: str, params: Dict[str, Any]) -> Dict[str, str]:
        vlan = params.get("vlan", "10")
        ae = params.get("group", "0")
        if issue_type == "LACP_MISCONFIG":
            return {
                "apply_script": f"set interfaces {port} ether-options 802.3ad ae{ae}\ncommit and-quit",
                "rollback_script": f"delete interfaces {port} ether-options 802.3ad\ncommit and-quit"
            }
        elif issue_type == "TRUNK_VLAN_MISSING":
            return {
                "apply_script": f"set interfaces {port} unit 0 family ethernet-switching vlan members {vlan}\ncommit and-quit",
                "rollback_script": f"delete interfaces {port} unit 0 family ethernet-switching vlan members {vlan}\ncommit and-quit"
            }
        elif issue_type == "ERR_DISABLED":
            return {
                "apply_script": f"delete interfaces {port} disable\ncommit and-quit",
                "rollback_script": f"set interfaces {port} disable\ncommit and-quit"
            }
        return super().generate_fix(issue_type, port, params)
