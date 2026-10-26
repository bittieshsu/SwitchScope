# -*- coding: utf-8 -*-
"""
ArubaOS-CX & HP ProCurve Switch Adapter
將 Aruba / HPE 交換機 CLI 輸出規範化為 SwitchScope 標準數據模型
"""
import re
from typing import Dict, Any, List
from core.adapters.base_adapter import BaseVendorAdapter

class ArubaAdapter(BaseVendorAdapter):
    vendor_id = "aruba"
    vendor_name = "Aruba (HPE) ArubaOS-CX / ProCurve"
    default_prompt_symbol = "#"

    def sniff(self, text: str) -> float:
        score = 0.0
        patterns = [
            (r"ArubaOS-CX|ArubaOS|ProCurve|HPE|Hewlett Packard", 0.6),
            (r"JL\d{3}[A-Z]|J\d{4}[A-Z]|Aruba\s+[2368]\d{3}", 0.4),
            (r"show\s+interface\s+brief|show\s+lacp\s+aggregates|show\s+vlan\s+summary", 0.5),
            (r"\b1/\d+/\d+\b", 0.3),  # Aruba port format 1/1/1
            (r"\blag\d+\b", 0.3),     # Aruba link aggregation lag1
            (r"vlan\s+\d+\s+tagged|vlan\s+\d+\s+untagged", 0.4)
        ]
        for pat, weight in patterns:
            if re.search(pat, text, re.IGNORECASE):
                score += weight
        return min(1.0, score)

    def parse(self, text: str) -> Dict[str, Any]:
        device_info = self._parse_system(text)
        ports_status = self._parse_interface_brief(text)
        ports_counters = self._parse_interface_extended(text)
        etherchannel = self._parse_lacp(text)
        vlans = self._parse_vlan(text)
        lldp = self._parse_lldp(text)

        # Build unified ports table
        ports_table = []
        all_ports = set(ports_status.keys()) | set(ports_counters.keys())
        
        # Sort ports naturally (e.g. 1/1/1, 1/1/2 ... 1/1/48, lag1)
        sorted_ports = sorted(list(all_ports), key=self._port_sort_key)

        for p in sorted_ports:
            stat = ports_status.get(p, {})
            cnt = ports_counters.get(p, {})
            
            p_record = {
                "port": p,
                "description": stat.get("description", ""),
                "status": stat.get("status", cnt.get("status", "down")),
                "vlan": stat.get("vlan", "1"),
                "duplex": stat.get("duplex", "full"),
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
            "raw_sections_found": ["system", "interface_brief", "interface_extended", "lacp", "vlan", "lldp"]
        }

    def _port_sort_key(self, p: str):
        nums = re.findall(r"\d+", p)
        if nums:
            return (0, [int(n) for n in nums])
        return (1, p)

    def _parse_system(self, text: str) -> Dict[str, Any]:
        info = {
            "hostname": "Aruba-Switch",
            "model": "Aruba CX Series",
            "version": "ArubaOS-CX",
            "vendor": "Aruba (HPE)",
            "serial": "Unknown",
            "uptime": "Unknown"
        }
        # ArubaOS-CX show system
        m_host = re.search(r"Hostname\s*:\s*(\S+)", text, re.I)
        if m_host:
            info["hostname"] = m_host.group(1)

        m_mod = re.search(r"(?:Product\s+Name|Model)\s*:\s*(.+?)$", text, re.M | re.I)
        if m_mod:
            info["model"] = m_mod.group(1).strip()
        else:
            m_mod2 = re.search(r"(Aruba\s+\d{4}[A-Z]?|JL\d{3}[A-Z]|J\d{4}[A-Z])", text, re.I)
            if m_mod2:
                info["model"] = m_mod2.group(1)

        m_ver = re.search(r"(?:Version|Firmware)\s*:\s*(\S+)", text, re.I)
        if m_ver:
            info["version"] = m_ver.group(1)

        m_ser = re.search(r"Serial\s+Number\s*:\s*(\S+)", text, re.I)
        if m_ser:
            info["serial"] = m_ser.group(1)

        m_up = re.search(r"Up\s+Time\s*:\s*(.+?)$", text, re.M | re.I)
        if m_up:
            info["uptime"] = m_up.group(1).strip()

        return info

    def _parse_interface_brief(self, text: str) -> Dict[str, Dict[str, Any]]:
        """
        Parses `show interface brief`
        Port    Native  Type          Enabled Status  Mode    Speed(Mb/s) Reason
        -------------------------------------------------------------------------
        1/1/1   1       10/100/1000T  yes     up      routed  1000        --
        1/1/24  10      10/100/1000T  yes     up      trunk   1000        --
        1/1/25  1       10G-SR        yes     down    access  auto        Link down
        lag1    1       --            yes     up      trunk   2000        --
        """
        ports = {}
        for line in text.splitlines():
            line_s = line.strip()
            if not line_s or line_s.startswith("Port") or line_s.startswith("---") or line_s.startswith("="):
                continue
            # match: 1/1/1 or lag1
            m = re.match(r"^([0-9a-zA-Z\/\-]+)\s+(\d+|\-\-)\s+(\S+)\s+(yes|no)\s+(up|down)\s+(\S+)\s+(\S+)", line_s, re.I)
            if m:
                port = m.group(1)
                vlan = m.group(2) if m.group(2) != "--" else "trunk"
                enabled = m.group(4).lower() == "yes"
                status_raw = m.group(5).lower()
                status = "connected" if (status_raw == "up" and enabled) else ("disabled" if not enabled else "notconnect")
                mode = m.group(6)
                speed = m.group(7)

                ports[port] = {
                    "port": port,
                    "status": status,
                    "vlan": "trunk" if mode.lower() == "trunk" else vlan,
                    "speed": speed if speed != "auto" else "1000",
                    "duplex": "full"
                }
        return ports

    def _parse_interface_extended(self, text: str) -> Dict[str, Dict[str, Any]]:
        """
        Parses `show interface extended` or counters section
        """
        counters = {}
        # Match per-port blocks: Interface 1/1/24 is up
        blocks = re.split(r"(?:^|\n)(?:Interface|Port)\s+([0-9a-zA-Z\/\-]+)\s+is\s+(up|down)", text, flags=re.I)
        
        if len(blocks) > 1:
            for i in range(1, len(blocks), 3):
                p_name = blocks[i]
                p_status = blocks[i+1]
                body = blocks[i+2] if (i+2 < len(blocks)) else ""

                crc = 0
                in_err = 0
                out_err = 0
                in_drop = 0
                out_drop = 0
                in_rate = 0
                out_rate = 0

                m_crc = re.search(r"(?:CRC|FCS)\s*(?:errors)?\s*[:=]?\s*(\d+)", body, re.I)
                if m_crc:
                    crc = int(m_crc.group(1))

                m_in_err = re.search(r"Input\s+(?:total\s+)?errors\s*[:=]?\s*(\d+)", body, re.I)
                if m_in_err:
                    in_err = int(m_in_err.group(1))

                m_out_err = re.search(r"Output\s+(?:total\s+)?errors\s*[:=]?\s*(\d+)", body, re.I)
                if m_out_err:
                    out_err = int(m_out_err.group(1))

                m_drop = re.search(r"drops?\s*[:=]?\s*(\d+)", body, re.I)
                if m_drop:
                    in_drop = int(m_drop.group(1))

                m_rate = re.search(r"(\d+)\s+bps", body, re.I)
                if m_rate:
                    in_rate = int(m_rate.group(1))

                counters[p_name] = {
                    "status": "connected" if p_status.lower() == "up" else "down",
                    "crc_errors": crc,
                    "in_errors": in_err,
                    "out_errors": out_err,
                    "in_drops": in_drop,
                    "out_drops": out_drop,
                    "collisions": 0,
                    "input_rate_bps": in_rate,
                    "output_rate_bps": in_rate
                }
        return counters

    def _parse_lacp(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show lacp aggregates`
        Aggregate  Port      Mode    Status
        -----------------------------------
        lag1       1/1/1     Active  Success
        lag1       1/1/2     Active  Blocked
        """
        lags = {}
        for line in text.splitlines():
            line_s = line.strip()
            m = re.match(r"^(lag\d+)\s+([0-9a-zA-Z\/\-]+)\s+(\S+)\s+(\S+)", line_s, re.I)
            if m:
                group_name = m.group(1)
                port_name = m.group(2)
                mode = m.group(3)
                status = m.group(4)
                
                # 'Blocked' or 'Suspended' is a failure
                is_suspended = "block" in status.lower() or "susp" in status.lower()
                port_state = "suspended" if is_suspended else "bundled"

                if group_name not in lags:
                    lags[group_name] = {
                        "group": re.sub(r"\D", "", group_name) or "1",
                        "bundle": group_name,
                        "port_channel": group_name,
                        "protocol": "LACP",
                        "status": "UP",
                        "members": [],
                        "ports": []
                    }
                lags[group_name]["members"].append({
                    "port": port_name,
                    "is_bundled": not is_suspended,
                    "is_suspended": is_suspended,
                    "is_down": False
                })
                lags[group_name]["ports"].append({
                    "port": port_name,
                    "state": port_state,
                    "mode": mode
                })
                lags[group_name]["has_suspended"] = any(m["is_suspended"] for m in lags[group_name]["members"])
                lags[group_name]["has_down"] = any(m["is_down"] for m in lags[group_name]["members"])
        return list(lags.values())

    def _parse_vlan(self, text: str) -> List[Dict[str, Any]]:
        vlans = []
        for line in text.splitlines():
            m = re.match(r"^\s*(\d+)\s+([A-Za-z0-9_\-]+)\s+(up|down)\s+(.+)$", line.strip(), re.I)
            if m:
                vlans.append({
                    "vlan_id": m.group(1),
                    "name": m.group(2),
                    "status": m.group(3),
                    "ports": m.group(4).strip()
                })
        return vlans

    def _parse_lldp(self, text: str) -> List[Dict[str, Any]]:
        neighbors = []
        for line in text.splitlines():
            m = re.match(r"^([0-9a-zA-Z\/\-]+)\s+([0-9a-fA-F\:\-]+)\s+(\S+)\s+(.+?)\s+([A-Za-z0-9_\-\.\:]+)$", line.strip())
            if m:
                neighbors.append({
                    "local_port": m.group(1),
                    "chassis_id": m.group(2),
                    "port_id": m.group(3),
                    "system_name": m.group(5)
                })
        return neighbors

    def generate_fix(self, issue_type: str, port: str, params: Dict[str, Any]) -> Dict[str, str]:
        vlan = params.get("vlan", "10")
        lag = params.get("group", "1")
        if issue_type == "LACP_MISCONFIG":
            return {
                "apply_script": f"configure terminal\ninterface {port}\n lag {lag}\n no shutdown\nexit\nwrite memory",
                "rollback_script": f"configure terminal\ninterface {port}\n no lag {lag}\n shutdown\nexit\nwrite memory"
            }
        elif issue_type == "TRUNK_VLAN_MISSING":
            return {
                "apply_script": f"configure terminal\ninterface {port}\n vlan trunk allowed {vlan}\nexit\nwrite memory",
                "rollback_script": f"configure terminal\ninterface {port}\n no vlan trunk allowed {vlan}\nexit\nwrite memory"
            }
        elif issue_type == "ERR_DISABLED":
            return {
                "apply_script": f"configure terminal\ninterface {port}\n disable\n enable\nexit",
                "rollback_script": f"configure terminal\ninterface {port}\n disable\nexit"
            }
        return super().generate_fix(issue_type, port, params)
