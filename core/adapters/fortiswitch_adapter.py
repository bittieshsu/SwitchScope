# -*- coding: utf-8 -*-
"""
Fortinet FortiSwitch Adapter
將 Fortinet FortiSwitch CLI 輸出規範化為 SwitchScope 標準數據模型
"""
import re
from typing import Dict, Any, List
from core.adapters.base_adapter import BaseVendorAdapter

class FortiSwitchAdapter(BaseVendorAdapter):
    vendor_id = "fortiswitch"
    vendor_name = "Fortinet FortiSwitch (FortiOS Switch-Controller)"
    default_prompt_symbol = "#"

    def sniff(self, text: str) -> float:
        score = 0.0
        patterns = [
            (r"FortiSwitch|FSW-\d{3}[A-Z]|FortiOS|FortiLink", 0.6),
            (r"diagnose\s+switch\s+physical-ports|diagnose\s+switch\s+trunk|diagnose\s+switch\s+vlan", 0.6),
            (r"\bport\d+\b", 0.3),  # FortiSwitch port naming port1, port2...
            (r"config\s+switch\s+physical-port|config\s+switch\s+trunk", 0.4),
            (r"get\s+system\s+status|get\s+switch-controller", 0.4)
        ]
        for pat, weight in patterns:
            if re.search(pat, text, re.IGNORECASE):
                score += weight
        return min(1.0, score)

    def parse(self, text: str) -> Dict[str, Any]:
        device_info = self._parse_status(text)
        ports_status = self._parse_ports_summary(text)
        ports_counters = self._parse_ports_stats(text)
        etherchannel = self._parse_trunks(text)
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
            "raw_sections_found": ["status", "physical_ports_summary", "physical_ports_stats", "trunks", "vlan", "lldp"]
        }

    def _port_sort_key(self, p: str):
        nums = re.findall(r"\d+", p)
        if nums:
            return (0, [int(n) for n in nums])
        return (1, p)

    def _parse_status(self, text: str) -> Dict[str, Any]:
        info = {
            "hostname": "FortiSwitch",
            "model": "FortiSwitch Series",
            "version": "FortiOS FOS",
            "vendor": "Fortinet",
            "serial": "Unknown",
            "uptime": "Unknown"
        }
        m_host = re.search(r"Hostname:\s*(\S+)", text, re.I)
        if m_host:
            info["hostname"] = m_host.group(1)

        m_ver = re.search(r"Version:\s*(FortiSwitch-\S+)\s+(v[0-9\.\,build]+)", text, re.I)
        if m_ver:
            info["model"] = m_ver.group(1)
            info["version"] = m_ver.group(2)
        else:
            m_fsw = re.search(r"(FSW-\d{3}[A-Z]|FortiSwitch-\d{3}[A-Z])", text, re.I)
            if m_fsw:
                info["model"] = m_fsw.group(1)

        m_ser = re.search(r"Serial-Number:\s*(\S+)", text, re.I)
        if m_ser:
            info["serial"] = m_ser.group(1)

        m_up = re.search(r"System\s+time:\s*(.+?)$", text, re.M | re.I)
        if m_up:
            info["uptime"] = m_up.group(1).strip()

        return info

    def _parse_ports_summary(self, text: str) -> Dict[str, Dict[str, Any]]:
        """
        Parses `diagnose switch physical-ports summary`
        Port    Status  Speed   Duplex  VLAN    Learning  PoE
        port1   up      1000M   full    1       enabled   --
        port24  up      1000M   full    100     enabled   --
        port48  down    auto    auto    1       enabled   --
        """
        ports = {}
        for line in text.splitlines():
            line_s = line.strip()
            m = re.match(r"^(port\d+|fortilink)\s+(up|down)\s+(\S+)\s+(\S+)\s+(\d+|\S+)", line_s, re.I)
            if m:
                port = m.group(1)
                status_raw = m.group(2).lower()
                speed = m.group(3).replace("M", "")
                duplex = m.group(4).lower()
                vlan = m.group(5)

                status = "connected" if status_raw == "up" else "notconnect"
                ports[port] = {
                    "port": port,
                    "status": status,
                    "speed": speed if speed != "auto" else "1000",
                    "duplex": duplex if duplex != "auto" else "full",
                    "vlan": vlan
                }
        return ports

    def _parse_ports_stats(self, text: str) -> Dict[str, Dict[str, Any]]:
        """
        Parses `diagnose switch physical-ports stats`
        """
        counters = {}
        blocks = re.split(r"(?:^|\n)(?:Port|Interface):\s*(port\d+|fortilink)", text, flags=re.I)
        if len(blocks) > 1:
            for i in range(1, len(blocks), 2):
                p_name = blocks[i]
                body = blocks[i+1] if (i+1 < len(blocks)) else ""

                crc = 0
                in_err = 0
                out_err = 0
                in_drop = 0
                out_drop = 0

                m_crc = re.search(r"(?:CRC|FCS)\s*(?:error)?\s*[:=]?\s*(\d+)", body, re.I)
                if m_crc:
                    crc = int(m_crc.group(1))

                m_err = re.search(r"Rx\s+error\s*[:=]?\s*(\d+)", body, re.I)
                if m_err:
                    in_err = int(m_err.group(1))

                m_drop = re.search(r"(?:discard|drop)\s*[:=]?\s*(\d+)", body, re.I)
                if m_drop:
                    in_drop = int(m_drop.group(1))

                counters[p_name] = {
                    "crc_errors": crc,
                    "in_errors": in_err,
                    "out_errors": 0,
                    "in_drops": in_drop,
                    "out_drops": 0,
                    "collisions": 0,
                    "input_rate_bps": 0,
                    "output_rate_bps": 0
                }
        return counters

    def _parse_trunks(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `diagnose switch trunk summary`
        Trunk-Name: fortilink
          Members: port47, port48
          Status: up
          LACP-Mode: active
          port47: bundled
          port48: suspended
        """
        trunks = {}
        curr_trunk = None
        for line in text.splitlines():
            line_s = line.strip()
            m_t = re.search(r"Trunk(?:-Name)?:\s*(\S+)", line_s, re.I)
            if m_t:
                curr_trunk = m_t.group(1)
                trunks[curr_trunk] = {
                    "group": re.sub(r"\D", "", curr_trunk) or "1",
                    "bundle": curr_trunk,
                    "port_channel": curr_trunk,
                    "protocol": "LACP",
                    "status": "UP",
                    "members": [],
                    "ports": []
                }
                continue

            if curr_trunk and ":" in line_s:
                parts = line_s.split(":")
                p_candidate = parts[0].strip()
                p_state = parts[1].strip().lower()
                if p_candidate.startswith("port"):
                    is_susp = "susp" in p_state or "down" in p_state
                    trunks[curr_trunk]["members"].append({
                        "port": p_candidate,
                        "is_bundled": not is_susp,
                        "is_suspended": is_susp,
                        "is_down": False
                    })
                    trunks[curr_trunk]["ports"].append({
                        "port": p_candidate,
                        "state": "suspended" if is_susp else "bundled"
                    })
                    trunks[curr_trunk]["has_suspended"] = any(m["is_suspended"] for m in trunks[curr_trunk]["members"])
                    trunks[curr_trunk]["has_down"] = any(m["is_down"] for m in trunks[curr_trunk]["members"])

        return list(trunks.values())

    def _parse_vlans(self, text: str) -> List[Dict[str, Any]]:
        vlans = []
        for line in text.splitlines():
            m = re.match(r"^VLAN\s+(\d+):\s*(\S+)\s*\((.+?)\)", line.strip(), re.I)
            if m:
                vlans.append({
                    "vlan_id": m.group(1),
                    "name": m.group(2),
                    "ports": m.group(3),
                    "status": "up"
                })
        return vlans

    def _parse_lldp(self, text: str) -> List[Dict[str, Any]]:
        neighbors = []
        for line in text.splitlines():
            m = re.match(r"^(port\d+):\s*(.+?)\s*\(([0-9a-zA-Z\.\:\-]+)\)", line.strip())
            if m:
                neighbors.append({
                    "local_port": m.group(1),
                    "system_name": m.group(2).strip(),
                    "chassis_id": m.group(3).strip(),
                    "port_id": m.group(1)
                })
        return neighbors

    def generate_fix(self, issue_type: str, port: str, params: Dict[str, Any]) -> Dict[str, str]:
        vlan = params.get("vlan", "100")
        if issue_type == "LACP_MISCONFIG":
            return {
                "apply_script": f"config switch trunk\n edit fortilink\n  set members {port}\n next\nend",
                "rollback_script": f"config switch trunk\n edit fortilink\n  unset members {port}\n next\nend"
            }
        elif issue_type == "TRUNK_VLAN_MISSING":
            return {
                "apply_script": f"config switch physical-port\n edit {port}\n  set allowed-vlans {vlan}\n next\nend",
                "rollback_script": f"config switch physical-port\n edit {port}\n  unset allowed-vlans {vlan}\n next\nend"
            }
        elif issue_type == "ERR_DISABLED":
            return {
                "apply_script": f"config switch physical-port\n edit {port}\n  set status down\n  set status up\n next\nend",
                "rollback_script": f"config switch physical-port\n edit {port}\n  set status down\n next\nend"
            }
        return super().generate_fix(issue_type, port, params)
