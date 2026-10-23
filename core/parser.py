"""
SwitchScope - Cisco CLI Parser Module
Parses raw Cisco show command outputs into structured Python dictionaries and pandas DataFrames.
Designed to handle full dumps or individual command snippets.
"""
import re
from datetime import datetime
from typing import Dict, Any, List, Optional

MONTHS_MAP = {
    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
    'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
}

class CiscoParser:
    def __init__(self):
        pass

    def parse_all(self, raw_text: str) -> Dict[str, Any]:
        """
        Main entry point: decomposes raw text into sections and parses each.
        """
        sections = self._split_sections(raw_text)
        timeline = self._build_chronological_timeline(raw_text)
        flapping_ports = self._analyze_flapping_ports(sections.get("logging", raw_text), global_timeline=timeline)
        timeline.pop("_latest_dt", None)

        cdp_neighbors = self._parse_cdp_neighbors(sections.get("cdp_neighbors", raw_text))
        lldp_neighbors = self._parse_lldp_neighbors(sections.get("lldp_neighbors", raw_text))
        mac_table = self._parse_mac_table(sections.get("mac_table", raw_text))
        arp_table = self._parse_arp_table(sections.get("arp_table", raw_text))

        parsed_data = {
            "device_info": self._parse_version(sections.get("version", raw_text)),
            "interfaces_status": self._parse_interfaces_status(sections.get("interfaces_status", raw_text)),
            "interfaces_counters": self._parse_interfaces_detailed(sections.get("interfaces_detailed", raw_text)),
            "etherchannel": self._parse_etherchannel(sections.get("etherchannel", raw_text)),
            "stack": self._parse_switch_stack(sections.get("stack", raw_text)),
            "routing": self._parse_ip_route(sections.get("routing", raw_text)),
            "ospf": self._parse_ospf_neighbor(sections.get("ospf_neighbor", raw_text)),
            "eigrp": self._parse_eigrp_neighbor(sections.get("eigrp_neighbor", raw_text)),
            "bgp": self._parse_bgp_summary(sections.get("bgp_summary", raw_text)),
            "mpls_ldp": self._parse_mpls_ldp(sections.get("mpls_ldp_neighbor", raw_text)),
            "vrf": self._parse_vrf(sections.get("vrf", raw_text)),
            "cdp_neighbors": cdp_neighbors,
            "lldp_neighbors": lldp_neighbors,
            "mac_table": mac_table,
            "arp_table": arp_table,
            "syslog": self._parse_logging(sections.get("logging", raw_text)),
            "flapping_ports": flapping_ports,
            "timeline": timeline,
            "raw_sections_found": list(sections.keys())
        }
        
        # Merge status with counters, neighbor telemetry, MAC and ARP
        parsed_data["ports_table"] = self._build_unified_ports_table(
            parsed_data["interfaces_status"],
            parsed_data["interfaces_counters"],
            flapping_ports,
            cdp_neighbors=cdp_neighbors,
            lldp_neighbors=lldp_neighbors,
            mac_table=mac_table,
            arp_table=arp_table
        )
        
        return parsed_data

    def _split_sections(self, text: str) -> Dict[str, str]:
        """
        Splits text into known command sections based on command invocation headers.
        """
        sections = {}
        patterns = {
            "version": r"(?:show\s+version|sh\s+ver)",
            "interfaces_status": r"(?:show\s+(?:interfaces|int)\s+status|sh\s+int\s+stat)",
            "interfaces_detailed": r"(?:show\s+(?:interfaces|int)\b(?!\s+(?:status|trunk|transceiver|brief))|sh\s+int\b(?!\s+stat))",
            "etherchannel": r"(?:show\s+etherchannel\s+summary|sh\s+ether(?:channel)?\s+sum)",
            "stack": r"(?:show\s+switch(?!\s+detail)|\bsh\s+switch\b)",
            "ospf_neighbor": r"(?:show\s+ip\s+ospf\s+neighbor|sh\s+ip\s+ospf\s+nei)",
            "eigrp_neighbor": r"(?:show\s+ip\s+eigrp\s+neighbors?|sh\s+ip\s+eigrp\s+nei)",
            "bgp_summary": r"(?:show\s+(?:ip\s+)?bgp\s+(?:all\s+|vpnv4\s+unicast\s+all\s+)?summary|sh\s+(?:ip\s+)?bgp\s+sum)",
            "mpls_ldp_neighbor": r"(?:show\s+mpls\s+ldp\s+neighbor|sh\s+mpls\s+ldp\s+nei)",
            "vrf": r"(?:show\s+(?:ip\s+)?vrf(?:\s+detail)?|sh\s+vrf)",
            "cdp_neighbors": r"(?:show\s+cdp\s+neighbors?(?:\s+detail)?|show\s+cdp\s+entry\s+\S+|sh\s+cdp\s+nei(?:\s+det)?)",
            "lldp_neighbors": r"(?:show\s+lldp\s+neighbors?(?:\s+detail)?|sh\s+lldp\s+nei(?:\s+det)?)",
            "mac_table": r"(?:show\s+mac(?:\s+address-table)?|sh\s+mac(?:\s+add)?)",
            "arp_table": r"(?:show\s+ip\s+arp|sh\s+ip\s+arp)",
            "routing": r"(?:show\s+ip\s+route|sh\s+ip\s+ro)",
            "logging": r"(?:show\s+log(?:ging)?|sh\s+log)"
        }

        # Find match indices
        matches = []
        for sec_name, pat in patterns.items():
            for m in re.finditer(rf"^[^\n\r#]*#?\s*{pat}.*?$", text, flags=re.MULTILINE | re.IGNORECASE):
                matches.append((m.start(), sec_name))
        
        # Sort and deduplicate matches
        seen_starts = set()
        unique_matches = []
        for start_idx, sec_name in sorted(matches, key=lambda x: x[0]):
            if start_idx not in seen_starts:
                unique_matches.append((start_idx, sec_name))
                seen_starts.add(start_idx)
        
        if unique_matches:
            for i in range(len(unique_matches)):
                start_idx, sec_name = unique_matches[i]
                end_idx = unique_matches[i + 1][0] if i + 1 < len(unique_matches) else len(text)
                sections[sec_name] = text[start_idx:end_idx]
        
        return sections

    def _parse_version(self, text: str) -> Dict[str, Any]:
        info = {
            "model": "Cisco Generic Switch",
            "uptime": "Unknown",
            "version": "Unknown",
            "serial": "Unknown"
        }
        m_model = re.search(r'(?:cisco\s+|Model Number\s*:\s*)(WS-C\S+|C9\S+|Catalyst\s+\S+)', text, re.I)
        if m_model:
            info["model"] = m_model.group(1).strip()
            
        m_up = re.search(r'uptime is\s+(.+)', text, re.I)
        uptime_days = 1.0
        if m_up:
            up_str = m_up.group(1).strip()
            info["uptime"] = up_str
            uptime_days = self._parse_uptime_days(up_str)
        info["uptime_days"] = uptime_days
            
        m_ver = re.search(r'(?:Version|Software\s+Version)\s+([\d\.\(\)\w\:]+)', text, re.I)
        if m_ver:
            info["version"] = m_ver.group(1).strip()
            
        m_sn = re.search(r'(?:System Serial Number|Processor board ID)\s*:\s*(\w+)', text, re.I)
        if m_sn:
            info["serial"] = m_sn.group(1).strip()
            
        return info

    def _parse_uptime_days(self, uptime_str: str) -> float:
        """
        Parses Cisco uptime string into total days float.
        e.g. '14 weeks, 2 days, 4 hours, 18 minutes' -> 100.18 days
        """
        days = 0.0
        m_yr = re.search(r'(\d+)\s+year', uptime_str)
        if m_yr: days += int(m_yr.group(1)) * 365
        m_wk = re.search(r'(\d+)\s+week', uptime_str)
        if m_wk: days += int(m_wk.group(1)) * 7
        m_day = re.search(r'(\d+)\s+day', uptime_str)
        if m_day: days += int(m_day.group(1))
        m_hr = re.search(r'(\d+)\s+hour', uptime_str)
        if m_hr: days += int(m_hr.group(1)) / 24.0
        return max(0.1, round(days, 2))

    def _parse_interfaces_status(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show interfaces status`
        Format:
        Port      Name               Status       Vlan       Duplex  Speed Type
        Gi1/0/1   Uplink-Core        connected    trunk      a-full a-1000 10/100/1000BaseTX
        Gi1/0/2                      notconnect   1            auto   auto 10/100/1000BaseTX
        Gi1/0/3                      err-disabled 10           auto   auto 10/100/1000BaseTX
        """
        results = []
        lines = text.splitlines()
        header_found = False
        
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            if re.match(r"^Port\s+Name\s+Status", line_str, re.I):
                header_found = True
                continue
            
            if header_found:
                # Cisco switchport pattern:
                # e.g. Gi1/0/1, Fa0/1, Te1/0/48, Po1
                m = re.match(r"^([A-Za-z0-9\/\.\-]+)\s+(.*?)\s+(connected|notconnect|err-disabled|disabled|faulty|inactive|suspended)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", line_str, re.I)
                if m:
                    results.append({
                        "port": m.group(1),
                        "description": m.group(2).strip(),
                        "status": m.group(3).lower(),
                        "vlan": m.group(4),
                        "duplex": m.group(5),
                        "speed": m.group(6),
                        "type": (m.group(7) or "").strip()
                    })
        return results

    def _parse_interfaces_detailed(self, text: str) -> Dict[str, Dict[str, Any]]:
        """
        Parses `show interfaces` counters:
        - In octets, Out octets
        - In errors, CRC, frame, buffer
        - Output errors, collisions
        - Drops / resets
        """
        interfaces = {}
        chunks = re.split(r"(?=\b(?:GigabitEthernet|FastEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|Port-channel|Vlan|Loopback)\d)", text)
        
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk:
                continue
            
            # Port identifier
            m_id = re.match(r"^([A-Za-z0-9\/\.\-]+)\s+is\s+(up|down|administratively down)", chunk, re.I)
            if not m_id:
                continue
            port_name = m_id.group(1)
            oper_status = m_id.group(2).lower()
            
            # Shorthand port name
            short_port = self._normalize_port(port_name)
            
            # Counters
            in_bytes = 0
            out_bytes = 0
            in_errors = 0
            crc_errors = 0
            out_errors = 0
            collisions = 0
            in_drops = 0
            out_drops = 0
            
            # 5 minute input rate
            m_in_rate = re.search(r"5 minute input rate\s+(\d+)\s+bits/sec", chunk)
            input_rate = int(m_in_rate.group(1)) if m_in_rate else 0
            
            m_out_rate = re.search(r"5 minute output rate\s+(\d+)\s+bits/sec", chunk)
            output_rate = int(m_out_rate.group(1)) if m_out_rate else 0
            
            m_in_pkt = re.search(r"(\d+)\s+bytes,\s+(\d+)\s+no buffer", chunk)
            if m_in_pkt:
                in_bytes = int(m_in_pkt.group(1))
                
            m_in_err = re.search(r"(\d+)\s+input errors,\s+(\d+)\s+CRC,\s+(\d+)\s+frame", chunk)
            if m_in_err:
                in_errors = int(m_in_err.group(1))
                crc_errors = int(m_in_err.group(2))
                
            m_out_err = re.search(r"(\d+)\s+output errors,\s+(\d+)\s+collisions", chunk)
            if m_out_err:
                out_errors = int(m_out_err.group(1))
                collisions = int(m_out_err.group(2))
                
            m_drops = re.search(r"Input queue:\s+\d+\/\d+\/(\d+)\/\d+", chunk)
            if m_drops:
                in_drops = int(m_drops.group(1))
                
            m_out_drops = re.search(r"Total output drops:\s+(\d+)", chunk)
            if m_out_drops:
                out_drops = int(m_out_drops.group(1))
                
            interfaces[short_port] = {
                "full_name": port_name,
                "oper_status": oper_status,
                "input_rate_bps": input_rate,
                "output_rate_bps": output_rate,
                "in_bytes": in_bytes,
                "in_errors": in_errors,
                "crc_errors": crc_errors,
                "out_errors": out_errors,
                "collisions": collisions,
                "in_drops": in_drops,
                "out_drops": out_drops
            }
        return interfaces

    def _parse_etherchannel(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show etherchannel summary`
        Format:
        Group  Port-channel  Protocol    Ports
        ------+-------------+-----------+-----------------------------------------------
        1      Po1(SU)         LACP      Gi1/0/1(P)    Gi1/0/2(s)
        2      Po2(SD)          -        Gi1/0/3(D)    Gi1/0/4(D)
        """
        groups = []
        lines = text.splitlines()
        header_passed = False
        
        for line in lines:
            line_str = line.strip()
            if "Port-channel" in line_str and "Protocol" in line_str:
                header_passed = True
                continue
            if re.match(r"^[\-\+]+$", line_str):
                continue
                
            if header_passed:
                # Group number, Po(status), Protocol, Ports...
                m = re.match(r"^(\d+)\s+(Po\d+(?:\([A-Za-z]+\))?)\s+(\S+)\s+(.*)$", line_str)
                if m:
                    grp_num = m.group(1)
                    po_name = m.group(2)
                    protocol = m.group(3)
                    ports_raw = m.group(4)
                    
                    # Parse individual member ports
                    member_ports = []
                    for pm in re.finditer(r"([A-Za-z0-9\/\.\-]+)\(([A-Za-z]+)\)", ports_raw):
                        p_name = self._normalize_port(pm.group(1))
                        p_flag = pm.group(2)
                        member_ports.append({
                            "port": p_name,
                            "flag": p_flag,
                            "is_bundled": "P" in p_flag,
                            "is_suspended": "s" in p_flag or "S" in p_flag,
                            "is_down": "D" in p_flag or "d" in p_flag
                        })
                    
                    po_status = "UP" if "(SU)" in po_name or "(RU)" in po_name else "DOWN"
                    groups.append({
                        "group": grp_num,
                        "bundle": po_name,
                        "protocol": protocol,
                        "status": po_status,
                        "members": member_ports,
                        "has_suspended": any(p["is_suspended"] for p in member_ports),
                        "has_down": any(p["is_down"] for p in member_ports)
                    })
        return groups

    def _parse_switch_stack(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show switch`
        Format:
        Switch#  Role      Mac Address     Priority Version  State
        ------------------------------------------------------------
        *1       Active    0018.ba3e.a200     15     V01     Ready
         2       Standby   0018.ba3e.b300     1      V01     Ready
         3       Member    0000.0000.0000     1      0       Provisioned
        """
        stack = []
        for line in text.splitlines():
            line_str = line.strip()
            m = re.match(r"^(\*?\d+)\s+(Active|Standby|Member)\s+([0-9a-fA-F\.]+)\s+(\d+)\s+(\S+)\s+(\S+)", line_str, re.I)
            if m:
                sw_num = m.group(1).replace("*", "")
                is_master = "*" in m.group(1)
                role = m.group(2)
                mac = m.group(3)
                prio = int(m.group(4))
                state = m.group(6)
                
                stack.append({
                    "switch_number": sw_num,
                    "is_master": is_master,
                    "role": role,
                    "mac": mac,
                    "priority": prio,
                    "state": state,
                    "is_healthy": state.lower() == "ready"
                })
        return stack

    def _parse_ip_route(self, text: str) -> Dict[str, Any]:
        """
        Parses `show ip route` overview and protocol breakdown
        """
        has_default_route = False
        default_next_hop = None
        
        m_gateway = re.search(r"Gateway of last resort is\s+(\S+)\s+to network\s+(\S+)", text)
        if m_gateway and m_gateway.group(1).lower() != "not":
            has_default_route = True
            default_next_hop = m_gateway.group(1)

        c_routes = len(re.findall(r"^[C]\s+\d+\.\d+\.\d+\.\d+", text, re.MULTILINE))
        s_routes = len(re.findall(r"^[S]\s+\d+\.\d+\.\d+\.\d+", text, re.MULTILINE))
        o_routes = len(re.findall(r"^[O][\sA-Z0-9\*]*\s+\d+\.\d+\.\d+\.\d+", text, re.MULTILINE))
        d_routes = len(re.findall(r"^[D][\sA-Z0-9\*]*\s+\d+\.\d+\.\d+\.\d+", text, re.MULTILINE))
        b_routes = len(re.findall(r"^[B][\sA-Z0-9\*]*\s+\d+\.\d+\.\d+\.\d+", text, re.MULTILINE))
        total_routes = c_routes + s_routes + o_routes + d_routes + b_routes
        if total_routes == 0:
            total_routes = len(re.findall(r"^[A-Z\*]{1,3}\s+\d+\.\d+\.\d+\.\d+", text, re.MULTILINE))

        return {
            "has_default_route": has_default_route,
            "default_next_hop": default_next_hop,
            "total_routes_detected": total_routes,
            "protocol_breakdown": {
                "connected": c_routes,
                "static": s_routes,
                "ospf": o_routes,
                "eigrp": d_routes,
                "bgp": b_routes
            }
        }

    def _parse_ospf_neighbor(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show ip ospf neighbor`
        """
        neighbors = []
        pat = r"(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+([A-Za-z0-9_\-]+)(?:/([A-Za-z0-9_\-]+|\s*-))?\s+(\d{2}:\d{2}:\d{2})\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)"
        for m in re.finditer(pat, text):
            nid = m.group(1)
            pri = int(m.group(2))
            state_raw = m.group(3).upper()
            role = (m.group(4) or "-").strip()
            dead_time = m.group(5)
            addr = m.group(6)
            intf = self._normalize_port(m.group(7))

            is_healthy = state_raw in ("FULL", "2WAY")
            anomaly = None
            if state_raw in ("EXSTART", "EXCHANGE"):
                anomaly = "MTU_MISMATCH"
            elif state_raw == "INIT":
                anomaly = "ONE_WAY_COMMUNICATION"
            elif state_raw in ("DOWN", "ATTEMPT"):
                anomaly = "NEIGHBOR_DOWN"

            neighbors.append({
                "neighbor_id": nid,
                "priority": pri,
                "state": state_raw,
                "role": role,
                "dead_time": dead_time,
                "address": addr,
                "interface": intf,
                "is_healthy": is_healthy,
                "anomaly": anomaly
            })
        return neighbors

    def _parse_eigrp_neighbor(self, text: str) -> Dict[str, Any]:
        """
        Parses `show ip eigrp neighbors`
        """
        as_match = re.search(r"AS\((\d+)\)", text)
        as_num = as_match.group(1) if as_match else None

        peers = []
        pat = r"^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)"
        for line in text.splitlines():
            m = re.match(pat, line)
            if m:
                peers.append({
                    "handle": m.group(1),
                    "address": m.group(2),
                    "interface": self._normalize_port(m.group(3)),
                    "hold_time": int(m.group(4)),
                    "uptime": m.group(5),
                    "srtt": int(m.group(6)),
                    "rto": int(m.group(7)),
                    "q_cnt": int(m.group(8)),
                    "seq_num": int(m.group(9)),
                    "is_healthy": int(m.group(8)) == 0
                })
        return {
            "as_number": as_num,
            "peers": peers
        }

    def _parse_bgp_summary(self, text: str) -> Dict[str, Any]:
        """
        Parses `show ip bgp summary` / `show bgp vpnv4 unicast all summary`
        """
        router_id = None
        local_as = None
        m_head = re.search(r"BGP router identifier\s+(\S+),\s+local AS number\s+(\d+)", text, re.I)
        if m_head:
            router_id = m_head.group(1)
            local_as = m_head.group(2)

        peers = []
        for line in text.splitlines():
            line_s = line.strip()
            if not line_s or line_s.startswith("Neighbor") or line_s.startswith("BGP") or line_s.startswith("Address"):
                continue
            m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+?)\s*$", line)
            if m:
                peer_ip = m.group(1)
                ver = m.group(2)
                remote_as = m.group(3)
                up_down = m.group(9)
                state_pfx = m.group(10).strip()

                is_established = False
                pfx_rcvd = None
                state = state_pfx
                anomaly = None

                if state_pfx.isdigit():
                    is_established = True
                    pfx_rcvd = int(state_pfx)
                    state = "Established"
                    if pfx_rcvd == 0:
                        anomaly = "ZERO_PREFIXES"
                else:
                    if "Active" in state_pfx:
                        anomaly = "TCP179_BLOCKED_OR_REFUSED"
                    elif "Idle (Admin)" in state_pfx:
                        anomaly = "ADMIN_SHUTDOWN"
                    elif "Idle" in state_pfx:
                        anomaly = "NO_ROUTE_OR_UPDATE_SOURCE"
                    elif "Connect" in state_pfx:
                        anomaly = "TCP_CONNECTING_TIMEOUT"

                peers.append({
                    "neighbor": peer_ip,
                    "version": ver,
                    "remote_as": remote_as,
                    "up_down": up_down,
                    "state": state,
                    "pfx_rcvd": pfx_rcvd,
                    "is_established": is_established,
                    "anomaly": anomaly
                })

        return {
            "router_id": router_id,
            "local_as": local_as,
            "peers": peers
        }

    def _parse_mpls_ldp(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show mpls ldp neighbor`
        """
        peers = []
        peer_blocks = re.split(r"(?=Peer LDP Ident:)", text)
        for blk in peer_blocks:
            m_id = re.search(r"Peer LDP Ident:\s*([0-9\.\:]+)", blk)
            if m_id:
                peer_id = m_id.group(1)
                m_state = re.search(r"State:\s*([A-Za-z0-9_\-]+)", blk)
                state = m_state.group(1) if m_state else "Unknown"
                is_oper = "oper" in state.lower()
                peers.append({
                    "peer_id": peer_id,
                    "state": state,
                    "is_operational": is_oper
                })
        return peers

    def _parse_vrf(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show ip vrf` / `show vrf detail`
        """
        vrfs = []
        pat = r"^\s*([A-Za-z0-9_\-]+)\s+(\d+:\d+|<not set>)\s*(.*)$"
        for line in text.splitlines():
            m = re.match(pat, line)
            if m and not line.strip().startswith("Name"):
                name = m.group(1)
                rd = m.group(2)
                intfs = m.group(3).strip()
                vrfs.append({
                    "name": name,
                    "rd": rd,
                    "interfaces": intfs,
                    "has_rd": rd != "<not set>"
                })
    def _parse_cdp_neighbors(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show cdp neighbors detail` or `show cdp neighbors`
        Returns a list of neighbor dictionaries.
        """
        neighbors = []
        if not text:
            return neighbors

        # Check if detail format exists
        if re.search(r"Device\s*ID\s*:", text, re.I):
            blocks = re.split(r"(?=-------------------------|Device\s*ID\s*:)", text)
            for blk in blocks:
                m_dev = re.search(r"Device\s*ID\s*:\s*([^\r\n]+)", blk, re.I)
                if not m_dev:
                    continue
                dev_id = m_dev.group(1).strip()
                
                # Management IP
                m_ip = re.search(r"IP\s*address\s*:\s*([0-9\.]+)", blk, re.I)
                mgmt_ip = m_ip.group(1) if m_ip else ""

                # Platform and capabilities
                m_plat = re.search(r"Platform\s*:\s*([^,]+)(?:,\s*Capabilities\s*:\s*([^\r\n]+))?", blk, re.I)
                platform = m_plat.group(1).strip() if m_plat and m_plat.group(1) else ""
                capabilities = m_plat.group(2).strip() if m_plat and m_plat.group(2) else ""

                # Interface and Port ID
                m_intf = re.search(r"Interface\s*:\s*([^,]+),\s*Port\s*ID\s*(?:\(outgoing\s*port\)\s*)?:\s*([^\r\n]+)", blk, re.I)
                if m_intf:
                    local_raw = m_intf.group(1).strip()
                    remote_port = m_intf.group(2).strip()
                else:
                    local_raw = ""
                    remote_port = ""

                # Native VLAN
                m_nvlan = re.search(r"Native\s*VLAN\s*:\s*(\d+)", blk, re.I)
                native_vlan = int(m_nvlan.group(1)) if m_nvlan else None

                # Duplex
                m_dup = re.search(r"Duplex\s*:\s*([A-Za-z]+)", blk, re.I)
                duplex = m_dup.group(1).lower() if m_dup else ""

                local_port = self._normalize_port(local_raw)
                remote_port_norm = self._normalize_port(remote_port)

                # Classify role
                plat_cap = (platform + " " + capabilities).lower()
                is_switch = "switch" in plat_cap or "ws-c" in plat_cap or "c9" in plat_cap or "n9k" in plat_cap
                is_router = "router" in plat_cap and not is_switch
                is_ap = "ap" in plat_cap or "air-" in plat_cap or "c91" in plat_cap
                is_phone = "phone" in plat_cap or "cp-" in plat_cap

                neighbors.append({
                    "protocol": "CDP",
                    "device_id": dev_id,
                    "local_port": local_port,
                    "remote_port": remote_port_norm,
                    "platform": platform,
                    "capabilities": capabilities,
                    "mgmt_ip": mgmt_ip,
                    "native_vlan": native_vlan,
                    "duplex": duplex,
                    "is_switch": is_switch,
                    "is_router": is_router,
                    "is_ap": is_ap,
                    "is_phone": is_phone
                })
        else:
            # Tabular show cdp neighbors
            lines = text.splitlines()
            header_passed = False
            pending_dev_id = ""

            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue
                if re.match(r"^Device\s+ID\s+Local\s+Intrfce", line_str, re.I):
                    header_passed = True
                    continue
                if not header_passed:
                    continue
                if re.match(r"^Capability\s+Codes", line_str, re.I) or re.match(r"^Total\s+cdp", line_str, re.I):
                    continue

                intf_match = re.search(r"\b(Gig|Fas|Ten|Twe|Eth|Port|Gi|Fa|Te|Fo|Hu)\s*([0-9\/\.\-]+)", line_str, re.I)
                parts = line_str.split()
                if not intf_match:
                    pending_dev_id = parts[0]
                    continue

                if pending_dev_id:
                    dev_id = pending_dev_id
                    pending_dev_id = ""
                    local_raw = parts[0] + (parts[1] if re.match(r"^\d", parts[1]) and not re.search(r"\d", parts[0]) else "")
                    rem = " ".join(parts[2:]) if (len(parts) > 1 and re.match(r"^\d", parts[1]) and not re.search(r"\d", parts[0])) else " ".join(parts[1:])
                else:
                    dev_id = parts[0]
                    # Local interface might be "Gig 1/0/24" (two tokens) or "Gig1/0/24" (one token)
                    if len(parts) > 2 and re.match(r"^[A-Za-z]+$", parts[1]) and re.match(r"^[0-9\/\.\-]+$", parts[2]):
                        local_raw = parts[1] + parts[2]
                        rem = " ".join(parts[3:])
                    else:
                        local_raw = parts[1]
                        rem = " ".join(parts[2:])

                # Extract remote port from the end
                remote_m = re.search(r"((?:Gig|Fas|Ten|Twe|Eth|Port|Gi|Fa|Te|Fo|Hu)\s*[0-9\/\.\-]+|Port\s*\d+|Eth\d+|[A-Za-z0-9\/\.\-]+)$", rem, re.I)
                remote_port = remote_m.group(1).replace(" ", "") if remote_m else ""

                local_port = self._normalize_port(local_raw.replace(" ", ""))
                remote_port_norm = self._normalize_port(remote_port)

                plat_cap = rem.lower()
                is_switch = "s" in plat_cap or "ws-c" in plat_cap or "c9" in plat_cap
                is_router = "r" in plat_cap
                is_ap = "air" in plat_cap or "ap" in plat_cap
                is_phone = "p" in plat_cap or "phone" in plat_cap

                neighbors.append({
                    "protocol": "CDP",
                    "device_id": dev_id,
                    "local_port": local_port,
                    "remote_port": remote_port_norm,
                    "platform": "",
                    "capabilities": "",
                    "mgmt_ip": "",
                    "native_vlan": None,
                    "duplex": "",
                    "is_switch": is_switch,
                    "is_router": is_router,
                    "is_ap": is_ap,
                    "is_phone": is_phone
                })

        return neighbors

    def _parse_lldp_neighbors(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show lldp neighbors detail` or `show lldp neighbors`
        """
        neighbors = []
        if not text:
            return neighbors

        if re.search(r"(?:Chassis\s*id:|System\s*Name:)", text, re.I):
            blocks = re.split(r"(?=-------------------------|Chassis\s*id:)", text)
            for blk in blocks:
                m_sys = re.search(r"System\s*Name\s*:\s*([^\r\n]+)", blk, re.I)
                m_chass = re.search(r"Chassis\s*id\s*:\s*([^\r\n]+)", blk, re.I)
                dev_id = (m_sys.group(1).strip() if m_sys else "") or (m_chass.group(1).strip() if m_chass else "")
                if not dev_id:
                    continue

                m_ip = re.search(r"Management\s*Addresses.*?IP:\s*([0-9\.]+)", blk, re.I | re.DOTALL)
                mgmt_ip = m_ip.group(1).strip() if m_ip else ""

                m_intf = re.search(r"Interface\s*:\s*([^,]+),\s*Port\s*ID\s*(?:\(outgoing\s*port\)\s*)?:\s*([^\r\n]+)", blk, re.I)
                if m_intf:
                    local_raw = m_intf.group(1).strip()
                    remote_port = m_intf.group(2).strip()
                else:
                    m_local = re.search(r"Local\s*Interface\s*:\s*([^\r\n]+)", blk, re.I)
                    local_raw = m_local.group(1).strip() if m_local else ""
                    m_rem = re.search(r"Port\s*id\s*:\s*([^\r\n]+)", blk, re.I)
                    remote_port = m_rem.group(1).strip() if m_rem else ""

                local_port = self._normalize_port(local_raw)
                remote_port_norm = self._normalize_port(remote_port)

                neighbors.append({
                    "protocol": "LLDP",
                    "device_id": dev_id,
                    "local_port": local_port,
                    "remote_port": remote_port_norm,
                    "platform": "",
                    "capabilities": "",
                    "mgmt_ip": mgmt_ip,
                    "native_vlan": None,
                    "duplex": "",
                    "is_switch": True,
                    "is_router": False,
                    "is_ap": False,
                    "is_phone": False
                })
        else:
            lines = text.splitlines()
            header_passed = False
            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue
                if re.match(r"^Device\s+ID\s+Local\s+Intf", line_str, re.I):
                    header_passed = True
                    continue
                if not header_passed or re.match(r"^Capability\s+codes", line_str, re.I):
                    continue

                parts = line_str.split()
                if len(parts) >= 5:
                    dev_id = parts[0]
                    local_raw = parts[1]
                    rem_port = parts[-1]
                    neighbors.append({
                        "protocol": "LLDP",
                        "device_id": dev_id,
                        "local_port": self._normalize_port(local_raw),
                        "remote_port": self._normalize_port(rem_port),
                        "platform": "",
                        "capabilities": "",
                        "mgmt_ip": "",
                        "native_vlan": None,
                        "duplex": "",
                        "is_switch": True,
                        "is_router": False,
                        "is_ap": False,
                        "is_phone": False
                    })

        return neighbors

    def _parse_mac_table(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show mac address-table [interface ...]`
        """
        entries = []
        if not text:
            return entries

        # Normalize spaced-out characters from terminal copies e.g. "D Y N A M I C"
        norm_text = re.sub(r"D\s+Y\s+N\s+A\s+M\s+I\s+C", "DYNAMIC", text, flags=re.I)
        norm_text = re.sub(r"S\s+T\s+A\s+T\s+I\s+C", "STATIC", norm_text, flags=re.I)

        for line in norm_text.splitlines():
            line_str = line.strip()
            # Match: Vlan  Mac_Address  Type  Ports
            # e.g.: 2007  0015.5d07.1e2d  DYNAMIC  Gi1/0/21
            m = re.match(r"^\s*(\d+|All)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|[0-9a-fA-F:]{17})\s+(\S+)\s+([A-Za-z0-9\/\.\-]+)", line_str)
            if m:
                vlan = m.group(1)
                mac = m.group(2).lower()
                mtype = m.group(3)
                port = self._normalize_port(m.group(4))
                entries.append({
                    "vlan": vlan,
                    "mac": mac,
                    "type": mtype,
                    "port": port
                })
        return entries

    def _parse_arp_table(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show ip arp [| include ...]`
        Format:
        Protocol  Address          Age (min)  Hardware Addr   Type   Interface
        Internet  10.20.7.35             14   0015.5d07.1e2d  ARPA   Vlan2007
        Internet  10.1.1.1                5   005d.73fe.dc00  ARPA   GigabitEthernet1/0/24
        """
        entries = []
        if not text:
            return entries

        for line in text.splitlines():
            line_str = line.strip()
            m = re.match(r"^\s*(?:Internet\s+)?([0-9\.]+)\s+(\S+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|[0-9a-fA-F:]{17})\s+(\S+)\s+([A-Za-z0-9\/\.\-]+)", line_str, re.I)
            if m:
                ip = m.group(1)
                age = m.group(2)
                mac = m.group(3).lower()
                encap = m.group(4)
                intf = self._normalize_port(m.group(5))
                entries.append({
                    "ip": ip,
                    "age": age,
                    "mac": mac,
                    "encap": encap,
                    "interface": intf
                })
        return entries

    def _parse_logging(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses `show logging` for critical Cisco Syslog events (%FACILITY-SEV-MNEMONIC)
        """
        events = []
        pattern = r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+):\s*(.*)"
        for line in text.splitlines():
            m = re.search(pattern, line)
            if m:
                facility = m.group(1)
                severity = int(m.group(2))
                mnemonic = m.group(3)
                message = m.group(4).strip()
                
                # We care primarily about critical, alert, error, warning, notification (0..5)
                if severity <= 5:
                    events.append({
                        "facility": facility,
                        "severity": severity,
                        "mnemonic": mnemonic,
                        "message": message,
                        "tag": f"%{facility}-{severity}-{mnemonic}"
                    })
        return events

    def _normalize_port(self, name: str) -> str:
        """
        Normalize port names e.g. GigabitEthernet1/0/1 -> Gi1/0/1
        """
        replacements = [
            (r"^GigabitEthernet", "Gi"),
            (r"^FastEthernet", "Fa"),
            (r"^TenGigabitEthernet", "Te"),
            (r"^TwentyFiveGigE", "Twe"),
            (r"^FortyGigabitEthernet", "Fo"),
            (r"^HundredGigE", "Hu"),
            (r"^Port-channel", "Po")
        ]
        for pat, repl in replacements:
            name = re.sub(pat, repl, name, flags=re.IGNORECASE)
        return name

    def _parse_timestamp(self, line: str, default_year: int = 2026) -> Optional[datetime]:
        """
        Parses Cisco timestamp formats:
        - Oct  7 07:16:21.396
        - *Oct 19 01:52:06.759
        - .Oct 10 08:44:53.991
        - Oct 19 2026 01:52:06
        - at 00:00:15 PST Sat Oct 10 2026
        - 2026-10-19T01:52:06
        """
        line_clean = line.strip()
        # 1. Standard Cisco: Oct  7 07:16:21.396 or *Oct 19 01:52:06
        m = re.match(r'^[\*\.]?\s*([A-Za-z]{3})\s+(\d+)\s+(?:(\d{4})\s+)?(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?', line_clean)
        if m:
            mon, day, yr, hr, minute, sec, _ms = m.groups()
            y = int(yr) if yr else default_year
            mon_idx = MONTHS_MAP.get(mon.lower(), 1)
            try:
                return datetime(y, mon_idx, int(day), int(hr), int(minute), int(sec))
            except ValueError:
                pass

        # 2. 'at 00:00:15 PST Sat Oct 10 2026' or '09:52:06 PST Mon Oct 19 2026'
        m2 = re.search(r'(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s+[A-Za-z]+\s+[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d+)\s+(\d{4})', line_clean)
        if m2:
            hr, minute, sec, mon, day, yr = m2.groups()
            mon_idx = MONTHS_MAP.get(mon.lower(), 1)
            try:
                return datetime(int(yr), mon_idx, int(day), int(hr), int(minute), int(sec))
            except ValueError:
                pass

        # 3. ISO format: 2026-10-19T01:52:06 or 2026-10-19 01:52:06
        m3 = re.search(r'(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})', line_clean)
        if m3:
            y, mon, d, h, mi, s = m3.groups()
            try:
                return datetime(int(y), int(mon), int(d), int(h), int(mi), int(s))
            except ValueError:
                pass

        return None

    def _build_chronological_timeline(self, text: str) -> Dict[str, Any]:
        """
        Builds a chronological timeline of all switch log events,
        identifying global start, end, recency, and clustering repetitive transitions.
        """
        # Detect year from text or default to current year
        m_yr = re.search(r'\b(202[0-9]|203[0-9])\b', text)
        detected_year = int(m_yr.group(1)) if m_yr else datetime.now().year

        lines = [l for l in text.splitlines() if l.strip()]
        line_records = []
        for line in lines:
            dt = self._parse_timestamp(line, detected_year)
            if dt:
                line_records.append((dt, line))

        if not line_records:
            return {
                "has_timeline": False,
                "detected_year": detected_year,
                "earliest_log": "N/A",
                "latest_log": "N/A",
                "latest_dt": None,
                "span_hours": 0.0,
                "span_days": 0.0,
                "active_count": 0,
                "recent_count": 0,
                "quiesced_count": 0,
                "events": []
            }

        # Sort all records chronologically
        line_records.sort(key=lambda x: x[0])
        earliest_dt = line_records[0][0]
        latest_dt = line_records[-1][0]
        span_hours = max(0.0, (latest_dt - earliest_dt).total_seconds() / 3600)
        span_days = span_hours / 24.0

        timeline_events = []
        i = 0
        while i < len(line_records):
            dt, line = line_records[i]
            diff_h = (latest_dt - dt).total_seconds() / 3600
            diff_d = diff_h / 24.0

            if diff_h > 24.0:
                recency_tag = "QUIESCED"
                time_ago_str = f"{diff_d:.1f} 天前"
            elif diff_h <= 2.0:
                recency_tag = "ACTIVE"
                time_ago_str = "剛才 / 進行中" if diff_h < 0.1 else f"{int(diff_h * 60)} 分鐘前"
            else:
                recency_tag = "RECENT"
                time_ago_str = f"{diff_h:.1f} 小時前"

            # Check for interface flap / updown pattern to cluster bursts
            m_flap = re.search(r"Interface\s+([A-Za-z0-9\/\.\-]+),\s+changed state to\s+(up|down)", line, re.I)
            if m_flap:
                port = self._normalize_port(m_flap.group(1))
                burst_records = [(dt, line, m_flap.group(2).lower())]
                j = i + 1
                while j < len(line_records):
                    next_dt, next_line = line_records[j]
                    next_flap = re.search(r"Interface\s+([A-Za-z0-9\/\.\-]+),\s+changed state to\s+(up|down)", next_line, re.I)
                    if next_flap and self._normalize_port(next_flap.group(1)) == port:
                        if (next_dt - burst_records[-1][0]).total_seconds() <= 3600:
                            burst_records.append((next_dt, next_line, next_flap.group(2).lower()))
                            j += 1
                            continue
                    break

                if len(burst_records) >= 2:
                    first_t = burst_records[0][0]
                    last_t = burst_records[-1][0]
                    flaps = sum(1 for b in burst_records if b[2] == "down")
                    end_diff_h = (latest_dt - last_t).total_seconds() / 3600
                    end_diff_d = end_diff_h / 24.0
                    end_tag = "QUIESCED" if end_diff_h > 24.0 else ("ACTIVE" if end_diff_h <= 2.0 else "RECENT")
                    end_ago_str = f"{end_diff_d:.1f} 天前" if end_diff_h > 24.0 else (f"{end_diff_h:.1f} 小時前" if end_diff_h >= 1 else "剛才")

                    timeline_events.append({
                        "timestamp": f"{first_t.strftime('%b %d %H:%M:%S')} ~ {last_t.strftime('%H:%M:%S')}",
                        "category": "LINK_FLAP",
                        "target": port,
                        "title": f"{port} 連線狀態震盪 (累積 {len(burst_records)} 次狀態轉換 / {flaps} 次斷線)",
                        "detail": f"最後震盪發生於 {last_t.strftime('%b %d %H:%M:%S')}。距最新日誌已平息 {end_diff_h:.1f} 小時 ({end_diff_d:.1f} 天)，後續無復發跡象。",
                        "recency_tag": end_tag,
                        "time_ago_str": end_ago_str,
                        "hours_ago": round(end_diff_h, 1),
                        "days_ago": round(end_diff_d, 1),
                        "is_quiesced": end_diff_h > 24.0
                    })
                    i = j
                    continue

            # Standard Syslog Event
            m_sys = re.search(r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+):\s*(.*)", line)
            if m_sys:
                fac, sev, mne, msg = m_sys.groups()
                tag = f"%{fac}-{sev}-{mne}"
                title = tag
                category = "GENERAL_SYSLOG"
                target = tag

                if "LOGIN_SUCCESS" in mne:
                    category = "ADMIN_LOGIN"
                    m_u = re.search(r"user:\s*([^\s\]]+)", msg)
                    m_ip = re.search(r"Source:\s*([^\s\]]+)", msg)
                    user_str = m_u.group(1) if m_u else "admin"
                    ip_str = m_ip.group(1) if m_ip else "unknown"
                    title = f"管理員 {user_str} SSH 登入成功"
                    target = f"user: {user_str}"
                    msg = f"來源 IP: {ip_str}，連線正常建立"
                elif "LOGOUT" in mne:
                    category = "ADMIN_LOGOUT"
                    m_u = re.search(r"User\s+([^\s]+)", msg)
                    user_str = m_u.group(1) if m_u else "admin"
                    title = f"管理員 {user_str} 登出會話"
                    target = f"user: {user_str}"
                elif "SMART_LIC" in fac:
                    category = "LICENSE_NOTICE"
                    title = "Cisco Smart Licensing 評估授權提醒"
                    target = "Smart Licensing"
                elif "UPDOWN" in mne:
                    category = "LINK_STATE"
                    m_p = re.search(r"Interface\s+([A-Za-z0-9\/\.\-]+)", msg)
                    target = self._normalize_port(m_p.group(1)) if m_p else "Interface"
                    title = f"{target} 狀態變更"
                elif "ADJ" in mne or "NBR" in mne:
                    category = "ROUTING_EVENT"
                    title = f"動態路由鄰居事件: {tag}"
                    target = fac

                timeline_events.append({
                    "timestamp": dt.strftime('%b %d %H:%M:%S'),
                    "category": category,
                    "target": target,
                    "title": title,
                    "detail": msg,
                    "recency_tag": recency_tag,
                    "time_ago_str": time_ago_str,
                    "hours_ago": round(diff_h, 1),
                    "days_ago": round(diff_d, 1),
                    "is_quiesced": diff_h > 24.0
                })
            else:
                timeline_events.append({
                    "timestamp": dt.strftime('%b %d %H:%M:%S'),
                    "category": "EVENT",
                    "target": "System",
                    "title": line[:50],
                    "detail": line,
                    "recency_tag": recency_tag,
                    "time_ago_str": time_ago_str,
                    "hours_ago": round(diff_h, 1),
                    "days_ago": round(diff_d, 1),
                    "is_quiesced": diff_h > 24.0
                })
            i += 1

        active_cnt = sum(1 for e in timeline_events if e["recency_tag"] == "ACTIVE")
        recent_cnt = sum(1 for e in timeline_events if e["recency_tag"] == "RECENT")
        quiesced_cnt = sum(1 for e in timeline_events if e["recency_tag"] == "QUIESCED")

        return {
            "has_timeline": True,
            "detected_year": detected_year,
            "earliest_log": earliest_dt.strftime('%b %d %H:%M:%S'),
            "latest_log": latest_dt.strftime('%b %d %H:%M:%S'),
            "latest_dt_iso": latest_dt.isoformat(),
            "_latest_dt": latest_dt,
            "span_hours": round(span_hours, 1),
            "span_days": round(span_days, 1),
            "active_count": active_cnt,
            "recent_count": recent_cnt,
            "quiesced_count": quiesced_cnt,
            "events": timeline_events
        }

    def _analyze_flapping_ports(self, text: str, global_timeline: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Detects interfaces that have frequent up/down state transitions (Link Flapping)
        and calculates flap count, timestamps, severity, and time-elapsed quiescence.
        """
        flaps_by_port = {}
        pattern = r'(?:([A-Za-z]{3}\s+\d+\s+[\d\:\.]+):?\s+)?.*?Interface\s+([A-Za-z0-9\/\.\-]+),\s+changed state to\s+(up|down)'
        
        for m in re.finditer(pattern, text, re.I):
            ts = m.group(1) or ""
            raw_p = m.group(2)
            state = m.group(3).lower()
            port = self._normalize_port(raw_p)
            
            if port not in flaps_by_port:
                flaps_by_port[port] = {
                    "port": port,
                    "down_count": 0,
                    "up_count": 0,
                    "transitions": [],
                    "first_seen": ts,
                    "last_seen": ts
                }
            
            entry = flaps_by_port[port]
            entry["transitions"].append({"state": state, "time": ts})
            if state == "down":
                entry["down_count"] += 1
            elif state == "up":
                entry["up_count"] += 1
                
            if ts:
                if not entry["first_seen"]:
                    entry["first_seen"] = ts
                entry["last_seen"] = ts

        detected_year = global_timeline.get("detected_year", 2026) if global_timeline else 2026
        latest_dt = global_timeline.get("_latest_dt") if global_timeline else None

        results = []
        for p, data in flaps_by_port.items():
            flaps = data["down_count"]
            if flaps >= 2 or len(data["transitions"]) >= 3:
                # Time elapsed calculation relative to latest log
                hours_since_latest = 0.0
                days_since_latest = 0.0
                is_historical_quiesced = False
                is_active_flapping = True

                last_dt = self._parse_timestamp(data["last_seen"], detected_year)
                if last_dt and latest_dt:
                    hours_since_latest = max(0.0, (latest_dt - last_dt).total_seconds() / 3600)
                    days_since_latest = hours_since_latest / 24.0
                    if hours_since_latest > 24.0:
                        is_historical_quiesced = True
                        is_active_flapping = False
                    elif hours_since_latest <= 2.0:
                        is_active_flapping = True
                    else:
                        is_active_flapping = False

                # Time-aware: check if last event occurred during off-hours (19:00 ~ 07:00)
                m_time = re.search(r"(\d{2}):(\d{2})", data["last_seen"])
                hour = int(m_time.group(1)) if m_time else None
                is_off_hours = bool(hour is not None and (hour >= 19 or hour < 7))

                if is_historical_quiesced:
                    severity = "NORMAL"
                elif flaps >= 3:
                    severity = "CRITICAL"
                else:
                    severity = "HIGH"

                results.append({
                    "port": p,
                    "flap_cycles": flaps,
                    "total_events": len(data["transitions"]),
                    "down_count": data["down_count"],
                    "up_count": data["up_count"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "hour": hour,
                    "is_off_hours": is_off_hours,
                    "hours_since_latest": round(hours_since_latest, 1),
                    "days_since_latest": round(days_since_latest, 1),
                    "is_historical_quiesced": is_historical_quiesced,
                    "is_active_flapping": is_active_flapping,
                    "severity": severity
                })
                
        results.sort(key=lambda x: x["flap_cycles"], reverse=True)
        return results

    def _build_unified_ports_table(self, status_list: List[Dict], counters_dict: Dict, flapping_ports: List[Dict] = None,
                                  cdp_neighbors: List[Dict] = None, lldp_neighbors: List[Dict] = None,
                                  mac_table: List[Dict] = None, arp_table: List[Dict] = None) -> List[Dict[str, Any]]:
        """
        Merges status, detailed counters, CDP/LLDP neighbors, MAC tables, and ARP records
        into a single unified list of port records for ML processing and CCIE topology correlation.
        """
        ports_dict = {}
        
        # 1. Populate from status list
        for s in status_list:
            short_p = self._normalize_port(s["port"])
            ports_dict[short_p] = {
                "port": short_p,
                "description": s.get("description", ""),
                "status": s.get("status", "unknown"),
                "vlan": s.get("vlan", "1"),
                "duplex": s.get("duplex", "auto"),
                "speed": s.get("speed", "auto"),
                "input_rate_bps": 0,
                "output_rate_bps": 0,
                "in_errors": 0,
                "crc_errors": 0,
                "out_errors": 0,
                "collisions": 0,
                "in_drops": 0,
                "out_drops": 0
            }
            
        # 2. Merge with detailed counters if present
        for p, c in counters_dict.items():
            short_p = self._normalize_port(p)
            if short_p not in ports_dict:
                ports_dict[short_p] = {
                    "port": short_p,
                    "description": "",
                    "status": c.get("oper_status", "unknown"),
                    "vlan": "1",
                    "duplex": "auto",
                    "speed": "auto",
                    "input_rate_bps": c.get("input_rate_bps", 0),
                    "output_rate_bps": c.get("output_rate_bps", 0),
                    "in_errors": c.get("in_errors", 0),
                    "crc_errors": c.get("crc_errors", 0),
                    "out_errors": c.get("out_errors", 0),
                    "collisions": c.get("collisions", 0),
                    "in_drops": c.get("in_drops", 0),
                    "out_drops": c.get("out_drops", 0)
                }
            else:
                ports_dict[short_p]["input_rate_bps"] = c.get("input_rate_bps", 0)
                ports_dict[short_p]["output_rate_bps"] = c.get("output_rate_bps", 0)
                ports_dict[short_p]["in_errors"] = c.get("in_errors", 0)
                ports_dict[short_p]["crc_errors"] = c.get("crc_errors", 0)
                ports_dict[short_p]["out_errors"] = c.get("out_errors", 0)
                ports_dict[short_p]["collisions"] = c.get("collisions", 0)
                ports_dict[short_p]["in_drops"] = c.get("in_drops", 0)
                ports_dict[short_p]["out_drops"] = c.get("out_drops", 0)

        # 3. Ensure flapping ports from syslog are reflected even if status commands were omitted
        if flapping_ports:
            for f in flapping_ports:
                p = f["port"]
                if p not in ports_dict:
                    ports_dict[p] = {
                        "port": p,
                        "description": f"Syslog Flapping ({f['flap_cycles']} 次震盪)",
                        "status": "flapping",
                        "vlan": "unknown",
                        "duplex": "unknown",
                        "speed": "unknown",
                        "input_rate_bps": 0,
                        "output_rate_bps": 0,
                        "in_errors": 0,
                        "crc_errors": 0,
                        "out_errors": 0,
                        "collisions": 0,
                        "in_drops": 0,
                        "out_drops": 0
                    }
                else:
                    ports_dict[p]["is_flapping"] = True
                    ports_dict[p]["flap_cycles"] = f["flap_cycles"]
                    if ports_dict[p]["status"] in ("unknown", ""):
                        ports_dict[p]["status"] = "flapping"

        # 4. Map CDP / LLDP Neighbor Telemetry
        cdp_by_port = {}
        if cdp_neighbors:
            for n in cdp_neighbors:
                lp = n.get("local_port")
                if lp:
                    cdp_by_port[lp] = n

        lldp_by_port = {}
        if lldp_neighbors:
            for n in lldp_neighbors:
                lp = n.get("local_port")
                if lp:
                    lldp_by_port[lp] = n

        # 5. Map MAC Address Table entries
        macs_by_port = {}
        if mac_table:
            for m in mac_table:
                mp = m.get("port")
                if mp:
                    if mp not in macs_by_port:
                        macs_by_port[mp] = []
                    macs_by_port[mp].append(m)

        # 6. Map ARP records (by interface and by MAC)
        arp_by_intf = {}
        arp_by_mac = {}
        if arp_table:
            for a in arp_table:
                ai = a.get("interface")
                am = a.get("mac")
                if ai:
                    if ai not in arp_by_intf:
                        arp_by_intf[ai] = []
                    arp_by_intf[ai].append(a)
                if am:
                    arp_by_mac[am.lower()] = a.get("ip")

        # Ensure all referenced ports in CDP, LLDP, or MAC tables exist in ports_dict
        all_referenced_ports = set(list(ports_dict.keys()) + list(cdp_by_port.keys()) + list(lldp_by_port.keys()) + list(macs_by_port.keys()))
        for p in all_referenced_ports:
            if p not in ports_dict:
                ports_dict[p] = {
                    "port": p,
                    "description": "",
                    "status": "connected",
                    "vlan": "1",
                    "duplex": "auto",
                    "speed": "auto",
                    "input_rate_bps": 0,
                    "output_rate_bps": 0,
                    "in_errors": 0,
                    "crc_errors": 0,
                    "out_errors": 0,
                    "collisions": 0,
                    "in_drops": 0,
                    "out_drops": 0
                }

        # 7. Enrich each port record with topology and addressing metadata
        for p, record in ports_dict.items():
            cdp_info = cdp_by_port.get(p)
            lldp_info = lldp_by_port.get(p)
            mac_list = [m["mac"] for m in macs_by_port.get(p, [])]

            ip_list = []
            for m in mac_list:
                if m in arp_by_mac:
                    ip = arp_by_mac[m]
                    if ip not in ip_list:
                        ip_list.append(ip)
            for a in arp_by_intf.get(p, []):
                if a["ip"] not in ip_list:
                    ip_list.append(a["ip"])

            record["cdp_neighbor"] = cdp_info
            record["lldp_neighbor"] = lldp_info
            record["mac_addresses"] = mac_list
            record["ip_addresses"] = ip_list

            if cdp_info:
                record["peer_device"] = cdp_info.get("device_id", "")
                record["peer_port"] = cdp_info.get("remote_port", "")
                record["peer_ip"] = cdp_info.get("mgmt_ip", "")
                record["peer_platform"] = cdp_info.get("platform", "")
                record["peer_type"] = "Switch" if cdp_info.get("is_switch") else ("AP" if cdp_info.get("is_ap") else ("Phone" if cdp_info.get("is_phone") else "Endpoint"))
            elif lldp_info:
                record["peer_device"] = lldp_info.get("device_id", "")
                record["peer_port"] = lldp_info.get("remote_port", "")
                record["peer_ip"] = lldp_info.get("mgmt_ip", "")
                record["peer_platform"] = lldp_info.get("platform", "")
                record["peer_type"] = "Device"
            elif ip_list:
                record["peer_device"] = f"Host ({', '.join(ip_list)})"
                record["peer_port"] = ""
                record["peer_ip"] = ip_list[0]
                record["peer_platform"] = "Endpoint Host"
                record["peer_type"] = "Host"
            elif mac_list:
                record["peer_device"] = f"Host ({len(mac_list)} MACs)"
                record["peer_port"] = ""
                record["peer_ip"] = ""
                record["peer_platform"] = "Endpoint NIC"
                record["peer_type"] = "Unmanaged Switch" if len(mac_list) >= 3 else "Host"
            else:
                record["peer_device"] = ""
                record["peer_port"] = ""
                record["peer_ip"] = ""
                record["peer_platform"] = ""
                record["peer_type"] = "None"
                
        return list(ports_dict.values())
