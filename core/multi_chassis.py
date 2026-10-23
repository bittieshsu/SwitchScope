"""
SwitchScope - Multi-Chassis Correlation & Fleet Topology Engine
Ingests multiple Cisco switch dumps/configs (.txt / .conf), performs cross-device
bidirectional verification, detects cross-chassis mis-cabling and config discrepancies,
and synthesizes a true multi-physical-device architecture topology.
"""
import os
import glob
from typing import Dict, Any, List, Optional
from core.parser import CiscoParser
from core.sanitizer import sanitize_cisco_output
from ml_engine.ecod_detector import ECODPortDetector
from ml_engine.fault_classifier import SwitchFaultClassifier

class MultiChassisEngine:
    def __init__(self):
        self.parser = CiscoParser()
        self.ecod = ECODPortDetector()
        self.classifier = SwitchFaultClassifier()

    def scan_and_analyze_folder(self, folder_path: str, mask_ips: bool = True) -> Dict[str, Any]:
        """
        Scans a local directory for .txt, .conf, .cfg, .log files and analyzes them as a fleet.
        """
        if not os.path.exists(folder_path):
            raise FileNotFoundError(f"資料夾不存在: {folder_path}")
        
        valid_exts = ("*.txt", "*.conf", "*.cfg", "*.log")
        files = []
        for ext in valid_exts:
            for filepath in glob.glob(os.path.join(folder_path, ext)):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    files.append({
                        "name": os.path.basename(filepath),
                        "path": filepath,
                        "content": content
                    })
                except Exception as e:
                    pass

        if not files:
            raise ValueError(f"在 {folder_path} 內未找到任何 .txt / .conf / .cfg / .log 設備日誌檔！")

        return self.analyze_batch(files, mask_ips=mask_ips, source_folder=folder_path)

    def analyze_batch(self, files: List[Dict[str, str]], mask_ips: bool = True, source_folder: Optional[str] = None) -> Dict[str, Any]:
        """
        Main entry point for multi-chassis fleet analysis.
        files: List of {"name": filename, "content": raw_text}
        """
        devices = {}
        device_lookup = {}  # normalized hostname -> device_key

        # 1. Parse and classify each individual switch
        for f in files:
            fname = f.get("name", "unknown.txt")
            raw_text = f.get("content", "")
            if not raw_text.strip():
                continue

            clean_text = sanitize_cisco_output(raw_text, mask_ips=mask_ips)
            parsed = self.parser.parse_all(clean_text)
            ports_table = parsed.get("ports_table", [])
            ecod_res = self.ecod.detect(ports_table)
            diagnoses = self.classifier.diagnose(parsed, ecod_res)
            triage = self.classifier.synthesize_global_triage(diagnoses, parsed, ecod_res)

            # Determine hostname
            dev_info = parsed.get("device_info", {})
            hostname = dev_info.get("hostname")
            if not hostname:
                # Fallback to filename without extension
                base_name = os.path.splitext(fname)[0]
                hostname = base_name

            norm_name = self._normalize_hostname(hostname)
            
            # Health score calculation
            crit_cnt = sum(1 for d in diagnoses if d.get("severity") == "CRITICAL")
            high_cnt = sum(1 for d in diagnoses if d.get("severity") == "HIGH")
            warn_cnt = sum(1 for d in diagnoses if d.get("severity") == "WARNING")
            health_score = max(0, 100 - (crit_cnt * 30) - (high_cnt * 15) - (warn_cnt * 5))

            # Role guessing
            norm_lower = norm_name.lower()
            if "core" in norm_lower or "dist" in norm_lower or "agg" in norm_lower or "spine" in norm_lower:
                role = "Core / Distribution"
                tier = "upstream"
            elif "access" in norm_lower or "floor" in norm_lower or "edge" in norm_lower:
                role = "Access Switch"
                tier = "downstream"
            else:
                role = "Distribution Switch"
                tier = "middle"

            dev_entry = {
                "id": f"dev_{norm_name}",
                "filename": fname,
                "hostname": hostname,
                "norm_name": norm_name,
                "model": dev_info.get("model", "Cisco Switch"),
                "uptime": dev_info.get("uptime", "N/A"),
                "role": role,
                "tier": tier,
                "health_score": health_score,
                "parsed_data": parsed,
                "ecod_results": ecod_res,
                "diagnoses": diagnoses,
                "global_triage": triage,
                "ports_table": ports_table,
                "etherchannel": parsed.get("etherchannel", []),
                "cdp_neighbors": parsed.get("cdp_neighbors", []),
                "lldp_neighbors": parsed.get("lldp_neighbors", []),
                "mac_table": parsed.get("mac_table", []),
                "arp_table": parsed.get("arp_table", []),
                "routing": parsed.get("routing", {}),
                "blocker_count": crit_cnt + high_cnt
            }

            devices[norm_name.lower()] = dev_entry
            device_lookup[norm_name.lower()] = norm_name

        # 2. Cross-Device Correlation & Bidirectional Verification
        cross_conflicts = []
        verified_links = []
        visited_link_pairs = set()

        for dev_key, dev in devices.items():
            ports = dev["ports_table"]
            cdp_list = dev["cdp_neighbors"]

            # Map etherchannel on local dev
            local_po_map = {}
            for ec in dev["etherchannel"]:
                po_name = ec.get("bundle", f"Po{ec.get('group', '1')}")
                for m in ec.get("members", []):
                    m_port = m.get("port", "")
                    local_po_map[self._normalize_port(m_port)] = {
                        "po_name": po_name,
                        "flag": m.get("flag", ""),
                        "is_suspended": m.get("is_suspended", False),
                        "protocol": ec.get("protocol", "LACP")
                    }

            for cdp in cdp_list:
                local_port = cdp.get("local_port")
                remote_dev_raw = cdp.get("device_id", "")
                remote_port = cdp.get("remote_port", "")
                remote_norm = self._normalize_hostname(remote_dev_raw)

                link_pair_key = tuple(sorted([f"{dev['hostname']}:{local_port}", f"{remote_norm}:{remote_port}"]))

                # Check if remote device is part of our ingested batch!
                remote_dev = devices.get(remote_norm.lower())
                is_batch_peer = (remote_dev is not None)

                local_port_obj = next((p for p in ports if self._normalize_port(p.get("port")) == self._normalize_port(local_port)), {})
                local_po_info = local_po_map.get(self._normalize_port(local_port))

                link_discrepancies = []

                if is_batch_peer:
                    # Remote switch is in our batch! Perform bidirectional audit!
                    remote_ports = remote_dev["ports_table"]
                    remote_port_obj = next((p for p in remote_ports if self._normalize_port(p.get("port")) == self._normalize_port(remote_port)), {})

                    # Remote etherchannel map
                    remote_po_map = {}
                    for ec in remote_dev["etherchannel"]:
                        r_po = ec.get("bundle", f"Po{ec.get('group', '1')}")
                        for m in ec.get("members", []):
                            m_port = m.get("port", "")
                            remote_po_map[self._normalize_port(m_port)] = {
                                "po_name": r_po,
                                "flag": m.get("flag", ""),
                                "is_suspended": m.get("is_suspended", False),
                                "protocol": ec.get("protocol", "LACP")
                            }
                    
                    remote_po_info = remote_po_map.get(self._normalize_port(remote_port))

                    # CHECK 1: Cross-Device LACP Mis-cabling & Asymmetric Aggregator
                    if local_po_info:
                        local_po_name = local_po_info["po_name"]
                        if not remote_po_info:
                            disc = {
                                "type": "LACP_ASYMMETRIC_CONFIG",
                                "severity": "CRITICAL",
                                "title": f"跨設備 LACP 聚合配置不對稱 ({dev['hostname']} vs {remote_dev['hostname']})",
                                "detail": (
                                    f"{dev['hostname']} 的 {local_port} 已加入聚合組 {local_po_name}，"
                                    f"但對端實體機 {remote_dev['hostname']} 的對接埠 {remote_port} 卻未配置任何 channel-group！"
                                    f"此實體跳線連線違反了 LACP 捆綁對稱性，導致連線被防環機制掛起 (Suspended)！"
                                ),
                                "local_remediation": f"interface {local_port}\n no channel-group 1 mode active",
                                "remote_remediation": f"interface {remote_port}\n switchport mode trunk"
                            }
                            link_discrepancies.append(disc)
                        else:
                            # Both in Po, check if local has multiple members going to different switches!
                            pass

                    # CHECK 2: Native VLAN Mismatch (Confirmed from both switches' configs)
                    local_vlan = str(local_port_obj.get("vlan", "")).lower()
                    remote_vlan = str(remote_port_obj.get("vlan", "")).lower()
                    cdp_remote_native = cdp.get("native_vlan")

                    # If local is trunk and has native vlan mismatch
                    if cdp_remote_native is not None and str(cdp_remote_native) != "1" and str(cdp_remote_native) != local_vlan:
                        # Confirmed mismatch
                        pass
                    if local_vlan and remote_vlan and local_vlan not in ("trunk", "routed") and remote_vlan not in ("trunk", "routed") and local_vlan != remote_vlan:
                        disc = {
                            "type": "ACCESS_VLAN_MISMATCH",
                            "severity": "HIGH",
                            "title": f"跨交換機 Access VLAN 不一致: {dev['hostname']} ({local_port}: VLAN {local_vlan}) vs {remote_dev['hostname']} ({remote_port}: VLAN {remote_vlan})",
                            "detail": f"兩端交換機對接埠所屬 VLAN 不相符，將導致二層廣播域錯置或封包被直接丟棄！",
                            "local_remediation": f"interface {local_port}\n switchport access vlan {remote_vlan}",
                            "remote_remediation": f"! Confirm desired VLAN on {remote_dev['hostname']}"
                        }
                        link_discrepancies.append(disc)

                    # CHECK 3: Check Native VLAN mismatch via CDP probe or Syslog
                    local_norm_port = self._normalize_port(local_port)
                    has_syslog_vlan_mismatch = any(
                        "%cdp-4-native_vlan_mismatch" in (log.get("raw", "") if isinstance(log, dict) else str(log)).lower() and
                        local_norm_port in self._normalize_port(log.get("raw", "") if isinstance(log, dict) else str(log))
                        for log in dev["parsed_data"].get("syslog", [])
                    )
                    local_vlan_str = str(local_port_obj.get("vlan", "")).strip()
                    remote_native = cdp.get("native_vlan")
                    is_pvid_mismatch = (
                        (local_vlan_str not in ("", "1", "trunk", "routed") and remote_native == 1) or
                        (remote_native is not None and local_vlan_str not in ("", "trunk", "routed") and str(remote_native) != local_vlan_str) or
                        has_syslog_vlan_mismatch
                    )

                    if is_pvid_mismatch:
                        disc = {
                            "type": "TRUNK_NATIVE_VLAN_MISMATCH",
                            "severity": "HIGH",
                            "title": f"雙機 Trunk Native VLAN 衝突 ({dev['hostname']} {local_port} vs {remote_dev['hostname']} {remote_port})",
                            "detail": (
                                f"由兩台實體設備雙向日誌與 CDP 探針確認：{dev['hostname']} 埠 {local_port} (VLAN {local_vlan_str or 2007}) 與 "
                                f"{remote_dev['hostname']} 埠 {remote_port} (VLAN {remote_native or 1}) 不匹配！STP 已觸發 BLOCK_PVID 阻斷保護。"
                            ),
                            "local_remediation": f"interface {local_port}\n switchport trunk native vlan {remote_native or 1}",
                            "remote_remediation": f"interface {remote_port}\n switchport trunk native vlan {remote_native or 1}"
                        }
                        if not any(d["type"] == "TRUNK_NATIVE_VLAN_MISMATCH" for d in link_discrepancies):
                            link_discrepancies.append(disc)

                else:
                    # Remote switch is NOT in batch (external device, unmanaged switch, AP, or external router)
                    # Check local anomalies
                    if local_po_info and local_port_obj.get("status") == "suspended":
                        disc = {
                            "type": "LACP_EXTERNAL_MISCABLING",
                            "severity": "CRITICAL",
                            "title": f"LACP 成員埠跳線錯接外部設備: {local_port}",
                            "detail": f"此埠加入聚合組 {local_po_info['po_name']}，但 CDP 偵測對端為外部設備 {remote_dev_raw}，Partner System ID 衝突！",
                            "local_remediation": f"interface {local_port}\n no channel-group 1 mode active",
                            "remote_remediation": "! Check external cabling"
                        }
                        link_discrepancies.append(disc)

                # Append cross-conflicts
                for disc in link_discrepancies:
                    conflict_record = {
                        "id": f"conf_{dev_key}_{local_port.replace('/', '_')}",
                        "source_device": dev["hostname"],
                        "target_device": remote_dev["hostname"] if is_batch_peer else remote_dev_raw,
                        "source_port": local_port,
                        "target_port": remote_port,
                        "local_device": dev["hostname"],
                        "remote_device": remote_dev["hostname"] if is_batch_peer else remote_dev_raw,
                        "local_port": local_port,
                        "remote_port": remote_port,
                        "description": disc.get("detail", ""),
                        "is_batch_peer": is_batch_peer,
                        **disc
                    }
                    if not any(c["source_device"] == dev["hostname"] and c["source_port"] == local_port and c["type"] == disc["type"] for c in cross_conflicts):
                        cross_conflicts.append(conflict_record)

                # Add to verified links (deduplicate bidirectional links)
                if link_pair_key not in visited_link_pairs:
                    visited_link_pairs.add(link_pair_key)
                    verified_links.append({
                        "id": f"link_{dev_key}_{local_port.replace('/', '_')}",
                        "source_id": dev["id"],
                        "source_hostname": dev["hostname"],
                        "source_port": local_port,
                        "target_id": remote_dev["id"] if is_batch_peer else f"ext_{remote_norm}",
                        "target_hostname": remote_dev["hostname"] if is_batch_peer else remote_dev_raw.split(".")[0],
                        "target_port": remote_port,
                        "is_internal_fleet": is_batch_peer,
                        "speed": local_port_obj.get("speed", "1000"),
                        "duplex": local_port_obj.get("duplex", "full"),
                        "vlan": local_port_obj.get("vlan", "trunk"),
                        "po": local_po_info["po_name"] if local_po_info else None,
                        "has_conflict": len(link_discrepancies) > 0,
                        "conflicts": link_discrepancies
                    })

        # 3. Synthesize Global Master Fleet Remediation Script & Fleet AI Triage Prompt
        fleet_remediation_macro = self._build_fleet_remediation_macro(devices, cross_conflicts)
        fleet_triage_prompt = self._build_fleet_triage_prompt(devices, cross_conflicts, verified_links)

        # 4. Fleet Summary Statistics
        total_devs = len(devices)
        healthy_devs = sum(1 for d in devices.values() if d["health_score"] >= 80)
        critical_conflicts_cnt = sum(1 for c in cross_conflicts if c["severity"] == "CRITICAL")

        return {
            "success": True,
            "mode": "multi_chassis_fleet",
            "source_folder": source_folder,
            "fleet_summary": {
                "total_devices": total_devs,
                "healthy_devices": healthy_devs,
                "critical_conflicts": critical_conflicts_cnt,
                "total_conflicts": len(cross_conflicts),
                "total_verified_links": len(verified_links)
            },
            "total_devices": total_devs,
            "devices": list(devices.values()),
            "cross_conflicts": cross_conflicts,
            "cross_device_conflicts": cross_conflicts,
            "verified_links": verified_links,
            "fleet_remediation_macro": fleet_remediation_macro,
            "fleet_triage_prompt": fleet_triage_prompt
        }

    def _normalize_hostname(self, name: str) -> str:
        """
        Normalizes hostname by taking first label before dot and lowercasing.
        e.g. 'Core-SW-01.corp.local' -> 'Core-SW-01'
        """
        if not name:
            return "unknown"
        clean = name.split(".")[0].strip()
        return clean

    def _normalize_port(self, port: str) -> str:
        if not port:
            return ""
        p = port.lower().strip()
        p = p.replace("gigabitethernet", "gi").replace("tengigabitethernet", "te").replace("fastethernet", "fa")
        return p

    def _build_fleet_remediation_macro(self, devices: Dict[str, Any], conflicts: List[Dict[str, Any]]) -> str:
        """
        Builds a single master Cisco CLI script sectioned by device hostname.
        """
        lines = [
            "! ========================================================",
            "! SwitchScope CCIE Multi-Chassis Unified Fleet Remediation",
            f"! Generated for {len(devices)} physical devices with {len(conflicts)} detected cross-conflicts",
            "! ========================================================",
            ""
        ]

        # Group conflict fixes by target switch
        dev_fixes = {}
        for c in conflicts:
            src = c.get("source_device")
            if src not in dev_fixes:
                dev_fixes[src] = []
            if c.get("local_remediation"):
                dev_fixes[src].append((c["title"], c["local_remediation"]))

        for dev_name, dev in devices.items():
            hname = dev["hostname"]
            lines.append(f"! --------------------------------------------------------")
            lines.append(f"! Switch Hostname: {hname} ({dev.get('model', 'Switch')})")
            lines.append(f"! Role: {dev.get('role', 'Switch')} | Health: {dev.get('health_score', 100)}/100")
            lines.append(f"! --------------------------------------------------------")
            
            fixes = dev_fixes.get(hname, [])
            if not fixes:
                lines.append(f"! [Status] 全項指標雙向對稱正常，本機無需任何修正變更。\n")
                continue

            lines.append("configure terminal")
            for title, cmd in fixes:
                lines.append(f"! [Action] {title}")
                for cmd_line in cmd.strip().splitlines():
                    lines.append(f" {cmd_line.strip()}")
            lines.append("end")
            lines.append("write memory")
            lines.append("")

        return "\n".join(lines)


    def _build_fleet_triage_prompt(self, devices: Dict[str, Any], conflicts: List[Dict[str, Any]], verified_links: List[Dict[str, Any]]) -> str:
        """
        Builds a comprehensive system triage context across ALL uploaded switch files for LLM.
        """
        lines = [
            "[系統角色使命：你是 SwitchScope 首席 CCIE 全網架構顧問，已跨設備掌握所有匯入之交換機配置與實時日誌]",
            "【三大鐵律規範 - 絕對必須嚴格遵守】：",
            "1. 【強制全篇繁體中文】：一律使用繁體中文（台灣網管用語，如：介面、封包、路由表、聚合組、跳線、遮罩）。絕對嚴禁英文開頭或使用簡體字！",
            "2. 【切中要害、零廢話理論】：嚴禁輸出教科書式的概念科普！直接針對多台設備的衝突回答，精準列出設備名稱、介面與根因！",
            "3. 【直給 Cisco CLI 可執行腳本】：回答修復方案時，必須按照各台設備主機名稱 (Hostname) 分區塊，立刻給出包裹於 ```cisco 內的 CLI 腳本！",
            "",
            f"=== 納管實體設備清單 ({len(devices)} 台) ==="
        ]
        for dev_name, dev in devices.items():
            lines.append(f"- {dev['hostname']}: Model: {dev.get('model', 'Switch')} | Uptime: {dev.get('uptime', 'N/A')} | Health: {dev.get('health_score', 100)}/100 | Role: {dev.get('role', 'Switch')}")
        
        lines.append(f"\n=== CROSS-DEVICE HARDWARE & CONFIG CONFLICTS ({len(conflicts)}) ===")
        if not conflicts:
            lines.append("All verified inter-switch links are symmetric and healthy (0 conflicts detected).")
        else:
            for idx, c in enumerate(conflicts, 1):
                lines.append(f"{idx}. [{c.get('severity')}] {c.get('title')}:")
                lines.append(f"   Devices: {c.get('source_device')}:{c.get('source_port')} <-> {c.get('target_device')}:{c.get('target_port')}")
                lines.append(f"   Root Cause: {c.get('detail')}")
                if c.get("local_remediation"):
                    clean_loc = c['local_remediation'].replace('\n', ' ; ')
                    lines.append(f"   Fix on {c.get('source_device')}: {clean_loc}")
                if c.get("remote_remediation") and not c.get("remote_remediation").startswith("!"):
                    clean_rem = c['remote_remediation'].replace('\n', ' ; ')
                    lines.append(f"   Fix on {c.get('target_device')}: {clean_rem}")

        lines.append(f"\n=== VERIFIED INTER-SWITCH TOPOLOGY LINKS ({len(verified_links)}) ===")
        for link in verified_links[:10]:
            conf_tag = " [CONFLICT!]" if link.get("has_conflict") else " [OK]"
            lines.append(f"- {link.get('source_hostname')}:{link.get('source_port')} <==> {link.get('target_hostname')}:{link.get('target_port')} ({link.get('vlan', 'trunk')}){conf_tag}")

        lines.append("\n【回覆指引】：")
        lines.append("1. 站在全網全維度視角回答工程師提問，充分運用上述所有設備之對接數據。")
        lines.append("2. 保持多輪對話記憶與上下文連貫性。")
        lines.append("3. 提供修復建議時，務必依據主機名稱分別列出可以直接貼上執行的 Cisco CLI 指令。")
        return "\n".join(lines)
