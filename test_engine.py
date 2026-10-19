import sys
from core.parser import CiscoParser
from ml_engine.ecod_detector import ECODPortDetector
from ml_engine.fault_classifier import SwitchFaultClassifier

def run_test():
    sample_text = """
office1-switch-15F#show version
Cisco IOS Software, Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.06.03
Switch uptime is 14 weeks, 2 days, 4 hours, 18 minutes

office1-switch-15F#show interfaces Gi1/0/21 status
Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/21     A_Blue 11_kerr     connected    2007       a-full a-1000 10/100/1000BaseTX

office1-switch-15F#show logging
Oct 15 21:45:01.099: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/21, changed state to down
Oct 15 21:45:02.099: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/21, changed state to down
Oct 15 21:45:07.299: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/21, changed state to up
Oct 15 21:45:08.359: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/21, changed state to up
Oct 16 02:09:18.271: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/33, changed state to down
Oct 16 02:09:19.276: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/33, changed state to down
Oct 16 02:09:50.774: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/33, changed state to up
Oct 16 02:09:51.775: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/33, changed state to up
Oct 16 02:10:20.028: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/33, changed state to down
Oct 16 02:10:21.031: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/33, changed state to down
Oct 16 02:10:26.530: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/33, changed state to up
"""

    parser = CiscoParser()
    parsed = parser.parse_all(sample_text)

    ecod = ECODPortDetector()
    ecod_res = ecod.detect(parsed['ports_table'])

    classifier = SwitchFaultClassifier()
    diagnoses = classifier.diagnose(parsed, ecod_res)

    print("=== DEVICE UPTIME DAYS ===")
    print(f"Uptime: {parsed['device_info'].get('uptime')} -> Days: {parsed['device_info'].get('uptime_days')}")

    print("\n=== FLAPPING PORTS (TIME-AWARE) ===")
    for fp in parsed.get('flapping_ports', []):
        print(f"  * {fp['port']}: {fp['flap_cycles']} cycles | last_seen: {fp['last_seen']} | is_off_hours: {fp['is_off_hours']}")

    print("\n=== TIME-AWARE DIAGNOSES ===")
    for d in diagnoses:
        print(f"  [{d['severity']}] {d['title']}")
        print(f"    Cause: {d['root_cause']}")

def run_routing_test():
    import os
    sample_path = os.path.join(os.path.dirname(__file__), "samples", "cisco_ccie_routing_sample.txt")
    if not os.path.exists(sample_path):
        return
    with open(sample_path, "r", encoding="utf-8") as f:
        text = f.read()

    parser = CiscoParser()
    parsed = parser.parse_all(text)
    ecod = ECODPortDetector()
    ecod_res = ecod.detect(parsed.get("ports_table", []))
    classifier = SwitchFaultClassifier()
    diagnoses = classifier.diagnose(parsed, ecod_res)
    triage = classifier.synthesize_global_triage(diagnoses, parsed, ecod_res)

    print("\n=== CCIE ROUTING FSM TEST ===")
    print(f"OSPF Neighbors: {len(parsed['ospf'])}")
    print(f"BGP Peers: {len(parsed['bgp']['peers'])}")
    print(f"Diagnoses Found: {len(diagnoses)}")
    print(f"Primary Blocker: {triage['primary_issue']['target']} | {triage['primary_issue']['title']}")
    assert any("OSPF" in d["fault_type"] for d in diagnoses), "OSPF diagnosis missing"
    assert any("BGP" in d["fault_type"] for d in diagnoses), "BGP diagnosis missing"
    assert any("EIGRP" in d["fault_type"] for d in diagnoses), "EIGRP diagnosis missing"
    print("[OK] All CCIE routing FSM assertions passed!")

def run_timeline_quiesced_test():
    import os
    sample_path = os.path.join(os.path.dirname(__file__), "samples", "cisco_timeline_quiesced_sample.txt")
    if not os.path.exists(sample_path):
        return
    with open(sample_path, "r", encoding="utf-8") as f:
        text = f.read()

    parser = CiscoParser()
    parsed = parser.parse_all(text)
    ecod = ECODPortDetector()
    ecod_res = ecod.detect(parsed.get("ports_table", []))
    classifier = SwitchFaultClassifier()
    diagnoses = classifier.diagnose(parsed, ecod_res)
    triage = classifier.synthesize_global_triage(diagnoses, parsed, ecod_res)

    print("\n=== TIME-SERIES & QUIESCENCE TEST ===")
    print(f"Timeline Span: {parsed['timeline']['span_days']} days ({parsed['timeline']['span_hours']} hours)")
    print(f"Timeline Events: {len(parsed['timeline']['events'])}")
    print(f"Quiesced Count: {parsed['timeline']['quiesced_count']}")
    print(f"Triage Status: {triage['status']}")
    print(f"Has Critical Blocker: {triage['has_critical_blocker']}")

    assert parsed['timeline']['has_timeline'] is True, "Timeline parsing failed"
    assert parsed['timeline']['span_days'] >= 10.0, "Timeline span days incorrect"
    assert triage['has_critical_blocker'] is False, "Historical event was falsely marked as critical blocker!"
    assert triage['status'] == "HEALTHY", "Switch should be marked HEALTHY when events are quiesced!"
    print("[OK] All Time-Series & Quiescence assertions passed!")

def run_cdp_topology_test():
    import os
    sample_path = os.path.join(os.path.dirname(__file__), "samples", "cisco_ccie_cdp_topology_sample.txt")
    if not os.path.exists(sample_path):
        return
    with open(sample_path, "r", encoding="utf-8") as f:
        text = f.read()

    parser = CiscoParser()
    parsed = parser.parse_all(text)
    ecod = ECODPortDetector()
    ecod_res = ecod.detect(parsed.get("ports_table", []))
    classifier = SwitchFaultClassifier()
    diagnoses = classifier.diagnose(parsed, ecod_res)
    triage = classifier.synthesize_global_triage(diagnoses, parsed, ecod_res)

    print("\n=== CCIE CDP/LLDP TOPOLOGY CORRELATION TEST ===")
    print(f"CDP Neighbors: {len(parsed['cdp_neighbors'])}")
    for n in parsed['cdp_neighbors']:
        print(f"  * {n['local_port']} -> {n['device_id']} ({n['remote_port']}) [IP: {n['mgmt_ip']}]")
    print(f"MAC Table Entries: {len(parsed['mac_table'])}")
    print(f"ARP Table Entries: {len(parsed['arp_table'])}")

    p21 = next((p for p in parsed['ports_table'] if p['port'] == 'Gi1/0/21'), None)
    assert p21 is not None, "Gi1/0/21 missing from ports_table"
    print(f"Gi1/0/21 MACs: {p21['mac_addresses']}")
    print(f"Gi1/0/21 IPs: {p21['ip_addresses']}")
    assert len(p21['mac_addresses']) >= 2, "Gi1/0/21 should have 2 MACs"
    assert "10.20.7.35" in p21['ip_addresses'], "Gi1/0/21 should be correlated with IP 10.20.7.35"

    print("\nDiagnoses Found:")
    for d in diagnoses:
        print(f"  [{d['severity']}] {d['fault_type']}: {d['title']}")

    miscabled = next((d for d in diagnoses if d['fault_type'] == 'LACP_CROSS_DEVICE_MISCABLING'), None)
    assert miscabled is not None, "LACP_CROSS_DEVICE_MISCABLING not detected"
    print(f"\n[OK] Detected Cross-Chassis Cabling Error: {miscabled['title']}")

    vlan_mismatch = next((d for d in diagnoses if d['fault_type'] == 'CDP_NATIVE_VLAN_MISMATCH'), None)
    assert vlan_mismatch is not None, "CDP_NATIVE_VLAN_MISMATCH not detected"
    print(f"[OK] Detected Native VLAN Mismatch: {vlan_mismatch['title']}")

    client_drop = next((d for d in diagnoses if d['fault_type'] == 'ACCESS_CLIENT_BUFFER_DROP'), None)
    assert client_drop is not None, "ACCESS_CLIENT_BUFFER_DROP not detected"
    assert client_drop['severity'] == "NORMAL", "Access drops should be severity NORMAL"
    print(f"[OK] Correctly classified Access Client Drops without alarming core: {client_drop['title']}")

    assert triage['primary_issue']['fault_type'] == 'LACP_CROSS_DEVICE_MISCABLING', "Primary blocker must be LACP_CROSS_DEVICE_MISCABLING"
    print(f"[OK] Primary Blocker correctly identified as: {triage['primary_issue']['target']} | {triage['primary_issue']['fault_type']}")
    print("[OK] All CCIE CDP topology assertions passed 100%!")

def run_multi_chassis_fleet_test():
    import os
    from core.multi_chassis import MultiChassisEngine
    print("\n=== MULTI-CHASSIS FLEET CROSS-CORRELATION TEST ===")
    demo_dir = os.path.join(os.path.dirname(__file__), "samples", "multi_chassis_demo")
    engine = MultiChassisEngine()
    res = engine.scan_and_analyze_folder(demo_dir)

    assert res["success"] is True, "Multi-chassis analysis failed"
    devices = res["devices"]
    assert len(devices) == 3, f"Expected 3 devices, got {len(devices)}"
    dev_names = [d["hostname"] for d in devices]
    print(f"Ingested Fleet Devices ({len(devices)}): {dev_names}")
    assert "Core-SW-01" in dev_names
    assert "office1-switch-15F" in dev_names
    assert "Floor2-Access-SW-02" in dev_names

    conflicts = res["cross_conflicts"]
    print(f"\nCross-Device Conflicts Detected ({len(conflicts)}):")
    for c in conflicts:
        print(f"  * [{c['severity']}] {c['type']}: {c['title']}")

    lacp_disc = next((c for c in conflicts if c["type"] == "LACP_ASYMMETRIC_CONFIG"), None)
    assert lacp_disc is not None, "LACP_ASYMMETRIC_CONFIG not detected between office15 and floor2"
    print(f"[OK] Cross-Chassis Asymmetric LACP Mis-cabling verified: {lacp_disc['source_device']} <-> {lacp_disc['target_device']}")

    vlan_disc = next((c for c in conflicts if c["type"] == "TRUNK_NATIVE_VLAN_MISMATCH"), None)
    assert vlan_disc is not None, "TRUNK_NATIVE_VLAN_MISMATCH not detected between office15 and core"
    print(f"[OK] Cross-Chassis Trunk Native VLAN Mismatch verified: {vlan_disc['source_device']} <-> {vlan_disc['target_device']}")

    macro = res["fleet_remediation_macro"]
    assert "office1-switch-15F" in macro
    assert "no channel-group 1 mode active" in macro
    assert "switchport trunk native vlan 1" in macro
    print("[OK] Master Fleet Remediation Macro synthesized correctly!")
    print("[OK] All Multi-Chassis Fleet assertions passed 100%!")

def run_ollama_gateway_test():
    from core.llm_gateway import LLMGateway
    print("\n=== OLLAMA & QWEN3.5 LOCAL LLM GATEWAY TEST ===")
    gateway = LLMGateway()
    assert gateway.default_model == "qwen3.5", f"Default model must be qwen3.5, got {gateway.default_model}"

    status = gateway.check_status()
    print(f"Ollama Online: {status.get('online')} | Default Model: {status.get('default_model')}")
    assert "qwen3.5" in status.get("recommended_laptop_models", [])

    # Test query fallback handling
    res = gateway.query_ollama("請用白話文解釋交換機發生了什麼事？", model="qwen3.5")
    assert res["success"] is True
    print(f"Query Source: {res.get('source')} | Model: {res.get('model_used')}")
    assert len(res.get("response", "")) > 50
    print("[OK] Ollama Qwen3.5 integration & fallback assertions passed 100%!")

if __name__ == '__main__':
    run_test()
    run_routing_test()
    run_timeline_quiesced_test()
    run_cdp_topology_test()
    run_multi_chassis_fleet_test()
    run_ollama_gateway_test()

