"""
SwitchScope - Local Web Server & API Gateway
Runs a zero-dependency Python HTTP server providing REST API for:
1. Cisco CLI text sanitization & parsing.
2. ECOD unsupervised outlier detection on hardware counters.
3. CatBoost decision tree fault diagnosis & CLI fix generation.
4. Local Ollama LLM escalation & interactive triage chat.
"""
import sys
import os
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver

from core.sanitizer import sanitize_cisco_output
from core.parser import CiscoParser
from core.adapters import VendorRouter
from core.cross_vendor_diff import CrossVendorDiffEngine
from ml_engine.ecod_detector import ECODPortDetector
from ml_engine.fault_classifier import SwitchFaultClassifier
from core.llm_gateway import LLMGateway
from core.multi_chassis import MultiChassisEngine

PORT = 8920
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

# Initialize singletons
parser = CiscoParser()
vendor_router = VendorRouter()
cross_vendor_engine = CrossVendorDiffEngine()
ecod_detector = ECODPortDetector()
fault_classifier = SwitchFaultClassifier()
llm_gateway = LLMGateway()
multi_chassis_engine = MultiChassisEngine()

class SwitchScopeHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in ("/", "/index.html"):
            index_path = os.path.join(WEB_DIR, "index.html")
            if os.path.exists(index_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(index_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "index.html not found")

        elif path == "/api/sample":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            sample_type = query_params.get("type", [""])[0]
            if sample_type == "flapping":
                sample_file = os.path.join(SAMPLES_DIR, "cisco_flapping_sample.txt")
            elif sample_type == "routing":
                sample_file = os.path.join(SAMPLES_DIR, "cisco_ccie_routing_sample.txt")
            elif sample_type == "timeline":
                sample_file = os.path.join(SAMPLES_DIR, "cisco_timeline_quiesced_sample.txt")
            elif sample_type in ("cdp", "topology"):
                sample_file = os.path.join(SAMPLES_DIR, "cisco_ccie_cdp_topology_sample.txt")
            elif sample_type == "aruba":
                sample_file = os.path.join(SAMPLES_DIR, "aruba_troubleshoot_sample.txt")
            elif sample_type == "juniper":
                sample_file = os.path.join(SAMPLES_DIR, "juniper_troubleshoot_sample.txt")
            elif sample_type in ("fortiswitch", "fortinet"):
                sample_file = os.path.join(SAMPLES_DIR, "fortiswitch_troubleshoot_sample.txt")
            else:
                sample_file = os.path.join(SAMPLES_DIR, "cisco_troubleshoot_sample.txt")

            if os.path.exists(sample_file):
                with open(sample_file, "r", encoding="utf-8") as f:
                    content = f.read()
                self._send_json({"success": True, "sample": content})
            else:
                self._send_json({"success": False, "error": "Sample file not found"}, status=404)

        elif path == "/api/sample-batch":
            demo_dir = os.path.join(SAMPLES_DIR, "multi_chassis_demo")
            files = []
            if os.path.exists(demo_dir):
                for fname in sorted(os.listdir(demo_dir)):
                    fpath = os.path.join(demo_dir, fname)
                    if os.path.isfile(fpath) and fname.endswith(".txt"):
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            files.append({"name": fname, "content": f.read()})
            self._send_json({"success": True, "files": files})

        elif path == "/api/sample-cross":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            pair_type = query_params.get("pair", ["cisco_aruba"])[0]
            if pair_type in ("fortiswitch", "cisco_fortiswitch"):
                file_a = os.path.join(SAMPLES_DIR, "cisco_vs_fortiswitch_sample_a.txt")
                file_b = os.path.join(SAMPLES_DIR, "cisco_vs_fortiswitch_sample_b.txt")
            else:
                file_a = os.path.join(SAMPLES_DIR, "cisco_vs_aruba_sample_a.txt")
                file_b = os.path.join(SAMPLES_DIR, "cisco_vs_aruba_sample_b.txt")

            content_a, content_b = "", ""
            if os.path.exists(file_a):
                with open(file_a, "r", encoding="utf-8", errors="ignore") as fa:
                    content_a = fa.read()
            if os.path.exists(file_b):
                with open(file_b, "r", encoding="utf-8", errors="ignore") as fb:
                    content_b = fb.read()

            self._send_json({"success": True, "device_a": content_a, "device_b": content_b})

        elif path == "/api/ollama/status":
            self._send_json(llm_gateway.check_status())

        elif path == "/api/health":
            ollama_stat = llm_gateway.check_status()
            self._send_json({
                "status": "online",
                "engine": "SwitchScope ML/LLM Dual-Tier Core",
                "ml_models": ["ECOD (PyOD)", "CatBoostClassifier"],
                "ollama": {
                    "online": ollama_stat.get("online", False),
                    "default_model": ollama_stat.get("default_model", "qwen3.5")
                }
            })
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            req_json = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            req_json = {}

        if path == "/api/analyze":
            raw_text = req_json.get("raw_text", "")
            mask_ips = req_json.get("mask_ips", False)
            vendor_hint = req_json.get("vendor", "auto")

            if not raw_text.strip():
                self._send_json({"success": False, "error": "輸入內容不可為空"}, status=400)
                return

            try:
                # 1. Sanitize
                clean_text = sanitize_cisco_output(raw_text, mask_ips=mask_ips)

                # 2. Parse via Multi-Vendor Adapter Router
                parsed_data, detected_vendor, confidence = vendor_router.parse(clean_text, vendor=vendor_hint)

                # 3. ML Tier 1A: ECOD Hardware Counter Outlier Detection
                ports_table = parsed_data.get("ports_table", [])
                ecod_results = ecod_detector.detect(ports_table)

                # 4. ML Tier 1B: CatBoost Fault Classification & CLI Fix Generator
                diagnoses = fault_classifier.diagnose(parsed_data, ecod_results)

                # 4B. CCIE Executive Triage: Primary Blocker & Unified Macros
                global_triage = fault_classifier.synthesize_global_triage(diagnoses, parsed_data, ecod_results)

                # 4C. Attach vendor-specific rollback scripts to diagnoses
                for d in diagnoses:
                    f_type = d.get("fault_type", "GENERIC")
                    p_name = d.get("port", "")
                    fix_data = vendor_router.generate_fix(detected_vendor, f_type, p_name, {})
                    d["rollback_script"] = fix_data.get("rollback_script", "")

                # 5. Format compact escalation prompt for Tier 2 LLM
                triage_prompt = llm_gateway.format_triage_prompt(parsed_data, ecod_results, diagnoses, global_triage=global_triage)

                # 6. Overall Health Score Calculation (100 base)
                critical_count = sum(1 for d in diagnoses if d.get("severity") == "CRITICAL")
                high_count = sum(1 for d in diagnoses if d.get("severity") == "HIGH")
                warning_count = sum(1 for d in diagnoses if d.get("severity") == "WARNING")
                health_score = max(0, 100 - (critical_count * 30) - (high_count * 15) - (warning_count * 5))

                self._send_json({
                    "success": True,
                    "health_score": health_score,
                    "detected_vendor": detected_vendor,
                    "vendor_confidence": round(confidence, 2),
                    "device_info": parsed_data.get("device_info", {}),
                    "ports_table": ports_table,
                    "etherchannel": parsed_data.get("etherchannel", []),
                    "vlans": parsed_data.get("vlans", []),
                    "stack": parsed_data.get("stack", []),
                    "routing": parsed_data.get("routing", {}),
                    "cdp_neighbors": parsed_data.get("cdp_neighbors", []),
                    "lldp_neighbors": parsed_data.get("lldp_neighbors", []),
                    "mac_table": parsed_data.get("mac_table", []),
                    "arp_table": parsed_data.get("arp_table", []),
                    "ecod_results": ecod_results,
                    "diagnoses": diagnoses,
                    "global_triage": global_triage,
                    "triage_prompt": triage_prompt,
                    "timeline": parsed_data.get("timeline", {}),
                    "syslog_count": len(parsed_data.get("syslog", []))
                })

            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)

        elif path == "/api/chat":
            prompt = req_json.get("prompt", "")
            model = req_json.get("model", "qwen3.5")
            messages = req_json.get("messages", None)

            if not prompt.strip() and not messages:
                self._send_json({"success": False, "error": "Prompt or messages cannot be empty"}, status=400)
                return

            res = llm_gateway.query_ollama(prompt=prompt, model=model, messages=messages)
            self._send_json(res)

        elif path == "/api/analyze-batch":
            files = req_json.get("files", [])
            mask_ips = req_json.get("mask_ips", True)
            if not files:
                self._send_json({"success": False, "error": "請至少提供一個設備日誌或配置檔！"}, status=400)
                return
            try:
                res = multi_chassis_engine.analyze_batch(files, mask_ips=mask_ips)
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)

        elif path == "/api/scan-folder":
            folder_path = req_json.get("folder_path", "").strip()
            mask_ips = req_json.get("mask_ips", True)
            if not folder_path:
                self._send_json({"success": False, "error": "請輸入本機設備日誌資料夾路徑！"}, status=400)
                return
            try:
                res = multi_chassis_engine.scan_and_analyze_folder(folder_path, mask_ips=mask_ips)
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)

        elif path == "/api/cross-vendor-diff":
            raw_a = req_json.get("device_a_text", "")
            raw_b = req_json.get("device_b_text", "")
            ven_a = req_json.get("device_a_vendor", "auto")
            ven_b = req_json.get("device_b_vendor", "auto")
            mask_ips = req_json.get("mask_ips", True)

            if not raw_a.strip() or not raw_b.strip():
                self._send_json({"success": False, "error": "請同時提供設備 A 與設備 B 之 CLI 輸出文字！"}, status=400)
                return

            try:
                res = cross_vendor_engine.analyze_interconnect(
                    raw_a, raw_b, vendor_a=ven_a, vendor_b=ven_b, mask_ips=mask_ips
                )
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)

        else:
            self.send_error(404, "Not Found")

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run_server():
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, SwitchScopeHandler)
    print(f"* [SwitchScope] ML & LLM Diagnostic Server running at http://localhost:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SwitchScope Server...")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
