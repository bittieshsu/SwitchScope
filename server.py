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

            if not raw_text.strip():
                self._send_json({"success": False, "error": "輸入內容不可為空"}, status=400)
                return

            try:
                # 1. Sanitize
                clean_text = sanitize_cisco_output(raw_text, mask_ips=mask_ips)

                # 2. Parse Cisco CLI
                parsed_data = parser.parse_all(clean_text)

                # 3. ML Tier 1A: ECOD Hardware Counter Outlier Detection
                ports_table = parsed_data.get("ports_table", [])
                ecod_results = ecod_detector.detect(ports_table)

                # 4. ML Tier 1B: CatBoost Fault Classification & CLI Fix Generator
                diagnoses = fault_classifier.diagnose(parsed_data, ecod_results)

                # 4B. CCIE Executive Triage: Primary Blocker & Unified Macros
                global_triage = fault_classifier.synthesize_global_triage(diagnoses, parsed_data, ecod_results)

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
                    "device_info": parsed_data.get("device_info", {}),
                    "ports_table": ports_table,
                    "etherchannel": parsed_data.get("etherchannel", []),
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

            if not prompt.strip():
                self._send_json({"success": False, "error": "Prompt cannot be empty"}, status=400)
                return

            res = llm_gateway.query_ollama(prompt, model=model)
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

        else:
            self.send_error(404, "Not Found")

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
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
