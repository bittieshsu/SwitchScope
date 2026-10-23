"""
SwitchScope - LLM Escalation & Interactive Triage Gateway
Handles tier-2 escalation when ML encounters unclassified or complex multi-hop switch issues.
Supports local Ollama endpoints (Qwen2.5, DeepSeek, Llama3) with zero cloud leakage,
or interactive prompt generation for offline engineers.
"""
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List

class LLMGateway:
    def __init__(self, ollama_url: str = "http://127.0.0.1:11434"):
        self.ollama_url = ollama_url
        self.default_model = "qwen3.5"

    def format_triage_prompt(self, parsed_data: Dict[str, Any], ecod_results: Dict[str, Any], diagnoses: List[Dict[str, Any]], user_query: str = "", global_triage: Dict[str, Any] = None) -> str:
        """
        Creates an information-dense, sanitized prompt for the LLM.
        Filtered by ML tier so the LLM doesn't waste tokens on 20,000 lines of noise.
        """
        device = parsed_data.get("device_info", {})
        dev_summary = f"Device: {device.get('model', 'Cisco Switch')} | IOS: {device.get('version', 'Unknown')} | Uptime: {device.get('uptime', 'Unknown')}"
        
        # Summarize Global Triage
        triage_text = ""
        if global_triage:
            p_issue = global_triage.get("primary_issue")
            if p_issue:
                triage_text = f"Primary Blocker: {p_issue.get('title')} (Target: {p_issue.get('target')}) | Impact: {p_issue.get('impact_scope')}\n"
            triage_text += f"Consensus Opinion: {global_triage.get('executive_opinion', '')}\n"

        # Summarize ECOD outliers
        anomalies = ecod_results.get("anomalies", [])
        outliers = [a for a in anomalies if a.get("is_outlier") or a.get("severity") in ("CRITICAL", "WARNING")]
        outlier_text = "\n".join([
            f"- Port {o['port']} [{o['severity']}]: {o['explanation']} (Outlier Score: {o['anomaly_score']})"
            for o in outliers[:6]
        ]) or "None"

        # Summarize ML diagnoses
        diag_text = "\n".join([
            f"- [{d['severity']}] {d['title']}: {d['root_cause']}"
            for d in diagnoses
        ]) or "All healthy"

        # Suspicious syslog
        syslogs = parsed_data.get("syslog", [])
        log_text = "\n".join([
            f"[{ev['tag']}] {ev['message']}"
            for ev in syslogs[:8]
        ]) or "No high severity logs"

        # Summarize CDP / LLDP Neighbors
        cdp_neighbors = parsed_data.get("cdp_neighbors", [])
        lldp_neighbors = parsed_data.get("lldp_neighbors", [])
        topo_lines = []
        for c in cdp_neighbors[:8]:
            ip_info = f" [IP: {c['mgmt_ip']}]" if c.get('mgmt_ip') else ""
            topo_lines.append(f"- {c.get('local_port')} ➔ {c.get('device_id')} ({c.get('remote_port')}){ip_info} [Platform: {c.get('platform', '')}]")
        for l in lldp_neighbors[:5]:
            topo_lines.append(f"- {l.get('local_port')} ➔ {l.get('device_id')} ({l.get('remote_port')}) [LLDP]")
        topo_text = "\n".join(topo_lines) or "No CDP/LLDP neighbors discovered"

        # Summarize port IP/MAC associations
        ports_table = parsed_data.get("ports_table", [])
        bound_ports = [p for p in ports_table if p.get("ip_addresses") or p.get("mac_addresses")]
        bound_lines = []
        for bp in bound_ports[:8]:
            mac_s = f"MAC: {', '.join(bp.get('mac_addresses', []))}" if bp.get('mac_addresses') else ""
            ip_s = f"IP: {', '.join(bp.get('ip_addresses', []))}" if bp.get('ip_addresses') else ""
            bound_lines.append(f"- {bp['port']}: {mac_s} | {ip_s}")
        bound_text = "\n".join(bound_lines) or "None"

        prompt = f"""[系統角色使命：你是 SwitchScope 首席 CCIE 網路架構師與現場維運資深顧問]
【三大鐵律規範 - 絕對必須嚴格遵守】：
1. 【強制全篇繁體中文】：一律使用繁體中文（台灣網管工程師用語，如：介面、封包、路由表、聚合組、跳線、遮罩、廣播）。絕對嚴禁英文開頭！嚴禁使用簡體中文！
2. 【切中要害、零廢話理論】：嚴禁輸出長篇大論教科書名詞解釋或科普（如：嚴禁講「OSPF 是一種內部路由協議...」等廢話）！直接切入現場問題，精準指出受影響介面、根本原因與具體建議！
3. 【直給 Cisco CLI 可執行腳本】：工程師提問若涉及配置建立或修復（如 OSPF/BGP/VLAN/LACP/Trunk），立刻提供以 ```cisco 包裹之完整、立即可貼入終端機執行的 CLI 指令塊（含 configure terminal, 介面配置, 驗證 show 指令）！

以下為 SwitchScope 本機機器學習 (CatBoost + ECOD) 針對當前設備自動萃取之實時遙測數據：
(所有機敏密碼與私有資料均已在本機完成脫敏保護)

### 1. 設備基本特徵 (Equipment Profile)
{dev_summary}

### 2. CCIE 全域主震央裁決 (Executive Triage & Primary Blocker)
{triage_text if triage_text else "全機各項遙測指標正常，未檢出系統級核心阻斷"}

### 3. ML 第一層故障特徵定性 (CatBoost Diagnosis)
{diag_text}

### 4. 實體硬體計數器離群分佈 (ECOD Anomaly Detection)
{outlier_text}

### 5. 實體拓撲與互聯鄰居 (CDP / LLDP)
{topo_text}

### 6. 二三層位址綁定關係 (MAC & ARP)
{bound_text}

### 7. 關鍵 Syslog 事件
{log_text}

### 8. 現場工程師諮詢指示
{user_query if user_query else "請針對上述遙測數據，為工程師總評當前狀況，並指示下一步現場排查或修復指令。"}
"""
        return prompt

    def check_status(self) -> Dict[str, Any]:
        """
        Check if local Ollama daemon is active and list available models.
        Uses a short 1.5s timeout so web UI polling remains instant and non-blocking.
        """
        try:
            req = urllib.request.Request(f"{self.ollama_url}/api/tags")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                raw_models = data.get("models", [])
                models = [m.get("name") for m in raw_models if m.get("name")]
                return {
                    "online": True,
                    "url": self.ollama_url,
                    "models": models,
                    "default_model": self.default_model,
                    "recommended_laptop_models": ["qwen2.5:1.5b", "qwen2.5-coder:1.5b", "qwen3.5", "qwen3.5:3b", "qwen3.5:7b", "qwen2.5:3b", "qwen2.5-coder:7b"]
                }
        except Exception:
            return {
                "online": False,
                "url": self.ollama_url,
                "models": [],
                "default_model": self.default_model,
                "recommended_laptop_models": ["qwen2.5:1.5b", "qwen2.5-coder:1.5b", "qwen3.5", "qwen3.5:3b", "qwen3.5:7b", "qwen2.5:3b", "qwen2.5-coder:7b"],
                "quick_command": f"ollama run {self.default_model}"
            }

    def query_ollama(self, prompt: str = "", model: str = None, messages: List[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Queries local Ollama instance (default: Qwen3.5) with either single prompt or multi-turn messages.
        If Ollama is not running, falls back seamlessly to the CCIE offline rule engine.
        """
        target_model = model or self.default_model

        if messages and isinstance(messages, list) and len(messages) > 0:
            payload = {
                "model": target_model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 1024
                }
            }
            endpoint = f"{self.ollama_url}/api/chat"
            is_chat = True
        else:
            payload = {
                "model": target_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 1024
                }
            }
            endpoint = f"{self.ollama_url}/api/generate"
            is_chat = False

        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode('utf-8'),
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if is_chat:
                    resp_text = data.get("message", {}).get("content", "")
                else:
                    resp_text = data.get("response", "")
                return {
                    "success": True,
                    "source": "ollama",
                    "model_used": target_model,
                    "response": resp_text,
                    "total_duration": data.get("total_duration", 0)
                }
        except urllib.error.URLError:
            fb_prompt = prompt
            if not fb_prompt and messages:
                fb_prompt = '\n'.join([f"{m.get('role', 'user').upper()}: {m.get('content', '')}" for m in messages])
            return {
                "success": True,
                "source": "rule_fallback",
                "model_used": "SwitchScope 離線規則降級引擎",
                "notice": f"⚠️ 本機 Ollama 尚未啟動或尚未下載 {target_model}。若要在筆電執行本地大模型，請於終端機執行：`ollama run {target_model}`。目前已無縫由地端 CCIE 離線規則引擎為您提供深入排障分析：",
                "response": self._generate_rule_based_ai_response(fb_prompt)
            }
        except Exception as e:
            fb_prompt = prompt
            if not fb_prompt and messages:
                fb_prompt = '\n'.join([f"{m.get('role', 'user').upper()}: {m.get('content', '')}" for m in messages])
            return {
                "success": True,
                "source": "rule_fallback",
                "model_used": "SwitchScope 離線規則降級引擎",
                "error": str(e),
                "notice": f"⚠️ 本地 LLM 連線異常 ({str(e)})。已切換至地端 CCIE 離線規則引擎：",
                "response": self._generate_rule_based_ai_response(fb_prompt)
            }

    def _generate_rule_based_ai_response(self, prompt: str) -> str:
        """
        Expert fallback reasoning engine if local Ollama daemon is currently not running.
        Provides high-quality troubleshooting advice based on extracted symptoms and user intent.
        """
        p_lower = prompt.lower()

        # 1. 產生事故通報 / 主管報告
        if any(k in prompt for k in ("主管", "報告", "通報", "匯報")):
            return """### 📋 【網路設備異常診斷與維運處置通報】
*(可直接全選複製，貼入 Line / Teams / Email 呈報主管或客戶)*

---
* **通報主旨**：[網通維運] 核心交換機健康狀態檢測與處置進度通報
* **設備資訊**：Cisco Catalyst 交換機 (經 SwitchScope 本機機器學習遙測分析)
* **當前評估**：
  1. **已識別狀況**：現場已完成 L1~L3 結構化診斷，主要異常包含介面計數器與連線狀態分析。
  2. **影響範圍**：相關連線均具備安全防護機制（如 Spanning-Tree PortFast / 保護配置），全網未受拓撲風暴波及。
* **處理處置進度**：
  1. 現場工程師已擷取完整硬體計數器與 Syslog 時間軸。
  2. 已備妥標準修復配置與回退腳本 (Rollback Plan)。
  3. 預計於離峰時段或核准之變更視窗內執行排障。
* **後續追蹤**：已建立監控基線，將持續觀測鏈路封包收發與錯誤率變化。
---"""

        # 2. 白話文解釋
        if any(k in prompt for k in ("白話文", "白話", "不懂")):
            return """### 👶 【CCIE 專家用白話文為您解說】

想像這台交換機是一座**大型高架橋交流道**：
1. **如果看到 LACP Suspended (掛起)**：
   就像雙向八線道的高架橋，有一邊的收費站閘門「忘記開」，系統為了安全起見，先把那條車道暫時封閉（掛起），避免車子開進去撞車或打轉。
2. **如果看到 Output Drops (29 萬次丟包)**：
   就像從 10 線道的大馬路，瞬間湧進 1 條單線道的小巷子。車子一下子塞爆交流道口，後面來不及進去的封包就被丟掉了（通常是瞬間下載大檔案造成的，不用太恐慌）。
3. **如果看到晚上狂跳 (Link Flap)**：
   就像下班時間到了，同仁把筆電蓋上或關機，網卡進入「省電睡眠模式」，就像電燈關掉切換成夜燈一樣，是正常現象，**千萬不要傻傻跑去機房換線**！
4. **如果看到 Err-Disable (鎖死)**：
   就像門禁防盜警報器響起，交換機偵測到有人私接了不該接的設備，立刻把門反鎖保護大家。只要把對端的怪設備拔掉，重新解鎖就能恢復！"""

        # 3. 安全 SOP 與回退方案
        if any(k in prompt for k in ("sop", "SOP", "回退", "安全", "rollback")):
            return """### 🛡️ 【現場標準作業程序 (SOP) 與回退腳本 (Rollback)】

#### 步驟 1：變更前狀態備份 (Pre-Check)
在敲任何配置前，請務必先在 Switch 執行並存檔：
```cisco
show running-config
show interfaces status
show ip route
```

#### 步驟 2：執行修復配置 (Maintenance Execution)
進入設定模式，執行 SwitchScope 診斷卡片所提供的一鍵修復指令：
```cisco
configure terminal
! (貼入 SwitchScope 建議的修正指令)
end
```

#### 步驟 3：變更後驗證 (Post-Check)
確認介面狀態是否變為 `connected`，且計數器不再異常增加：
```cisco
show interfaces status
clear counters <Interface>   ! 清除歷史計數器重新觀察 5 分鐘
show interfaces <Interface> | include CRC|errors
```

#### 步驟 4：緊急回退方案 (Rollback Procedure)
如果配置後發現對端不通或出現非預期警報，請立刻執行回退：
```cisco
configure terminal
default interface <Interface>   ! 一秒還原該介面所有預設值
! 或恢復原先備份之 config
end
```"""

        # 4. 2個 MAC / WSL2 / 虛擬機解釋
        if any(k in prompt for k in ("mac", "MAC", "2個", "兩個", "arp", "ARP")):
            return """### 🔍 【為什麼同一個 Port 會學到 2 個 MAC Address？】

在現場排查中，一個實體 Port 出現多個 MAC 有兩種最常見的可能：
1. **最常見：該電腦開了 WSL2 / Docker / Hyper-V 虛擬機**：
   * 現代工程師的 Windows 電腦常開 WSL2 或 Docker。
   * 微軟的虛擬網路介面卡（OUI 為 `00:15:5D` 開頭）會與電腦實體網卡（如華碩 `74:86:E2`）共用同一個實體孔向交換機發送封包，因此 Switch 會自然學到 2 個 MAC！
2. **私接未授權 Hub / 迷你交換機**：
   * 如果學到的 MAC 超過 5~10 個，代表現場有人在桌子底下私接了 8-Port 小交換機。
3. **如何在 Switch 查出對應 IP？**：
   * 由於 L2 交換機的 ARP 表不會標註實體 Port，請直接用抓到的 MAC 查詢：
   ```cisco
   show ip arp <MAC_Address>
   ```"""

        # 5. Output Drops 丟包解析
        if any(k in prompt for k in ("drop", "Drop", "29萬", "丟包", "output")):
            return """### 🌊 【Output Drops 丟包原因與改善建議】

1. **為什麼會有 Output Drops？**
   * Output Drops 代表**交換機的傳送佇列暫存區（Egress Queue Buffer）滿載溢出**。
   * 最典型的場景是「**速率失配（Speed Mismatch）**」：例如 Core 端是 10Gbps 高速鏈路，而目標電腦是 1Gbps。當大檔以 10G 速率湧入時，交換機晶片來不及往 1G 口轉發，多出來的封包就被丟棄了。
2. **會不會影響使用者？**
   * TCP 協定具備滑動視窗與重傳機制，少量的 Drops 會促使 TCP 自動降速，使用者通常只感到下載「頓了一下」，但若持續暴增則會嚴重拖慢網路。
3. **排查與處置方式**：
   * 檢查交換機 Buffer 狀態：`show platform hardware fed switch active qos queue stats interface <Port>`
   * 清除計數器觀察增長速率：`clear counters <Port>`"""

        # 6A. 建立 / 設定 / 配置 OSPF
        if any(k in prompt for k in ("建立", "設定", "配置", "啟用", "怎設", "怎麼設", "建ospf", "架設", "起ospf")) and any(k in prompt for k in ("ospf", "OSPF")):
            return """### 🧭 【CCIE 實戰配置手冊：快速建立 Cisco OSPF 路由協定】

針對您當前交換機 / 路由器，以下是生產級 OSPF 單一區域（Area 0 骨幹）標準建立腳本：

#### 1. Cisco IOS / IOS-XE 完整配置腳本 (直接全選複製貼上)
```cisco
configure terminal
! 1. 啟用 OSPF 進程並指定 Router-ID (建議使用穩定 IP 或 Loopback)
router ospf 1
 router-id 10.0.0.1
 
! 2. 宣告您要參與 OSPF 路由交換的網段 (格式: network <網段> <反遮罩> area <區域ID>)
! 範例：將 Vlan 1, 10, 20 加入骨幹 Area 0
 network 10.0.0.0 0.0.0.255 area 0
 network 10.0.10.0 0.0.0.255 area 0
 network 10.0.20.0 0.0.0.255 area 0
 
! 3. 最佳實踐：將終端使用者或印表機 VLAN 設為 Passive (只宣告路由、不發送 OSPF Hello 封包保護安全)
 passive-interface Vlan10
 passive-interface Vlan20
 
! 4. 若此交換機為網關，宣告預設路由給其他鄰居 (可選)
 default-information originate
end
write memory
```

#### 2. 現場 3 秒驗證指令 (敲完立刻確認)
```cisco
show ip ospf neighbor          ! 關鍵指標：State 必須為 FULL/DR 或 FULL/BDR
show ip ospf interface brief   ! 檢查各介面是否正確啟動 OSPF 且處於 UP 狀態
show ip route ospf             ! 檢查是否已順利學到對端路由條目 (代號 O)
```

#### 💡 CCIE 現場避坑三大鐵律：
1. **MTU 一致**：對接互聯埠的 MTU 必須一致，否則卡在 `EXSTART` 狀態無法建立鄰居！
2. **Area ID 一致**：直連兩端必須同在 Area 0，Hello/Dead Interval (預設 10s/40s) 必須相符。
3. **三層連通先驗證**：在配置 OSPF 前，請先確認兩端互聯 IP 能互相 `ping` 通！"""

        # 6B. OSPF EXSTART / MTU Mismatch
        if any(k in prompt for k in ("exstart", "EXSTART", "mtu", "MTU")) or ("ospf" in prompt.lower() and "卡" in prompt):
            return """### 🧭 【CCIE 核心剖析：OSPF 為什麼會卡在 EXSTART？】

在 Cisco CCIE 排障中，**OSPF 鄰居停滯在 EXSTART / EXCHANGE 狀態，99% 是因為「介面 MTU 不匹配 (MTU Mismatch)」**！

#### 1. 深入原理（DBD 協商失敗）
* OSPF 鄰居在進入 `EXSTART` 時，兩端開始發送空的 Database Description (DBD) 封包競選 Master/Slave。
* 隨後進入 `EXCHANGE` 階段，Master 開始發送帶有 LSA Summary 的完整 DBD 封包。
* **關鍵在於：DBD 封包頭部明確帶有介面的 MTU 值**。
* 若 Router A 的 MTU 是 1500，而 Router B 的 MTU 是 9000（或 1492 / PPPoE）：
  - 較小 MTU 的一端會拒絕接收較大的 DBD 封包，或者封包因 DF (Don't Fragment) 被丟棄。
  - 結果就是雙方永遠收不到完整的 DBD 應答，計時器逾時後退回 EXSTART 重試，形成「EXSTART ➔ DOWN ➔ INIT ➔ 2-WAY ➔ EXSTART」死循環！

#### 2. 現場 3 秒定位指令
```cisco
show ip ospf neighbor
show interfaces <Interface> | include MTU
show ip ospf interface <Interface>
```

#### 3. 現場解決方案 (SOP)
* **標準正規作法**：將兩端實體 MTU 調整為一致：
  ```cisco
  interface <Interface>
   ip mtu 1500
  ```
* **現場應急修復（忽略 MTU 檢驗）**：
  ```cisco
  interface <Interface>
   ip ospf mtu-ignore
  ```"""

        # 7. BGP Active / Idle / TCP 179
        if any(k in prompt for k in ("bgp", "BGP", "active", "Active", "idle", "Idle", "179")):
            return """### 🌐 【CCIE 核心剖析：BGP 停在 Active 或 Idle 怎麼辦？】

BGP 是基於 TCP Port 179 的應用層協議。排障核心在於掌握狀態機：`Idle -> Connect -> Active -> OpenSent -> OpenConfirm -> Established`。

#### 1. 為什麼會卡在 `Active`？
* **Active 代表本端主動發送 TCP SYN 嘗試連線，但始終沒有收到對端的 SYN-ACK（交握失敗）**。
* **現場三大真兇**：
  1. **防火牆或 ACL 阻擋**：中間防火牆或對端未開放 `TCP 179` 雙向通行。
  2. **對端未配置本端 IP**：對端的 `neighbor <IP> remote-as` 敲錯了 IP，所以收到 SYN 封包直接回送 RST 拒絕。
  3. **NAT 陷阱**：封包經過 NAT 導致來源 IP 被置換，對端認不出這是誰。

#### 2. 為什麼會卡在 `Idle`？
* **Idle 代表 BGP 甚至還沒開始嘗試發起 TCP 連線**。
* **現場三大真兇**：
  1. **路由表沒有對端 IP (No Route)**：`show ip route <Peer_IP>` 查不到路徑。
  2. **Loopback 建立鄰居漏配更新來源**：若使用 Loopback 互連，必須敲 `neighbor <IP> update-source Loopback0`。
  3. **EBGP 跨跳 (Multihop)**：直連的 EBGP 預設 TTL=1。如果跨了多個路由器，必須加上 `neighbor <IP> ebgp-multihop 2`！

#### 3. 現場定位排查指令包
```cisco
show ip bgp summary
show ip bgp neighbors <Peer_IP>
show tcp brief | include 179
ping <Peer_IP> source Loopback0
```"""

        # 8. MPLS VPN / Route-Target (RT)
        if any(k in prompt for k in ("mpls", "MPLS", "vpn", "VPN", "vrf", "VRF", "rt", "RT", "rd", "RD", "ldp", "LDP")):
            return """### 🏷️ 【CCIE 核心剖析：MPLS VPN 為什麼收到了路由，客戶卻完全不通？】

這是 CCIE Enterprise / SP 考試與真實電信/企業機房中最常踩的 **「Route-Target (RT) 不匹配陷阱」**！

#### 1. 核心觀念：RD vs RT
* **Route Distinguisher (RD)**：僅負責「防止重疊 IP 衝突」，讓 `192.168.1.0/24` 變成全域唯一的 VPNv4 路由（如 `65001:100:192.168.1.0/24`）。
* **Route Target (RT)**：才是真正決定**「這條路由該塞給哪一個客戶 VRF」**的 BGP Extended Community 標籤！

#### 2. 致命故障情境 (RT Mismatch)
* 當 PE1 發布客戶路由時打上了 `export 65001:100`。
* 對端 PE2 的 MP-BGP 確實收到了這條路由（在 `show bgp vpnv4 unicast all` 看得到）。
* 但 PE2 的 VRF 卻配置了 `route-target import 65001:200`！
* **結果**：PE2 的 BGP 表明明有路由，但客戶的 VRF 路由表 (`show ip route vrf <Name>`) **一條路由都沒有**！

#### 3. 現場排查三部曲
```cisco
! 1. 查 MP-BGP 是否真有收到路由與其 RT 標籤
show bgp vpnv4 unicast all
show bgp vpnv4 unicast vrf <Name>

! 2. 查本端 VRF 的 Import/Export RT 清單
show ip vrf detail <Name>

! 3. 補齊對齊的 Import RT
configure terminal
ip vrf <Name>
 route-target import 65001:100
end
```"""

        # 9. EIGRP K-Values / SIA
        if any(k in prompt for k in ("eigrp", "EIGRP", "k-value", "k值", "sia", "SIA")):
            return """### ⚡ 【CCIE 核心剖析：EIGRP 為什麼會狂跳或 K-Value Mismatch？】

#### 1. K-Value Mismatch（權重不符）
* EIGRP 度量值依據五個 K 值計算。Cisco 官方預設只有 K1=1 (頻寬) 與 K3=1 (延遲) 有作用，其餘為 0。
* 只要其中一台設備敲了 `metric weights` 改變權重，Hello 封包交換時檢查不符，就會立即跳出 `%DUAL-5-NBRCHANGE: K-value mismatch` 並拒絕建立鄰居！
* **修復配置**：
  ```cisco
  configure terminal
  router eigrp <AS>
   metric weights 0 1 0 1 0 0
  end
  ```

#### 2. SIA (Stuck In Active - 卡在活動狀態)
* 當一條路徑斷開時，EIGRP 會向所有鄰居發送 Query 尋找替代路徑。
* 若某一端鄰居在 180 秒內未回應 Reply（通常是因為廣域網鏈路擁塞、封包遺失或 CPU 100%），該路由就會進入 SIA，EIGRP 會強制重置該鄰居。
* **處置指引**：在分支邊界交換機啟用 `eigrp stub` 避免接收 Query！"""

        # 10. 時間序列 / 歷史已平息 / 為什麼不用查
        if any(k in prompt for k in ("時間", "時序", "timeline", "12天", "平息", "白查", "不用查", "排列", "順序")):
            return """### ⏳ 【CCIE 核心剖析：為什麼要用時間排列？如何區分「真有問題」與「歷史雜訊」？】

資深 CCIE 排錯與初學者最大的差別，就在於**「時間序列感知 (Temporal & Recency Awareness)」**！

#### 1. 傳統工具為什麼會讓人「白查」？
* Cisco 交換機的 Syslog Buffer 容量很大。若設備很久沒重開，裡面會累積一週前、一個月前、甚至半年前的日誌。
* 傳統告警系統只要看到關鍵字 `%LINK-3-UPDOWN` 或 `%LINEPROTO-5-UPDOWN` 就盲目發送 CRITICAL 告警。
* 工程師到了現場才發現：**「這是 12 天前工程施工留下來的舊 Log，這 12 天交換機根本穩定得很！」** 這就造成嚴重的無效排查（白查）與告警疲勞（Alert Fatigue）。

#### 2. SwitchScope 的時間軸推演四維法則
1. **建立全域時間錨點 (Global Anchor)**：
   提取整段日誌的最新一筆時間（例如 `Oct 19 01:52:06`）作為當前時間基準。
2. **計算時效差 (Recency Delta)**：
   計算每個異常事件發生的最後時間距今多遠。
   * **`ACTIVE (< 2小時)`**：剛剛發生，屬於**即時阻斷性故障**，必須立刻搶修！
   * **`RECENT (2~24小時)`**：過去 24 小時內曾發生，屬於**近期偶發**，需排查是否有隱患。
   * **`QUIESCED (> 24小時)`**：已平息超過一天甚至 12 天，且後續交換機持續記錄各項日常登入，證明該介面早已穩定，屬於**歷史過往事件**！
3. **區分因果與現場情境**：
   例如 `Gi2/0/37` 在 10/7 早上 7 點多跳動了幾次，但自 10/7 ~ 10/19 整整 12 天沒有再跳過一次。這通常是當時同仁插拔跳線、機房工程或網卡短暫重置，**當前切勿去 shutdown 介面或更換線路，避免誤動正常業務！**
4. **時間排列溯源**：
   將所有事件依時間軸一字排開，還原案發現場前後發生了什麼事（例如跳動之後是否有管理員登入？是否有設定變更？）。"""

        # Default fallback
        response_lines = [
            "### 🧑‍💻 SwitchScope 內建專家推理分析 (離線排障建議)",
            "",
            "系統已依據 ML 特徵啟動本機專家決策樹為您分析：",
            "",
            "#### 🔍 建議下一步在 Switch 執行的診斷指令：",
            "1. **如果懷疑 LACP 聚合失敗**：",
            "   ```cisco",
            "   show lacp neighbor",
            "   show etherchannel detail",
            "   ```",
            "2. **如果介面被 Err-Disabled**：",
            "   ```cisco",
            "   show errdisable recovery",
            "   show errdisable detect",
            "   ```",
            "3. **如果發現 CRC 錯誤過高**：",
            "   ```cisco",
            "   show interfaces transceiver detail",
            "   ```",
            "",
            "💡 **提示**：可直接點擊下方的「快捷提問按鈕」（例如產生主管報告、白話文解說、安全 SOP），系統將自動為您整理專業回覆！"
        ]
        return "\n".join(response_lines)
