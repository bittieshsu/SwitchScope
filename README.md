# ⬡ SwitchScope — 智慧網通設備異常透視與排障儀

<div align="center">

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![ECOD](https://img.shields.io/badge/Engine-PyOD%20ECOD-emerald.svg)](https://github.com/yzhao062/pyod)
[![CatBoost](https://img.shields.io/badge/Classifier-CatBoost-purple.svg)](https://catboost.ai/)
[![Local AI](https://img.shields.io/badge/Copilot-Local%20Ollama%20%2B%20CCIE%20Rules-cyan.svg)]()
[![Supply Chain](https://img.shields.io/badge/Supply%20Chain-AAA%20Pinned%20Hashes-success.svg)]()
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Air--Gapped%20Local-success.svg)]()
[![Zero-Dependency](https://img.shields.io/badge/Fallback-Zero--Dependency%20Pure%20Python-orange.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**專為網路管理員、系統整合商 (SI) 與機房駐點工程師打造的雙層式架構排障神器！**  
**100% 地端離線運算 ｜ 機敏密碼自動脫敏 ｜ 機器學習秒級快篩 ｜ CCIE 戰情報告 ｜ 全網拓撲與雙向交叉校驗**

</div>

---

## 🌟 為什麼需要 SwitchScope？

在維護 Cisco 等企業級交換機與路由器時，工程師經常透過 **Console 扁線（Serial COM）** 或跳板機 **SSH** 連線，面臨四大現場維運折磨：

1. **文字海嘯，肉眼比對極度耗時**：
   敲了 `show tech-support`、`show log`、`show int` 幾千幾萬行，看不出到底是哪條線路在掉包，關鍵錯誤往往隱沒在海量輸出中。
2. **經典組態地雷難以察覺**：
   * **LACP 聚合組掛起**：成員埠標記為 `(s) suspended`，容易被忽略，常因對端未開 LACP、模式錯配或跳線錯插造成。
   * **實體線路老化 (CRC 累積)**：光模組衰退或線路受干擾，導致 TCP 頻繁重傳，很難在 48 個 Port 的計數器中一眼看出離群異常。
   * **連接埠鎖死 (Err-Disabled)**：BPDU Guard 觸發、Port-Security 違規或本機迴圈 (Loopback)。
3. **多台設備配置孤島，跨機衝突找不到**：
   Switch A 設了 Trunk VLAN 2007，對端 Switch B 卻是 VLAN 1；或 A 台設了 Po1 Active，B 台卻根本沒配 channel-group。單機看全都「正常」，連在一起全網癱瘓。
4. **客戶資安嚴禁上雲**：
   金融、政府、半導體機房**嚴禁**將設備 Config、路由表與 IP 拓撲丟上公開 AI（如 OpenAI/Claude），且現場通常處於**無外網環境 (Air-Gapped)**。

---

## 📊 方案對比表 (Feature Comparison)

| 功能特點 / 解決方案 | 傳統人工手動排障 | 公開雲端 AI (ChatGPT/Claude) | 昂貴網管平台 (SolarWinds/PRTG) | ⬡ SwitchScope 本地雙層排障儀 |
| :--- | :---: | :---: | :---: | :---: |
| **資安合規 (100% 斷網運行)** | ✅ 免上雲 | ❌ **嚴重資安違規 (機敏外流)** | ⚠️ 需建置地端專用 Server | 🏆 **100% 本機離線、斷網可用** |
| **機敏資訊自動脫敏** | ❌ 需手動刪除 | ❌ 人工易疏漏 | ⚠️ 需額外設定遮蔽規則 | 🏆 **自動抹除密碼、Hash、Community** |
| **分析速度** | 🐢 30~60 分鐘逐行肉眼查 | ⏳ 15~30 秒 (受限雲端速度) | ⚠️ 依輪詢週期定時告警 | ⚡ **< 1 秒 毫秒級極速出圖出表** |
| **CRC / 封包異常偵測** | ❌ 48 埠數值龐大易漏看 | ⚠️ 容易數值幻覺或漏看 | ⚠️ 僅支援靜態門檻值 | ⚡ **ECOD 無監督異常演算法秒抓離群埠** |
| **交換機面板與全網拓撲** | ❌ 無 | ❌ 無法呈現前面板與拓撲 | ⚠️ 需配置複雜 SNMP 掃描 | 🎨 **純 SVG 動態前面板 + 智慧架構圖** |
| **跨設備雙向對稱校驗** | ❌ 需切換多個視窗手動比對 | ❌ 上下文長度受限、對比混亂 | ⚠️ 多僅呈現連線，不核對細節組態 | 🔍 **自動比對雙端 LACP/VLAN/MTU 衝突** |
| **直接產出 Cisco 修復指令** | ⚠️ 需查閱 Cisco 手冊 | ⚠️ 容易夾雜大量理論科普英文 | ❌ 僅告警不給修復腳本 | 🛠️ **直接輸出繁中 `config t` 貼上即修** |
| **建置門檻與相依性** | 零門檻 | 需聯網與付費帳號 | 昂貴 License、需龐大主機 | 🚀 **雙擊即開、零外部相依容錯保證** |

---

## 🚀 雙層式架構設計 (Two-Tier Architecture)

SwitchScope 不做「拿大砲打蒼蠅」的事（不盲目將海量數據全塞給昂貴且緩慢的 LLM），而是採用**最科學的兩階段聯防機制**：

```
                    ┌─────────────────────────┐
                    │ Cisco Switch CLI 輸出   │
                    └────────────┬────────────┘
                                 │
                 (正則剖析器結構化為 DataFrame)
                                 │
                                 ▼
┌────────────────────────────────────────────────────────┐
│ 第一層：輕量機器學習引擎 (ML Tier - 本機純 CPU 毫秒級)   │
│  1. ⚡ ECOD (PyOD) : 無監督累積分布檢測，秒抓 CRC/丟包離群埠│
│  2. 🌲 CatBoost     : 決策樹分類常見網路故障並給予信心度  │
└────────────────────────────────┬───────────────────────┘
                                 │
           ┌─────────────────────┴─────────────────────┐
           ▼                                           ▼
 [常見已知問題 (信心度 > 90%)]              [罕見疑難 / 複雜跨網段問題]
 1 秒內輸出【根因分析 + 修復指令】           自動啟動【第二層：Tier-2 互動式排障】
 範例：LACP 掛起、Err-Disabled、CRC 衰退     由 Local LLM / 專家決策樹進行多輪問答
```

---

## 🖥️ 介面預覽 (Dashboard Architecture)

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ ⬡ SwitchScope   [單機深度排障] [多台實體設備跨機聯動] [⚡ 跨廠牌對接檢驗儀]   字體: [A-] [標準] [A+]   🟢 Ollama │
├────────────────────────┬───────────────────────────────────────────┬────────────────────────────────────┤
│ 📋 CLI 文字輸入區       │ 👑 CCIE 主震央裁決 (Primary Blocker)        │ 🤖 CCIE Copilot                    │
│  [載入範例 ▼]          │  [Po1: Gi1/0/2 LACP Suspended 聚合組掛起]  │                                    │
│  - Cisco / Aruba 實戰  │  - 影響層面: 頻寬減半，冗餘失效 (CRITICAL)   │ 戰情報告主動開場：                 │
│  - Junos / FortiSwitch │  - 立即下一動: 執行一鍵採集指令包           │ 「主震央為 Po1，                   │
│  - 動態路由 (OSPF/BGP) │                                           │  已產出修復指令，                  │
│  - 時序平息 (免白查)    ├───────────────────────────────────────────┤  請確認對端開關...」                │
│  - 實體拓撲連動 (CDP)  │ 🖧 實體交換機面板模擬 (48-Port Faceplate)   │                                    │
│                        │  [🟢][🟢][🟠][🔴] ... [CRC 離群橘燈/鎖死紅燈]│ 💬 連續多輪記憶：                   │
│ [🚀 開始 ML 智慧診斷]  ├───────────────────────────────────────────┤  Q: 我要建立 OSPF 怎麼協助我？      │
│                        │ 🔌 跨設備實體拓撲架構圖 (純 SVG 動態繪製)  │  A: 提供完整 CLI `router ospf 1`   │
│ [雙欄跨廠牌對撞校驗]   │  [上聯 Cisco] ── (差集比對) ── [接入 Aruba]│     `network ...`                  │
└────────────────────────┴───────────────────────────────────────────┴────────────────────────────────────┘
```

---

## 💎 十一大核心模組

### 模組 0：👑 CCIE 全域會診總評與統整下一動 (Unified Executive Triage)
* **主震央裁決 (Primary Blocker)**：杜絕碎片化逐孔排查！自動從全機眾多雜訊中，精準抓出最要命的致命核心故障（如骨幹 LACP 聚合掛起、全網 TCN 風暴跳動），並與次要周邊故障進行主次分流。
* **智慧過濾免白查**：時間感知 (Time-Aware) 自動識別下班離峰休眠，標記為安全，避免現場人員白費工。
* **全域統整深度採集指令包 (一鍵搞定)**：自動將所有需要深入查驗的指令彙整成「單一 Cisco CLI 巨集腳本」，現場人員只要複製一次貼上，秒速完成全機所有疑點事證採集！
* **全域整合現場修復腳本**：依照優先級排序，先集中火力止血修復主因，再恢復次要連接埠。

### 模組 1：⚡ ECOD 實體計數器無監督離群檢測 (Unsupervised Anomaly)
* 採用國際頂尖異常檢測演算法 **ECOD（Empirical Cumulative Distribution-based Outlier Detection）**。
* **無須事先標註標籤**，自動計算 48 埠之 CRC、Input/Output Errors、Collisions、Queue Drops 的經驗累積分布。
* 精確指出：「*Gi1/0/13 之 CRC 錯誤為全交換機 99.8th 百分位離群值，高度懷疑 SFP 光模組或線路老化！*」

### 模組 2：🌲 CatBoost 決策樹故障分類與修復指令生成
* 針對 Cisco 核心運行狀態進行專家特徵分類：
  * `LACP_BUNDLE_SUSPENDED`：LACP 捆綁組成員掛起診斷。
  * `BPDU_GUARD_ERR_DISABLE` / `LOOP_DETECTED_ERR_DISABLE`：埠安全鎖死。
  * `DUPLEX_HALF_MISMATCH`：雙工半雙工碰撞異常。
  * `STACK_MEMBER_UNREADY`：Cisco StackWise 堆疊成員脫機或狀態異常。
  * `DEFAULT_ROUTE_MISSING`：預設路由缺失引發黑洞。
* **一鍵複製修復指令**：直接產生可以直接貼回 Switch 的 `configure terminal` 修正腳本！

### 模組 3：🖧 實體交換機面板模擬器 (Switch Faceplate Simulation)
* 視覺化模擬 24/48 埠前面板 LED 狀態：
  * 🟢 **綠燈**：正常連線且計數器健康。
  * 🔴 **紅燈**：介面處於 Err-Disabled 鎖死狀態。
  * 🟠 **橘燈**：LACP 掛起 (Suspended) 或 ECOD 判定數值嚴重離群。
  * ⚫ **灰燈**：離線或未啟用。
* **點擊連接埠**：彈出詳細遙測視窗（CRC、封包收發、VLAN、雙工速限）。

### 模組 4：⏳ CCIE 時序事件溯源與時效感知時間軸 (Time-Series Recency Timeline)
* **全域時間錨點 (Global Anchor)**：自動解析全機日誌之時間戳記，精準計算日誌涵蓋跨度（例如：涵蓋 11.8 天 / 282.5 小時）。
* **時效三級分流 (Recency Triaging)**：
  * 🔴 **`ACTIVE (< 2小時)`**：即時進行中阻斷性故障，立即發布 CRITICAL 告警。
  * 🟡 **`RECENT (2~24小時)`**：過去 24 小時內曾發生，列為 WARNING 保持觀察。
  * 🟢 **`QUIESCED (> 24小時)`**：歷史已平息雜訊！例如 12 天前施工插拔線路，後續 280 小時完全零復發。系統自動降級為 NORMAL、維持設備 100 分健康度，**徹底杜絕無效白查 (Alert Fatigue)**！
* **時序軌道視覺化**：自動將連續 Up/Down 震盪智慧聚類為單一節點，按時間前後依序排列。

### 模組 5：🌐 CCIE 三層動態路由狀態機診斷 (Deterministic Routing FSM)
* **OSPF FSM 狀態機解析**：精準秒抓 `EXSTART / EXCHANGE`（99% 為 MTU Mismatch 協商失敗）與 `INIT`（單向連通/Multicast 224.0.0.5 丟包）。
* **BGP Peering 分析**：精確區分 `Active`（TCP Port 179 被防火牆/ACL 阻擋或對端未配置本端 IP）與 `Idle`（缺少路由或漏配 update-source）。
* **EIGRP 權重診斷**：自動偵測 `%DUAL-5-NBRCHANGE: K-value mismatch` 並產出標準還原腳本；即時防範 SIA (Stuck-In-Active)。
* **MPLS L3VPN 轉發穿透**：剖析 Control Plane (BGP VPNv4) 與 Data Plane (LDP / MPLS 標籤) 分離故障，定位 RT (Route-Target) 與 RD 概念地雷。

### 模組 6：🔌 CCIE 跨設備實體拓撲連動與架構圖視覺化 (Multi-Chassis Architecture & Topology Visualizer)
* **單機排查 (CCNP) 升級為全網架構拓撲排查 (CCIE)**：打破單座交換機的資訊孤島！整合 `show cdp neighbors [detail]`、`show lldp neighbors`、`show mac address-table` 與 `show ip arp`，直接在網頁端**動態繪製全網上下聯架構拓撲圖**！
* **100% 地端離線純 SVG 動態繪製**：完全零外部 npm 或 CDN 相依，在極嚴格的氣隙斷網機房（Air-Gapped）也能順暢秒開秒繪！
* **三層階層式架構透視 (Hierarchical Tiering)**：
  * ▲ **上聯核心骨幹層 (Upstream Core / Distribution)**：自動識別核心設備（如 `Core-SW-01`）與上聯主幹。
  * ◆ **本機受檢設備層 (Local Switch Under Test - DUT)**：居中顯現受檢機身、聚合組與各埠連動關係。
  * ▼ **下聯接入與終端層 (Downstream Access & Endpoints)**：自動分類二層接入交換機（如 `Floor2-Access-SW-02`）、無線 AP、VoIP 電話以及經由 MAC/ARP 反查出來的終端主機群。
* **實體線路色彩編碼與動態異常警示**：
  * 🚨 **紅色呼吸脈衝虛線 (Pulsing Red Link)**：**跨設備錯插跳線 (Cross-Device Mis-cabling)**！例如 `Po1` 之 `Gi1/0/2` 誤插至接入交換機，即刻閃爍紅燈警告！
  * 🟠 **橘黃色虛線 (Amber Dashed Link)**：**Trunk Native VLAN 衝突**！兩端 PVID 不符導致 STP `BLOCK_PVID_LOCAL` 阻斷。
  * 🌊 **橘色點狀線 (Orange Dotted Link)**：**緩衝區溢位丟包 (Output Drops)**！透視是終端 PC 休眠突發還是骨幹擁塞。
  * 🔗 **深藍色粗線 (Blue Solid Link)**：**Port-Channel 聚合組 (LACP/PAgP)**！直觀標示聚合成員關係。

### 模組 7：🤖 Tier-2 本地 AI 排障助理 (CCIE Reasoning Copilot)
* **分析完畢主動開場戰報（Proactive Briefing）**：
  * 一鍵分析完畢後，AI Copilot **第一時間在聊天室主動發布【CCIE 戰情總評與速報】**，包含主震央裁決、健康評分與建議行動，工程師無須手動貼文字或組織問題！
* **卡片一鍵呼叫 AI 深入推演**：
  * 主震央卡片與每張細部診斷卡片均具備一鍵連動按鈕（`🤖 呼叫 CCIE Copilot 深入推理解析`），直接帶入上下文開始即時推演！
* **連續多輪上下文記憶 (Multi-Turn Continuous Memory)**：
  * 支援連續對話歷史（保留全機實時遙測 + 最近 4 輪 Q&A 一問一答），連續追問介面修復、驗證指令，AI 絕不失憶！
* **CCIE 實戰三大鐵律**：
  1. **【強制全篇繁體中文】**：嚴禁英文開頭或簡體字，一律採用台灣網管專業用語（介面、遮罩、跳線、封包、聚合組）。
  2. **【切中要害、零教科書廢話】**：嚴禁名詞科普理論（如：嚴禁講「OSPF 是內部路由協議...」等廢話）！直接切入故障根因！
  3. **【直給 Cisco CLI 可執行腳本】**：問怎麼建（如 OSPF/BGP/VLAN/Trunk），立刻在 ```cisco 內提供完整的 `configure terminal` 程式碼區塊與驗證指令！
* **普通筆電超輕量模型專屬優化 (1.5B ~ 3B)**：
  * 專門適配 `qwen2.5:1.5b`（不到 1GB，純 CPU 秒回）、`qwen2.5-coder:1.5b`、`qwen3.5:3b`，8GB 文書筆電順暢運行不卡頓！
* **雙軌無縫降級 (Zero-Downtime Fallback)**：
  * 若未安裝或未啟動 Ollama，系統自動無縫降級至 SwitchScope **CCIE 離線專家規則引擎**，斷網機房照常精準應答！

### 模組 8：🏢 全網多實體設備批次匯入、雙向校驗與全網架構拓撲 (Multi-Chassis Real Fleet Engine)
* **多設備批次拖曳上傳與本機資料夾一鍵掃描**（支援 2 ~ 50 台交換機備份檔一次匯入）。
* **真正的「多實體機雙向交叉驗證」 (Bidirectional Cross-Device Verification)**：
  1. **LACP 雙向聚合對稱性**：Switch A 將 `Gi1/0/2` 設為 `Po1 active`，但對端 Switch B 的 `Gi1/0/48` 竟然沒配 Port-Channel！秒級抓出不對稱配置與跨機錯插。
  2. **雙機 Trunk Native VLAN 與 Allowed VLAN 衝突**：同時調閱兩機互聯埠，實時比對 PVID 是否相符，防止 STP `BLOCK_PVID` 阻斷。
  3. **雙機 MTU 差異**：預防 MTU 1500 vs 9000 導致 OSPF 死在 `EXSTART`。
* **全網跨設備衝突矩陣與一體化修復腳本 (Master Fleet Remediation Macro)**：
  * 表格化列出所有跨機衝突，並依主機名稱 (Hostname) 分區塊產生整網一鍵修正 macro。
* **全網多機多檔案 AI 知識庫連動**：
  * Fleet Copilot 自動載入所有實體交換機的日誌與互聯關係，支援跨檔案連續追問！

### 模組 9：⚡ 跨廠牌雙欄對接檢驗儀 (Cross-Vendor Dual-Pane Link Inspector)
* **雙欄對撞實戰工作區**：左欄貼【設備 A】（如 Core Cisco）、右欄貼【設備 B】（如 Access Aruba / FortiSwitch），支援一鍵載入實戰範例。
* **四大廠牌自動特徵嗅探**：自適應識別 Cisco IOS/NX-OS、ArubaOS-CX、Juniper Junos、FortiSwitch。
* **五重對接衝突深度審計**：
  1. ⚡ **Trunk VLAN 差集黑洞**：自動比對 Allowed / Tagged VLAN，揪出單邊漏配造成的封包沉沒。
  2. ⚡ **跨廠牌 LACP 聚合阻塞**：一端 LACP Active、另一端靜態 Trunk，導致端口遭防環機制標記為 Suspended 斷線。
  3. ⚡ **MTU 巨框與速率雙工衝突**：揪出 1500 vs 9000 或 1000M vs 2000M 導致的連線震盪。
  4. ⚡ **實體線路光衰與 CRC 累積**：秒抓互聯線路劣化。
* **雙端成對原廠修復與回滾腳本 (Remediation & Rollback)**：同時產出雙邊原廠 CLI，並附安全回滾指令（Rollback）。

### 模組 10：🛡️ 軟體供應鏈安全加固與零相依純地端安全模式 (Supply Chain Security & Zero-Dependency Safe Mode)
* **密碼學雜湊鎖定 (`requirements.lock`)**：
  * 提供鎖定官方二進位 Wheel 之 `requirements.lock`，強制啟用 `--require-hashes` 與 `--only-binary :all:`：
    ```bash
    pip install --require-hashes --only-binary :all: -r requirements.lock
    ```
  * 徹底防止安裝期任意程式碼執行 (`setup.py` ACE) 與 PyPI 投毒。
* **極限安全機房：零相依純 Python 模式 (Zero-Dependency Safe Mode)**：
  * 在國防、金融、半導體機房等嚴禁執行 `pip install` 的跳板機上，**完全不安裝任何第三方 pip 套件亦可 100% 正常運行**，攻擊面直接歸零！
* **一鍵供應鏈安全審計儀 (`tools/audit_supply_chain.py`)**：
  * 評級達 **AAA 級**，一鍵檢測 PyPI 鏡像源安全、掃描 Typosquatting 惡意包、校驗鎖定檔雜湊。

---

## 📋 支援的 Cisco CLI 常用指令清單

SwitchScope 正則剖析器採用**智慧容錯與區塊切片技術**，你可以一次貼上單個指令、多個指令，或是直接貼入完整的 `show tech-support`：

| Cisco 指令 | 解析項目與用途 | 對應之分析模組 |
| :--- | :--- | :--- |
| `show version` | 機型、IOS-XE 版本、CPU、記憶體、連續運行時間 (Uptime) | 基礎資訊與健康面板 |
| `show switch` / `show switch stack-ports` | StackWise 堆疊成員角色 (Active/Standby/Member)、優先權、狀態 | 堆疊脫機與狀態診斷 |
| `show interfaces status` | 各 Port 連線狀態 (connected/err-disabled)、VLAN、雙工速度、SFP 類型 | 面板模擬、雙工錯配、鎖死偵測 |
| `show interfaces` / `show interfaces counters` | 5 分鐘流量速率、CRC 錯誤計數、Input/Output Errors、Collisions | **ECOD 無監督異常離群檢測** |
| `show etherchannel summary` | Port-Channel 聚合組狀態 (SU/SD)、協議 (LACP/PAgP)、成員埠掛起 `(s)` | **LACP 聚合掛起根因診斷** |
| `show ip route` | 預設路由 (0.0.0.0/0)、直連網段 (C)、靜態路由 (S)、黑洞路由檢測 | 路由可達性分析 |
| `show logging` / `show log` | BPDU Guard、Port-Security、UDLD、鏈路震盪時間戳記 | **時效感知時序溯源 (免白查)** |
| `show ip ospf neighbor` | OSPF 鄰居狀態機 (`FULL`, `2WAY`, `EXSTART`, `EXCHANGE`, `INIT`) | **動態路由 FSM 狀態機解析** |
| `show ip bgp summary` | BGP Autonomous System、Peering 狀態 (`Established`, `Active`, `Idle`) | BGP TCP 179 / ACL 阻斷偵測 |
| `show cdp neighbors [detail]` | 對端交換機 Hostname、連線對接連接埠、平台型號、Native VLAN | **全網架構拓撲圖 & 錯插跳線秒抓** |
| `show lldp neighbors [detail]` | 多廠牌 (LLDP) 鄰居設備名稱、遠端埠號、系統能力 | 跨廠牌架構拓撲對接 |
| `show mac address-table` | 動態學習之 MAC 位址、對應 Port、VLAN | 接入終端設備反查與定位 |
| `show ip arp` | IP 與 MAC 對應表 | 終端主機 IP 穿透辨識 |

---

## 🔰 小白 / 輕薄文書筆電專用：零門檻 3 步驟懶人上手指南

> [!TIP]
> **先吃一顆定心丸**：**你完全不需要安裝 Ollama，也能 100% 正常使用 SwitchScope 進行全功能排障！**  
> 核心的「交換機故障診斷」、「CRC 離群值檢測」、「CCIE 專家決策樹」、「跨機拓撲衝突比對」與「自動產生修復 CLI」，全部由內建純 Python 演算法毫秒級完成，根本不需要 GPU，也不需要 LLM！

---

### 第一步：安裝 Python（如果電腦連 Python 都沒有）
SwitchScope 支援最簡化自動安裝：
* **直接雙擊 `啟動服務.bat`（推薦）**：
  若偵測到未安裝 Python，視窗會自動提示輸入 `1`，系統將自動透過 Windows 官方 `winget` 一鍵下載並配置好 Python 3.11，全程不需點擊下一步！
* **或者開啟 Windows 終端機 (PowerShell)**，貼上指令執行：
  ```powershell
  winget install Python.Python.3.11
  ```
* **手動下載**：前往 [Python 官方網站](https://www.python.org/downloads/) 下載安裝（**請務必勾選「Add python.exe to PATH」**）。

---

### 第二步：啟動 SwitchScope（雙擊即用）
* **Windows**：直接雙擊資料夾內的 **`啟動服務.bat`**。
* **macOS**：在 Finder 中雙擊 **`啟動服務.command`**。
* **Linux / 跳板機**：執行 `./launcher.sh` 或 `python3 server.py`。
* 瀏覽器會自動開啟網頁面板：`http://localhost:8920/`。
* 把 Cisco 交換機的 Log 或 Show 指令（例如 `show int status`、`show log` 等）貼到左側文字框，點擊「🚀 開始 ML 智慧診斷」，1 秒內全部圖表、拓撲圖與修復指令就出來了！
* **字體大小隨心調**：頂端導航列提供 **`字體大小: [A-] [標準] [A+]`**，高解析度筆電與大螢幕可隨時放大閱讀！

---

### 第三步：（可選）普通文書筆電想開啟「地端 AI 互動聊天」怎麼做？
如果你手邊是一台**普通筆電（如 8GB 或 16GB 記憶體、無獨立顯示卡、只有 CPU/內顯）**，想要跟 AI 即時對話，請依照以下指引，**千萬不要亂裝動輒數十 GB 的肥大模型以免筆電風扇狂轉甚至當機**：

1. **安裝 Ollama（只需 1 分鐘）**：
   前往 [Ollama 官方網站 (ollama.com)](https://ollama.com/download) 下載安裝檔，點擊下一步安裝完成。
2. **普通筆電最佳輕量模型推薦（複製指令執行）**：
   打開終端機（CMD 或 PowerShell），依照你的電腦規格挑選一個複製貼上執行：
   * 🚀 **極致省電 / 8GB 普通筆電首選（檔案不到 1GB，純 CPU 秒回）**：
     ```bash
     ollama run qwen2.5:1.5b
     ```
   * 💻 **代碼特化版（適合 Cisco CLI 與腳本生成）**：
     ```bash
     ollama run qwen2.5-coder:1.5b
     ```
   * ⚡ **標準輕量平衡版（3B 參數，極致推理）**：
     ```bash
     ollama run qwen3.5:3b
     ```
3. **自動無縫熱接**：
   下載完成後，重新整理 SwitchScope 網頁，右上角狀態燈會自動變成 `🟢 Ollama: 已連線`，上方模型選單也會自動選中！
   * *註：若機房現場完全斷網或沒開 Ollama，SwitchScope 會自動切換為【🛡️ CCIE 離線規則降級引擎】，依然能針對所有故障提供精準回答！*

---

## 💼 極限斷網（Air-Gapped / 機房跳板機）隨身碟攜帶指南

在軍工、金融或高科技晶圓廠等**完全斷絕外部網路 (Air-Gapped)** 的機房中，請依此步驟攜帶與運行：

1. **在有網電腦準備隨身碟**：
   將整個 `SwitchScope` 專案資料夾直接複製至隨身碟或維運隨行筆電。
2. **跳板機免安裝任何套件**：
   即使跳板機或機房 PC **無法連外下載 pip 套件**，SwitchScope 內建的純 Python 零相依引擎（Zero-Dependency Engine）亦會自動接管所有 ECOD 異常偵測與決策樹分類。
3. **插入隨身碟雙擊即開**：
   直接在隨身碟內點擊 `啟動服務.bat` 或在終端機執行 `python server.py`，開啟瀏覽器即可完全在地端進行排障！

---

## 📁 專案目錄結構

```text
SwitchScope/
  ├── core/
  │    ├── parser.py           # Cisco CLI 多指令正則剖析器 (Status, Counters, LACP, CDP/LLDP, Routing, Timeline)
  │    ├── sanitizer.py        # 地端機敏密碼、Community、IP 脫敏防護器
  │    ├── multi_chassis.py    # 全網多實體設備雙向校驗、衝突檢測與全網架構引擎 (含 Fleet Prompt 合成)
  │    └── llm_gateway.py      # 本地 Ollama 多輪對話串接與 CCIE 實戰規則決策樹
  ├── ml_engine/
  │    ├── ecod_detector.py    # 雙軌異常檢測 (C 語言 PyOD ECOD + 零相依純 Python ECOD 容錯)
  │    └── fault_classifier.py # 雙軌故障分類 (CatBoost 決策樹 + 零相依純 Python 專家決策樹)
  ├── tools/
  │    └── audit_supply_chain.py # 供應鏈安全與依賴完整性審計儀 (評級 AAA)
  ├── web/
  │    └── index.html          # 前端現代化面板 (前面板模擬 + 全網架構拓撲 + 主動戰報 + 多輪記憶 + 字體縮放)
  ├── samples/
  │    ├── multi_chassis_demo/ # 3 台實體設備對接示範包 (Core-SW-01, office1-15F, Floor2-02)
  │    ├── cisco_troubleshoot_sample.txt      # 實戰多重故障排查範例 Log (LACP + BPDU + CRC)
  │    ├── cisco_flapping_sample.txt          # 高頻震盪與離峰下班休眠實戰 Log
  │    ├── cisco_ccie_routing_sample.txt      # CCIE 核心路由實戰 Log (OSPF EXSTART + BGP + EIGRP)
  │    ├── cisco_timeline_quiesced_sample.txt # 12 天前歷史平息事件 (時間序列感知免白查)
  │    └── cisco_ccie_cdp_topology_sample.txt # CCIE 實體拓撲連動 Log (跨交換機錯插 + 上聯穿透)
  ├── requirements.txt         # 嚴格釘選之套件清單 (含供應鏈安全警示)
  ├── requirements.lock        # 密碼學 SHA-256 雜湊鎖定檔 (--require-hashes 專用)
  ├── server.py                # 本機輕量 API 伺服器 (支援批次上傳與多輪對話端點)
  ├── test_engine.py           # 自動化迴歸測試套件 (涵蓋 L2/L3/CDP拓撲/時序感知/多機聯動/供應鏈安全)
  ├── launcher.ps1             # Windows PowerShell 智慧環境檢查與安全啟動器 (支援 winget 自動安裝 Python)
  ├── 啟動服務.bat              # Windows 雙擊極速啟動 (自動開啟瀏覽器)
  ├── 啟動服務.command          # macOS Finder 雙擊極速啟動 (自動開啟 Safari/Chrome)
  ├── launcher.sh              # Linux / macOS 終端通用啟動腳本
  ├── LICENSE                  # MIT 開源授權條款
  └── README.md                # 專案詳細說明文件
```

---

## 🎯 內建實戰示範包 (Built-in Samples Guide)

在單機模式工具列中，點選「載入範例」可即時體驗不同真實維運場景：
1. **實戰故障 (Troubleshoot)**：LACP 聚合組掛起、BPDU Guard 鎖死、CRC 物理線路嚴重老化。
2. **端口震盪 (Flapping)**：高頻跳動偵測 vs. 夜間離峰下班睡眠正常待機智慧區分（免白查）。
3. **動態路由 (Routing FSM)**：OSPF MTU 不匹配卡在 EXSTART、BGP Active 狀態 TCP 179 阻斷。
4. **時序感知 (Timeline Quiesced)**：12 天前施工插拔日誌自動平息判定（維持 100 分健康，防警報疲勞）。
5. **CDP拓撲 (Topology)**：完整呈現上下聯骨幹、接入交換機與終端 PC，透視跨交換機實體錯插跳線！

在「多台實體設備跨機聯動」模式中，點選「載入示範設備包」即可一次載入 3 台實體交換機，秒級體驗跨設備雙向驗證與全網一鍵修復腳本！

---

## ❓ 常見問答 (FAQ)

### Q1: 我的筆電只有 8GB 記憶體，沒有獨立顯卡，跑得動嗎？
**完全跑得動！** SwitchScope 核心的 ML 演算法與正則剖析引擎完全使用 CPU 執行，記憶體佔用小於 **35MB**。  
若想開啟地端 AI 對話，請選用 `qwen2.5:1.5b`（模型大小僅 980MB），即使在 8GB 文書筆電上也能秒速生成回答，不卡頓、不熱當。

### Q2: 設備的密碼、IP 或敏感設定會不會外流？
**絕對不會！** 
1. 程式碼 100% 開源，純本機運行，完全沒有任何外部上報追蹤或雲端連線。
2. 內建 `core/sanitizer.py` 會在地端剖析前，自動將 `enable secret`、`password 7`、SNMP Community 字串以及客戶機敏資訊進行密碼學遮蔽。

### Q3: 如果我的交換機不是 Cisco，可以用嗎？
SwitchScope 2.0 已擴充支援 **Cisco、ArubaOS-CX、Juniper Junos、FortiSwitch** 多廠牌適配器，並提供「⚡ 跨廠牌對接檢驗儀 (Cross-Vendor Dual-Pane Link Inspector)」，左欄貼設備 A（如 Core Cisco）、右欄貼設備 B（如 Access Aruba / FortiSwitch），能秒級比對 Trunk VLAN 差集黑洞、跨廠 LACP 模式衝突與 MTU 錯配，並同步產出雙邊原廠修復與回滾指令！

### Q4: 執行 `python test_engine.py` 會測什麼？
測試套件會自動對 7 大子系統進行回歸校驗：
- `test_parser`：驗證多種 Cisco 指令結構化。
- `test_ecod_engine`：驗證無監督異常離群算法（含純 Python fallback）。
- `test_fault_classifier`：驗證決策樹故障分類與修復指令生成。
- `test_routing_fsm`：驗證 OSPF/BGP/EIGRP 狀態機診斷。
- `test_timeline_recency`：驗證歷史平息與時間序列分析。
- `test_multi_chassis`：驗證跨機 LACP/VLAN/MTU 雙向衝突矩陣。
- `test_supply_chain`：校驗依賴清單與 SHA-256 鎖定檔。

---

## 👨‍💻 作者與貢獻者 (Author & Contributors)

* **Kerr** ([@kerr20801](https://github.com/kerr20801)) — 專案發起與核心架構設計
* 🤖 **[Google Gemini](https://gemini.google.com)** — AI 結對編程夥伴 (Pair Programming Copilot)
* 延續 `PacketScope` 與 `NetScope` 之維運工具矩陣，專注解決地端現場網管與 SI 核心痛點。歡迎提 PR 與 Issue 交流！

---

## 📄 授權條款 (License)

本專案採用 [MIT License](LICENSE) 開源授權，歡迎自由修改、擴充與整合於內部維運流程中。

---

## ⚠️ 免責與實機聲明 (Disclaimer)

> 💡 **老實說聲明 (Honest Note)**：  
> 本工具核心規則、決策樹與排障邏輯深度針對 **Cisco** 實機環境調校與驗證；其他廠牌（ArubaOS-CX、Juniper Junos、FortiSwitch）適配器與跨廠牌對接目前**其他廠牌沒測過，只用 AI 測過就好 XD**。  
> 現場套用修復指令前請務必人工複核（或先備妥各家安全回滾腳本），歡迎有各廠牌實體設備環境的各路大神提 PR / Issue 一起抓蟲補完！🙏

