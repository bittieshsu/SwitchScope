# ⬡ SwitchScope — 智慧網通設備異常透視與排障儀

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-lightgrey.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![ECOD](https://img.shields.io/badge/Engine-PyOD%20ECOD-emerald.svg)](https://github.com/yzhao062/pyod)
[![CatBoost](https://img.shields.io/badge/Classifier-CatBoost-purple.svg)](https://catboost.ai/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Air--Gapped%20Local-success.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

專為**網路管理員、系統整合商 (SI) 與機房駐點工程師**打造的**雙層式架構（機器學習快篩 + 地端 AI 互動推理）**排障神兵利器！  
**100% 地端本機運算、支援無網斷網環境（Air-Gapped）、客戶機敏資訊自動脫敏不外傳。**

---

## 🌟 解決什麼核心痛點？

在維護 Cisco 等各廠牌 Switch、Router 時，工程師通常只能透過 **Console 扁線（Serial COM）** 或跳板機 **SSH** 連線，面臨三大維運折磨：
1. **文字海嘯，人眼比對極度耗時**：
   敲了 `show tech-support`、`show log`、`show int` 幾千幾萬行，看不出到底是哪條線路在掉包，關鍵錯誤隱沒在海量輸出中。
2. **經典組態地雷難以察覺**：
   * **LACP 聚合掛起**：成員埠標記為 `(s) suspended`，肉眼容易漏看，常因對端未開 LACP 或 VLAN 不匹配造成。
   * **實體線路老化 (CRC 累積)**：光模組衰退或線路受干擾，導致 TCP 頻繁重傳，普通人很難在 48 個 Port 的計數器中一眼看出離群異常。
   * **連接埠鎖死 (Err-Disabled)**：BPDU Guard 觸發、Port-Security 違規或本機迴圈 (Loopback)。
3. **客戶資安嚴禁上雲**：
   金融、政府、半導體機房**嚴禁**將設備 Config、路由表與 IP 拓撲丟上公開 AI（如 OpenAI/Claude），且現場通常處於**無外網環境 (Air-Gapped)**。

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

## 💎 五大核心模組

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
* **爆炸半徑 (Blast Radius) 動態加權**：路由故障自動加權冠上全域最高優先級主震央 (Primary Blocker)。

### 模組 6：🔌 CCIE 跨設備實體拓撲連動與架構圖視覺化 (Multi-Chassis Architecture & Topology Visualizer)
* **單機排查 (CCNP) 升級為全網架構拓撲排查 (CCIE)**：打破單座交換機的資訊孤島！整合 `show cdp neighbors [detail]`、`show lldp neighbors`、`show mac address-table` 與 `show ip arp`，直接在網頁端**動態繪製全網上下聯架構拓撲圖**！
* **100% 地端離線純 SVG 動態繪製**：完全零外部 npm 或 CDN 相依，在極嚴格的氣隙斷網機房（Air-Gapped）也能順暢秒開秒繪！
* **三層階層式架構透視 (Hierarchical Tiering)**：
  * ▲ **上聯核心骨幹層 (Upstream Core / Distribution)**：自動識別核心設備（如 `Core-SW-01`）與上聯主幹。
  * ◆ **本機受檢設備層 (Local Switch Under Test - DUT)**：居中顯現受檢機身、聚合組與各埠連動關係。
  * ▼ **下聯接入與終端層 (Downstream Access & Endpoints)**：自動分類二層接入交換機（如 `Floor2-Access-SW-02`）、無線 AP、VoIP 電話以及經由 MAC/ARP 反查出來的終端電腦主機群（如 `PC: 10.20.7.35`）。
* **實體線路色彩編碼與動態異常警示**：
  * 🚨 **紅色呼吸脈衝虛線 (Pulsing Red Link)**：**跨設備錯插跳線 (Cross-Device Mis-cabling)**！例如 `Po1` 之 `Gi1/0/2` 誤插至接入交換機，即刻閃爍紅燈警告，避免燒機或防環掛起！
  * 🟠 **橘黃色虛線 (Amber Dashed Link)**：**Trunk Native VLAN 衝突**！兩端 PVID 不符導致 STP `BLOCK_PVID_LOCAL` 阻斷。
  * 🌊 **橘色點狀線 (Orange Dotted Link)**：**緩衝區溢位丟包 (Output Drops)**！透視是終端 PC 休眠突發還是骨幹擁塞。
  * 🔗 **深藍色粗線 (Blue Solid Link)**：**Port-Channel 聚合組 (LACP/PAgP)**！直觀標示聚合成員關係。
* **交互式拓撲穿透檢驗儀 (Interactive Topology Inspector)**：
  * 點擊畫布上任一**節點 (Node)** 或 **線路 (Link)**，下方立即展開 CCIE 深度對接詳情：
    * 本端介面與狀態、對端設備 ID、對端遠端埠號、管理 IP、平台型號。
    * 雙向速率、雙工、Trunk VLAN、學習到之 MAC 地址清單與 ARP IP。
    * **CCIE 專家根因剖析與直接複製修復 CLI 指令**！
* **拓撲智慧多維度切換過濾**：
  * 🔘 **全部拓撲**：完整呈現交換機全網上下游鄰居與端點。
  * 🚨 **僅看異常鏈路**：集中檢視發生錯插、VLAN 衝突或丟包之問題鏈路。
  * 🏢 **交換機幹道 (Trunks)**：隱藏終端主機，專注骨幹與接入交換機對接。
  * 💻 **終端設備與主機**：檢視所有接入層客戶端與無線 AP。

### 模組 7：🤖 Tier-2 本地 AI 排障助理 (CCIE Reasoning Copilot)
* **最新輕量模型首選 Qwen3.5 (筆電最佳化 ⭐)**：
  * 預設支援最新輕量級 **Qwen3.5**（可選 `qwen3.5:3b` 極速版或 `qwen3.5:7b` 標準版），記憶體僅需 3~6GB！
  * **筆電友善度極高**：相較 Gemma 4 等動輒數十 GB 的肥大模型，Qwen3.5 兼具卓越的 CCIE 邏輯推理與極致速度，不會讓工程師筆電風扇狂轉或記憶體爆掉。
* **前端動態熱接與即時狀態偵測**：
  * 前端自動每秒偵測本地 Ollama (`http://127.0.0.1:11434`) 在線狀態，支援下拉即時切換已安裝之模型或自訂模型。
  * 附帶一鍵複製指令：`ollama run qwen3.5`，終端機啟動後即刻無縫熱接。
* **單機與全網多機雙模 Copilot (Fleet Copilot)**：
  * 不僅支援單機故障諮詢，在全網多設備（Multi-Chassis）模式下，能自動注入整網衝突矩陣與拓撲關係，向 Qwen3.5 諮詢跨機修復優先順序。
* **資料自動脫敏與防外洩**：
  * 丟給 AI 前自動過濾 `enable secret`、密碼 Hash、SNMP Community 與私有 IP，100% 本機離線運算，零雲端外洩風險。
* **雙軌無縫降級 (Zero-Downtime Fallback)**：
  * 若未安裝或未啟動 Ollama，系統自動無縫降級至 SwitchScope **CCIE 離線專家規則引擎**，確保斷網機房現場依然隨時可用！

### 模組 8：🏢 全網多實體設備批次匯入、雙向校驗與全網架構拓撲 (Multi-Chassis Real Fleet Engine)
* **解決「單機視角不是真多台」的終極痛點**：
  * 現實維運中，維運人員或客戶通常擁有多台 Switch 的 `show run`、`show tech` 或備份 `.conf / .txt` 檔。
  * SwitchScope 全新支援**多設備批次拖曳上傳**（支援 2 ~ 50 台一次匯入）與**本機指定資料夾一鍵掃描**！
* **真正的「多實體機雙向交叉驗證」 (Bidirectional Cross-Device Verification)**：
  * 不只依賴單機猜測，而是同時比對 Switch A 與 Switch B 兩端的實體配置與狀態：
    1. **LACP 雙向聚合對稱性**：Switch A 將 `Gi1/0/2` 設為 `Po1 active`，但對端 Switch B 的 `Gi1/0/48` 竟然沒配 Port-Channel！秒級抓出不對稱配置與跨機錯插。
    2. **雙機 Trunk Native VLAN 與 Allowed VLAN 衝突**：同時調閱兩機互聯埠，實時比對 PVID 是否相符，防止 STP `BLOCK_PVID` 阻斷。
    3. **雙機 MTU / Jumbo Frame 差異**：預防 MTU 1500 vs 9000 導致 OSPF 死在 `EXSTART`。
    4. **雙向佈線真實度驗證**：比對兩台設備的 CDP/LLDP 對接互聯真實紀錄。
* **全網跨設備衝突矩陣與一體化修復腳本 (Master Fleet Remediation Macro)**：
  * 表格化列出所有跨機衝突、受影響介面、雙機根因剖析。
  * **一鍵複製全網多機修復腳本**：按各實體設備 Hostname 自動分段（`! === Core-SW-01 ===`, `! === office1-switch-15F ===`），一次修復全網所有交換機！

---

## 📁 專案架構

```text
SwitchScope/
  ├── core/
  │    ├── parser.py           # Cisco CLI 多指令正則剖析器 (Status, Counters, LACP, CDP/LLDP, Routing, Timeline)
  │    ├── sanitizer.py        # 地端機敏密碼、Community、IP 脫敏防護器
  │    ├── multi_chassis.py    # 全網多實體設備雙向校驗、衝突檢測與全網架構引擎 (NEW)
  │    └── llm_gateway.py      # 本地 Ollama 串接與離線 CCIE 專家決策樹
  ├── ml_engine/
  │    ├── ecod_detector.py    # PyOD ECOD 實體計數器無監督異常檢測
  │    └── fault_classifier.py # CatBoost 決策樹、跨設備拓撲連動、路由狀態機與全域會診總評引擎
  ├── web/
  │    └── index.html          # 前端現代化面板 (單機透視 + 全網多實體機跨機聯動 + 衝突矩陣 + 拓撲)
  ├── samples/
  │    ├── multi_chassis_demo/ # 3 台實體設備對接示範包 (Core-SW-01, office1-15F, Floor2-02) (NEW)
  │    ├── cisco_troubleshoot_sample.txt      # 實戰多重故障排查範例 Log (LACP + BPDU + CRC)
  │    ├── cisco_flapping_sample.txt          # 高頻震盪與離峰下班休眠實戰 Log
  │    ├── cisco_ccie_routing_sample.txt      # CCIE 核心路由實戰 Log (OSPF EXSTART + BGP + EIGRP)
  │    ├── cisco_timeline_quiesced_sample.txt # 12 天前歷史平息事件 (時間序列感知免白查)
  │    └── cisco_ccie_cdp_topology_sample.txt # CCIE 實體拓撲連動 Log (跨交換機錯插 + 上聯穿透)
  ├── server.py                # 本機輕量 API 伺服器 (支援批次上傳與資料夾掃描)
  ├── test_engine.py           # 自動化迴歸測試套件 (涵蓋 L2/L3/CDP拓撲/時序感知/多實體機聯動)
  ├── launcher.ps1             # 智慧環境檢查與相依性修復啟動器
  ├── 啟動服務.bat              # Windows 雙擊極速啟動 (自動開啟瀏覽器)
  ├── LICENSE                  # MIT 開源授權條款
  └── README.md                # 專案詳細說明文件
```

---

## 🚀 快速開始

1. 雙擊執行目錄中的 **`啟動服務.bat`**。
2. 預設瀏覽器會自動開啟控制台：`http://localhost:8920/`。
3. 點擊頂部的 **`📋 載入多重故障實戰範例`**。
4. 點擊 **`🚀 開始 ML 智慧診斷`**，秒速體驗 ECOD 與 CatBoost 的威力！

---

## 👨‍💻 作者 (Author)
* **Kerr** ([@kerr20801](https://github.com/kerr20801))
* 延續 `PacketScope` 與 `NetScope` 之維運工具矩陣，專注解決地端現場網管與 SI 核心痛點。
