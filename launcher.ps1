# SwitchScope Launcher & Environment Doctor
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "SwitchScope - 智慧網通設備異常透視與排障儀"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "    [SwitchScope] 智慧網通設備異常透視與排障儀" -ForegroundColor Cyan
Write-Host "    Dual-Tier ML (ECOD + CatBoost) & Local AI Copilot" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. 檢測 Python 執行環境
$pythonCmd = $null

if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py -3"
} else {
    # 搜尋常見安裝目錄 (例如 AppData)
    $localPy = Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($localPy) {
        $pythonCmd = $localPy.FullName
    }
}

if (-not $pythonCmd) {
    Write-Host "[!] 錯誤：未偵測到 Python 執行環境！" -ForegroundColor Red
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "SwitchScope 採用本機機器學習演算法 (ECOD 與 CatBoost) 進行毫秒級異常排查，"
    Write-Host "需要 Python 3.10+ 環境。"
    Write-Host ""
    Write-Host "【建議安裝方式】（二選一）：" -ForegroundColor Yellow
    Write-Host "  1. 透過 Windows 終端機輸入指令一鍵安裝："
    Write-Host "     winget install Python.Python.3.11" -ForegroundColor Green
    Write-Host ""
    Write-Host "  2. 前往 Python 官方網站下載安裝檔："
    Write-Host "     https://www.python.org/downloads/" -ForegroundColor Green
    Write-Host "     * 特別提醒：安裝時請務必勾選【Add python.exe to PATH】！" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "是否要為您開啟 Python 官網下載頁面？(Y/N，預設 Y)"
    if ($choice -eq "" -or $choice.ToUpper() -eq "Y") {
        Start-Process "https://www.python.org/downloads/"
    }
    Write-Host ""
    Write-Host "請於安裝完成後，重新執行此啟動檔即可。" -ForegroundColor Gray
    Read-Host "按 Enter 鍵關閉視窗..."
    exit 1
}

Write-Host "[1/3] 檢測到 Python 環境：" -ForegroundColor Green -NoNewline
Write-Host " $pythonCmd" -ForegroundColor White
$ver = & $pythonCmd --version 2>&1
Write-Host "      版本：$ver" -ForegroundColor Gray
Write-Host ""

# 2. 檢測相依機器學習套件 (CatBoost, PyOD, Pandas)
Write-Host "[2/3] 檢查機器學習套件 (CatBoost, PyOD, Pandas)..." -ForegroundColor Yellow
$pkgCheck = & $pythonCmd -c "import catboost, pyod, pandas" 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[!] 提示：未偵測到 C 語言加速之 CatBoost/PyOD/Pandas 套件。" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[SwitchScope 供應鏈安全防護與執行模式]" -ForegroundColor Cyan
    Write-Host "  [1] 啟用「零相依純地端安全模式」(Zero-Dependency Safe Mode - 推薦安全首選)" -ForegroundColor Green
    Write-Host "      * 100% 免除 pip install，使用純 Python 內建標準庫運作！"
    Write-Host "      * 徹底免疫 PyPI 惡意投毒、Typosquatting 偽裝包與供應鏈攻擊。"
    Write-Host "      * 適合銀行、政府、半導體機房與隔離跳板機環境。"
    Write-Host ""
    Write-Host "  [2] 執行「密碼學雜湊鎖定安全安裝」(Secure Hash-Pinned Pip Install)" -ForegroundColor Yellow
    Write-Host "      * 使用 requirements.lock，對每個 Wheel 嚴格校驗 SHA-256 雜湊值！"
    Write-Host "      * 強制啟用 --only-binary :all:，徹底禁止執行任何 setup.py 安裝期腳本。"
    Write-Host ""
    Write-Host "  [3] 從本地「離線 Wheelhouse 資料夾」載入 (Air-Gapped Local Wheelhouse)" -ForegroundColor White
    Write-Host "      * 完全不連外網，僅從本機 wheelhouse/ 資料夾載入預先審核的套件。"
    Write-Host "-------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    $modeChoice = Read-Host "請選擇執行模式 (1/2/3，按 Enter 預設 1 直接啟動零相依安全模式)"

    if ($modeChoice -eq "2") {
        Write-Host ""
        Write-Host "正在透過 pip 執行密碼學雜湊核對安裝 (SHA-256 Verified)..." -ForegroundColor Cyan
        $lockPath = Join-Path $PSScriptRoot "requirements.lock"
        & $pythonCmd -m pip install --require-hashes --only-binary :all: -r $lockPath
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] 雜湊核對或安裝失敗！可能原因：檔案遭篡改或網路連線異常。" -ForegroundColor Red
            Read-Host "按 Enter 鍵結束..."
            exit 1
        }
        Write-Host "[OK] 官方驗證套件安裝成功！" -ForegroundColor Green
    } elseif ($modeChoice -eq "3") {
        $wheelDir = Join-Path $PSScriptRoot "wheelhouse"
        if (-not (Test-Path $wheelDir)) {
            Write-Host "[!] 錯誤：未找到本地 wheelhouse/ 資料夾！" -ForegroundColor Red
            Read-Host "按 Enter 鍵結束..."
            exit 1
        }
        Write-Host "正在從本地離線 wheelhouse 資料夾安裝套件..." -ForegroundColor Cyan
        & $pythonCmd -m pip install --no-index --find-links $wheelDir -r (Join-Path $PSScriptRoot "requirements.txt")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] 離線安裝失敗。" -ForegroundColor Red
            Read-Host "按 Enter 鍵結束..."
            exit 1
        }
        Write-Host "[OK] 本地離線套件安裝成功！" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "[OK] 已切換至【零相依純地端安全模式】，無須安裝任何第三方 pip 套件！" -ForegroundColor Green
        Write-Host "     * 異常檢測引擎：Native Python ECOD (純標準庫數學計算)" -ForegroundColor Gray
        Write-Host "     * 故障分類引擎：Native Python CCIE 專家規則決策樹" -ForegroundColor Gray
    }
} else {
    Write-Host "[OK] 所有機器學習核心套件均已就緒！(C 語言加速版 ECOD + CatBoost)" -ForegroundColor Green
}

Write-Host ""

# 3. 啟動伺服器與開啟瀏覽器
Write-Host "[3/3] 啟動 SwitchScope 伺服器並開啟瀏覽器..." -ForegroundColor Green
Write-Host "      本機控制台：http://localhost:8920/" -ForegroundColor Cyan
Write-Host ""

Start-Process "http://localhost:8920/"
Set-Location -Path $PSScriptRoot
& $pythonCmd "$PSScriptRoot\server.py"

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[!] 伺服器異常中斷。" -ForegroundColor Red
    Read-Host "按 Enter 鍵結束..."
}
