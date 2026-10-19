# SwitchScope Launcher & Environment Doctor
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "SwitchScope — 智慧網通設備異常透視與排障儀"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "    ⬡ SwitchScope — 智慧網通設備異常透視與排障儀" -ForegroundColor Cyan
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
    Write-Host "[!] 提示：檢測到尚未安裝完整的機器學習套件。" -ForegroundColor Yellow
    Write-Host "    缺少套件：catboost, pyod, pandas" -ForegroundColor DarkYellow
    Write-Host ""
    $installChoice = Read-Host "是否要現在自動為您執行 pip install 安裝必要套件？(Y/N，預設 Y)"
    if ($installChoice -eq "" -or $installChoice.ToUpper() -eq "Y") {
        Write-Host ""
        Write-Host "正在透過 pip 安裝必要套件，請稍候（約需 1~2 分鐘）..." -ForegroundColor Cyan
        $reqPath = Join-Path $PSScriptRoot "requirements.txt"
        & $pythonCmd -m pip install -r $reqPath
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] 套件安裝失敗，請確認網路連線或手動執行：pip install -r requirements.txt" -ForegroundColor Red
            Read-Host "按 Enter 鍵結束..."
            exit 1
        }
        Write-Host "[OK] 套件安裝成功！" -ForegroundColor Green
    } else {
        Write-Host "您選擇手動安裝。請於終端機執行：pip install -r requirements.txt 後再啟動。" -ForegroundColor Yellow
        Read-Host "按 Enter 鍵結束..."
        exit 1
    }
} else {
    Write-Host "[OK] 所有機器學習核心套件均已就緒！" -ForegroundColor Green
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
