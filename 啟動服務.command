#!/usr/bin/env bash
# ==============================================================================
# SwitchScope - macOS 一鍵雙擊啟動腳本 (macOS Finder Double-Click Launcher)
# ==============================================================================
set -e

# 切換至腳本所在絕對目錄 (解決從 Finder 雙擊執行時預設工作目錄在 ~ 使用者家目錄的問題)
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "==================================================================="
echo "    ⬡ SwitchScope — 智慧網通設備異常透視與排障儀 (macOS)"
echo "    Dual-Tier ML (ECOD + CatBoost) & Local AI Copilot"
echo "==================================================================="
echo ""

# 1. 檢測 Python 3 環境
PYTHON_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "❌ [錯誤] 未偵測到 Python 執行環境！"
    echo "-------------------------------------------------------------------"
    echo "SwitchScope 採用本機機器學習與智慧分析，需要 Python 3.10+ 環境。"
    echo ""
    echo "【建議安裝方式】（二選一）："
    echo "  1. 透過 Homebrew 一鍵安裝："
    echo "     brew install python"
    echo ""
    echo "  2. 前往 Python 官網下載 macOS 安裝檔："
    echo "     https://www.python.org/downloads/"
    echo "-------------------------------------------------------------------"
    echo ""
    read -p "按 Enter 鍵關閉視窗..."
    exit 1
fi

echo "✅ [1/2] 檢測到 Python 環境: $($PYTHON_CMD --version)"
echo ""

# 2. 啟動伺服器並自動在 macOS 開啟預設瀏覽器 (Safari / Chrome)
echo "🚀 [2/2] 正在啟動 SwitchScope 伺服器並開啟瀏覽器..."
echo "      本機控制台: http://localhost:8920/"
echo ""

# 背景延遲 1 秒後開啟網頁
(sleep 1 && open "http://localhost:8920/") &

# 啟動 SwitchScope 核心服務
exec "$PYTHON_CMD" "$DIR/server.py"
