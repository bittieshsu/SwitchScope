#!/usr/bin/env bash
# ==============================================================================
# SwitchScope - Linux & macOS 通用啟動器 (Universal POSIX Launcher)
# ==============================================================================
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "==================================================================="
echo "    ⬡ SwitchScope — 智慧網通設備異常透視與排障儀"
echo "    Dual-Tier ML (ECOD + CatBoost) & Local AI Copilot"
echo "==================================================================="
echo ""

PYTHON_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "❌ [錯誤] 未偵測到 Python 3 執行環境！"
    echo "請先安裝 Python 3 (如: brew install python 或 sudo apt install python3)"
    exit 1
fi

echo "✅ [1/2] 檢測到 Python 環境: $($PYTHON_CMD --version)"
echo "🚀 [2/2] 正在啟動 SwitchScope 伺服器並開啟瀏覽器..."
echo "      本機控制台: http://localhost:8920/"
echo ""

# 自動開啟預設瀏覽器 (依系統判定 open, xdg-open, 或 Python webbrowser 模組)
if command -v open >/dev/null 2>&1; then
    (sleep 1 && open "http://localhost:8920/") &
elif command -v xdg-open >/dev/null 2>&1; then
    (sleep 1 && xdg-open "http://localhost:8920/") &
else
    (sleep 1 && "$PYTHON_CMD" -m webbrowser "http://localhost:8920/") &
fi

exec "$PYTHON_CMD" "$DIR/server.py"
