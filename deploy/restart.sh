#!/system/bin/sh
DIR=$(cd "$(dirname "$0")" && pwd)
echo "[*] Stopping old MCP..."
pkill -f "$DIR/mcp" 2>/dev/null
sleep 1
echo "[*] Starting MCP v6.0 from $DIR..."
cd "$DIR"
nohup ./mcp -p 65534 </dev/null >./mcp.log 2>&1 &
sleep 2
PID=$(pidof mcp 2>/dev/null || pgrep -f "$DIR/mcp")
if [ -n "$PID" ]; then
    echo "[+] MCP started, PID=$PID"
    echo "[+] Log: $DIR/mcp.log"
else
    echo "[-] Failed to start! Check $DIR/mcp.log"
fi
