#!/system/bin/sh
# MCP RE v7 一键安装脚本
# 用法: su -c "sh install.sh [安装目录]"

INSTALL_DIR="${1:-/data/adb/mcp_re_v6}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== MCP RE v7.0 Installer ==="
echo "源目录: $SCRIPT_DIR"
echo "安装到: $INSTALL_DIR"

# 创建安装目录
mkdir -p "$INSTALL_DIR"

# 复制所有文件
echo "[1/5] 复制主程序..."
cp "$SCRIPT_DIR/mcp" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/mcp_boot" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/stackplz" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/paradise" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/restart.sh" "$INSTALL_DIR/" 2>/dev/null
chmod 755 "$INSTALL_DIR/mcp" "$INSTALL_DIR/mcp_boot" "$INSTALL_DIR/stackplz" "$INSTALL_DIR/paradise"

echo "[2/5] 复制内核模块..."
mkdir -p "$INSTALL_DIR/kmodules"
cp "$SCRIPT_DIR/kmodules/"*.ko "$INSTALL_DIR/kmodules/"

echo "[3/5] 复制预加载库..."
mkdir -p "$INSTALL_DIR/preload_libs"
cp "$SCRIPT_DIR/preload_libs/"*.so "$INSTALL_DIR/preload_libs/"

echo "[4/5] 复制配置文件..."
mkdir -p "$INSTALL_DIR/user/config"
cp "$SCRIPT_DIR/user/config/"*.json "$INSTALL_DIR/user/config/"

echo "[5/5] 复制 radare2..."
mkdir -p "$INSTALL_DIR/radare2"
cp -r "$SCRIPT_DIR/radare2/bin" "$INSTALL_DIR/radare2/"
cp -r "$SCRIPT_DIR/radare2/lib" "$INSTALL_DIR/radare2/"
cp -r "$SCRIPT_DIR/radare2/share" "$INSTALL_DIR/radare2/"
chmod 755 "$INSTALL_DIR/radare2/bin/"*

# 创建兼容符号链接
echo "[*] 创建 Paradise 兼容符号链接..."
mkdir -p /data/adb/CD/stackplz
ln -sf "$INSTALL_DIR/stackplz" /data/adb/CD/stackplz/stackplz 2>/dev/null

echo ""
echo "=== 安装完成 ==="
echo "启动主 MCP:  su -c \"cd $INSTALL_DIR && nohup ./mcp -p 65534 </dev/null >./mcp.log 2>&1 &\""
echo "启动 Boot:   su -c \"echo 1 | nohup $INSTALL_DIR/mcp_boot </dev/null >./boot.log 2>&1 &\""
