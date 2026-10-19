#!/system/bin/sh

DIR="/data/adb/mimosa"

# 1. 确定 iproute2 工具集
TERMUX_IP="/data/data/com.termux/files/usr/bin"
if [ -f "$TERMUX_IP/ip" ]; then
    IP_CMD="env LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib $TERMUX_IP/ip"
else
    IP_CMD="ip"
fi

# 2. 先撤规则：一次性批量清理 pref 7900 ~ 9000 之间的所有 IPv4 策略路由
$IP_CMD rule show 2>/dev/null | awk -F':' '
    {
        pref = $1 + 0
        if (pref >= 7900 && pref <= 9000) {
            printf "rule del pref %d\n", pref
        }
    }
' | $IP_CMD -batch - 2>/dev/null

# 一次性批量清理 pref 7900 ~ 9000 之间的所有 IPv6 策略路由
$IP_CMD -6 rule show 2>/dev/null | awk -F':' '
    {
        pref = $1 + 0
        if (pref >= 7900 && pref <= 9000) {
            printf "rule del pref %d\n", pref
        }
    }
' | $IP_CMD -6 -batch - 2>/dev/null

# 清空 IPv4 与 IPv6 的 table 80 路由表
$IP_CMD route flush table 80 2>/dev/null
$IP_CMD -6 route flush table 80 2>/dev/null

# 3. 后杀进程：优雅退出 eBPF 与核心
pkill -15 sklookup 2>/dev/null
pkill -15 -f "$DIR/mihomo" 2>/dev/null
pkill -15 mihomo 2>/dev/null

sleep 0.3

# 兜底强杀
pkill -9 sklookup 2>/dev/null
pkill -9 -f "$DIR/mihomo" 2>/dev/null
pkill -9 mihomo 2>/dev/null

exit 0