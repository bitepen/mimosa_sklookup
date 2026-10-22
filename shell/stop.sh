#!/system/bin/sh

DIR="/data/adb/mimosa"

# 1. 确定 iproute2 工具集
TERMUX_BIN="/data/data/com.termux/files/usr/bin"
TERMUX_LIB="/data/data/com.termux/files/usr/lib"
if [ -f "$TERMUX_BIN/ip" ]; then
    IP_CMD="env LD_LIBRARY_PATH=$TERMUX_LIB $TERMUX_BIN/ip"
else
    IP_CMD="ip"
fi

# 2. 先撤规则：流量瞬间无感切回物理直连
# 使用 while 循环彻底清空对应 pref 下的所有叠加规则（涵盖 10000-99999 与 2000-2000 两套规则）
for p in 7890 7990 8000 8900 8901 8902 9000 9001; do
    while $IP_CMD rule del pref "$p" 2>/dev/null; do :; done
done

for p in 8000; do
    while $IP_CMD -6 rule del pref "$p" 2>/dev/null; do :; done
done

# 兜底清理其他可能指向 table 80 的残留规则
$IP_CMD rule show 2>/dev/null | grep "lookup 80" | while read -r line; do
    pref="${line%%:*}"
    [ -n "$pref" ] && $IP_CMD rule del pref "$pref" 2>/dev/null
done

# 清空路由表 80
$IP_CMD route flush table 80 2>/dev/null

# 3. 后杀进程：优雅卸载 eBPF 与核心
pkill -15 -x sklookup 2>/dev/null
pkill -15 -f "$DIR/mihomo" 2>/dev/null
pkill -15 -x mihomo 2>/dev/null

sleep 0.3

# 兜底强杀
pkill -9 -x sklookup 2>/dev/null
pkill -9 -f "$DIR/mihomo" 2>/dev/null
pkill -9 -x mihomo 2>/dev/null

exit 0