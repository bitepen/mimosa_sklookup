#!/system/bin/sh

DIR="/data/adb/mimosa"
cd "$DIR" || exit 1

TARGET_UIDS="10000-99999 2000-2000"

TERMUX_BIN="/data/data/com.termux/files/usr/bin"
TERMUX_LIB="/data/data/com.termux/files/usr/lib"
TERMUX_IP="$TERMUX_BIN/ip"

if [ ! -f "$TERMUX_IP" ]; then
    echo "[-] 致命错误：未找到 Termux 版 ip 工具"
    exit 1
fi
IP_CMD="env LD_LIBRARY_PATH=$TERMUX_LIB $TERMUX_IP"
SS_CMD="env LD_LIBRARY_PATH=$TERMUX_LIB $TERMUX_BIN/ss"

# 停止旧进程与旧规则
sh "$DIR/stop.sh" >/dev/null 2>&1

mkdir -p "$DIR/log"
ls -1t "$DIR/log"/mimosa_*.log 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
ls -1t "$DIR/log"/sklookup_*.log 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null

LOG_TIME=$(date "+%Y%m%d%H%M")
LOG_FILE="$DIR/log/mimosa_${LOG_TIME}.log"
SK_LOG_FILE="$DIR/log/sklookup_${LOG_TIME}.log"

chmod +x "$DIR/mihomo" "$DIR/sklookup" 2>/dev/null
"$DIR/mihomo" -d "$DIR" > "$LOG_FILE" 2>&1 &
MIHOMO_PID=$!

READY=0
for i in 1 2 3 4 5; do
    sleep 1
    if ! kill -0 "$MIHOMO_PID" 2>/dev/null; then
        echo "[-] Mihomo 启动崩溃" >> "$LOG_FILE"
        sh "$DIR/stop.sh"
        exit 1
    fi
    if [ -f "$TERMUX_BIN/ss" ] && $SS_CMD -tln 2>/dev/null | grep -q ":7891 "; then
        READY=1; break
    elif grep -q ":1ED3 " /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
        READY=1; break
    fi
done

if [ "$READY" -ne 1 ]; then
    echo "[-] 等待 7891 端口超时" >> "$LOG_FILE"
    sh "$DIR/stop.sh"
    exit 1
fi

# 策略路由配置
$IP_CMD route flush table 80 2>/dev/null
$IP_CMD route add local default dev lo src 127.0.0.1 table 80

# 私网直连跳过锚点
$IP_CMD rule add nop pref 9001 2>/dev/null
$IP_CMD rule add to 10.0.0.0/8 goto 9001 pref 8900 2>/dev/null
$IP_CMD rule add to 172.16.0.0/12 goto 9001 pref 8901 2>/dev/null
$IP_CMD rule add to 192.168.0.0/16 goto 9001 pref 8902 2>/dev/null

# 针对目标 UID 注入规则（彻底排除 UID 0）
for uid in $TARGET_UIDS; do
    # 捕获 UDP 53 出站（触发 sk_lookup 劫持）
    $IP_CMD rule add uidrange "$uid" ipproto 17 dport 53 lookup 80 pref 7890 2>/dev/null
    # 阻断 Fake-IP 的 UDP（退回 TCP）
    $IP_CMD rule add to 198.18.0.0/16 uidrange "$uid" ipproto 17 type unreachable pref 7990 2>/dev/null
    # 捕获 Fake-IP TCP 流量
    $IP_CMD rule add to 198.18.0.0/16 uidrange "$uid" ipproto 6 lookup 80 pref 8000 2>/dev/null
    # 阻断公网 IPv6
    $IP_CMD -6 rule add to 2000::/3 uidrange "$uid" type unreachable pref 8000 2>/dev/null
    # 捕获公网 TCP 出站
    $IP_CMD rule add uidrange "$uid" ipproto 6 lookup 80 pref 9000 2>/dev/null
done

# 拉起 sklookup
"$DIR/sklookup" "$MIHOMO_PID" 7891 > "$SK_LOG_FILE" 2>&1 &
SK_PID=$!
sleep 1

if ! kill -0 "$SK_PID" 2>/dev/null; then
    echo "[-] sklookup 启动失败" >> "$LOG_FILE"
    sh "$DIR/stop.sh"
    exit 1
fi

echo "[+] Mimosa eBPF 透明代理启动成功"
exit 0