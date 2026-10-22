#!/system/bin/sh

DIR="/data/adb/mimosa"
cd "$DIR" || exit 1

# 需接管的 UID 列表：普通应用 (10000-99999) + Shell/LSPosed 寄生管理器 (2000)
# 严格排除 UID 0 (Mihomo 核心防回环) 与 1000/1001 (系统与电话 VoLTE/IMS 服务)
TARGET_UIDS="10000-99999 2000-2000"

# 1. 强制依赖检查（置于最顶端，避免产生孤儿进程）
TERMUX_BIN="/data/data/com.termux/files/usr/bin"
TERMUX_LIB="/data/data/com.termux/files/usr/lib"
TERMUX_IP="$TERMUX_BIN/ip"

if [ ! -f "$TERMUX_IP" ]; then
    echo "[-] 致命错误：未找到 Termux 版 ip 工具。请在 Termux 中执行 pkg install iproute2"
    exit 1
fi
IP_CMD="env LD_LIBRARY_PATH=$TERMUX_LIB $TERMUX_IP"
SS_CMD="env LD_LIBRARY_PATH=$TERMUX_LIB $TERMUX_BIN/ss"

# 2. 启动前环境重置（确保无残留进程与旧路由规则）
sh "$DIR/stop.sh" >/dev/null 2>&1

# 3. 准备日志环境并自动清理历史旧日志（保留最近 10 个）
mkdir -p "$DIR/log"
ls -1t "$DIR/log"/mimosa_*.log 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
ls -1t "$DIR/log"/sklookup_*.log 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null

LOG_TIME=$(date "+%Y%m%d%H%M")
LOG_FILE="$DIR/log/mimosa_${LOG_TIME}.log"
SK_LOG_FILE="$DIR/log/sklookup_${LOG_TIME}.log"

# 4. 赋予执行权限并启动 Mihomo
chmod +x "$DIR/mihomo" "$DIR/sklookup" 2>/dev/null
"$DIR/mihomo" -d "$DIR" > "$LOG_FILE" 2>&1 &
MIHOMO_PID=$!

# 等待 7891 端口监听就绪（优先调用 Termux ss，无环境则同时探查 tcp 与 tcp6）
READY=0
for i in 1 2 3 4 5; do
    sleep 1
    if ! kill -0 "$MIHOMO_PID" 2>/dev/null; then
        echo "[-] Mihomo 启动崩溃，退出" >> "$LOG_FILE"
        sh "$DIR/stop.sh"
        exit 1
    fi
    if [ -f "$TERMUX_BIN/ss" ] && $SS_CMD -tln 2>/dev/null | grep -q ":7891 "; then
        READY=1; break
    elif grep -q ":1ED3 " /proc/net/tcp /proc/net/tcp6 2>/dev/null; then # 1ED3 为 7891 十六进制
        READY=1; break
    fi
done

if [ "$READY" -ne 1 ]; then
    echo "[-] 等待 7891 端口超时，启动终止" >> "$LOG_FILE"
    sh "$DIR/stop.sh"
    exit 1
fi

# 5. 策略路由体系配置
$IP_CMD route flush table 80 2>/dev/null
$IP_CMD route add local default dev lo src 127.0.0.1 table 80

# 5.1 放行局域网私网 TCP（先建立 9001 锚点，彻底消除 [unresolved]）
$IP_CMD rule add nop pref 9001 2>/dev/null
$IP_CMD rule add to 10.0.0.0/8 goto 9001 pref 8900 2>/dev/null
$IP_CMD rule add to 172.16.0.0/12 goto 9001 pref 8901 2>/dev/null
$IP_CMD rule add to 192.168.0.0/16 goto 9001 pref 8902 2>/dev/null

# 5.2 按目标 UID 范围批量注入接管规则（彻底将 Fake-IP 限制在目标 UID，杜绝 UID 0 死锁）
for uid in $TARGET_UIDS; do
    # 捕获 UDP 53 DNS 出站至 table 80 触发 sk_lookup
    $IP_CMD rule add uidrange "$uid" ipproto 17 dport 53 lookup 80 pref 7890 2>/dev/null
    # 掐断发往 Fake-IP 的 UDP（迫使 QUIC 0ms 极速回退 TCP）
    $IP_CMD rule add to 198.18.0.0/16 uidrange "$uid" ipproto 17 type unreachable pref 7990 2>/dev/null
    # 捕获访问 Fake-IP 的 TCP 流量至 table 80
    $IP_CMD rule add to 198.18.0.0/16 uidrange "$uid" ipproto 6 lookup 80 pref 8000 2>/dev/null
    # 阻断公网 IPv6 直连（仅限 2000::/3，放行 fe80:: 局域网与基带 VoLTE IPv6）
    $IP_CMD -6 rule add to 2000::/3 uidrange "$uid" type unreachable pref 8000 2>/dev/null
    # 捕获公网直连 IP 的 TCP 出站至 table 80
    $IP_CMD rule add uidrange "$uid" ipproto 6 lookup 80 pref 9000 2>/dev/null
done

# 6. 拉起 sklookup 并挂载 eBPF Link（同时接管 TCP 7891 与 UDP 53）
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