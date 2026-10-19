#!/system/bin/sh

DIR="/data/adb/mimosa"
CONF_FILE="$DIR/mimosa.conf"
cd "$DIR" || exit 1

# 1. 强制依赖检查（移至最顶端，避免产生孤儿进程）
TERMUX_BIN="/data/data/com.termux/files/usr/bin"
TERMUX_IP="$TERMUX_BIN/ip"
if [ ! -f "$TERMUX_IP" ]; then
    echo "[-] 致命错误：未找到 Termux 版 ip 工具。请在 Termux 中执行 pkg install iproute2" >&2
    exit 1
fi
IP_CMD="env LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib $TERMUX_IP"

# 2. 解析 mimosa.conf 配置文件（提供默认值兜底）
MIHOMO_PORT=7891
UDP_MODE="block"
IPV6_MODE="block"
BLACKLIST_ENABLE="true"

if [ -f "$CONF_FILE" ]; then
    eval "$(awk -F'=' '
        /^\[black_list\]/ { exit }
        /^[[:space:]]*[A-Z0-9_]+[[:space:]]*=/ {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1)
            sub(/#.*$/, "", $2)
            gsub(/^[[:space:]"'\'']+|[[:space:]"'\'']+$/, "", $2)
            printf "%s=\"%s\"\n", $1, $2
        }
    ' "$CONF_FILE")"
fi

CAPTURE_UDP_FLAG=0
[ "$UDP_MODE" = "capture" ] && CAPTURE_UDP_FLAG=1

CAPTURE_IPV6_FLAG=0
[ "$IPV6_MODE" = "capture" ] && CAPTURE_IPV6_FLAG=1

# 3. 启动前先清理可能残留的旧进程与旧路由规则
sh "$DIR/stop.sh" >/dev/null 2>&1

# 4. 准备日志环境并自动清理历史旧日志（保留最近 10 个）
mkdir -p "$DIR/log"
ls -1t "$DIR/log"/mimosa_*.log 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
ls -1t "$DIR/log"/sklookup_*.log 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null

LOG_TIME=$(date "+%Y%m%d%H%M%S")
LOG_FILE="$DIR/log/mimosa_${LOG_TIME}.log"
SK_LOG_FILE="$DIR/log/sklookup_${LOG_TIME}.log"

# 5. 赋予执行权限并启动 Mihomo（使用 >> 追加模式，防止日志偏移覆写）
chmod +x "$DIR/mihomo" "$DIR/sklookup" 2>/dev/null
: > "$LOG_FILE"
"$DIR/mihomo" -d "$DIR" >> "$LOG_FILE" 2>&1 &
MIHOMO_PID=$!

# 等待监听端口就绪（优先调用 Termux ss，无环境则探查 /proc/net/tcp）
READY=0
PORT_HEX=$(printf "%04X" "$MIHOMO_PORT")
SS_CMD="env LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib $TERMUX_BIN/ss"

for i in $(seq 1 25); do
    sleep 0.2
    if ! kill -0 "$MIHOMO_PID" 2>/dev/null; then
        echo "[-] Mihomo 启动崩溃，退出！错误日志：" | tee -a "$LOG_FILE" >&2
        cat "$LOG_FILE" >&2
        sh "$DIR/stop.sh"
        exit 1
    fi
    if [ -f "$TERMUX_BIN/ss" ] && $SS_CMD -tln 2>/dev/null | grep -q ":${MIHOMO_PORT} "; then
        READY=1; break
    elif grep -iq ":${PORT_HEX} " /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
        READY=1; break
    fi
done

if [ "$READY" -ne 1 ]; then
    echo "[-] 等待 ${MIHOMO_PORT} 端口超时，启动终止" | tee -a "$LOG_FILE" >&2
    sh "$DIR/stop.sh"
    exit 1
fi

# 6. 拉起 sklookup 并挂载 eBPF Link
: > "$SK_LOG_FILE"
"$DIR/sklookup" "$MIHOMO_PID" "$MIHOMO_PORT" "$CAPTURE_UDP_FLAG" "$CAPTURE_IPV6_FLAG" >> "$SK_LOG_FILE" 2>&1 &
SK_PID=$!
sleep 0.5

if ! kill -0 "$SK_PID" 2>/dev/null; then
    echo "[-] sklookup 启动失败！错误日志：" | tee -a "$LOG_FILE" >&2
    cat "$SK_LOG_FILE" >&2
    sh "$DIR/stop.sh"
    exit 1
fi

# 7. 解析包名黑名单并合并连续 UID 区间（格式：start-end pref）
BLACKLIST_RANGES=""
if [ "$BLACKLIST_ENABLE" = "true" ] && [ -f "$CONF_FILE" ] && [ -f /data/system/packages.list ]; then
    BLACKLIST_RANGES=$(awk '
        /^\[black_list\]/ { in_list=1; next }
        in_list {
            sub(/#.*$/, "")
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            if ($0 != "") print $0
        }
    ' "$CONF_FILE" | awk '
        NR==FNR { pkgs[$1]=1; next }
        ($1 in pkgs) { print $2 }
    ' - /data/system/packages.list | sort -n -u | awk '
        BEGIN { start = -1; end = -1; pref = 8100 }
        {
            uid = $1 + 0
            if (uid < 10000) next
            if (start == -1) {
                start = uid; end = uid
            } else if (uid == end + 1) {
                end = uid
            } else {
                if (pref <= 8899) printf "%d-%d %d\n", start, end, pref++
                start = uid; end = uid
            }
        }
        END {
            if (start != -1 && pref <= 8899) printf "%d-%d %d\n", start, end, pref++
        }
    ')
fi

# 8. 构建并批量注入 IPv4 策略路由（单次 ip -batch 调用）
# 捕获的三个目标 UID 区间：0-0 (root/系统更新), 2000-2000 (shell/LSPosed), 10000-99999 (普通应用)
TARGET_UID_RANGES="0-0 2000-2000 10000-99999"

$IP_CMD route flush table 80 2>/dev/null
{
    echo "route add local default dev lo src 127.0.0.1 table 80"

    # 8.1 最高优先级：放行 Mihomo 自身流量（匹配 config.yaml 中的 routing-mark: 16777216），防 UID 0 回环
    echo "rule add fwmark 0x01000000/0x01000000 goto 9001 pref 7900"

    # 8.2 发往 Fake-IP (198.18.0.0/16) 的 UDP 处理
    if [ "$UDP_MODE" = "capture" ]; then
        echo "rule add to 198.18.0.0/16 ipproto 17 lookup 80 pref 7990"
    else
        echo "rule add to 198.18.0.0/16 ipproto 17 type unreachable pref 7990"
    fi

    # 8.3 劫持所有访问 Fake-IP 的 TCP 流量
    echo "rule add to 198.18.0.0/16 ipproto 6 lookup 80 pref 8000"

    # 8.4 包名黑名单直连放行（排在 DNS 与公网捕获之前，直接走物理网卡）
    if [ -n "$BLACKLIST_RANGES" ]; then
        echo "$BLACKLIST_RANGES" | while read -r range pref; do
            [ -n "$range" ] && echo "rule add uidrange $range goto 9001 pref $pref"
        done
    fi

    # 8.5 放行局域网私网、链路本地与组播流量（保障 Quick Share / Wi-Fi Direct 原生直连）
    echo "rule add to 10.0.0.0/8 goto 9001 pref 8900"
    echo "rule add to 172.16.0.0/12 goto 9001 pref 8901"
    echo "rule add to 192.168.0.0/16 goto 9001 pref 8902"
    echo "rule add to 169.254.0.0/16 goto 9001 pref 8903"
    echo "rule add to 224.0.0.0/4 goto 9001 pref 8904"

    # 8.6 针对三大目标 UID 区间捕获 DNS (UDP 53)、全端口 UDP 与 TCP
    for urange in $TARGET_UID_RANGES; do
        echo "rule add uidrange $urange ipproto 17 dport 53 lookup 80 pref 8990"

        if [ "$UDP_MODE" = "capture" ]; then
            echo "rule add uidrange $urange ipproto 17 lookup 80 pref 8995"
        elif [ "$UDP_MODE" = "block" ]; then
            echo "rule add uidrange $urange ipproto 17 type unreachable pref 8995"
        fi

        echo "rule add uidrange $urange ipproto 6 lookup 80 pref 9000"
    done
} | $IP_CMD -batch - 2>> "$LOG_FILE"

# 9. 构建并批量注入 IPv6 策略路由
$IP_CMD -6 route flush table 80 2>/dev/null
if [ "$IPV6_MODE" = "block" ]; then
    {
        echo "rule add fwmark 0x01000000/0x01000000 goto 9001 pref 7900"

        if [ -n "$BLACKLIST_RANGES" ]; then
            echo "$BLACKLIST_RANGES" | while read -r range pref; do
                [ -n "$range" ] && echo "rule add uidrange $range goto 9001 pref $pref"
            done
        fi

        for urange in $TARGET_UID_RANGES; do
            echo "rule add to 2000::/3 uidrange $urange type unreachable pref 8990"
        done
    } | $IP_CMD -6 -batch - 2>> "$LOG_FILE"

elif [ "$IPV6_MODE" = "capture" ]; then
    {
        echo "route add local default dev lo table 80"
        echo "rule add fwmark 0x01000000/0x01000000 goto 9001 pref 7900"

        if [ "$UDP_MODE" = "capture" ]; then
            echo "rule add to fc00::/18 ipproto 17 lookup 80 pref 7990"
        else
            echo "rule add to fc00::/18 ipproto 17 type unreachable pref 7990"
        fi
        echo "rule add to fc00::/18 ipproto 6 lookup 80 pref 8000"

        if [ -n "$BLACKLIST_RANGES" ]; then
            echo "$BLACKLIST_RANGES" | while read -r range pref; do
                [ -n "$range" ] && echo "rule add uidrange $range goto 9001 pref $pref"
            done
        fi

        for urange in $TARGET_UID_RANGES; do
            echo "rule add uidrange $urange ipproto 17 dport 53 lookup 80 pref 8990"
            if [ "$UDP_MODE" = "capture" ]; then
                echo "rule add to 2000::/3 uidrange $urange ipproto 17 lookup 80 pref 8995"
            elif [ "$UDP_MODE" = "block" ]; then
                echo "rule add to 2000::/3 uidrange $urange ipproto 17 type unreachable pref 8995"
            fi
            echo "rule add to 2000::/3 uidrange $urange ipproto 6 lookup 80 pref 9000"
        done
    } | $IP_CMD -6 -batch - 2>> "$LOG_FILE"
fi

echo "[+] Mimosa eBPF 透明代理启动成功 (UDP=$UDP_MODE, IPv6=$IPV6_MODE, Blacklist=$BLACKLIST_ENABLE)" | tee -a "$LOG_FILE"
exit 0