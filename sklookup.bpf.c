#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MIHOMO_PORT 7891
#define AF_INET 2

/* 扩充为 2 个槽位：
 * Key 0: TCP 7891 (常规 TCP 透明代理)
 * Key 1: UDP 7891 (TPROXY UDP，承载 DNS 劫持与常规 UDP)
 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} redirect_socket SEC(".maps");

SEC("sk_lookup")
int sk_lookup_redirect(struct bpf_sk_lookup *ctx)
{
    __u32 key = 0;
    struct bpf_sock *sk;

    /* 1. 仅接管 IPv4 流量，防止 IPv6 (如 ::1 回环) 下 local_ip4 为 0 被误劫持 */
    if (ctx->family != AF_INET)
        return SK_PASS;

    __u32 dst_ip = bpf_ntohl(ctx->local_ip4);

    /* 2. 排除回环、私网、链路本地与多播/广播地址
     * 作用：避免命中 local 表 (pref 0) 的局域网入站连接被 sk_lookup 抢先截胡塞进 Mihomo
     */
    if ((dst_ip >> 24) == 127 ||                      /* 127.0.0.0/8 回环 */
        (dst_ip >> 24) == 10 ||                       /* 10.0.0.0/8 私网 */
        (dst_ip & 0xfff00000) == 0xac100000 ||        /* 172.16.0.0/12 私网 */
        (dst_ip & 0xffff0000) == 0xc0a80000 ||        /* 192.168.0.0/16 私网 */
        (dst_ip & 0xffff0000) == 0xa9fe0000 ||        /* 169.254.0.0/16 链路本地 */
        (dst_ip & 0xf0000000) == 0xe0000000 ||        /* 224.0.0.0/4 组播 */
        dst_ip == 0xffffffff || dst_ip == 0)          /* 受限广播与未指定地址 */
        return SK_PASS;

    /* 3. TCP 流量分支 */
    if (ctx->protocol == IPPROTO_TCP) {
        /* 防死锁：排除发往 Mihomo 监听端口自身的流量 */
        if (ctx->local_port == MIHOMO_PORT)
            return SK_PASS;

        key = 0; /* 取 TCP 7891 socket */
    }
    /* 4. UDP 流量分支：仅拦截发往 53 端口的 DNS 查询 */
    else if (ctx->protocol == IPPROTO_UDP && ctx->local_port == 53) {
        key = 1; /* 取 UDP 7891 TPROXY socket */
    }
    /* 其他未纳管流量直接放行 */
    else {
        return SK_PASS;
    }

    /* 5. 查找目标套接字并分派 */
    sk = bpf_map_lookup_elem(&redirect_socket, &key);
    if (!sk)
        return SK_PASS;

    bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
    bpf_sk_release(sk);

    return SK_PASS;
}