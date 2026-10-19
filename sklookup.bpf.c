#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/*
 * 由用户态 sklookup 在加载前通过 skel->rodata 注入的只读配置
 * BPF 验证器会在加载期直接裁剪未启用的常量分支
 */
const volatile __u16 cfg_mihomo_port  = 7891;
const volatile __u8  cfg_capture_udp  = 0; /* 0: 仅劫持 UDP 53, 1: 捕获全端口 UDP */
const volatile __u8  cfg_capture_ipv6 = 0; /* 0: 忽略 IPv6,     1: 捕获 IPv6 */

/*
 * Key 0: TCP 7891 (常规 TCP 透明代理双栈套接字)
 * Key 1: UDP 7891 (TPROXY UDP 双栈套接字，承载 DNS 劫持与全端口 UDP)
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

    /* 1. 地址族检查与回环/链路本地地址保护 */
    if (ctx->family == AF_INET) {
        /* 排除发往 127.0.0.0/8 回环地址的连接 */
        if ((bpf_ntohl(ctx->local_ip4) >> 24) == 127)
            return SK_PASS;
    } else if (ctx->family == AF_INET6) {
        /* 若未启用 IPv6 捕获，直接放行 */
        if (!cfg_capture_ipv6)
            return SK_PASS;

        __u32 w0 = bpf_ntohl(ctx->local_ip6[0]);
        __u32 w1 = bpf_ntohl(ctx->local_ip6[1]);
        __u32 w2 = bpf_ntohl(ctx->local_ip6[2]);
        __u32 w3 = bpf_ntohl(ctx->local_ip6[3]);

        /* 排除 IPv6 回环地址 ::1 */
        if (w0 == 0 && w1 == 0 && w2 == 0 && w3 == 1)
            return SK_PASS;

        /* 排除 IPv6 链路本地地址 fe80::/10 */
        if ((w0 & 0xffc00000) == 0xfe800000)
            return SK_PASS;

        /* 排除 IPv4 映射回环地址 ::ffff:127.0.0.0/104 */
        if (w0 == 0 && w1 == 0 && w2 == 0x0000ffff && (w3 >> 24) == 127)
            return SK_PASS;
    } else {
        return SK_PASS;
    }

    /* 2. 协议与端口分支判定 */
    if (ctx->protocol == IPPROTO_TCP) {
        /* 防死锁：排除发往 Mihomo 监听端口自身的流量 */
        if (ctx->local_port == cfg_mihomo_port)
            return SK_PASS;

        key = 0; /* 导向 TCP 7891 socket */
    } else if (ctx->protocol == IPPROTO_UDP) {
        /* 防死锁：排除发往 Mihomo 监听端口自身的流量 */
        if (ctx->local_port == cfg_mihomo_port)
            return SK_PASS;

        /* 53 端口始终劫持；其余 UDP 端口根据 cfg_capture_udp 开关决定 */
        if (ctx->local_port == 53 || cfg_capture_udp) {
            key = 1; /* 导向 UDP 7891 TPROXY socket */
        } else {
            return SK_PASS;
        }
    } else {
        return SK_PASS;
    }

    /* 3. 查找目标套接字并分派 */
    sk = bpf_map_lookup_elem(&redirect_socket, &key);
    if (!sk)
        return SK_PASS;

    bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
    bpf_sk_release(sk);

    return SK_PASS;
}