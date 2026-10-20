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
 */
const volatile __u16 cfg_mihomo_port  = 7891;
const volatile __u8  cfg_capture_udp  = 0; /* 0: 仅劫持 UDP 53, 1: 捕获全端口 UDP */
const volatile __u8  cfg_capture_ipv6 = 0; /* 0: 忽略 IPv6,     1: 捕获 IPv6 */

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} redirect_socket SEC(".maps");

SEC("sk_lookup")
int sk_lookup_redirect(struct bpf_sk_lookup *ctx)
{
    /*
     * 关键修复：在入口处一次性将常用字段读入标量局部变量，
     * 彻底杜绝 Clang 在分支跳转间生成针对 ctx 指针的动态寄存器算术运算 (r2 += r3)
     */
    __u32 family     = ctx->family;
    __u32 protocol   = ctx->protocol;
    __u32 local_port = ctx->local_port;
    __u32 key = 0;
    struct bpf_sock *sk;

    /* 1. 地址族检查与回环/链路本地地址保护 */
    if (family == AF_INET) {
        /* 排除发往 127.0.0.0/8 回环地址的连接 */
        __u32 ip4 = ctx->local_ip4;
        if ((bpf_ntohl(ip4) >> 24) == 127)
            return SK_PASS;
    } else if (family == AF_INET6) {
        /* 若未开启 IPv6 捕获，直接放行 */
        if (!cfg_capture_ipv6)
            return SK_PASS;

        __u32 w0 = bpf_ntohl(ctx->local_ip6[0]);
        __u32 w1 = bpf_ntohl(ctx->local_ip6[1]);
        __u32 w2 = bpf_ntohl(ctx->local_ip6[2]);
        __u32 w3 = bpf_ntohl(ctx->local_ip6[3]);

        /* 排除 IPv6 回环地址 ::1 */
        if (w0 == 0 && w1 == 0 && w2 == 0 && w3 == 1)
            return SK_PASS;

        /* 排除 IPv4 映射回环地址 ::ffff:127.0.0.0/104 */
        if (w0 == 0 && w1 == 0 && w2 == 0x0000ffff && (w3 >> 24) == 127)
            return SK_PASS;

        /*
         * 针对 fe80::/10 链路本地地址：
         * 允许劫持发往路由器 fe80:: 的 UDP 53 (DNS) 查询，其余非 DNS 链路本地流量直接放行
         */
        if ((w0 & 0xffc00000) == 0xfe800000) {
            if (!(protocol == IPPROTO_UDP && local_port == 53))
                return SK_PASS;
        }
    } else {
        return SK_PASS;
    }

    /* 2. 协议与端口分支判定（使用局部变量，不再对 ctx 解引用） */
    if (protocol == IPPROTO_TCP) {
        /* 防死锁：排除发往 Mihomo 监听端口自身的流量 */
        if (local_port == cfg_mihomo_port)
            return SK_PASS;

        key = 0; /* 取 TCP 7891 socket */
    } else if (protocol == IPPROTO_UDP) {
        /* 防死锁：排除发往 Mihomo 监听端口自身的流量 */
        if (local_port == cfg_mihomo_port)
            return SK_PASS;

        /* 53 端口始终劫持；其余 UDP 端口根据 cfg_capture_udp 开关决定 */
        if (local_port == 53 || cfg_capture_udp) {
            key = 1; /* 取 UDP 7891 TPROXY socket */
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