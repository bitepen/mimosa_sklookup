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
    __u32 key = 0;
    struct bpf_sock *sk;

    /* 1. 地址族检查与回环/链路本地地址保护 */
    if (ctx->family == AF_INET) {
        if ((bpf_ntohl(ctx->local_ip4) >> 24) == 127)
            return SK_PASS;
    } else if (ctx->family == AF_INET6) {
        if (!cfg_capture_ipv6)
            return SK_PASS;

        __u32 w0 = bpf_ntohl(ctx->local_ip6[0]);
        __u32 w1 = bpf_ntohl(ctx->local_ip6[1]);
        __u32 w2 = bpf_ntohl(ctx->local_ip6[2]);
        __u32 w3 = bpf_ntohl(ctx->local_ip6[3]);

        if (w0 == 0 && w1 == 0 && w2 == 0 && w3 == 1)
            return SK_PASS;
        if ((w0 & 0xffc00000) == 0xfe800000)
            return SK_PASS;
        if (w0 == 0 && w1 == 0 && w2 == 0x0000ffff && (w3 >> 24) == 127)
            return SK_PASS;
    } else {
        return SK_PASS;
    }

    /* 2. 协议与端口分支判定 */
    if (ctx->protocol == IPPROTO_TCP) {
        if (ctx->local_port == cfg_mihomo_port)
            return SK_PASS;
        key = 0;
    } else if (ctx->protocol == IPPROTO_UDP) {
        if (ctx->local_port == cfg_mihomo_port)
            return SK_PASS;
        if (ctx->local_port == 53 || cfg_capture_udp) {
            key = 1;
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