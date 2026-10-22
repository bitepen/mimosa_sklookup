#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MIHOMO_PORT 7891
#define AF_INET 2

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

    /* 1. 仅接管 IPv4 流量 */
    if (ctx->family != AF_INET)
        return SK_PASS;

    /* 2. 【核心修复】UDP 53 优先拦截：
     * 无论目标是 192.168.x.1 还是 8.8.8.8，只要是 53 DNS，绝不检查私网段，立刻送往 Mihomo！
     */
    if (ctx->protocol == IPPROTO_UDP) {
        if (ctx->local_port == 53) {
            key = 1; /* UDP 7891 TPROXY */
        } else {
            return SK_PASS;
        }
    }
    /* 3. TCP 流量分支：仅在 TCP 流量中检查回环与私网地址，防止局域网互联死锁 */
    else if (ctx->protocol == IPPROTO_TCP) {
        /* 排除发往 Mihomo 监听端口自身的流量 */
        if (ctx->local_port == MIHOMO_PORT)
            return SK_PASS;

        __u32 dst_ip = bpf_ntohl(ctx->local_ip4);

        /* 私网/回环过滤只对 TCP 生效（保护 Quick Share / 局域网服务原生直连） */
        if ((dst_ip >> 24) == 127 ||                      /* 127.0.0.0/8 回环 */
            (dst_ip >> 24) == 10 ||                       /* 10.0.0.0/8 私网 */
            (dst_ip & 0xfff00000) == 0xac100000 ||        /* 172.16.0.0/12 私网 */
            (dst_ip & 0xffff0000) == 0xc0a80000 ||        /* 192.168.0.0/16 私网 */
            (dst_ip & 0xffff0000) == 0xa9fe0000 ||        /* 169.254.0.0/16 链路本地 */
            (dst_ip & 0xf0000000) == 0xe0000000 ||        /* 224.0.0.0/4 组播 */
            dst_ip == 0xffffffff || dst_ip == 0)          /* 广播与全0 */
            return SK_PASS;

        key = 0; /* TCP 7891 */
    }
    else {
        return SK_PASS;
    }

    /* 4. 分派套接字 */
    sk = bpf_map_lookup_elem(&redirect_socket, &key);
    if (!sk)
        return SK_PASS;

    bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
    bpf_sk_release(sk);

    return SK_PASS;
}