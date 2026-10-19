#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "sklookup.skel.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* 支持按 target_type (SOCK_STREAM / SOCK_DGRAM) 精准克隆套接字 */
static int get_mihomo_socket_fd(int pid, int target_port, int target_type)
{
    int pidfd = syscall(__NR_pidfd_open, pid, 0);
    if (pidfd < 0) {
        perror("pidfd_open failed");
        return -1;
    }

    char fd_dir_path[64];
    snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
    DIR *dir = opendir(fd_dir_path);
    if (!dir) {
        perror("opendir /proc/[pid]/fd failed");
        close(pidfd);
        return -1;
    }

    struct dirent *entry;
    int target_sock = -1;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        int remote_fd = atoi(entry->d_name);
        if (remote_fd <= 2)
            continue;

        int local_fd = syscall(__NR_pidfd_getfd, pidfd, remote_fd, 0);
        if (local_fd < 0)
            continue;

        int sock_type = 0;
        socklen_t type_len = sizeof(sock_type);
        if (getsockopt(local_fd, SOL_SOCKET, SO_TYPE, &sock_type, &type_len) < 0 || sock_type != target_type) {
            close(local_fd);
            continue;
        }

        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);

        if (getsockname(local_fd, (struct sockaddr *)&ss, &len) == 0) {
            int port = 0;
            if (ss.ss_family == AF_INET) {
                port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
            } else if (ss.ss_family == AF_INET6) {
                port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
            }

            if (port == target_port) {
                target_sock = local_fd;
                break;
            }
        }
        close(local_fd);
    }

    closedir(dir);
    close(pidfd);
    return target_sock;
}

/* 自动打开 Android 根 cgroup v2 目录 */
static int open_root_cgroup(const char *custom_path)
{
    const char *candidates[] = {
        custom_path,
        "/sys/fs/cgroup",
        "/dev/cg2_bpf",
        NULL
    };

    for (int i = 0; i < 3; i++) {
        if (!candidates[i] || candidates[i][0] == '\0')
            continue;
        int fd = open(candidates[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            printf("[+] Opened cgroup v2 root: %s (fd=%d)\n", candidates[i], fd);
            return fd;
        }
    }
    return -1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <mihomo_pid> [target_port] [capture_udp:0|1] [capture_ipv6:0|1] [cgroup_path]\n",
                argv[0]);
        return 1;
    }

    int mihomo_pid   = atoi(argv[1]);
    int target_port  = (argc >= 3) ? atoi(argv[2]) : 7891;
    int capture_udp  = (argc >= 4) ? (atoi(argv[3]) != 0) : 0;
    int capture_ipv6 = (argc >= 5) ? (atoi(argv[4]) != 0) : 0;
    const char *cg_path = (argc >= 6) ? argv[5] : NULL;

    struct sklookup_bpf *skel = NULL;
    struct bpf_link *sk_link = NULL;
    struct bpf_link *cg_link = NULL;
    int tcp_fd = -1;
    int udp_fd = -1;
    int netns_fd = -1;
    int cgroup_fd = -1;
    __u32 key_tcp = 0;
    __u32 key_udp = 1;
    int ret = 1;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 1. 抓取 TCP 7891 */
    printf("[+] Fetching TCP socket for port %d from PID %d...\n", target_port, mihomo_pid);
    tcp_fd = get_mihomo_socket_fd(mihomo_pid, target_port, SOCK_STREAM);
    if (tcp_fd < 0) {
        fprintf(stderr, "[-] Could not find TCP socket on port %d in PID %d\n", target_port, mihomo_pid);
        goto cleanup;
    }
    printf("[+] Cloned TCP socket FD: %d\n", tcp_fd);

    /* 2. 抓取 UDP 7891 (TPROXY) */
    printf("[+] Fetching UDP socket for port %d from PID %d...\n", target_port, mihomo_pid);
    udp_fd = get_mihomo_socket_fd(mihomo_pid, target_port, SOCK_DGRAM);
    if (udp_fd < 0) {
        fprintf(stderr, "[-] Could not find UDP socket on port %d in PID %d\n", target_port, mihomo_pid);
        goto cleanup;
    }
    printf("[+] Cloned UDP socket FD: %d\n", udp_fd);

    /* 3. 打开 netns 与 cgroup v2 句柄 */
    netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (netns_fd < 0) {
        perror("[-] open netns failed");
        goto cleanup;
    }

    cgroup_fd = open_root_cgroup(cg_path);
    if (cgroup_fd < 0) {
        perror("[-] open cgroup v2 root failed");
        goto cleanup;
    }

    /* 4. 打开 BPF 骨架并写入只读配置参数 (.rodata) */
    printf("[+] Opening BPF skeleton and injecting config...\n");
    skel = sklookup_bpf__open();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open BPF skeleton\n");
        goto cleanup;
    }

    skel->rodata->cfg_mihomo_pid   = (__u32)mihomo_pid;
    skel->rodata->cfg_mihomo_port  = (__u16)target_port;
    skel->rodata->cfg_capture_udp  = (__u8)capture_udp;
    skel->rodata->cfg_capture_ipv6 = (__u8)capture_ipv6;

    /* 5. 加载并验证 BPF 程序 */
    if (sklookup_bpf__load(skel) < 0) {
        fprintf(stderr, "[-] Failed to load BPF skeleton\n");
        goto cleanup;
    }

    /* 6. 注册 TCP 与 UDP 套接字到 SOCKMAP */
    int map_fd = bpf_map__fd(skel->maps.redirect_socket);
    if (bpf_map_update_elem(map_fd, &key_tcp, &tcp_fd, BPF_ANY) < 0) {
        perror("[-] bpf_map_update_elem (TCP) failed");
        goto cleanup;
    }
    if (bpf_map_update_elem(map_fd, &key_udp, &udp_fd, BPF_ANY) < 0) {
        perror("[-] bpf_map_update_elem (UDP) failed");
        goto cleanup;
    }
    printf("[+] Registered TCP(Key 0) & UDP(Key 1) to SOCKMAP\n");

    /* 7. 挂载 cgroup/sock_create（必须在拉起流量路由前生效，确保防回环） */
    cg_link = bpf_program__attach_cgroup(skel->progs.mark_mihomo_sock, cgroup_fd);
    if (!cg_link) {
        fprintf(stderr, "[-] Failed to attach cgroup/sock_create: %s (errno=%d)\n",
                strerror(errno), errno);
        goto cleanup;
    }
    printf("[+] Attached cgroup/sock_create (PID %d -> mark 0x01000000)\n", mihomo_pid);

    /* 8. 挂载 netns sk_lookup */
    sk_link = bpf_program__attach_netns(skel->progs.sk_lookup_redirect, netns_fd);
    if (!sk_link) {
        fprintf(stderr, "[-] Failed to attach SK_LOOKUP: %s (errno=%d)\n",
                strerror(errno), errno);
        goto cleanup;
    }

    printf("\n[+] ==========================================\n");
    printf("[+] SK_LOOKUP & CGROUP_MARK are now ACTIVE!\n");
    printf("[+] Mihomo PID    : %d (Bypass Mark: 0x01000000)\n", mihomo_pid);
    printf("[+] Target Port   : %d\n", target_port);
    printf("[+] Capture UDP   : %s\n", capture_udp ? "ALL PORTS" : "DNS (Port 53) ONLY");
    printf("[+] Capture IPv6  : %s\n", capture_ipv6 ? "ENABLED" : "DISABLED");
    printf("[+] Press Ctrl+C to stop and detach\n");
    printf("[+] ==========================================\n\n");
    fflush(stdout);

    ret = 0;
    while (running) {
        pause();
    }

    printf("\n[+] Detaching and cleaning up...\n");

cleanup:
    if (sk_link)
        bpf_link__destroy(sk_link);
    if (cg_link)
        bpf_link__destroy(cg_link);
    if (skel)
        sklookup_bpf__destroy(skel);
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    if (netns_fd >= 0)
        close(netns_fd);
    if (tcp_fd >= 0)
        close(tcp_fd);
    if (udp_fd >= 0)
        close(udp_fd);

    printf("[+] Completed. Exited cleanly.\n");
    return ret;
}