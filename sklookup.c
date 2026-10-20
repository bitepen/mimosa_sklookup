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

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <mihomo_pid> [target_port] [capture_udp:0|1] [capture_ipv6:0|1]\n",
                argv[0]);
        return 1;
    }

    int mihomo_pid   = atoi(argv[1]);
    int target_port  = (argc >= 3) ? atoi(argv[2]) : 7891;
    int capture_udp  = (argc >= 4) ? (atoi(argv[3]) != 0) : 0;
    int capture_ipv6 = (argc >= 5) ? (atoi(argv[4]) != 0) : 0;

    struct sklookup_bpf *skel = NULL;
    struct bpf_link *sk_link = NULL;
    int tcp_fd = -1;
    int udp_fd = -1;
    int netns_fd = -1;
    __u32 key_tcp = 0;
    __u32 key_udp = 1;
    int ret = 1;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[+] Fetching TCP socket for port %d from PID %d...\n", target_port, mihomo_pid);
    tcp_fd = get_mihomo_socket_fd(mihomo_pid, target_port, SOCK_STREAM);
    if (tcp_fd < 0) {
        fprintf(stderr, "[-] Could not find TCP socket on port %d in PID %d\n", target_port, mihomo_pid);
        goto cleanup;
    }
    printf("[+] Cloned TCP socket FD: %d\n", tcp_fd);

    printf("[+] Fetching UDP socket for port %d from PID %d...\n", target_port, mihomo_pid);
    udp_fd = get_mihomo_socket_fd(mihomo_pid, target_port, SOCK_DGRAM);
    if (udp_fd < 0) {
        fprintf(stderr, "[-] Could not find UDP socket on port %d in PID %d\n", target_port, mihomo_pid);
        goto cleanup;
    }
    printf("[+] Cloned UDP socket FD: %d\n", udp_fd);

    netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    if (netns_fd < 0) {
        perror("[-] open netns failed");
        goto cleanup;
    }

    printf("[+] Opening BPF skeleton and injecting config...\n");
    skel = sklookup_bpf__open();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open BPF skeleton\n");
        goto cleanup;
    }

    skel->rodata->cfg_mihomo_port  = (__u16)target_port;
    skel->rodata->cfg_capture_udp  = (__u8)capture_udp;
    skel->rodata->cfg_capture_ipv6 = (__u8)capture_ipv6;

    if (sklookup_bpf__load(skel) < 0) {
        fprintf(stderr, "[-] Failed to load BPF skeleton\n");
        goto cleanup;
    }

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

    sk_link = bpf_program__attach_netns(skel->progs.sk_lookup_redirect, netns_fd);
    if (!sk_link) {
        fprintf(stderr, "[-] Failed to attach SK_LOOKUP: %s (errno=%d)\n",
                strerror(errno), errno);
        goto cleanup;
    }

    printf("\n[+] ==========================================\n");
    printf("[+] SK_LOOKUP is now ACTIVE!\n");
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
    if (skel)
        sklookup_bpf__destroy(skel);
    if (netns_fd >= 0)
        close(netns_fd);
    if (tcp_fd >= 0)
        close(tcp_fd);
    if (udp_fd >= 0)
        close(udp_fd);

    printf("[+] Completed. Exited cleanly.\n");
    return ret;
}