// Real guest capability probes. Each runs in a child with a deadline; namespace/mount
// changes never affect the caller. Build statically for use in arbitrary OCI images.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/io_uring.h>
#include <linux/kvm.h>
#include <linux/magic.h>
#include <linux/memfd.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static int error(void) { return errno ? errno : EIO; }
static int close_result(int fd) { if (fd < 0) return error(); close(fd); return 0; }
static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return error();
    ssize_t n = write(fd, data, strlen(data));
    int result = n == (ssize_t)strlen(data) ? 0 : error();
    close(fd);
    return result;
}
static int ns_mount(void) { return unshare(CLONE_NEWNS) ? error() : 0; }
static int ns_net(void) { return unshare(CLONE_NEWNET) ? error() : 0; }
static int ns_ipc(void) { return unshare(CLONE_NEWIPC) ? error() : 0; }
static int ns_uts(void) { return unshare(CLONE_NEWUTS) ? error() : 0; }
static int ns_cgroup(void) { return unshare(CLONE_NEWCGROUP) ? error() : 0; }
static int ns_user(void) {
    char map[64]; uid_t uid = getuid(); gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER)) return error();
    int e = write_file("/proc/self/setgroups", "deny");
    if (e && e != ENOENT) return e;
    snprintf(map, sizeof(map), "0 %u 1", uid);
    if ((e = write_file("/proc/self/uid_map", map))) return e;
    snprintf(map, sizeof(map), "0 %u 1", gid);
    return write_file("/proc/self/gid_map", map);
}
static int ns_pid(void) {
    if (unshare(CLONE_NEWPID)) return error();
    pid_t pid = fork();
    if (pid < 0) return error();
    if (!pid) _exit(getpid() == 1 ? 0 : 1);
    int status;
    if (waitpid(pid, &status, 0) < 0) return error();
    return WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : EIO;
}
static int cgroup(void) {
    struct statfs fs;
    if (statfs("/sys/fs/cgroup", &fs)) return error();
    if (fs.f_type != CGROUP2_SUPER_MAGIC) return ENODEV;
    char dir[128], path[160];
    snprintf(dir, sizeof(dir), "/sys/fs/cgroup/flexvm-probe-%d", getpid());
    if (mkdir(dir, 0700)) return error();
    const char *files[] = {"memory.max", "cpu.max", "pids.max"};
    const char *values[] = {"67108864", "50000 100000", "64"};
    int result = 0;
    for (unsigned i = 0; i < sizeof(files)/sizeof(*files); i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
        if ((result = write_file(path, values[i]))) {
            // A writable cgroup2 hierarchy without activated parent controllers is a
            // configuration gap, not evidence that the kernel lacks those controllers.
            if (result == ENOENT) result = EAGAIN;
            break;
        }
    }
    if (rmdir(dir) && !result) result = error();
    return result;
}
static int private_mounts(void) {
    if (unshare(CLONE_NEWNS)) return error();
    return mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ? error() : 0;
}
static int capacity(void) {
    struct statvfs fs;
    if (statvfs("/", &fs)) return error();
    return fs.f_blocks && fs.f_bavail && fs.f_files && fs.f_ffree ? 0 : ENOSPC;
}
static int overlay(void) {
    int result = private_mounts();
    if (result) return result;
    char dir[] = "/tmp/flexvm-probe-XXXXXX";
    if (!mkdtemp(dir)) return error();
    if (mount("tmpfs", dir, "tmpfs", 0, "size=1m,nr_inodes=128")) { result = error(); rmdir(dir); return result; }
    char paths[4][160], options[512];
    const char *names[] = {"lower", "upper", "work", "merged"};
    for (unsigned i = 0; i < 4; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/%s", dir, names[i]);
        if (mkdir(paths[i], 0700)) { result = error(); goto out; }
    }
    snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s", paths[0], paths[1], paths[2]);
    if (mount("overlay", paths[3], "overlay", 0, options)) { result = error(); goto out; }
    char file[180]; snprintf(file, sizeof(file), "%s/check", paths[3]);
    int fd = open(file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) result = error(); else { if (write(fd, "ok", 2) != 2) result = error(); close(fd); }
    umount2(paths[3], MNT_DETACH);
out:
    umount2(dir, MNT_DETACH); rmdir(dir); return result;
}
static int fuse(void) {
    int result = private_mounts(); if (result) return result;
    int fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (fd < 0) return error();
    char dir[] = "/tmp/flexvm-fuse-XXXXXX", options[128];
    if (!mkdtemp(dir)) { result = error(); close(fd); return result; }
    snprintf(options, sizeof(options), "fd=%d,rootmode=40000,user_id=%u,group_id=%u", fd, getuid(), getgid());
    if (mount("flexvm-probe", dir, "fuse", 0, options)) result = error();
    else umount2(dir, MNT_DETACH);
    close(fd); rmdir(dir); return result;
}
static int tun_kind(short flags) {
    if (unshare(CLONE_NEWNET)) return error();
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) return error();
    struct ifreq req = {0}; req.ifr_flags = flags | IFF_NO_PI;
    snprintf(req.ifr_name, sizeof(req.ifr_name), "fvp%%d");
    int result = ioctl(fd, TUNSETIFF, &req) ? error() : 0;
    close(fd); return result;
}
static int tun(void) { return tun_kind(IFF_TUN); }
static int tap(void) { return tun_kind(IFF_TAP); }
static int seccomp(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {.len = sizeof(filter)/sizeof(*filter), .filter = filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return error();
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) return error();
    errno = 0;
    return syscall(SYS_getppid) == -1 && errno == EPERM ? 0 : EIO;
}
static int bpf(void) {
    union bpf_attr attr = {0}; attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(uint32_t); attr.value_size = sizeof(uint32_t); attr.max_entries = 1;
    return close_result(syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr)));
}
static int perf(void) {
    struct perf_event_attr attr = {0}; attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE; attr.config = PERF_COUNT_SW_CPU_CLOCK; attr.exclude_kernel = 1;
    return close_result(syscall(SYS_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC));
}
static int pidfd(void) { return close_result(syscall(SYS_pidfd_open, getpid(), 0)); }
static int memfd(void) { return close_result(syscall(SYS_memfd_create, "flexvm-probe", MFD_CLOEXEC)); }
static int io_uring(void) {
    struct io_uring_params params = {0};
    return close_result(syscall(SYS_io_uring_setup, 2, &params));
}
static int kvm(void) {
    int fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (fd < 0) return error();
    int result = ioctl(fd, KVM_GET_API_VERSION, 0);
    if (result != KVM_API_VERSION) { result = result < 0 ? error() : EPROTO; close(fd); return result; }
    int vm = ioctl(fd, KVM_CREATE_VM, 0); result = close_result(vm); close(fd); return result;
}
static int netfilter(unsigned subsystem, unsigned command) {
    if (unshare(CLONE_NEWNET)) return error();
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) return error();
    struct { struct nlmsghdr h; struct nfgenmsg g; } req = {0};
    req.h.nlmsg_len = sizeof(req); req.h.nlmsg_type = (subsystem << 8) | command;
    req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; req.h.nlmsg_seq = 1;
    req.g.nfgen_family = AF_UNSPEC; req.g.version = NFNETLINK_V0;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    int result = 0;
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) result = error();
    else {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 1000) <= 0) result = ETIMEDOUT;
        else {
            union { struct nlmsghdr header; char bytes[8192]; } buf;
            ssize_t n = recv(fd, buf.bytes, sizeof(buf.bytes), 0);
            if (n < (ssize_t)sizeof(struct nlmsghdr)) result = n < 0 ? error() : EPROTO;
            else {
                struct nlmsghdr *msg = &buf.header;
                if (msg->nlmsg_type == NLMSG_ERROR) {
                    if (n < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr))) result = EPROTO;
                    else result = -((struct nlmsgerr *)NLMSG_DATA(msg))->error;
                }
            }
        }
    }
    close(fd); return result;
}
static int nftables(void) { return netfilter(NFNL_SUBSYS_NFTABLES, NFT_MSG_GETTABLE); }
static int conntrack(void) { return netfilter(NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET); }
static int iptables(void) {
    if (unshare(CLONE_NEWNET)) return error();
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
    if (fd < 0) return error();
    struct ipt_getinfo info = {0}; snprintf(info.name, sizeof(info.name), "filter");
    socklen_t len = sizeof(info);
    int result = getsockopt(fd, IPPROTO_IP, IPT_SO_GET_INFO, &info, &len) ? error() : 0;
    close(fd); return result;
}
struct probe { const char *name; int (*run)(void); };
static struct probe probes[] = {
    {"namespace.user", ns_user}, {"namespace.mount", ns_mount}, {"namespace.pid", ns_pid},
    {"namespace.network", ns_net}, {"namespace.ipc", ns_ipc}, {"namespace.uts", ns_uts},
    {"namespace.cgroup", ns_cgroup}, {"cgroup.delegation", cgroup}, {"storage.overlay", overlay},
    {"storage.capacity", capacity}, {"storage.fuse", fuse}, {"network.tun", tun}, {"network.tap", tap}, {"security.seccomp", seccomp},
    {"kernel.bpf", bpf}, {"kernel.perf", perf}, {"kernel.pidfd", pidfd}, {"kernel.memfd", memfd},
    {"kernel.io_uring", io_uring}, {"network.nftables", nftables}, {"network.conntrack", conntrack},
    {"network.iptables_legacy", iptables}, {"virtualization.kvm", kvm},
};
static int isolated(int (*run)(void)) {
    int pipefd[2]; if (pipe2(pipefd, O_CLOEXEC)) return error();
    pid_t pid = fork();
    if (pid < 0) { int e = error(); close(pipefd[0]); close(pipefd[1]); return e; }
    if (!pid) {
        close(pipefd[0]); alarm(5); int result = run();
        ssize_t ignored = write(pipefd[1], &result, sizeof(result)); (void)ignored; _exit(0);
    }
    close(pipefd[1]); struct pollfd ready = {.fd = pipefd[0], .events = POLLIN};
    int result = ETIMEDOUT;
    if (poll(&ready, 1, 6000) > 0) {
        if (read(pipefd[0], &result, sizeof(result)) != sizeof(result)) result = EIO;
    } else kill(pid, SIGKILL);
    close(pipefd[0]);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    return result;
}
static void json_string(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const void *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
static const char *probe_status(int e, const char *name) {
    if (!e) return "supported";
    if (e == EPERM || e == EACCES) return "denied";
    if (e == EAGAIN && !strcmp(name, "cgroup.delegation")) return "unconfigured";
    if (e == ENOENT) return "missing";
    if (e == ENOSYS || e == ENODEV || e == EOPNOTSUPP || e == EPROTONOSUPPORT || e == ENOPROTOOPT)
        return "unsupported";
    return "error";
}
int main(int argc, char **argv) {
    if (argc > 2) { fprintf(stderr, "usage: guest-probe [PROBE]\n"); return 64; }
    unsigned count = 0;
    for (unsigned i = 0; i < sizeof(probes)/sizeof(*probes); i++)
        if (argc == 1 || !strcmp(argv[1], probes[i].name)) count++;
    if (!count) { fprintf(stderr, "unknown probe\n"); return 64; }
    struct utsname system; if (uname(&system)) return 1;
    printf("{\"schema_version\":1,\"uid\":%u,\"architecture\":", getuid()); json_string(system.machine);
    printf(",\"kernel\":"); json_string(system.release); printf(",\"probes\":[");
    unsigned emitted = 0;
    for (unsigned i = 0; i < sizeof(probes)/sizeof(*probes); i++) {
        if (argc == 2 && strcmp(argv[1], probes[i].name)) continue;
        int e = isolated(probes[i].run);
        if (emitted++) putchar(',');
        printf("{\"name\":"); json_string(probes[i].name);
        const char *status = probe_status(e, probes[i].name);
        printf(",\"status\":"); json_string(status); printf(",\"errno\":%d,\"detail\":", e);
        const char *detail = e ? strerror(e) : "probe succeeded";
        if (e == EAGAIN && !strcmp(probes[i].name, "cgroup.delegation"))
            detail = "parent cgroup controllers are not activated/delegated";
        json_string(detail); putchar('}');
    }
    puts("]}"); return 0;
}
