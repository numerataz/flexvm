#ifndef FIRECRACKER_TEST_NET_H
#define FIRECRACKER_TEST_NET_H

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#define FLEXVM_TEST_TAP "flexvmtap"
#define FLEXVM_TEST_HOST "192.0.2.1"
#define FLEXVM_TEST_GUEST "192.0.2.2"
#define FLEXVM_TEST_PORT 5555
#define FLEXVM_TEST_PACKET "FlexVM Firecracker network"

static int configure_test_link(int fd, const char *name, const char *address)
{
    struct ifreq request = {0};
    struct sockaddr_in ipv4 = {.sin_family = AF_INET};

    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    inet_pton(AF_INET, address, &ipv4.sin_addr);
    memcpy(&request.ifr_addr, &ipv4, sizeof(ipv4));
    if (ioctl(fd, SIOCSIFADDR, &request) < 0)
        return -1;
    inet_pton(AF_INET, "255.255.255.0", &ipv4.sin_addr);
    memcpy(&request.ifr_netmask, &ipv4, sizeof(ipv4));
    if (ioctl(fd, SIOCSIFNETMASK, &request) < 0 || ioctl(fd, SIOCGIFFLAGS, &request) < 0)
        return -1;
    request.ifr_flags |= IFF_UP;
    return ioctl(fd, SIOCSIFFLAGS, &request);
}

static struct sockaddr_in test_network_peer(void)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(FLEXVM_TEST_PORT)};
    inet_pton(AF_INET, FLEXVM_TEST_HOST, &address.sin_addr);
    return address;
}

static int test_datagram_socket(time_t timeout_seconds)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    const struct timeval timeout = {.tv_sec = timeout_seconds};

    if (fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

#endif
