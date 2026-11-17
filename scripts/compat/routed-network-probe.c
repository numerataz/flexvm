#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int listener(int type) {
    int fd = socket(AF_INET6, type, 0);
    struct sockaddr_in6 addr = { .sin6_family = AF_INET6, .sin6_port = htons(28143) };
    if (fd == -1 || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind routed probe");
        return -1;
    }
    return fd;
}

int main(void) {
    int tcp = listener(SOCK_STREAM);
    int udp = listener(SOCK_DGRAM);
    if (tcp < 0 || udp < 0 || listen(tcp, 8) < 0) return 1;
    struct pollfd sockets[] = {{tcp, POLLIN, 0}, {udp, POLLIN, 0}, {-1, POLLIN, 0}};
    char buffer[4096];
    while (poll(sockets, 3, -1) >= 0) {
        if (sockets[0].revents) {
            if (sockets[2].fd != -1) close(sockets[2].fd);
            sockets[2].fd = accept(tcp, NULL, NULL);
        }
        if (sockets[1].revents) {
            struct sockaddr_in6 peer;
            socklen_t len = sizeof(peer);
            ssize_t size = recvfrom(udp, buffer, sizeof(buffer), 0, (struct sockaddr *)&peer, &len);
            if (size < 0 || sendto(udp, buffer, size, 0, (struct sockaddr *)&peer, len) != size) return 2;
        }
        if (sockets[2].revents) {
            ssize_t size = read(sockets[2].fd, buffer, sizeof(buffer));
            if (size <= 0) {
                close(sockets[2].fd);
                sockets[2].fd = -1;
            } else if (write(sockets[2].fd, buffer, size) != size) return 3;
        }
    }
    perror("poll routed probe");
    return 4;
}
