#include "cote3_protocol.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int connect_gateway(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { 0 };
    if (fd < 0)
        return -1;
    address.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(address.sun_path, path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    const char *socket_path = "/run/cote3-mon/gateway.sock";
    const char *operation_name;
    const char *key;
    const char *value = "";
    struct c3m_request request = { 0 };
    struct c3m_response response;
    int argument = 1;
    int fd;
    if (argc > 3 && !strcmp(argv[1], "--socket")) {
        socket_path = argv[2];
        argument = 3;
    }
    if (argc - argument < 2) {
        fprintf(stderr, "usage: %s [--socket PATH] put|get|delete KEY [VALUE]\n", argv[0]);
        return 2;
    }
    operation_name = argv[argument++];
    key = argv[argument++];
    if (!strcmp(operation_name, "put")) {
        if (argument >= argc) {
            fprintf(stderr, "put requires VALUE\n");
            return 2;
        }
        request.operation = C3M_OP_PUT;
        value = argv[argument];
    } else if (!strcmp(operation_name, "get")) {
        request.operation = C3M_OP_GET;
    } else if (!strcmp(operation_name, "delete")) {
        request.operation = C3M_OP_DELETE;
    } else {
        fprintf(stderr, "unknown operation\n");
        return 2;
    }
    request.key_len = (uint32_t)strlen(key);
    request.value_len = (uint32_t)strlen(value);
    if (!request.key_len || request.key_len > C3M_MAX_KEY_BYTES ||
        request.value_len > C3M_MAX_VALUE_BYTES) {
        fprintf(stderr, "key or value outside protocol bounds\n");
        return 2;
    }
    memcpy(request.key, key, request.key_len);
    memcpy(request.value, value, request.value_len);
    request.request_id = ((uint64_t)time(NULL) << 32) ^ (uint64_t)getpid();
    fd = connect_gateway(socket_path);
    if (fd < 0) {
        perror("connect");
        return 1;
    }
    if (c3m_send_request(fd, &request) || c3m_recv_response(fd, &response)) {
        fprintf(stderr, "gateway protocol failure\n");
        close(fd);
        return 1;
    }
    close(fd);
    printf("%s", c3m_status_name(response.status));
    if (response.value_len)
        printf(" %.*s", (int)response.value_len, response.value);
    putchar('\n');
    return response.status == C3M_STATUS_OK ? 0 : 1;
}

