#include "cote3_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static uint64_t monotonic_ns(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static void sleep_us(long microseconds)
{
    struct timespec duration = {
        .tv_sec = microseconds / 1000000,
        .tv_nsec = (microseconds % 1000000) * 1000,
    };
    while (nanosleep(&duration, &duration) && errno == EINTR)
        ;
}

static uint32_t random_u32(uint32_t *state)
{
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

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

static int write_full(int fd, const void *buffer, size_t length)
{
    const uint8_t *cursor = buffer;
    while (length) {
        ssize_t count = write(fd, cursor, length);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        cursor += (size_t)count;
        length -= (size_t)count;
    }
    return 0;
}

static int invoke(const char *socket_path, struct c3m_request *request)
{
    struct c3m_response response;
    int fd = connect_gateway(socket_path);
    if (fd < 0)
        return -1;
    if (c3m_send_request(fd, request) || c3m_recv_response(fd, &response)) {
        close(fd);
        return -1;
    }
    close(fd);
    return response.status;
}

static int malformed(const char *socket_path)
{
    uint8_t header[C3M_REQUEST_HEADER_SIZE] = { 0 };
    uint32_t value32;
    uint16_t value16;
    int fd = connect_gateway(socket_path);
    if (fd < 0)
        return -1;
    value32 = htonl(C3M_MAGIC); memcpy(header, &value32, 4);
    value16 = htons(C3M_VERSION); memcpy(header + 4, &value16, 2);
    value16 = htons(C3M_OP_PUT); memcpy(header + 6, &value16, 2);
    value32 = htonl(1); memcpy(header + 16, &value32, 4);
    value32 = htonl(C3M_MAX_VALUE_BYTES + 1); memcpy(header + 20, &value32, 4);
    if (write_full(fd, header, sizeof(header)) || write_full(fd, "k", 1)) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static void fill_request(struct c3m_request *request, uint64_t id, uint16_t operation,
                         unsigned int key_number, size_t value_size, uint8_t fill)
{
    char key[32];
    int key_len = snprintf(key, sizeof(key), "key-%02u", key_number % 32);
    memset(request, 0, sizeof(*request));
    request->request_id = id;
    request->operation = operation;
    request->key_len = (uint32_t)key_len;
    request->value_len = (uint32_t)value_size;
    memcpy(request->key, key, request->key_len);
    memset(request->value, fill, value_size);
}

int main(int argc, char **argv)
{
    const char *scenario;
    const char *socket_path = "/run/cote3-mon/gateway.sock";
    double duration = 60.0;
    uint32_t seed = 42;
    uint64_t request_id = 1;
    uint64_t deadline;
    int index;
    if (argc < 2) {
        fprintf(stderr, "usage: %s SCENARIO [--socket PATH] [--duration SECONDS] [--seed N]\n", argv[0]);
        return 2;
    }
    scenario = argv[1];
    for (index = 2; index < argc; ++index) {
        if (!strcmp(argv[index], "--socket") && index + 1 < argc)
            socket_path = argv[++index];
        else if (!strcmp(argv[index], "--duration") && index + 1 < argc)
            duration = strtod(argv[++index], NULL);
        else if (!strcmp(argv[index], "--seed") && index + 1 < argc)
            seed = (uint32_t)strtoul(argv[++index], NULL, 10);
        else {
            fprintf(stderr, "invalid argument\n");
            return 2;
        }
    }
    if (duration <= 0.0)
        return 2;
    deadline = monotonic_ns() + (uint64_t)(duration * 1000000000.0);
    while (monotonic_ns() < deadline) {
        struct c3m_request request;
        uint32_t random_value = random_u32(&seed);
        if (!strcmp(scenario, "steady")) {
            uint16_t operation = (request_id % 4 == 0) ? C3M_OP_DELETE
                : (request_id % 4 == 1 ? C3M_OP_PUT : C3M_OP_GET);
            fill_request(&request, request_id, operation, random_value, operation == C3M_OP_PUT ? 64 : 0, 'S');
            (void)invoke(socket_path, &request);
            sleep_us(10000);
        } else if (!strcmp(scenario, "bursty")) {
            unsigned int burst;
            for (burst = 0; burst < 8 && monotonic_ns() < deadline; ++burst) {
                fill_request(&request, request_id++, C3M_OP_PUT, random_value + burst, 96, 'B');
                (void)invoke(socket_path, &request);
            }
            sleep_us(80000);
            continue;
        } else if (!strcmp(scenario, "large_value")) {
            fill_request(&request, request_id, C3M_OP_PUT, random_value, 3072, 'L');
            (void)invoke(socket_path, &request);
            sleep_us(20000);
        } else if (!strcmp(scenario, "flood")) {
            fill_request(&request, request_id, C3M_OP_PUT, random_value, 32, 'F');
            (void)invoke(socket_path, &request);
        } else if (!strcmp(scenario, "malformed")) {
            (void)malformed(socket_path);
            sleep_us(2000);
        } else if (!strcmp(scenario, "error_storm")) {
            fill_request(&request, request_id, C3M_OP_GET, 31, 0, 0);
            memcpy(request.key, "never-created", 13);
            request.key_len = 13;
            (void)invoke(socket_path, &request);
            sleep_us(2000);
        } else if (!strcmp(scenario, "replay")) {
            fill_request(&request, request_id, C3M_OP_PUT, 0, 128, 'R');
            memcpy(request.key, "replayed-key", 12);
            request.key_len = 12;
            (void)invoke(socket_path, &request);
            sleep_us(2000);
        } else {
            fprintf(stderr, "unknown scenario: %s\n", scenario);
            return 2;
        }
        ++request_id;
    }
    printf("sent %llu requests\n", (unsigned long long)(request_id - 1));
    return 0;
}
