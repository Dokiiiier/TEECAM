#include "cote3_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static uint64_t host_to_network_u64(uint64_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(value >> 32))) |
           ((uint64_t)htonl((uint32_t)value) << 32);
#else
    return value;
#endif
}

static uint64_t network_to_host_u64(uint64_t value)
{
    return host_to_network_u64(value);
}

static int read_full(int fd, void *buffer, size_t length)
{
    uint8_t *cursor = buffer;
    while (length) {
        ssize_t count = read(fd, cursor, length);
        if (count == 0)
            return -1;
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

static void put_u16(uint8_t *buffer, uint16_t value)
{
    value = htons(value);
    memcpy(buffer, &value, sizeof(value));
}

static void put_u32(uint8_t *buffer, uint32_t value)
{
    value = htonl(value);
    memcpy(buffer, &value, sizeof(value));
}

static void put_u64(uint8_t *buffer, uint64_t value)
{
    value = host_to_network_u64(value);
    memcpy(buffer, &value, sizeof(value));
}

static uint16_t get_u16(const uint8_t *buffer)
{
    uint16_t value;
    memcpy(&value, buffer, sizeof(value));
    return ntohs(value);
}

static uint32_t get_u32(const uint8_t *buffer)
{
    uint32_t value;
    memcpy(&value, buffer, sizeof(value));
    return ntohl(value);
}

static uint64_t get_u64(const uint8_t *buffer)
{
    uint64_t value;
    memcpy(&value, buffer, sizeof(value));
    return network_to_host_u64(value);
}

int c3m_recv_request(int fd, struct c3m_request *request)
{
    uint8_t header[C3M_REQUEST_HEADER_SIZE];
    uint32_t magic;
    uint16_t version;

    memset(request, 0, sizeof(*request));
    if (read_full(fd, header, sizeof(header)))
        return -1;
    magic = get_u32(header);
    version = get_u16(header + 4);
    request->operation = get_u16(header + 6);
    request->request_id = get_u64(header + 8);
    request->key_len = get_u32(header + 16);
    request->value_len = get_u32(header + 20);
    if (magic != C3M_MAGIC || version != C3M_VERSION)
        return -1;
    if (request->operation < C3M_OP_PUT || request->operation > C3M_OP_DELETE)
        return -1;
    if (!request->key_len || request->key_len > C3M_MAX_KEY_BYTES ||
        request->value_len > C3M_MAX_VALUE_BYTES)
        return -1;
    if (request->operation != C3M_OP_PUT && request->value_len)
        return -1;
    if (read_full(fd, request->key, request->key_len))
        return -1;
    if (request->value_len && read_full(fd, request->value, request->value_len))
        return -1;
    return 0;
}

int c3m_send_request(int fd, const struct c3m_request *request)
{
    uint8_t header[C3M_REQUEST_HEADER_SIZE];
    if (!request->key_len || request->key_len > C3M_MAX_KEY_BYTES ||
        request->value_len > C3M_MAX_VALUE_BYTES)
        return -1;
    put_u32(header, C3M_MAGIC);
    put_u16(header + 4, C3M_VERSION);
    put_u16(header + 6, request->operation);
    put_u64(header + 8, request->request_id);
    put_u32(header + 16, request->key_len);
    put_u32(header + 20, request->value_len);
    if (write_full(fd, header, sizeof(header)) ||
        write_full(fd, request->key, request->key_len))
        return -1;
    return request->value_len ? write_full(fd, request->value, request->value_len) : 0;
}

int c3m_recv_response(int fd, struct c3m_response *response)
{
    uint8_t header[C3M_RESPONSE_HEADER_SIZE];
    memset(response, 0, sizeof(*response));
    if (read_full(fd, header, sizeof(header)))
        return -1;
    if (get_u32(header) != C3M_MAGIC || get_u16(header + 4) != C3M_VERSION)
        return -1;
    response->status = get_u16(header + 6);
    response->request_id = get_u64(header + 8);
    response->value_len = get_u32(header + 16);
    if (response->status > C3M_STATUS_PROTOCOL_ERROR ||
        response->value_len > C3M_MAX_VALUE_BYTES)
        return -1;
    return response->value_len ? read_full(fd, response->value, response->value_len) : 0;
}

int c3m_send_response(int fd, const struct c3m_response *response)
{
    uint8_t header[C3M_RESPONSE_HEADER_SIZE];
    if (response->value_len > C3M_MAX_VALUE_BYTES)
        return -1;
    put_u32(header, C3M_MAGIC);
    put_u16(header + 4, C3M_VERSION);
    put_u16(header + 6, response->status);
    put_u64(header + 8, response->request_id);
    put_u32(header + 16, response->value_len);
    if (write_full(fd, header, sizeof(header)))
        return -1;
    return response->value_len ? write_full(fd, response->value, response->value_len) : 0;
}

const char *c3m_operation_name(uint16_t operation)
{
    switch (operation) {
    case C3M_OP_PUT: return "PUT";
    case C3M_OP_GET: return "GET";
    case C3M_OP_DELETE: return "DELETE";
    default: return "REJECT";
    }
}

const char *c3m_status_name(uint16_t status)
{
    switch (status) {
    case C3M_STATUS_OK: return "OK";
    case C3M_STATUS_INVALID: return "INVALID";
    case C3M_STATUS_NOT_FOUND: return "NOT_FOUND";
    case C3M_STATUS_BACKEND_ERROR: return "BACKEND_ERROR";
    case C3M_STATUS_TOO_LARGE: return "TOO_LARGE";
    default: return "PROTOCOL_ERROR";
    }
}

