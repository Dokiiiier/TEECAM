#ifndef COTE3_PROTOCOL_H
#define COTE3_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define C3M_MAGIC UINT32_C(0x43334d31)
#define C3M_VERSION UINT16_C(1)
#define C3M_REQUEST_HEADER_SIZE 24u
#define C3M_RESPONSE_HEADER_SIZE 20u
#define C3M_MAX_KEY_BYTES 64u
#define C3M_MAX_VALUE_BYTES 4096u

enum c3m_operation {
    C3M_OP_PUT = 1,
    C3M_OP_GET = 2,
    C3M_OP_DELETE = 3,
};

enum c3m_status {
    C3M_STATUS_OK = 0,
    C3M_STATUS_INVALID = 1,
    C3M_STATUS_NOT_FOUND = 2,
    C3M_STATUS_BACKEND_ERROR = 3,
    C3M_STATUS_TOO_LARGE = 4,
    C3M_STATUS_PROTOCOL_ERROR = 5,
};

struct c3m_request {
    uint64_t request_id;
    uint16_t operation;
    uint32_t key_len;
    uint32_t value_len;
    uint8_t key[C3M_MAX_KEY_BYTES];
    uint8_t value[C3M_MAX_VALUE_BYTES];
};

struct c3m_response {
    uint64_t request_id;
    uint16_t status;
    uint32_t value_len;
    uint8_t value[C3M_MAX_VALUE_BYTES];
};

int c3m_recv_request(int fd, struct c3m_request *request);
int c3m_send_request(int fd, const struct c3m_request *request);
int c3m_recv_response(int fd, struct c3m_response *response);
int c3m_send_response(int fd, const struct c3m_response *response);
const char *c3m_operation_name(uint16_t operation);
const char *c3m_status_name(uint16_t status);

#endif

