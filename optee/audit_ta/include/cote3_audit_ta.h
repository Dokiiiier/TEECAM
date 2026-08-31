#ifndef COTE3_AUDIT_TA_H
#define COTE3_AUDIT_TA_H

#include <stdint.h>

#define COTE3_AUDIT_TA_UUID \
    { 0xd4f052d5, 0x8fd3, 0x4cb8, \
      { 0xa4, 0x97, 0x3f, 0x6a, 0x0c, 0xb8, 0x87, 0x10 } }

#define COTE3_AUDIT_CMD_REGISTER_MODEL 0
#define COTE3_AUDIT_CMD_APPEND_ALERT 1
#define COTE3_AUDIT_CMD_GET_HEAD 2
#define COTE3_AUDIT_CMD_VERIFY 3

#define COTE3_AUDIT_HASH_SIZE 32

struct cote3_audit_receipt {
    uint64_t sequence;
    uint8_t previous_head[COTE3_AUDIT_HASH_SIZE];
    uint8_t alert_hash[COTE3_AUDIT_HASH_SIZE];
    uint8_t model_hash[COTE3_AUDIT_HASH_SIZE];
    uint8_t head[COTE3_AUDIT_HASH_SIZE];
};

struct cote3_audit_head {
    uint64_t sequence;
    uint8_t model_hash[COTE3_AUDIT_HASH_SIZE];
    uint8_t head[COTE3_AUDIT_HASH_SIZE];
};

#endif

