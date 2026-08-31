/* UUID and command interface from OP-TEE optee_examples/secure_storage. */
#ifndef SECURE_STORAGE_TA_H
#define SECURE_STORAGE_TA_H

#define TA_SECURE_STORAGE_UUID \
    { 0xf4e750bb, 0x1437, 0x4fbf, \
      { 0x87, 0x85, 0x8d, 0x35, 0x80, 0xc3, 0x49, 0x94 } }

#define TA_SECURE_STORAGE_CMD_READ_RAW 0
#define TA_SECURE_STORAGE_CMD_WRITE_RAW 1
#define TA_SECURE_STORAGE_CMD_DELETE 2

#endif

