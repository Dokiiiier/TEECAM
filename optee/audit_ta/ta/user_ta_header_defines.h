#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <cote3_audit_ta.h>

#define TA_UUID COTE3_AUDIT_TA_UUID
#define TA_FLAGS (TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE (4 * 1024)
#define TA_DATA_SIZE (32 * 1024)
#define TA_DESCRIPTION "COTE3-Mon audit receipt chain"
#define TA_VERSION "0.1.0"

#endif

