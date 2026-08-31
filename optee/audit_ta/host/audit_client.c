#include <cote3_audit_ta.h>
#include <tee_client_api.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode_hash(const char *text, uint8_t output[32])
{
    unsigned int index;
    if (strlen(text) != 64)
        return -1;
    for (index = 0; index < 32; ++index) {
        int high = hex_value(text[index * 2]);
        int low = hex_value(text[index * 2 + 1]);
        if (high < 0 || low < 0)
            return -1;
        output[index] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static void print_hash(const uint8_t value[32])
{
    unsigned int index;
    for (index = 0; index < 32; ++index)
        printf("%02x", value[index]);
}

static int decode_sequence(const char *text, uint64_t *output)
{
    char *end = NULL;
    unsigned long long value;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno || !*text || !end || *end)
        return -1;
    *output = (uint64_t)value;
    return 0;
}

static void print_usage(const char *program)
{
    fprintf(stderr,
        "usage: %s register HASH | append HASH | head | "
        "verify SEQUENCE PREVIOUS_HEAD ALERT_HASH MODEL_HASH HEAD\n",
        program);
}

int main(int argc, char **argv)
{
    const TEEC_UUID uuid = COTE3_AUDIT_TA_UUID;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation = { 0 };
    TEEC_Result result;
    uint32_t origin = 0;
    uint8_t digest[32];
    if (argc < 2) {
        print_usage(argv[0]);
        return 2;
    }
    result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS)
        goto error_context;
    result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC,
                              NULL, NULL, &origin);
    if (result != TEEC_SUCCESS)
        goto error_session;
    if (!strcmp(argv[1], "register") && argc == 3) {
        if (decode_hash(argv[2], digest))
            goto usage;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                                                TEEC_NONE, TEEC_NONE);
        operation.params[0].tmpref.buffer = digest;
        operation.params[0].tmpref.size = sizeof(digest);
        result = TEEC_InvokeCommand(&session, COTE3_AUDIT_CMD_REGISTER_MODEL,
                                    &operation, &origin);
    } else if (!strcmp(argv[1], "append") && argc == 3) {
        struct cote3_audit_receipt receipt;
        if (decode_hash(argv[2], digest))
            goto usage;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                                TEEC_NONE, TEEC_NONE);
        operation.params[0].tmpref.buffer = digest;
        operation.params[0].tmpref.size = sizeof(digest);
        operation.params[1].tmpref.buffer = &receipt;
        operation.params[1].tmpref.size = sizeof(receipt);
        result = TEEC_InvokeCommand(&session, COTE3_AUDIT_CMD_APPEND_ALERT,
                                    &operation, &origin);
        if (result == TEEC_SUCCESS) {
            printf("{\"sequence\":%llu,\"previous_head\":\"", (unsigned long long)receipt.sequence);
            print_hash(receipt.previous_head);
            printf("\",\"alert_hash\":\""); print_hash(receipt.alert_hash);
            printf("\",\"model_hash\":\""); print_hash(receipt.model_hash);
            printf("\",\"head\":\""); print_hash(receipt.head); printf("\"}\n");
        }
    } else if (!strcmp(argv[1], "head") && argc == 2) {
        struct cote3_audit_head head;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
                                                TEEC_NONE, TEEC_NONE);
        operation.params[0].tmpref.buffer = &head;
        operation.params[0].tmpref.size = sizeof(head);
        result = TEEC_InvokeCommand(&session, COTE3_AUDIT_CMD_GET_HEAD,
                                    &operation, &origin);
        if (result == TEEC_SUCCESS) {
            printf("{\"sequence\":%llu,\"model_hash\":\"", (unsigned long long)head.sequence);
            print_hash(head.model_hash); printf("\",\"head\":\"");
            print_hash(head.head); printf("\"}\n");
        }
    } else if (!strcmp(argv[1], "verify") && argc == 7) {
        struct cote3_audit_receipt receipt = { 0 };
        if (decode_sequence(argv[2], &receipt.sequence) ||
            decode_hash(argv[3], receipt.previous_head) ||
            decode_hash(argv[4], receipt.alert_hash) ||
            decode_hash(argv[5], receipt.model_hash) ||
            decode_hash(argv[6], receipt.head))
            goto usage;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                                                TEEC_NONE, TEEC_NONE);
        operation.params[0].tmpref.buffer = &receipt;
        operation.params[0].tmpref.size = sizeof(receipt);
        result = TEEC_InvokeCommand(&session, COTE3_AUDIT_CMD_VERIFY,
                                    &operation, &origin);
        if (result == TEEC_SUCCESS)
            puts("VALID");
    } else {
usage:
        print_usage(argv[0]);
        TEEC_CloseSession(&session);
        TEEC_FinalizeContext(&context);
        return 2;
    }
    if (result != TEEC_SUCCESS) {
        fprintf(stderr, "audit TA command failed: 0x%x origin 0x%x\n", result, origin);
        TEEC_CloseSession(&session);
        TEEC_FinalizeContext(&context);
        return 1;
    }
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
error_session:
    TEEC_FinalizeContext(&context);
error_context:
    fprintf(stderr, "failed to open audit TA: 0x%x origin 0x%x\n", result, origin);
    return 1;
}
