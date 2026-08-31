#include "backend.h"
#include "secure_storage_ta.h"

#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

struct optee_context {
    TEEC_Context context;
    TEEC_Session session;
};

static int invoke(struct c3m_backend *backend, uint32_t command, const uint8_t *key,
                  size_t key_len, uint8_t *value, size_t *value_len, int input)
{
    struct optee_context *state = backend->private_data;
    TEEC_Operation operation = { 0 };
    uint32_t origin = 0;
    TEEC_Result result;
    operation.paramTypes = input
        ? TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE)
        : TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = (void *)key;
    operation.params[0].tmpref.size = key_len;
    operation.params[1].tmpref.buffer = value;
    operation.params[1].tmpref.size = *value_len;
    result = TEEC_InvokeCommand(&state->session, command, &operation, &origin);
    if (result == TEEC_ERROR_ITEM_NOT_FOUND)
        return C3M_BACKEND_NOT_FOUND;
    if (result != TEEC_SUCCESS)
        return C3M_BACKEND_FAILURE;
    *value_len = operation.params[1].tmpref.size;
    return C3M_BACKEND_OK;
}

static int optee_put(struct c3m_backend *backend, const uint8_t *key, size_t key_len,
                     const uint8_t *value, size_t value_len)
{
    return invoke(backend, TA_SECURE_STORAGE_CMD_WRITE_RAW, key, key_len,
                  (uint8_t *)value, &value_len, 1);
}

static int optee_get(struct c3m_backend *backend, const uint8_t *key, size_t key_len,
                     uint8_t *value, size_t *value_len)
{
    return invoke(backend, TA_SECURE_STORAGE_CMD_READ_RAW, key, key_len,
                  value, value_len, 0);
}

static int optee_delete(struct c3m_backend *backend, const uint8_t *key, size_t key_len)
{
    struct optee_context *state = backend->private_data;
    TEEC_Operation operation = { 0 };
    uint32_t origin = 0;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                                            TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = (void *)key;
    operation.params[0].tmpref.size = key_len;
    TEEC_Result result = TEEC_InvokeCommand(&state->session,
        TA_SECURE_STORAGE_CMD_DELETE, &operation, &origin);
    if (result == TEEC_ERROR_ITEM_NOT_FOUND)
        return C3M_BACKEND_NOT_FOUND;
    return result == TEEC_SUCCESS ? C3M_BACKEND_OK : C3M_BACKEND_FAILURE;
}

static void optee_destroy(struct c3m_backend *backend)
{
    struct optee_context *state = backend->private_data;
    TEEC_CloseSession(&state->session);
    TEEC_FinalizeContext(&state->context);
    free(state);
    free(backend);
}

struct c3m_backend *c3m_optee_backend_create(void)
{
    static const struct c3m_backend_ops operations = {
        .put = optee_put,
        .get = optee_get,
        .delete_object = optee_delete,
        .destroy = optee_destroy,
    };
    const TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
    struct c3m_backend *backend = calloc(1, sizeof(*backend));
    struct optee_context *state = calloc(1, sizeof(*state));
    uint32_t origin = 0;
    if (!backend || !state)
        goto error;
    if (TEEC_InitializeContext(NULL, &state->context) != TEEC_SUCCESS)
        goto error;
    if (TEEC_OpenSession(&state->context, &state->session, &uuid, TEEC_LOGIN_PUBLIC,
                         NULL, NULL, &origin) != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&state->context);
        goto error;
    }
    backend->ops = &operations;
    backend->private_data = state;
    return backend;
error:
    free(state);
    free(backend);
    return NULL;
}

