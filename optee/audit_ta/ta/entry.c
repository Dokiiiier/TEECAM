#include <cote3_audit_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define STATE_MAGIC UINT32_C(0x43334131)
#define STATE_VERSION UINT32_C(1)

static const uint8_t object_id[] = "cote3mon-audit-state-v1";
static const uint8_t domain[] = "C3MAUDIT1";

struct audit_state {
    uint32_t magic;
    uint32_t version;
    uint64_t sequence;
    uint32_t model_registered;
    uint8_t key[COTE3_AUDIT_HASH_SIZE];
    uint8_t model_hash[COTE3_AUDIT_HASH_SIZE];
    uint8_t head[COTE3_AUDIT_HASH_SIZE];
};

static void encode_u64_be(uint8_t output[8], uint64_t value)
{
    unsigned int index;
    for (index = 0; index < 8; ++index)
        output[7 - index] = (uint8_t)(value >> (index * 8));
}

static TEE_Result save_state(const struct audit_state *state)
{
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    TEE_Result result = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE, object_id, sizeof(object_id) - 1,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
            TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE,
        TEE_HANDLE_NULL, state, sizeof(*state), &object);
    if (object != TEE_HANDLE_NULL)
        TEE_CloseObject(object);
    return result;
}

static TEE_Result load_state(struct audit_state *state)
{
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    size_t count = 0;
    TEE_Result result = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE, object_id, sizeof(object_id) - 1,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &object);
    if (result == TEE_ERROR_ITEM_NOT_FOUND) {
        TEE_MemFill(state, 0, sizeof(*state));
        state->magic = STATE_MAGIC;
        state->version = STATE_VERSION;
        TEE_GenerateRandom(state->key, sizeof(state->key));
        return save_state(state);
    }
    if (result != TEE_SUCCESS)
        return result;
    result = TEE_ReadObjectData(object, state, sizeof(*state), &count);
    TEE_CloseObject(object);
    if (result != TEE_SUCCESS)
        return result;
    if (count != sizeof(*state) || state->magic != STATE_MAGIC ||
        state->version != STATE_VERSION)
        return TEE_ERROR_CORRUPT_OBJECT;
    return TEE_SUCCESS;
}

static TEE_Result compute_hmac(const struct audit_state *state, uint64_t sequence,
                               const uint8_t previous[32], const uint8_t alert[32],
                               const uint8_t model[32], uint8_t output[32])
{
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    TEE_ObjectHandle key = TEE_HANDLE_NULL;
    TEE_Attribute attribute;
    uint8_t message[sizeof(domain) - 1 + 8 + 32 + 32 + 32];
    uint8_t sequence_bytes[8];
    size_t output_size = 32;
    size_t offset = 0;
    TEE_Result result;

    encode_u64_be(sequence_bytes, sequence);
    TEE_MemMove(message + offset, domain, sizeof(domain) - 1);
    offset += sizeof(domain) - 1;
    TEE_MemMove(message + offset, sequence_bytes, sizeof(sequence_bytes));
    offset += sizeof(sequence_bytes);
    TEE_MemMove(message + offset, previous, 32);
    offset += 32;
    TEE_MemMove(message + offset, alert, 32);
    offset += 32;
    TEE_MemMove(message + offset, model, 32);

    result = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, 256, &key);
    if (result != TEE_SUCCESS)
        goto out;
    TEE_InitRefAttribute(&attribute, TEE_ATTR_SECRET_VALUE, state->key, sizeof(state->key));
    result = TEE_PopulateTransientObject(key, &attribute, 1);
    if (result != TEE_SUCCESS)
        goto out;
    result = TEE_AllocateOperation(&operation, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, 256);
    if (result != TEE_SUCCESS)
        goto out;
    result = TEE_SetOperationKey(operation, key);
    if (result != TEE_SUCCESS)
        goto out;
    TEE_MACInit(operation, NULL, 0);
    result = TEE_MACComputeFinal(operation, message, sizeof(message), output, &output_size);
    if (result == TEE_SUCCESS && output_size != 32)
        result = TEE_ERROR_GENERIC;
out:
    if (operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(operation);
    if (key != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(key);
    return result;
}

static TEE_Result register_model(uint32_t parameter_types, TEE_Param parameters[4])
{
    struct audit_state state;
    uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    TEE_Result result;
    if (parameter_types != expected || parameters[0].memref.size != 32)
        return TEE_ERROR_BAD_PARAMETERS;
    result = load_state(&state);
    if (result != TEE_SUCCESS)
        return result;
    if (state.sequence && TEE_MemCompare(state.model_hash, parameters[0].memref.buffer, 32))
        return TEE_ERROR_ACCESS_CONFLICT;
    TEE_MemMove(state.model_hash, parameters[0].memref.buffer, 32);
    state.model_registered = 1;
    return save_state(&state);
}

static TEE_Result append_alert(uint32_t parameter_types, TEE_Param parameters[4])
{
    struct audit_state state;
    struct cote3_audit_receipt receipt;
    uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    TEE_Result result;
    if (parameter_types != expected || parameters[0].memref.size != 32)
        return TEE_ERROR_BAD_PARAMETERS;
    if (parameters[1].memref.size < sizeof(receipt)) {
        parameters[1].memref.size = sizeof(receipt);
        return TEE_ERROR_SHORT_BUFFER;
    }
    result = load_state(&state);
    if (result != TEE_SUCCESS)
        return result;
    if (!state.model_registered)
        return TEE_ERROR_BAD_STATE;
    TEE_MemFill(&receipt, 0, sizeof(receipt));
    receipt.sequence = state.sequence + 1;
    TEE_MemMove(receipt.previous_head, state.head, 32);
    TEE_MemMove(receipt.alert_hash, parameters[0].memref.buffer, 32);
    TEE_MemMove(receipt.model_hash, state.model_hash, 32);
    result = compute_hmac(&state, receipt.sequence, receipt.previous_head,
                          receipt.alert_hash, receipt.model_hash, receipt.head);
    if (result != TEE_SUCCESS)
        return result;
    state.sequence = receipt.sequence;
    TEE_MemMove(state.head, receipt.head, 32);
    result = save_state(&state);
    if (result != TEE_SUCCESS)
        return result;
    TEE_MemMove(parameters[1].memref.buffer, &receipt, sizeof(receipt));
    parameters[1].memref.size = sizeof(receipt);
    return TEE_SUCCESS;
}

static TEE_Result get_head(uint32_t parameter_types, TEE_Param parameters[4])
{
    struct audit_state state;
    struct cote3_audit_head head;
    uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    TEE_Result result;
    if (parameter_types != expected)
        return TEE_ERROR_BAD_PARAMETERS;
    if (parameters[0].memref.size < sizeof(head)) {
        parameters[0].memref.size = sizeof(head);
        return TEE_ERROR_SHORT_BUFFER;
    }
    result = load_state(&state);
    if (result != TEE_SUCCESS)
        return result;
    head.sequence = state.sequence;
    TEE_MemMove(head.model_hash, state.model_hash, 32);
    TEE_MemMove(head.head, state.head, 32);
    TEE_MemMove(parameters[0].memref.buffer, &head, sizeof(head));
    parameters[0].memref.size = sizeof(head);
    return TEE_SUCCESS;
}

static TEE_Result verify_receipt(uint32_t parameter_types, TEE_Param parameters[4])
{
    struct audit_state state;
    struct cote3_audit_receipt *receipt;
    uint8_t expected_head[32];
    uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    TEE_Result result;
    if (parameter_types != expected || parameters[0].memref.size != sizeof(*receipt))
        return TEE_ERROR_BAD_PARAMETERS;
    receipt = parameters[0].memref.buffer;
    result = load_state(&state);
    if (result != TEE_SUCCESS)
        return result;
    result = compute_hmac(&state, receipt->sequence, receipt->previous_head,
                          receipt->alert_hash, receipt->model_hash, expected_head);
    if (result != TEE_SUCCESS)
        return result;
    return TEE_MemCompare(expected_head, receipt->head, 32) == 0
        ? TEE_SUCCESS : TEE_ERROR_MAC_INVALID;
}

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parameter_types, TEE_Param parameters[4],
                                    void **session_context)
{
    (void)parameters;
    (void)session_context;
    return parameter_types == TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)
        ? TEE_SUCCESS : TEE_ERROR_BAD_PARAMETERS;
}

void TA_CloseSessionEntryPoint(void *session_context)
{
    (void)session_context;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t command,
                                      uint32_t parameter_types, TEE_Param parameters[4])
{
    (void)session_context;
    switch (command) {
    case COTE3_AUDIT_CMD_REGISTER_MODEL:
        return register_model(parameter_types, parameters);
    case COTE3_AUDIT_CMD_APPEND_ALERT:
        return append_alert(parameter_types, parameters);
    case COTE3_AUDIT_CMD_GET_HEAD:
        return get_head(parameter_types, parameters);
    case COTE3_AUDIT_CMD_VERIFY:
        return verify_receipt(parameter_types, parameters);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
