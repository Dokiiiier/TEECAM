#include "backend.h"

#include <stdlib.h>
#include <string.h>

struct object {
    struct object *next;
    size_t key_len;
    size_t value_len;
    uint8_t *key;
    uint8_t *value;
};

static struct object *find_object(struct object *head, const uint8_t *key, size_t key_len)
{
    for (; head; head = head->next)
        if (head->key_len == key_len && !memcmp(head->key, key, key_len))
            return head;
    return NULL;
}

static int mock_put(struct c3m_backend *backend, const uint8_t *key, size_t key_len,
                    const uint8_t *value, size_t value_len)
{
    struct object **head = backend->private_data;
    struct object *object = find_object(*head, key, key_len);
    uint8_t *replacement = malloc(value_len ? value_len : 1);
    if (!replacement)
        return C3M_BACKEND_FAILURE;
    memcpy(replacement, value, value_len);
    if (!object) {
        object = calloc(1, sizeof(*object));
        if (!object) {
            free(replacement);
            return C3M_BACKEND_FAILURE;
        }
        object->key = malloc(key_len);
        if (!object->key) {
            free(replacement);
            free(object);
            return C3M_BACKEND_FAILURE;
        }
        memcpy(object->key, key, key_len);
        object->key_len = key_len;
        object->next = *head;
        *head = object;
    } else {
        free(object->value);
    }
    object->value = replacement;
    object->value_len = value_len;
    return C3M_BACKEND_OK;
}

static int mock_get(struct c3m_backend *backend, const uint8_t *key, size_t key_len,
                    uint8_t *value, size_t *value_len)
{
    struct object *object = find_object(*(struct object **)backend->private_data, key, key_len);
    if (!object)
        return C3M_BACKEND_NOT_FOUND;
    if (*value_len < object->value_len)
        return C3M_BACKEND_FAILURE;
    memcpy(value, object->value, object->value_len);
    *value_len = object->value_len;
    return C3M_BACKEND_OK;
}

static int mock_delete(struct c3m_backend *backend, const uint8_t *key, size_t key_len)
{
    struct object **cursor = backend->private_data;
    while (*cursor) {
        struct object *object = *cursor;
        if (object->key_len == key_len && !memcmp(object->key, key, key_len)) {
            *cursor = object->next;
            free(object->key);
            free(object->value);
            free(object);
            return C3M_BACKEND_OK;
        }
        cursor = &object->next;
    }
    return C3M_BACKEND_NOT_FOUND;
}

static void mock_destroy(struct c3m_backend *backend)
{
    struct object *object = *(struct object **)backend->private_data;
    while (object) {
        struct object *next = object->next;
        free(object->key);
        free(object->value);
        free(object);
        object = next;
    }
    free(backend->private_data);
    free(backend);
}

struct c3m_backend *c3m_mock_backend_create(void)
{
    static const struct c3m_backend_ops operations = {
        .put = mock_put,
        .get = mock_get,
        .delete_object = mock_delete,
        .destroy = mock_destroy,
    };
    struct c3m_backend *backend = calloc(1, sizeof(*backend));
    if (!backend)
        return NULL;
    backend->private_data = calloc(1, sizeof(struct object *));
    if (!backend->private_data) {
        free(backend);
        return NULL;
    }
    backend->ops = &operations;
    return backend;
}

