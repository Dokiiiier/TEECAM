#ifndef COTE3_BACKEND_H
#define COTE3_BACKEND_H

#include <stddef.h>
#include <stdint.h>

struct c3m_backend;

struct c3m_backend_ops {
    int (*put)(struct c3m_backend *, const uint8_t *, size_t, const uint8_t *, size_t);
    int (*get)(struct c3m_backend *, const uint8_t *, size_t, uint8_t *, size_t *);
    int (*delete_object)(struct c3m_backend *, const uint8_t *, size_t);
    void (*destroy)(struct c3m_backend *);
};

struct c3m_backend {
    const struct c3m_backend_ops *ops;
    void *private_data;
};

enum c3m_backend_result {
    C3M_BACKEND_OK = 0,
    C3M_BACKEND_NOT_FOUND = 1,
    C3M_BACKEND_FAILURE = 2,
};

struct c3m_backend *c3m_mock_backend_create(void);
struct c3m_backend *c3m_optee_backend_create(void);

#endif

