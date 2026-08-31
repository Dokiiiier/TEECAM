#include "backend.h"
#include "cote3_protocol.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static uint64_t fingerprint_secret;

struct request_metrics {
    double *latencies_us;
    size_t count;
    size_t capacity;
    uint64_t errors;
    uint64_t first_start_ns;
    uint64_t last_end_ns;
    bool allocation_failed;
};

static void stop_handler(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static uint64_t realtime_ns(void)
{
    struct timespec value;
    clock_gettime(CLOCK_REALTIME, &value);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static uint64_t monotonic_ns(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static uint64_t fingerprint_update(uint64_t hash, const void *data, size_t length)
{
    const uint8_t *bytes = data;
    size_t index;
    for (index = 0; index < length; ++index) {
        hash ^= bytes[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t keyed_fingerprint(const struct c3m_request *request, bool include_value)
{
    uint64_t hash = UINT64_C(1469598103934665603) ^ fingerprint_secret;
    hash = fingerprint_update(hash, &request->key_len, sizeof(request->key_len));
    hash = fingerprint_update(hash, request->key, request->key_len);
    if (include_value) {
        hash = fingerprint_update(hash, &request->operation, sizeof(request->operation));
        hash = fingerprint_update(hash, &request->value_len, sizeof(request->value_len));
        hash = fingerprint_update(hash, request->value, request->value_len);
    }
    hash ^= fingerprint_secret >> 17;
    hash *= UINT64_C(1099511628211);
    return hash;
}

static void initialise_fingerprint_secret(void)
{
    struct timespec realtime = { 0 };
    struct timespec monotonic = { 0 };
    clock_gettime(CLOCK_REALTIME, &realtime);
    clock_gettime(CLOCK_MONOTONIC, &monotonic);
    fingerprint_secret = (uint64_t)realtime.tv_sec ^
        ((uint64_t)realtime.tv_nsec << 32) ^ (uint64_t)monotonic.tv_nsec ^
        ((uint64_t)(unsigned int)getpid() << 16);
    if (!fingerprint_secret)
        fingerprint_secret = UINT64_C(0x9e3779b97f4a7c15);
}

static int compare_double(const void *left, const void *right)
{
    double a = *(const double *)left;
    double b = *(const double *)right;
    return (a > b) - (a < b);
}

static double percentile(double *values, size_t count, double probability)
{
    double position, weight;
    size_t lower, upper;
    if (!count)
        return 0.0;
    position = (double)(count - 1) * probability;
    lower = (size_t)position;
    upper = lower + (position > (double)lower ? 1u : 0u);
    weight = position - (double)lower;
    return values[lower] * (1.0 - weight) + values[upper] * weight;
}

static void record_metric(struct request_metrics *metrics, uint64_t start_ns,
                          uint64_t end_ns, uint16_t status)
{
    if (!metrics->count)
        metrics->first_start_ns = start_ns;
    metrics->last_end_ns = end_ns;
    if (status != C3M_STATUS_OK)
        metrics->errors++;
    if (metrics->count == metrics->capacity) {
        size_t capacity = metrics->capacity ? metrics->capacity * 2u : 1024u;
        double *resized = realloc(metrics->latencies_us, capacity * sizeof(*resized));
        if (!resized) {
            metrics->allocation_failed = true;
            return;
        }
        metrics->latencies_us = resized;
        metrics->capacity = capacity;
    }
    metrics->latencies_us[metrics->count++] = (double)(end_ns - start_ns) / 1000.0;
}

static int write_summary(const char *path, struct request_metrics *metrics)
{
    FILE *output;
    double elapsed_seconds = 0.0;
    double throughput = 0.0;
    if (!path)
        return 0;
    if (metrics->allocation_failed) {
        errno = ENOMEM;
        return -1;
    }
    if (metrics->count > 1)
        elapsed_seconds = (double)(metrics->last_end_ns - metrics->first_start_ns) / 1e9;
    if (elapsed_seconds > 0.0)
        throughput = (double)metrics->count / elapsed_seconds;
    qsort(metrics->latencies_us, metrics->count, sizeof(*metrics->latencies_us), compare_double);
    output = fopen(path, "w");
    if (!output)
        return -1;
    fprintf(output,
        "{\"schema\":\"cote3-mon-gateway-summary-v1\",\"requests\":%llu,"
        "\"errors\":%llu,\"elapsed_seconds\":%.9f,\"throughput_rps\":%.9f,"
        "\"latency_p50_us\":%.6f,\"latency_p95_us\":%.6f,"
        "\"latency_p99_us\":%.6f}\n",
        (unsigned long long)metrics->count,
        (unsigned long long)metrics->errors,
        elapsed_seconds, throughput,
        percentile(metrics->latencies_us, metrics->count, 0.50),
        percentile(metrics->latencies_us, metrics->count, 0.95),
        percentile(metrics->latencies_us, metrics->count, 0.99));
    return fclose(output);
}

static void safe_identifier(char *target, size_t target_size, const char *source)
{
    size_t index;
    if (!source || !*source)
        source = "unknown";
    for (index = 0; index + 1 < target_size && source[index]; ++index) {
        char value = source[index];
        bool safe = (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                    (value >= '0' && value <= '9') || value == '-' || value == '_' || value == '.';
        target[index] = safe ? value : '_';
    }
    target[index] = '\0';
}

static uint16_t dispatch(struct c3m_backend *backend, const struct c3m_request *request,
                         struct c3m_response *response)
{
    int result;
    size_t output_size = sizeof(response->value);
    switch (request->operation) {
    case C3M_OP_PUT:
        result = backend->ops->put(backend, request->key, request->key_len,
                                   request->value, request->value_len);
        break;
    case C3M_OP_GET:
        result = backend->ops->get(backend, request->key, request->key_len,
                                   response->value, &output_size);
        if (result == C3M_BACKEND_OK)
            response->value_len = (uint32_t)output_size;
        break;
    case C3M_OP_DELETE:
        result = backend->ops->delete_object(backend, request->key, request->key_len);
        break;
    default:
        return C3M_STATUS_INVALID;
    }
    if (result == C3M_BACKEND_OK)
        return C3M_STATUS_OK;
    if (result == C3M_BACKEND_NOT_FOUND)
        return C3M_STATUS_NOT_FOUND;
    return C3M_STATUS_BACKEND_ERROR;
}

static void log_event(FILE *telemetry, const char *run_id, const char *container_id,
                      const char *scenario, bool is_attack, const struct c3m_request *request,
                      uint16_t status, double latency_us, bool parsed)
{
    uint64_t key_fingerprint = 0;
    uint64_t request_fingerprint = 0;
    char key_fingerprint_text[17] = "";
    char request_fingerprint_text[17] = "";
    if (!telemetry)
        return;
    if (parsed) {
        key_fingerprint = keyed_fingerprint(request, false);
        request_fingerprint = keyed_fingerprint(request, true);
        snprintf(key_fingerprint_text, sizeof(key_fingerprint_text), "%016llx",
                 (unsigned long long)key_fingerprint);
        snprintf(request_fingerprint_text, sizeof(request_fingerprint_text), "%016llx",
                 (unsigned long long)request_fingerprint);
    }
    fprintf(telemetry,
        "{\"container_id\":\"%s\",\"error_origin\":\"%s\",\"event_type\":\"request\"," 
        "\"input_bytes\":%u,\"is_attack\":%s,\"key_fingerprint\":\"%s\"," 
        "\"latency_us\":%.3f,\"operation\":\"%s\"," 
        "\"request_id\":%llu,\"result\":\"%s\",\"run_id\":\"%s\",\"scenario\":\"%s\"," 
        "\"request_fingerprint\":\"%s\"," 
        "\"ts_unix_ns\":%llu}\n",
        container_id,
        status == C3M_STATUS_OK ? "none" : (parsed ? "backend" : "gateway"),
        parsed ? request->key_len + request->value_len : 0,
        is_attack ? "true" : "false",
        key_fingerprint_text,
        latency_us,
        parsed ? c3m_operation_name(request->operation) : "REJECT",
        (unsigned long long)(parsed ? request->request_id : 0),
        c3m_status_name(status), run_id, scenario,
        request_fingerprint_text,
        (unsigned long long)realtime_ns());
    fflush(telemetry);
}

static int serve(const char *socket_path, FILE *telemetry, struct c3m_backend *backend,
                 const char *run_id, const char *container_id, const char *scenario,
                 bool is_attack, struct request_metrics *metrics)
{
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { 0 };
    if (listener < 0)
        return -1;
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        close(listener);
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(address.sun_path, socket_path);
    unlink(socket_path);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        chmod(socket_path, 0660) || listen(listener, 32)) {
        close(listener);
        unlink(socket_path);
        return -1;
    }
    while (!stopping) {
        int connection = accept(listener, NULL, NULL);
        struct c3m_request request;
        struct c3m_response response = { 0 };
        uint64_t start_ns;
        uint64_t end_ns;
        bool parsed;
        if (connection < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        start_ns = monotonic_ns();
        parsed = c3m_recv_request(connection, &request) == 0;
        if (parsed) {
            response.request_id = request.request_id;
            response.status = dispatch(backend, &request, &response);
            (void)c3m_send_response(connection, &response);
        } else {
            response.status = C3M_STATUS_PROTOCOL_ERROR;
        }
        end_ns = monotonic_ns();
        record_metric(metrics, start_ns, end_ns, response.status);
        log_event(telemetry, run_id, container_id, scenario, is_attack,
                  &request, response.status, (double)(end_ns - start_ns) / 1000.0, parsed);
        close(connection);
    }
    close(listener);
    unlink(socket_path);
    return 0;
}

int main(int argc, char **argv)
{
    const char *socket_path = "/run/cote3-mon/gateway.sock";
    const char *telemetry_path = "telemetry.jsonl";
    const char *summary_path = NULL;
    const char *backend_name = "mock";
    bool telemetry_enabled = true;
    const char *raw_run_id = getenv("COTE3_RUN_ID");
    const char *raw_container_id = getenv("COTE3_CONTAINER_ID");
    const char *raw_scenario = getenv("COTE3_SCENARIO");
    bool is_attack = getenv("COTE3_IS_ATTACK") && !strcmp(getenv("COTE3_IS_ATTACK"), "1");
    char run_id[65], container_id[65], scenario[65];
    struct c3m_backend *backend;
    FILE *telemetry;
    struct request_metrics metrics = { 0 };
    int index;
    for (index = 1; index < argc; ++index) {
        if (!strcmp(argv[index], "--socket") && index + 1 < argc)
            socket_path = argv[++index];
        else if (!strcmp(argv[index], "--telemetry") && index + 1 < argc)
            telemetry_path = argv[++index];
        else if (!strcmp(argv[index], "--no-telemetry"))
            telemetry_enabled = false;
        else if (!strcmp(argv[index], "--summary") && index + 1 < argc)
            summary_path = argv[++index];
        else if (!strcmp(argv[index], "--backend") && index + 1 < argc)
            backend_name = argv[++index];
        else {
            fprintf(stderr, "usage: %s [--socket PATH] [--telemetry PATH|--no-telemetry] "
                            "[--summary PATH] [--backend mock|optee]\n", argv[0]);
            return 2;
        }
    }
    safe_identifier(run_id, sizeof(run_id), raw_run_id);
    safe_identifier(container_id, sizeof(container_id), raw_container_id);
    safe_identifier(scenario, sizeof(scenario), raw_scenario);
    initialise_fingerprint_secret();
    backend = !strcmp(backend_name, "mock") ? c3m_mock_backend_create() : c3m_optee_backend_create();
    if (!backend) {
        fprintf(stderr, "failed to initialise %s backend\n", backend_name);
        return 1;
    }
    telemetry = NULL;
    if (telemetry_enabled) {
        telemetry = fopen(telemetry_path, "a");
        if (!telemetry) {
            perror("telemetry");
            backend->ops->destroy(backend);
            return 1;
        }
    }
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
    printf("COTE3-Mon gateway listening on %s (%s backend)\n", socket_path, backend_name);
    int result = serve(socket_path, telemetry, backend, run_id, container_id, scenario,
                       is_attack, &metrics);
    if (result)
        perror("gateway");
    if (telemetry)
        fclose(telemetry);
    if (write_summary(summary_path, &metrics)) {
        perror("summary");
        result = -1;
    }
    free(metrics.latencies_us);
    backend->ops->destroy(backend);
    return result ? 1 : 0;
}
