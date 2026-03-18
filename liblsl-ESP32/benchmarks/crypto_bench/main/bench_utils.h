#ifndef BENCH_UTILS_H
#define BENCH_UTILS_H

#include <stdint.h>
#include <stddef.h>

/* Number of iterations for each benchmark */
#define BENCH_ITERATIONS 1000

/* Benchmark result for a single operation */
typedef struct {
    const char *name;
    uint32_t iterations;
    double mean_us;
    double min_us;
    double max_us;
    double stddev_us;
    double ops_per_sec;
    /* For throughput benchmarks */
    size_t payload_bytes;
    double throughput_mbps;
} bench_result_t;

/* Get current time in microseconds (monotonic) */
int64_t bench_time_us(void);

/* Run a benchmark and compute statistics.
 * Performs a warmup phase (10 iterations), then invokes fn
 * iterations times. Timing is per-call.
 * The result struct is filled with statistics. */
typedef void (*bench_fn_t)(void *arg);
void bench_run(const char *name, bench_fn_t fn, void *arg, uint32_t iterations,
               size_t payload_bytes, bench_result_t *result);

/* Print a benchmark result to serial */
void bench_print_result(const bench_result_t *result);

/* Print a section header */
void bench_print_header(const char *section);

/* Print memory stats (free heap, min free heap) */
void bench_print_memory(const char *label);

#endif /* BENCH_UTILS_H */
