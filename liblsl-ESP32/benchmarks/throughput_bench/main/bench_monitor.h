// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef BENCH_MONITOR_H
#define BENCH_MONITOR_H

#include <stdint.h>

/* Start the background resource monitor task (core 0, priority 3).
 * Samples heap, stack HWM, and WiFi RSSI every second. */
void bench_monitor_start(void);

/* Stop the monitor task. */
void bench_monitor_stop(void);

/* Print a JSON summary of collected resource metrics. */
void bench_monitor_print_summary(void);

/* Get the current minimum free heap observed. */
uint32_t bench_monitor_get_heap_min(void);

#endif /* BENCH_MONITOR_H */
