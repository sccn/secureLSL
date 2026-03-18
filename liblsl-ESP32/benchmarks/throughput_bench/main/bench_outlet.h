// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef BENCH_OUTLET_H
#define BENCH_OUTLET_H

/* Run the outlet benchmark. Pushes samples at the configured rate
 * and reports timing statistics via serial JSON. Blocks until
 * the configured duration expires. */
void bench_outlet_run(void);

#endif /* BENCH_OUTLET_H */
