// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#include "lsl_clock.h"
#include "lsl_esp32.h"
#include "esp_timer.h"

double clock_get_time(void)
{
    return (double)esp_timer_get_time() / 1000000.0;
}

double lsl_esp32_local_clock(void)
{
    return clock_get_time();
}
