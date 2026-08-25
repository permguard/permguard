// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// The knee: latency at fixed, rising request rates.
//
// Open model — requests arrive on schedule whether or not earlier ones have answered — which is how
// real traffic behaves and the only shape that measures latency honestly. The output to look at is
// the latency percentile at each step: flat, flat, flat, knee. The rate where the knee starts is
// the number capacity planning wants, and it is always lower than `peak.js`'s ceiling.

import { hitVersion } from './lib.js';

const STEP = __ENV.BENCH_STEP_DURATION || '30s';

export const options = {
  scenarios: {
    ladder: {
      executor: 'ramping-arrival-rate',
      startRate: Number(__ENV.BENCH_START_RATE || 1000),
      timeUnit: '1s',
      preAllocatedVUs: 500,
      maxVUs: Number(__ENV.BENCH_MAX_VUS || 10000),
      stages: [
        { target: Number(__ENV.BENCH_RATE_1 || 5000), duration: STEP },
        { target: Number(__ENV.BENCH_RATE_2 || 20000), duration: STEP },
        { target: Number(__ENV.BENCH_RATE_3 || 50000), duration: STEP },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    // Generous on purpose: the threshold is a tripwire for regressions between runs, not a target.
    // Tighten it once a machine's baseline is known.
    http_req_duration: [`p(95)<${__ENV.BENCH_P95_MS || 100}`],
  },
};

export default hitVersion;
