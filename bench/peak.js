// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// The ceiling: how many requests per second the plane answers when the generator never waits.
//
// Closed loop — each virtual user fires its next request the moment the previous one answers — so
// the measured rate *is* the plane's capacity for this concurrency, not an arrival rate somebody
// chose. The latency numbers from this mode are NOT the ones to quote: a closed loop coordinates
// with the server's slowness (the infamous coordinated omission), which is what `ladder.js` exists
// to avoid. Quote throughput from here, latency from the ladder.
//
// Run it against a plane started with the capacity profile (`task bench:server`): under default
// limits the shed layer answers 503 beyond 256 in flight — measuring that is `shed.js`'s job.

import { hitVersion } from './lib.js';

export const options = {
  scenarios: {
    peak: {
      executor: 'constant-vus',
      vus: Number(__ENV.BENCH_VUS || 256),
      duration: __ENV.BENCH_DURATION || '30s',
    },
  },
  // No latency thresholds on purpose: this mode's latency is not meaningful. Failures still are.
  thresholds: {
    http_req_failed: ['rate<0.01'],
    checks: ['rate>0.99'],
  },
};

export default hitVersion;
