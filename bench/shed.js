// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// What overload looks like, on purpose.
//
// Run against `task bench:server:shed`, which lowers the request ceiling to 16 and disables the
// per-address connection bound. Both are what isolating this layer requires: the generator is one
// address, so under full defaults the per-address cap (256 sockets) fires first — and today's
// handlers are so fast that, by Little's law, the in-flight count never reaches the default ceiling
// of 256 at any load one machine can produce. The number under test is the behaviour, not the
// ceiling: excess answered 503 immediately, the rest served, nothing falling over.
//
// The correct behaviour is not "everything answers": it is that the excess is answered 503
// immediately (shed, not queued), the requests inside the limit keep their latency, and the plane
// never falls over. A run where every request got 200 measured nothing.

import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { BASE } from './lib.js';

// A 503 here is the defence working, so it must not count as a failed request — without this, k6's
// own failure metric reads "27% failed" about a server doing exactly what it was told to.
http.setResponseCallback(http.expectedStatuses(200, 503));

const served = new Counter('bench_served');
const shed = new Counter('bench_shed');

export const options = {
  scenarios: {
    flood: {
      executor: 'constant-vus',
      vus: Number(__ENV.BENCH_VUS || 600), // 600 > the default 256 in flight
      duration: __ENV.BENCH_DURATION || '30s',
    },
  },
  thresholds: {
    // The plane must answer *something* to everybody — 200 or 503, never a transport error.
    http_req_failed: ['rate<0.01'],
    bench_served: ['count>0'],
    // And the shed layer must actually have fired, or the run measured nothing.
    bench_shed: ['count>0'],
  },
};

export default function () {
  const answer = http.get(`${BASE}/version`, { tags: { endpoint: 'version' } });

  check(answer, { 'answered, one way or the other': (r) => r.status === 200 || r.status === 503 });

  if (answer.status === 200) {
    served.add(1);
  } else if (answer.status === 503) {
    shed.add(1);
  }
}
