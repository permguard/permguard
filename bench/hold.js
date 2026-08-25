// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// How many connections the plane can *hold*, which is a different question from how many requests
// it can serve: a held connection is a task, buffers and possibly a TLS session, spent whether or
// not anything travels on it — and it is what the connection limits exist to bound.
//
// Each virtual user opens one keep-alive connection and keeps it warm with a request every few
// seconds. The stages climb the connection count; what to watch is the server's own gauge —
// `permguard_surface_connections` on the Overview and Load test dashboards — against the k6 VU
// line, plus refusals and memory. The test passes while every held connection still gets answers.
//
// Run against `task bench:server` (connections=20000, per-address bound off). Two client-side
// ceilings to know about before blaming the server: `ulimit -n` in the k6 shell, and the ephemeral
// ports one source address has toward one destination — on macOS that is 16,384 by default
// (`sysctl net.inet.ip.portrange.first` = 49152), measured as the generator dying with "can't
// assign requested address" at ~16.3k held. Widen it with
// `sudo sysctl -w net.inet.ip.portrange.first=32768`, or generate from a second machine.

import { sleep } from 'k6';
import { hitVersion } from './lib.js';

const HOLD = Number(__ENV.BENCH_HOLD_SECONDS || 5);

export const options = {
  scenarios: {
    hold: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { target: Number(__ENV.BENCH_HOLD_1 || 1000), duration: '30s' },
        { target: Number(__ENV.BENCH_HOLD_1 || 1000), duration: '30s' }, // plateau: is it stable?
        { target: Number(__ENV.BENCH_HOLD_2 || 5000), duration: '30s' },
        { target: Number(__ENV.BENCH_HOLD_2 || 5000), duration: '30s' },
        { target: Number(__ENV.BENCH_HOLD_3 || 15000), duration: '60s' },
        { target: Number(__ENV.BENCH_HOLD_3 || 15000), duration: '60s' },
      ],
      gracefulRampDown: '10s',
    },
  },
  // Keep-alive is the point: one VU, one connection, for the VU's whole life.
  noConnectionReuse: false,
  thresholds: {
    http_req_failed: ['rate<0.01'],
    checks: ['rate>0.99'],
  },
};

export default function () {
  hitVersion();

  // Quiet, not idle: a request every few seconds keeps the connection out of the header-timeout's
  // reach and proves the server still answers on every held socket, while spending almost no
  // throughput — this test is about sockets, not requests.
  sleep(HOLD);
}
