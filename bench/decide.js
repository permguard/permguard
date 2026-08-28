// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// What a decision costs.
//
// The other benchmarks in this directory measure the transport with nothing behind it. This one
// measures the thing the product exists to do: a `permguard.pdp.v1` evaluation against a mirrored
// ledger, through a profile's partitions and their engines.
//
// # What a decision is made of, measured
//
// On one laptop, release build, load generator on the same machine, `examples/basics` applied —
// the numbers this script produced when it was written:
//
//   uncontended, no decision log     median  0.47 ms
//   uncontended, decision log on     median  4.9  ms
//   16 VUs,      no decision log     median  3.9  ms   p95 6.8 ms   2313 req/s
//   16 VUs,      decision log on     median 13.0  ms   p95  26 ms    528 req/s
//
// Two things worth reading off that. The **evaluation** is sub-millisecond: Cedar and Rego over a
// compiled partition, out of memory. The **durable record** is roughly ten times it, and it is the
// dominant cost of a decision on a plane that keeps an audit trail — the answer is not given until
// the record is on disk. That is a trade a deployment makes deliberately, so this script measures
// the default (log on) and the note above says what turning it off buys.
//
// A batch of eight costs about what one costs when the log is off (4.3 ms against 4.0 ms): the
// evaluation is not the expensive part, which is exactly what boxcarring is for.
//
// # Warm, and said so
//
// A data plane compiles a partition once per commit and answers from memory afterwards, so the
// first request against a ledger pays for a compilation and the rest do not. That is a real
// property and a misleading average, so the run starts with a short warm-up stage whose
// measurements are discarded by tagging: what the thresholds below judge is the warm path, which
// is the one a deployment lives on.
//
// Needs a data plane mirroring the ledger — `examples/basics` applied, as the README's five
// minutes leaves it:
//
//   task run:all
//   permguard -w examples/basics apply -m bench
//   k6 run bench/decide.js

import { hitDecision, hitDecisionBatch } from './lib.js';

export const options = {
  scenarios: {
    // Cold: one virtual user, briefly, so the first answers include whatever compilation costs.
    warm_up: {
      executor: 'constant-vus',
      vus: 1,
      duration: '10s',
      tags: { phase: 'cold' },
      exec: 'single',
    },
    // Warm: the path a deployment actually lives on.
    single: {
      executor: 'constant-vus',
      vus: 16,
      duration: '60s',
      startTime: '12s',
      tags: { phase: 'warm' },
      exec: 'single',
    },
    // The same work asked in batches, to show what boxcarring buys.
    batched: {
      executor: 'constant-vus',
      vus: 4,
      duration: '60s',
      startTime: '75s',
      tags: { phase: 'warm' },
      exec: 'batched',
    },
  },
  thresholds: {
    // Judged on the warm path only: a threshold covering the cold stage would be judging a
    // compilation nobody's steady state pays for.
    //
    // Set from the measurements above with room to spare, and deliberately so. Hardware is not
    // specified here — this runs on a laptop with the load generator beside the server, and in CI
    // on something else again — so a threshold tuned to the millisecond would be a flake, not a
    // check. What these catch is a regression of *kind*: a decision that starts costing ten times
    // what it did, which is the shape every performance bug in this path has taken.
    'http_req_duration{phase:warm,endpoint:evaluation}': ['p(95)<150', 'p(99)<300'],
    'http_req_duration{phase:warm,endpoint:evaluations}': ['p(95)<400'],
    // A decision that is not a decision is not a measurement.
    checks: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
  },
};

export function single() {
  hitDecision();
}

export function batched() {
  hitDecisionBatch(8);
}
