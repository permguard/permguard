// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// What a decision costs.
//
// The other benchmarks in this directory measure the transport with nothing behind it. This one
// measures the thing the product exists to do: a `permguard.pdp.v1` evaluation against a mirrored
// ledger, through a profile's partitions and their engines.
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
    // Judged on the warm path only. A threshold that included the cold stage would be judging a
    // compilation nobody's steady state pays for.
    'http_req_duration{phase:warm,endpoint:evaluation}': ['p(95)<25', 'p(99)<50'],
    'http_req_duration{phase:warm,endpoint:evaluations}': ['p(95)<100'],
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
