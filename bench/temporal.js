// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// What an occurrence costs.
//
// `decide.js` measures a stateless decision, whose dominant cost is the durable decision record.
// This measures the other interface, where there are *two* durable writes in the critical path —
// the event journal and the decision log — and where the answer additionally depends on a history
// that has to be replayed into an engine before anything is decided.
//
// # What is being separated
//
// Three shapes, run as three stages, so the numbers can be read against each other rather than
// averaged into one:
//
//   history_only   a `Login::response`: recorded, observed, **no verdict**
//   deciding       a `Read::request`:   recorded, observed, and decided against the history
//   concurrent     the same deciding submission from many VUs at once
//
// The first two differ by exactly the evaluation, so the gap between them is what deciding against
// a history costs on top of keeping one. The third is what group commit is for: `fsync` costs about
// the same for one record as for a hundred, so submissions that overlap share one, and per-request
// latency should stay far closer to flat than the VU count would suggest.
//
// # Read the plane's own numbers beside these
//
// Latency from out here cannot tell a slow disk from a slow evaluation. The plane publishes both,
// and this benchmark is meant to be read with them open:
//
//   permguard_temporal_append_seconds     the durable write — the floor under every submission
//   permguard_temporal_apply_seconds      observing and deciding
//   permguard_temporal_flushes_total      against submissions_total: flushes per submission
//   permguard_temporal_batch_records      how many records one flush covered
//
// A `flushes_total / submissions_total` ratio near one under the concurrent stage means nothing is
// being amortised, which is the first thing to check if that stage's latency scales with VUs.
//
// # No numbers are quoted here
//
// Unlike `decide.js`, this file states no measured baseline. One has not been taken on hardware
// worth naming, and a number invented here would be read as one that was measured. Run it, record
// what your hardware does, and put that in your own notes.
//
// Needs a data plane with the temporal interface on and the example applied:
//
//   task run:experimental
//   permguard -w examples/dogwood-session-access apply -m bench
//   k6 run bench/temporal.js

import { hitTemporal } from './lib.js';

export const options = {
  scenarios: {
    // Cold: the first submissions pay for compiling the partition and for whatever history the
    // ledger already holds being replayed into a fresh engine. Discarded by tagging.
    warm_up: {
      executor: 'constant-vus',
      vus: 1,
      duration: '10s',
      tags: { phase: 'cold' },
      exec: 'history_only',
    },
    // Recorded and observed, with no verdict to produce.
    history_only: {
      executor: 'constant-vus',
      vus: 1,
      duration: '30s',
      startTime: '12s',
      tags: { phase: 'warm' },
      exec: 'history_only',
    },
    // The same write, plus deciding against the history it just joined.
    deciding: {
      executor: 'constant-vus',
      vus: 1,
      duration: '30s',
      startTime: '44s',
      tags: { phase: 'warm' },
      exec: 'deciding',
    },
    // Overlapping submissions, which is where group commit either works or does not.
    concurrent: {
      executor: 'constant-vus',
      vus: 16,
      duration: '60s',
      startTime: '76s',
      tags: { phase: 'warm' },
      exec: 'deciding',
    },
  },
  thresholds: {
    // Judged on the warm path only: a threshold covering the cold stage would be judging a
    // compilation and a replay that no steady state pays for.
    //
    // Deliberately loose, and for the same reason `decide.js` says: hardware is not specified here,
    // and a threshold tuned to the millisecond would be a flake rather than a check. What these
    // catch is a regression of *kind* — a submission that starts costing ten times what it did,
    // which is the shape every performance bug in a durable path has taken.
    'http_req_duration{phase:warm,kind:response}': ['p(95)<300'],
    'http_req_duration{phase:warm,kind:request}': ['p(95)<500'],
    // A submission that was refused is not a measurement of a submission.
    checks: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
  },
};

// A user per VU, because the example's event schema partitions history by the caller: one shared
// user would make every VU's submissions land in one history, and the run would measure how a
// single history grows rather than how the interface behaves.
function user() {
  return `bench-${__VU}`;
}

export function history_only() {
  hitTemporal(user(), 'response', 'Login');
}

export function deciding() {
  hitTemporal(user(), 'request', 'Read');
}
