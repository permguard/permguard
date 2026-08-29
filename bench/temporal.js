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
// a history costs on top of keeping one. The third exercises two deliberately different pieces of
// concurrency: overlapping durable appends may share one `fsync`, while application remains
// ordered one occurrence at a time inside a ledger. Its latency is therefore a bounded queue, not
// a promise of flat per-request latency; the journal metrics below show whether group commit still
// amortised the durable part of that queue.
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
// # Baseline
//
// The release-build baseline below is refreshed only from a complete successful run. It is a
// reference point, not a cross-machine SLA: disk, filesystem and co-locating k6 with the server
// materially affect a path that waits for durable writes.
//
//   measured:  p50 / p95 / p99 are emitted by `summaryTrendStats`
//   server:    `permguard-all-in-one --release`, local filesystem
//   client:    k6 on the same host
//   workload:  exactly the three warm stages declared in this file
//
//   2026-08-29, Apple M4 Max, fresh local volume, 1,944 iterations, zero failed requests:
//
//     history response, 1 VU    53.74 /   60.63 /   66.32 ms
//     deciding request, 1 VU    72.47 /   83.29 /   91.68 ms
//     deciding request, 16 VU    1.18 /    1.45 /    1.56 s
//
// Needs a data plane with the temporal interface on and the example applied:
//
//   task run:experimental
//   permguard -w examples/dogwood-session-access apply -m bench
//   k6 run bench/temporal.js
//
// For a comparable baseline, start from a fresh volume: retained history is part of the work and a
// used volume intentionally measures a different state. Event identities include a per-run value,
// scenario, VU and iteration, so an accidental second run is still new work rather than a stream
// of `event_id_conflict` refusals. Set `PERMGUARD_TEMPORAL_RUN_ID` when reproducible identities are
// useful; never reuse it against the same journal.

import { fail, sleep } from 'k6';
import http from 'k6/http';

import {
  hitTemporal,
  nowInstant,
  occurrenceBody,
  PDP,
  TEMPORAL_RUN,
} from './lib.js';

export const options = {
  summaryTrendStats: ['avg', 'med', 'p(50)', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    // Cold: the first submissions pay for compiling the partition and for whatever history the
    // ledger already holds being replayed into a fresh engine. Discarded by tagging.
    warm_up: {
      executor: 'constant-vus',
      vus: 1,
      duration: '10s',
      tags: { phase: 'cold', stage: 'warm_up' },
      exec: 'history_only',
    },
    // Recorded and observed, with no verdict to produce.
    history_only: {
      executor: 'constant-vus',
      vus: 1,
      duration: '30s',
      startTime: '12s',
      tags: { phase: 'warm', stage: 'single' },
      exec: 'history_only',
    },
    // The same write, plus deciding against the history it just joined.
    deciding: {
      executor: 'constant-vus',
      vus: 1,
      duration: '30s',
      startTime: '44s',
      tags: { phase: 'warm', stage: 'single' },
      exec: 'deciding',
    },
    // Overlapping submissions, which is where group commit either works or does not.
    concurrent: {
      executor: 'constant-vus',
      vus: 16,
      duration: '60s',
      startTime: '76s',
      tags: { phase: 'warm', stage: 'concurrent' },
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
    'http_req_duration{phase:warm,stage:single,kind:response}': [
      'p(95)<300',
      'p(99)<600',
    ],
    'http_req_duration{phase:warm,stage:single,kind:request}': [
      'p(95)<500',
      'p(99)<1000',
    ],
    // The concurrent stage is judged separately, and it has to be: submissions to one ledger are
    // applied one at a time — the sequencer imposes the journal's order rather than the
    // scheduler's — so sixteen of them overlapping is a queue by design, not a regression. Holding
    // it to a per-request latency target would fail the design instead of testing it, which is
    // what a single `stage`-blind threshold did.
    //
    // What is worth asserting is that group commit is buying something. Sixteen submissions fully
    // serialised would cost sixteen times the single-VU p(95); this is that product, so the check
    // fails exactly when overlapping stops being cheaper than not overlapping.
    'http_req_duration{phase:warm,stage:concurrent,kind:request}': [
      'p(95)<1800',
      'p(99)<3000',
    ],
    // A release baseline is evidence only when every measured submission completed correctly.
    // Tolerating even one refusal would let a faster error path improve the latency distribution.
    'checks{phase:cold}': ['rate==1'],
    'checks{phase:warm}': ['rate==1'],
    'http_req_failed{phase:cold}': ['rate==0'],
    'http_req_failed{phase:warm}': ['rate==0'],
  },
};

// A control-plane apply and the data-plane mirror are intentionally asynchronous. Do not turn
// that deployment convergence into thousands of `ledger_empty` samples: prove the exact temporal
// route is usable first, retrying only the one state that means the mirror has not arrived yet.
// The probe is a history-only occurrence under its own pin and is therefore outside every
// measured user's history.
export function setup() {
  const eventId = `bench-${TEMPORAL_RUN}-preflight`;
  const until = Date.now() + 45000;
  let answer;

  while (Date.now() < until) {
    answer = http.post(
      `${PDP}/temporal/v1alpha1/events`,
      occurrenceBody('benchmark-preflight', 'response', 'Login', nowInstant(), eventId),
      {
        headers: { 'content-type': 'application/json' },
        tags: { endpoint: 'temporal', kind: 'response', phase: 'preflight' },
      },
    );
    if (answer.status === 200) {
      return;
    }

    let code = null;
    try {
      code = answer.json('code');
    } catch (_) {
      // The bounded diagnostic below is more useful than replacing it with a JSON parse error.
    }
    if (answer.status !== 503 || code !== 'ledger_empty') {
      fail(
        `temporal preflight failed: status=${answer.status} body=${String(answer.body).slice(0, 512)}`,
      );
    }
    sleep(1);
  }

  fail(
    `temporal preflight timed out: status=${answer?.status} body=${String(answer?.body).slice(0, 512)}`,
  );
}

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
