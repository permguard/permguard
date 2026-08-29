// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// What every benchmark shares: where the plane is, and what a correct answer looks like.
//
// # Two things are measured here, and they are not the same thing
//
// `hitVersion` and `hitHealth` measure the **transport stack alone** — TCP, TLS, HTTP/1 and
// HTTP/2, the limits, the routing — with no domain logic in the way. That is the baseline every
// API's cost is measured against, and it is what `peak`, `hold`, `ladder`, `shed` and `tls` use.
//
// `hitDecision` measures the **decision path**: a real `permguard.pdp.v1` evaluation against a
// mirrored ledger, through the profile's partitions and their engines. A benchmark suite that
// reported only the first while the product's reason to exist is the second would be measuring
// the wrong thing and saying so in tenths of a millisecond.

import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';

// The endpoint under test. The same script runs against local and remote by changing this alone.
export const BASE = __ENV.PERMGUARD_URL || 'http://127.0.0.1:7556';

// One request against the identity endpoint, checked for shape and not just status: a load test
// that only counts 200s would happily benchmark an error page.
export function hitVersion() {
  const answer = http.get(`${BASE}/version`, { tags: { endpoint: 'version' } });

  check(answer, {
    'answered 200': (r) => r.status === 200,
    'named a plane': (r) => {
      try {
        return typeof r.json('plane') === 'string';
      } catch (_) {
        return false;
      }
    },
  });

  return answer;
}

export function hitHealth() {
  const answer = http.get(`${BASE}/health`, { tags: { endpoint: 'health' } });

  check(answer, { 'answered 200': (r) => r.status === 200 });

  return answer;
}

// The decision endpoint, and what a real answer looks like.
//
// `PERMGUARD_PDP_URL` is the data plane (`:7656` locally); `PERMGUARD_ZONE` and `PERMGUARD_LEDGER`
// name a ledger it mirrors. The request is deliberately one a policy has to think about: the
// subject reaches the resource through the entity store the request carries, so the store is
// walked rather than skipped.
export const PDP = __ENV.PERMGUARD_PDP_URL || 'http://127.0.0.1:7656';
export const ZONE = __ENV.PERMGUARD_ZONE || 'acme';
export const LEDGER = __ENV.PERMGUARD_LEDGER || 'main-ledger';
export const PROFILE = __ENV.PERMGUARD_PROFILE || 'default';

// One decision request, in the shape `examples/basics` decides.
export function decisionBody(subject = 'alice') {
  return JSON.stringify({
    zone: ZONE,
    ledger: LEDGER,
    profile: PROFILE,
    subject: { type: 'User', id: subject },
    action: { name: 'read' },
    resource: { type: 'Document', id: 'budget-2026' },
    context: { time: '2026-08-24T10:00:00Z' },
    partition_inputs: {
      cedar: {
        type: 'permguard.cedar.entities.v1',
        data: [
          { uid: { type: 'Group', id: 'finance' }, attrs: {}, parents: [] },
          {
            uid: { type: 'User', id: subject },
            attrs: {},
            parents: [{ type: 'Group', id: 'finance' }],
          },
          {
            uid: { type: 'Document', id: 'budget-2026' },
            attrs: { owner: { __entity: { type: 'User', id: 'carol' } } },
            parents: [],
          },
        ],
      },
    },
  });
}

// One evaluation, checked for a *decision* and not merely a 200.
//
// A load test that counted status codes would happily benchmark a plane refusing every request —
// `400 zone_required` is as fast as anything gets. So the check reads the answer: a boolean
// decision, and the identity of whatever decided it.
export function hitDecision(subject = 'alice') {
  const answer = http.post(`${PDP}/access/v1/evaluation`, decisionBody(subject), {
    headers: { 'content-type': 'application/json' },
    tags: { endpoint: 'evaluation' },
  });

  check(answer, {
    'answered 200': (r) => r.status === 200,
    'decided': (r) => {
      try {
        return typeof r.json('decision') === 'boolean';
      } catch (_) {
        return false;
      }
    },
    'cited a policy': (r) => {
      try {
        const policies = r.json('context.policies');
        return Array.isArray(policies) && policies.length > 0;
      } catch (_) {
        return false;
      }
    },
  });

  return answer;
}

// A boxcarred request: several questions in one exchange, which is the shape a PEP uses when it
// has a page of them. What this measures against `hitDecision` is what boxcarring is *for*.
export function hitDecisionBatch(count = 8) {
  const evaluations = [];
  for (let at = 0; at < count; at += 1) {
    evaluations.push({ request_id: `q${at}`, action: { name: 'read' } });
  }
  const body = JSON.parse(decisionBody());
  body.evaluations = evaluations;

  const answer = http.post(`${PDP}/access/v1/evaluations`, JSON.stringify(body), {
    headers: { 'content-type': 'application/json' },
    tags: { endpoint: 'evaluations' },
  });

  check(answer, {
    'answered 200': (r) => r.status === 200,
    'answered every question': (r) => {
      try {
        return r.json('evaluations').length === count;
      } catch (_) {
        return false;
      }
    },
  });

  return answer;
}

// ─── The temporal interface ──────────────────────────────────────────────────

export const TEMPORAL_ZONE = __ENV.PERMGUARD_TEMPORAL_ZONE || 'acme';
export const TEMPORAL_LEDGER = __ENV.PERMGUARD_TEMPORAL_LEDGER || 'agent-governance';
export const TEMPORAL_PROFILE = __ENV.PERMGUARD_TEMPORAL_PROFILE || 'temporal';
export const TEMPORAL_RUN = __ENV.PERMGUARD_TEMPORAL_RUN_ID || `${Date.now()}`;

// One occurrence, as `examples/dogwood-session-access` shapes them.
//
// Every submission carries a distinct `event_id`, because an id already recorded is answered from
// what was stored — correct, and about a tenth of the work. Benchmarking that would be measuring
// the deduplication index rather than the write.
export function occurrenceBody(user, kind, action, at, eventId = null) {
  return JSON.stringify({
    store: { zone: TEMPORAL_ZONE, ledger: TEMPORAL_LEDGER, profile: TEMPORAL_PROFILE },
    event: {
      type: 'permguard.dogwood.event.v1',
      data: {
        // Scenario is part of the identity because k6 may reuse a VU between sequential
        // scenarios and reset its iteration counter. The run id makes a second benchmark against
        // the same retained journal new work rather than a conflicting retry.
        event_id:
          eventId || `bench-${TEMPORAL_RUN}-${exec.scenario.name}-${__VU}-${__ITER}-${kind}`,
        kind,
        action: `Drupe::Action::${action}`,
        principal: `Drupe::OAuthUser::"${user}"`,
        resource: 'Drupe::Gateway::"gw1"',
        logged:
          action === 'Login'
            ? { input: { user, server: 's1' }, ...(kind === 'response' ? { output: {} } : {}) }
            : { input: { user, document: 'doc1' } },
        request_context: {
          input: action === 'Login' ? { user, server: 's1' } : { user, document: 'doc1' },
        },
        occurred_at: at,
      },
    },
  });
}

// The instant a submission claims, as the interface spells them: whole seconds, UTC.
//
// Taken from the load generator's own clock rather than fixed, because the plane checks it against
// skew and lateness bounds — a benchmark sending a constant timestamp would start being refused
// partway through the run, and would measure the refusal.
export function nowInstant() {
  return `${new Date().toISOString().slice(0, 19)}Z`;
}

// One occurrence submitted, checked for what the interface actually promises.
//
// Not a status code: a `200` here can be a *recorded* occurrence with no verdict, which is the
// right answer for a history-only kind and the wrong thing to count as a decision. So the check
// reads the outcome, and the watermark that proves the record is durable.
export function hitTemporal(user, kind, action) {
  const answer = http.post(
    `${PDP}/temporal/v1alpha1/events`,
    occurrenceBody(user, kind, action, nowInstant()),
    {
      headers: { 'content-type': 'application/json' },
      tags: { endpoint: 'temporal', kind },
    },
  );

  if (answer.status !== 200) {
    // The benchmark uses synthetic occurrences, so this is safe to print. One failed submission
    // invalidates the release baseline: stop immediately rather than measuring thousands of fast
    // refusal paths and flooding CI. Bound the body in case an unexpected proxy page answered.
    exec.test.abort(
      `temporal submission failed: status=${answer.status} body=${String(answer.body).slice(0, 512)}`,
    );
  }

  check(answer, {
    'answered 200': (r) => r.status === 200,
    'durable': (r) => {
      try {
        return typeof r.json('watermark.sequence') === 'number';
      } catch (_) {
        return false;
      }
    },
    'said which history it ranged over': (r) => {
      try {
        return typeof r.json('history.mode') === 'string';
      } catch (_) {
        return false;
      }
    },
  });

  return answer;
}
