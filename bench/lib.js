// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// What every benchmark shares: where the plane is, and what a correct answer looks like.
//
// Today the public surface is `GET /version`, `GET /health` and gRPC `GetInfo` — the whole of it.
// That is deliberate as a benchmark: it measures the transport stack alone (TCP, TLS, HTTP/1 and
// HTTP/2, the limits, the routing) with no domain logic in the way, which makes these numbers the
// baseline every future API's cost is measured against.

import http from 'k6/http';
import { check } from 'k6';

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
