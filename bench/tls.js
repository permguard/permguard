// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// The price of the handshake, and of mutual TLS on top.
//
// Against a TLS or mutual-TLS profile (`task run-as-tls:control` / `task run-as-mtls:control`).
// k6 reports connection and TLS handshake time separately (`http_req_connecting`,
// `http_req_tls_handshaking`), so this run answers two questions at once: what a request costs on a
// warm connection, and what the first request on a cold one pays.
//
//   PERMGUARD_URL=https://127.0.0.1:7556 \
//   BENCH_CA=.volume/control-plane-mtls/tls/ca.pem \
//   BENCH_CERT=.volume/control-plane-mtls/tls/client.pem \
//   BENCH_KEY=.volume/control-plane-mtls/tls/client.key \
//   k6 run bench/tls.js
//
// BENCH_CERT/BENCH_KEY are optional: leave them out against the plain-TLS profile. The generated
// authority is not in the system store, so the CA has to be named — or set BENCH_INSECURE=true,
// which is the same trade `--tls-skip-verify` is: development only.

import { hitVersion } from './lib.js';

export const options = {
  scenarios: {
    tls: {
      executor: 'constant-vus',
      vus: Number(__ENV.BENCH_VUS || 128),
      duration: __ENV.BENCH_DURATION || '30s',
    },
  },
  insecureSkipTLSVerify: (__ENV.BENCH_INSECURE || 'false') === 'true',
  tlsAuth:
    __ENV.BENCH_CERT && __ENV.BENCH_KEY
      ? [
          {
            cert: open(__ENV.BENCH_CERT),
            key: open(__ENV.BENCH_KEY),
          },
        ]
      : undefined,
  thresholds: {
    http_req_failed: ['rate<0.01'],
    checks: ['rate>0.99'],
  },
};

export default hitVersion;
