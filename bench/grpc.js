// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// The same question over gRPC: how fast does `GetInfo` answer, and does HTTP/2 with protobuf cost
// more or less than HTTP/1 with JSON on this stack? Run beside `peak.js` at the same concurrency
// and the difference between the two reports is the answer.
//
// Plain by default. For the mutual-TLS profile (`task run-as-mtls:control`, gRPC on 6443) set:
//
//   PERMGUARD_GRPC_ADDR=127.0.0.1:6443 BENCH_TLS=true \
//   BENCH_CA=.volume/control-plane-mtls/tls/ca.pem \
//   BENCH_CERT=.volume/control-plane-mtls/tls/client.pem \
//   BENCH_KEY=.volume/control-plane-mtls/tls/client.key
//
// The generated client is `cn:local-operator`, which is exactly who the profile's allow list names —
// so this also exercises the peer-authorisation gate on every connection.

import grpc from 'k6/net/grpc';
import { check } from 'k6';

const ADDR = __ENV.PERMGUARD_GRPC_ADDR || '127.0.0.1:6443';
const TLS = (__ENV.BENCH_TLS || 'false') === 'true';

const client = new grpc.Client();
client.load(['../crates/permguard-control-plane/proto'], 'permguard/control/v1/control_plane.proto');

// Connections are per virtual user and reused across iterations: a gRPC channel carrying many calls
// is the shape the metric `permguard_surface_connections` expects to see.
let connected = false;

export const options = {
  scenarios: {
    calls: {
      executor: 'constant-vus',
      vus: Number(__ENV.BENCH_VUS || 64),
      duration: __ENV.BENCH_DURATION || '30s',
    },
  },
  thresholds: {
    grpc_req_duration: [`p(95)<${__ENV.BENCH_P95_MS || 100}`],
    checks: ['rate>0.99'],
  },
};

export default function () {
  if (!connected) {
    const params = { plaintext: !TLS };

    client.connect(ADDR, params);
    connected = true;
  }

  const answer = client.invoke('permguard.control.v1.ControlPlane/GetInfo', {});

  check(answer, {
    'answered OK': (r) => r && r.status === grpc.StatusOK,
    'named a plane': (r) => r && r.message && r.message.plane === 'control',
  });
}
