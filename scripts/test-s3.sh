#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Runs the tests of the object store against a disposable S3 server (iteration 03, WP-27.3).
#
# It starts one S3 gateway over a directory of its own, on a free port of the loopback
# interface, with credentials and a certificate authority made for this run, creates one
# bucket, points `PERMGUARD_TEST_S3` and `PERMGUARD_TEST_S3_CA` at them, runs the tests, and
# removes the container whatever happened.
#
#   scripts/test-s3.sh                      the tests of the client's own crate
#   scripts/test-s3.sh -E 'test(list)'      a part of them: arguments replace the selection
#   scripts/test-s3.sh --then <command…>    runs the command with the server up, so
#                                           `scripts/test-s3.sh --then scripts/test-postgres.sh`
#                                           runs the stores that need both
#
# Without Docker, start a server yourself and set `PERMGUARD_TEST_S3` as
# `host=… port=… bucket=… access=… secret=… region=…`: the tests need nothing else. Every test
# works under a prefix of its own.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Pinned by digest: the server a test trusts is the one that was read.
IMAGE="${PERMGUARD_TEST_S3_IMAGE:-versity/versitygw@sha256:8319a530d08d537426e2f855bae5280709795dc73a3f0c347973ef915d6343c5}"
NAME="permguard-test-s3-$$"
ACCESS="$(head -c 10 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SECRET="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
BUCKET="permguard"
WORK="$(mktemp -d -t permguard-test-s3.XXXXXX)"

cleanup() {
    docker rm -f "${NAME}" >/dev/null 2>&1 || true
    rm -rf "${WORK}"
}
trap cleanup EXIT

# A certificate authority made for this run, and the server's certificate under it.
mkdir -p "${WORK}/tls" "${WORK}/data/${BUCKET}"
(
    cd "${WORK}/tls"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=permguard test authority" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
        -keyout ca.key -out ca.crt 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
    printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > san.cnf
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
        -extfile san.cnf -out server.crt 2>/dev/null
    chmod 644 server.key
)

docker run --detach --rm --name "${NAME}" \
    --env ROOT_ACCESS_KEY="${ACCESS}" \
    --env ROOT_SECRET_KEY="${SECRET}" \
    --volume "${WORK}/tls:/tls:ro" \
    --tmpfs /data \
    --publish 127.0.0.1::7070 \
    "${IMAGE}" --cert /tls/server.crt --key /tls/server.key posix /data >/dev/null

PORT="$(docker port "${NAME}" 7070/tcp | head -1 | sed 's/.*://')"

# A bucket of the gateway is a directory of what it serves.
docker exec "${NAME}" mkdir -p "/data/${BUCKET}"

ready=""
for _ in $(seq 1 60); do
    if curl --silent --output /dev/null --cacert "${WORK}/tls/ca.crt" "https://127.0.0.1:${PORT}/"; then
        ready="yes"
        break
    fi
    sleep 1
done
if [ -z "${ready}" ]; then
    printf 'error: the S3 container did not become ready\n' >&2
    exit 1
fi

export PERMGUARD_TEST_S3_CA="${WORK}/tls/ca.crt"
export PERMGUARD_TEST_S3="host=127.0.0.1 port=${PORT} bucket=${BUCKET} access=${ACCESS} secret=${SECRET} region=us-east-1"

cd "${ROOT}"
if [ "${1:-}" = "--then" ]; then
    shift
    "$@"
    exit $?
fi
if [ "$#" -gt 0 ]; then
    FILTER=("$@")
else
    FILTER=(-E 'package(permguard-s3)')
fi
cargo nextest run --workspace --all-features --locked "${FILTER[@]}"
