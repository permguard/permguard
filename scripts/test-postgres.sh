#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Runs the tests of the PostgreSQL backend against a disposable server (iteration 03, WP-27.1).
#
# It starts one PostgreSQL container on a free port of the loopback interface, with a password
# made for this run, points `PERMGUARD_TEST_POSTGRES` at it, runs the tests, and removes the
# container whatever happened. Arguments are passed to the test runner, so
# `scripts/test-postgres.sh -E 'test(lease)'` runs a part of them.
#
# Without Docker, start a server yourself and set `PERMGUARD_TEST_POSTGRES` to its connection
# string: the tests need nothing else. Every test works in a schema of its own and drops it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${PERMGUARD_TEST_POSTGRES_IMAGE:-postgres:17}"
NAME="permguard-test-postgres-$$"
PASSWORD="$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"

cleanup() {
    docker rm -f "${NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach --rm --name "${NAME}" \
    --env POSTGRES_USER=permguard \
    --env POSTGRES_PASSWORD="${PASSWORD}" \
    --env POSTGRES_DB=permguard \
    --publish 127.0.0.1::5432 \
    "${IMAGE}" >/dev/null

PORT="$(docker port "${NAME}" 5432/tcp | head -1 | sed 's/.*://')"

# The image starts the server twice: once to initialize, then for good. It is ready when it
# answers on the published port.
ready=""
for _ in $(seq 1 60); do
    if docker exec "${NAME}" pg_isready --host 127.0.0.1 --username permguard --dbname permguard >/dev/null 2>&1 \
        && docker exec "${NAME}" psql --host 127.0.0.1 --username permguard --dbname permguard --command 'SELECT 1' >/dev/null 2>&1; then
        ready="yes"
        break
    fi
    sleep 1
done
if [ -z "${ready}" ]; then
    printf 'error: the PostgreSQL container did not become ready\n' >&2
    exit 1
fi

# TLS on, with a certificate authority made for this run inside the container: the tests of a
# verified connection read the authority from the file named below.
CA_FILE="$(mktemp -t permguard-test-postgres-ca.XXXXXX)"
cleanup_all() {
    rm -f "${CA_FILE}"
    cleanup
}
trap cleanup_all EXIT
docker exec --user postgres "${NAME}" sh -c '
    set -e
    d=/var/lib/postgresql/tls
    mkdir -p "$d" && cd "$d"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=permguard test authority" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
        -keyout ca.key -out ca.crt 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
    printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > san.cnf
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
        -extfile san.cnf -out server.crt 2>/dev/null
    chmod 600 server.key
    psql --host 127.0.0.1 --username permguard --dbname permguard --quiet \
        --command "ALTER SYSTEM SET ssl_cert_file = '"'"'$d/server.crt'"'"'" \
        --command "ALTER SYSTEM SET ssl_key_file = '"'"'$d/server.key'"'"'" \
        --command "ALTER SYSTEM SET ssl = on" \
        --command "SELECT pg_reload_conf()" >/dev/null
'
docker exec "${NAME}" cat /var/lib/postgresql/tls/ca.crt > "${CA_FILE}"

cd "${ROOT}"
PERMGUARD_TEST_POSTGRES_CA="${CA_FILE}" \
PERMGUARD_TEST_POSTGRES="host=127.0.0.1 port=${PORT} user=permguard password=${PASSWORD} dbname=permguard" \
    cargo nextest run -p permguard-postgres --locked "$@"
