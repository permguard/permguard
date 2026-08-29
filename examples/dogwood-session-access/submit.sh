#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Submit one fixture as a live occurrence. Fixtures keep fixed timestamps for reproducible offline
# tests; this adapter gives the submitted copy a current timestamp and a run-scoped event id.

set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
endpoint="${PERMGUARD_DATA_PLANE_ENDPOINT:-http://127.0.0.1:7656}"
session="${PERMGUARD_DEMO_ID:-}"
input=""

usage() {
    printf 'usage: %s [--endpoint URL] [--session ID] <occurrence.json>\n' "$(basename "$0")" >&2
    printf '\nThe input may be relative to the current directory or to %s.\n' "${example_dir}" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --endpoint)
            if [ "$#" -lt 2 ]; then
                usage
                exit 64
            fi
            endpoint="$2"
            shift 2
            ;;
        --session)
            if [ "$#" -lt 2 ]; then
                usage
                exit 64
            fi
            session="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            printf "error: unknown option '%s'\n" "$1" >&2
            usage
            exit 64
            ;;
        *)
            if [ -n "${input}" ]; then
                printf 'error: only one event document may be submitted at a time\n' >&2
                usage
                exit 64
            fi
            input="$1"
            shift
            ;;
    esac
done

if [ "$#" -gt 0 ] || [ -z "${input}" ]; then
    usage
    exit 64
fi

for dependency in jq curl; do
    if ! command -v "${dependency}" >/dev/null 2>&1; then
        printf "error: '%s' is required for this demo\n" "${dependency}" >&2
        exit 69
    fi
done

if [ -f "${input}" ]; then
    document="${input}"
elif [ -f "${example_dir}/${input}" ]; then
    document="${example_dir}/${input}"
else
    printf "error: no event document at '%s' or '%s'\n" "${input}" "${example_dir}/${input}" >&2
    exit 66
fi

original_id="$({ jq -er '.event.data.event_id | select(type == "string" and length > 0)' "${document}"; } 2>/dev/null)" || {
    printf "error: '%s' has no string 'event.data.event_id'\n" "${document}" >&2
    exit 65
}

# The fixtures share `01J8Z9-` as their deterministic prefix. Keeping the rest means the ordinary
# event and `conflicting-retry.json` resolve to the same live id, which is exactly what that refusal
# demonstrates. A caller may provide a different session for every run without editing any JSON.
suffix="${original_id#*-}"
if [ -z "${session}" ]; then
    session="demo-$(date +%s)-$$"
    printf "note: no session was supplied; using '%s' for this submission\n" "${session}" >&2
fi
event_id="${session}-${suffix}"

response_file="$(mktemp "${TMPDIR:-/tmp}/permguard-dogwood-response.XXXXXX")"
trap 'rm -f -- "${response_file}"' EXIT

status="$({
    jq --arg event_id "${event_id}" \
        '.event.data.event_id = $event_id
         | .event.data.occurred_at = (now | todate)' "${document}"
} | curl --silent --show-error \
    --output "${response_file}" \
    --write-out '%{http_code}' \
    --request POST "${endpoint%/}/temporal/v1alpha1/events" \
    --header 'content-type: application/json' \
    --data-binary @-)"

if ! jq . "${response_file}"; then
    printf 'error: the data plane returned a non-JSON response\n' >&2
    sed -n '1,80p' "${response_file}" >&2
    exit 76
fi
printf 'HTTP %s\n' "${status}" >&2

case "${status}" in
    2??) exit 0 ;;
    *) exit 1 ;;
esac
