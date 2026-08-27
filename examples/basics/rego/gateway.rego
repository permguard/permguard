# METADATA
# custom:
#   alias: gateway-access
package gateway.access

import rego.v1

default allow := false

# Users may read; only admins may mutate.
#
# The types are the ledger's vocabulary — the ones the Cedar schema beside this
# partition declares. One request reaches every partition of a profile, so the
# two speak the same nouns.
allow if {
    input.subject.type == "User"
    input.action.name == "read"
}

allow if {
    input.subject.properties.role == "admin"
    input.action.name in {"create", "update", "delete"}
}
