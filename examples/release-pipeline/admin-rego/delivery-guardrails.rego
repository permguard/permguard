# METADATA
# custom:
#   alias: delivery-guardrails
package delivery.guardrails

import rego.v1

# The guardrails only ever say no. A `deny` here overrides a permit from the
# Cedar partition, which is what lets the two describe different things: Cedar
# answers "is this person entitled", these rules answer "is it safe right now".
default deny := false

# Separation of duties. Whoever created a release cannot be the one to approve
# it — the single control that makes an approval mean anything.
deny if {
	input.action.name == "release:signoff"
	input.subject.id == input.resource.properties.created_by
}

# A release whose tests did not pass is not approvable.
deny if {
	input.action.name == "release:signoff"
	not input.context.tests_passed
}

# Neither is one whose artifact nobody signed.
deny if {
	input.action.name == "release:signoff"
	not input.context.artifact_signed
}

# A release the pipeline marked high risk needs the tests to have passed *and* the
# artifact signed — which the two rules above already require — and is refused
# outright when nobody stated the risk at all.
#
# The properties of an action reach Rego where they always did, as
# `input.action.properties`. Cedar reads the same values as `context.action`,
# because it has nowhere else to read them; one request, two readings, no second
# field for a caller to keep in step.
deny if {
	input.action.name == "release:signoff"
	input.action.properties.risk == "high"
	not input.context.artifact_signed
}

# A service the request declares frozen is not deployed to, whoever asks.
#
# The list arrives as this partition's own entity graph — `entities.partitions`
# addressed to `admin-rego`, in a shape a Rego module reads. The Cedar partition
# beside it receives its own graph in Cedar's shape, from the same request: one
# question, two graphs, neither readable by the other.
deny if {
	some frozen in data.entities[_].frozen_services
	frozen == input.resource.id
}

# Rolling production back is an incident action, not a routine one: the person
# has to be on call, and there has to be an incident to answer.
deny if {
	input.action.name == "deployment:rollback"
	input.context.environment == "production"
	not incident_response
}

incident_response if {
	input.context.on_call
	input.context.incident_active
}
