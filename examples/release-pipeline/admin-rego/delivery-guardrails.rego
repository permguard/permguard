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
