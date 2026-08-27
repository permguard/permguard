# METADATA
# custom:
#   alias: pipeline-workloads
package delivery.pipeline

import rego.v1

# What the pipeline itself may do. The subjects here are workloads, not people,
# and the Cedar schema does not model them as principals — which is why the
# `pipeline` profile answers with this partition alone.
default allow := false

# The build may upload an artifact, for the service it is the build of.
allow if {
	input.subject.type == "Workload"
	input.subject.id == "ci-pipeline"
	input.action.name == "artifact:upload"
	input.subject.properties.identity_verified
	input.subject.properties.repository == input.resource.properties.service
}

# Signing is one workload's job and nobody else's. Any other identity asking for
# it is refused by absence: no rule says yes.
allow if {
	input.subject.type == "Workload"
	input.subject.id == "artifact-signer"
	input.action.name == "artifact:sign"
	input.subject.properties.identity_verified
}

# The controller deploys a release that cleared every gate. A release that did
# not clear them is refused the same way — nothing permits it.
allow if {
	input.subject.type == "Workload"
	input.subject.id == "deployment-controller"
	input.action.name == "deployment:execute"
	input.subject.properties.identity_verified
	input.context.release_approved
	input.context.artifact_signed
	input.context.security_scan == "passed"
}
