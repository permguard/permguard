// Who may open a release: a member of the team that owns the service.
//
// Nothing here reads the state of the release or of an incident — that is the
// guardrails' job, in the Rego partition. This answers one question: does this
// person stand in the right relation to this service?

@alias("release-authors")
permit (
    principal,
    action == Action::"release:create",
    resource
) when {
    principal in resource.owner
};
