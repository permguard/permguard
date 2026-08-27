// Who may roll a service back: a member of the team that owns it.
//
// Deliberately as wide as ownership. Narrowing it to "on call, during an
// incident" is a condition of the moment, not of the org chart, and it lives
// with the other guardrails.

@alias("rollback-responders")
permit (
    principal,
    action == Action::"deployment:rollback",
    resource
) when {
    principal in resource.owner
};
