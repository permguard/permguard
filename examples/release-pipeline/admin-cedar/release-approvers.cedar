// Who may sign a release off: a release manager of the owning team.
//
// Being entitled is not the same as being allowed. Whether *this* approval is
// acceptable — the author is somebody else, the tests passed, the artifact is
// signed — is decided by the guardrails, which can refuse what this permits.

// A high-risk release needs a Release Manager *of the owning team*; anything else
// only needs a Release Manager. `context.action` is where an action's properties
// arrive: Cedar cannot carry attributes on an action entity, so Permguard projects
// `action.properties` here, and the schema above declares the shape.
@alias("release-approvers")
permit (
    principal,
    action == Action::"release:signoff",
    resource
) when {
    principal.role == "ReleaseManager" &&
    principal in resource.service.owner &&
    (if context has action then context.action.risk != "critical" else true)
};
