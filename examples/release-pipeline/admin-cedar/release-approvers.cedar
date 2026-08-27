// Who may sign a release off: a release manager of the owning team.
//
// Being entitled is not the same as being allowed. Whether *this* approval is
// acceptable — the author is somebody else, the tests passed, the artifact is
// signed — is decided by the guardrails, which can refuse what this permits.

@alias("release-approvers")
permit (
    principal,
    action == Action::"release:signoff",
    resource
) when {
    principal.role == "ReleaseManager" &&
    principal in resource.service.owner
};
