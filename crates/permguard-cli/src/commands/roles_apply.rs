// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard iam roles apply plan|run` (WP-8.1, `2-security/7` Roles): converges a Host to
//! a declared set of roles, their members and the grants `role:<name>` holds.
//!
//! | Step   | What it does                                                                                    |
//! | ------ | ----------------------------------------------------------------------------------------------- |
//! | `plan` | reads the file, resolves every member to its principal, compares with the Host, writes the plan |
//! | `run`  | compares again; refused when the changes differ from the plan's, else applies them in order     |
//!
//! The order only ever widens access before it narrows it: roles are created and described, members
//! added and grants issued first, then members removed and grants revoked. A role the file does not
//! name is left as it is and listed in the plan as undeclared. Running a plan twice, or applying the
//! same file again, changes nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;

use permguard_control_client::host::Host;
use permguard_host::api::directory::{CreateRole, Member as MemberBody, UpdateRole};
use serde::{Deserialize, Serialize};

use super::directory::{client, principal_of};
use super::host::{Reserved, read_json, render_json, request_id, rooted_file};
use crate::args::{Globals, RolesApplyAction, Who};
use crate::failure::{EXIT_READY, Failure};
use crate::trace::Trace;

/// What a plan file says it is.
const PLAN_KIND: &str = permguard_core::domains::format::ROLES_APPLY_PLAN_V1;

/// The largest roles file read.
const MOST_FILE_BYTES: usize = 1024 * 1024;

/// The roles file: each role by name.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RolesFile {
    roles: BTreeMap<String, DeclaredRole>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredRole {
    #[serde(default)]
    description: String,
    #[serde(default)]
    members: Vec<DeclaredMember>,
    #[serde(default)]
    grants: Vec<DeclaredGrant>,
}

/// A member as the command line names one, exactly one key: `local: paperino`,
/// `user: entra:alice@acme.com`, `issuer: entra` or `principal: spiffe://acme/ops`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredMember {
    local: Option<String>,
    user: Option<String>,
    issuer: Option<String>,
    principal: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredGrant {
    operations: Vec<String>,
    selector: String,
    #[serde(default)]
    types: Vec<String>,
    #[serde(default)]
    expires: Option<String>,
}

/// A grant of a role, compared by what it allows: operations and types in order, `*` for no types.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantShape {
    operations: Vec<String>,
    selector: String,
    types: Vec<String>,
    expires: Option<String>,
}

impl GrantShape {
    fn new(
        operations: &[String],
        selector: &str,
        types: &[String],
        expires: Option<String>,
    ) -> Self {
        let sorted = |values: &[String]| {
            let mut values: Vec<String> = values.to_vec();
            values.sort();
            values.dedup();
            values
        };
        let types = if types.is_empty() {
            vec!["*".to_owned()]
        } else {
            sorted(types)
        };
        Self {
            operations: sorted(operations),
            selector: selector.to_owned(),
            types,
            expires,
        }
    }
}

/// A role as the file wants it, every member resolved to its principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WantedRole {
    description: String,
    members: BTreeSet<String>,
    grants: BTreeSet<GrantShape>,
}

/// One change, in the order a run applies them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
enum Change {
    CreateRole {
        role: String,
        description: String,
    },
    DescribeRole {
        role: String,
        description: String,
    },
    AddMember {
        role: String,
        member: String,
    },
    IssueGrant {
        role: String,
        grant: GrantShape,
    },
    RemoveMember {
        role: String,
        member: String,
    },
    RevokeGrant {
        role: String,
        grant_id: String,
        grant: GrantShape,
    },
}

/// What `plan` writes and `run` reads.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    kind: String,
    wanted: BTreeMap<String, WantedRole>,
    changes: Vec<Change>,
    /// Roles on the Host the file does not name: left as they are.
    undeclared: Vec<String>,
}

/// A role as the Host holds it, with the ids of its active grants by shape.
struct HeldRole {
    description: String,
    members: BTreeSet<String>,
    grants: BTreeMap<GrantShape, Vec<(String, u64)>>,
}

pub(super) fn apply(
    globals: &Globals,
    backend: &dyn Host,
    action: RolesApplyAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    match action {
        RolesApplyAction::Plan { file, out } => {
            let file = rooted_file(globals, &file);
            let bytes = crate::confirm::read_bytes(Some(&file), "roles file", MOST_FILE_BYTES)?;
            // The plan file is claimed before the Host is read: a plan is never written over.
            let reserved = Reserved::claim(&rooted_file(globals, &out))?;
            let plan = plan_roles(backend, &bytes).map_err(|mut failure| {
                if failure.message.starts_with("not a roles file") {
                    failure.message = format!("{}: {}", file.display(), failure.message);
                }
                failure
            })?;
            reserved.fill(&serde_json::to_vec_pretty(&plan).map_err(Failure::internal)?)?;
            trace.say(format!("{} changes planned", plan.changes.len()));
            render_json(&plan, globals, trace)?;
        }
        RolesApplyAction::Run { confirm_file } => {
            let plan: Plan = read_json(&rooted_file(globals, &confirm_file), "roles plan")?;
            if plan.kind != PLAN_KIND {
                return Err(Failure::usage(format!(
                    "{} is not a roles plan",
                    confirm_file.display()
                )));
            }
            run_roles(backend, &plan)?;
            for change in &plan.changes {
                trace.say(format!("applied {change:?}"));
            }
            render_json(
                &serde_json::json!({"applied": plan.changes.len(), "changes": plan.changes}),
                globals,
                trace,
            )?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

/// A roles file planned against the Host, as `iam roles apply plan` writes it: every change listed,
/// removals included, nothing applied (2-security/7 Roles). What Permguard Admin calls.
pub fn plan_roles(backend: &dyn Host, file: &[u8]) -> Result<Plan, Failure> {
    let declared: RolesFile = serde_norway::from_slice(file)
        .map_err(|error| Failure::usage(format!("not a roles file: {error}")))?;
    let wanted = resolve(backend, declared)?;
    let (held, undeclared) = held(backend, &wanted)?;
    Ok(Plan {
        kind: PLAN_KIND.to_owned(),
        changes: changes(&wanted, &held),
        wanted,
        undeclared,
    })
}

/// Runs a plan, compared again first: one the Host moved past is refused, never half applied
/// over another's changes. Answers how many changes it applied.
pub fn run_roles(backend: &dyn Host, plan: &Plan) -> Result<usize, Failure> {
    let (held, _) = held(backend, &plan.wanted)?;
    if changes(&plan.wanted, &held) != plan.changes {
        return Err(Failure::usage(
            "the Host's roles changed since the plan was made: plan again",
        ));
    }
    for change in &plan.changes {
        run(backend, change)?;
    }
    Ok(plan.changes.len())
}

/// The file's roles, each member resolved through the Host's providers.
fn resolve(
    backend: &dyn Host,
    declared: RolesFile,
) -> Result<BTreeMap<String, WantedRole>, Failure> {
    let mut wanted = BTreeMap::new();
    for (name, role) in declared.roles {
        let mut members = BTreeSet::new();
        for member in role.members {
            let named = [
                &member.local,
                &member.user,
                &member.issuer,
                &member.principal,
            ]
            .iter()
            .filter(|named| named.is_some())
            .count();
            if named != 1 {
                return Err(Failure::usage(format!(
                    "role `{name}`: a member names exactly one of local, user, issuer or principal"
                )));
            }
            let who = Who {
                local: member.local,
                user: member.user,
                issuer: member.issuer,
                principal: member.principal,
            };
            members.insert(principal_of(backend, &who)?);
        }
        let grants = role
            .grants
            .into_iter()
            .map(|grant| {
                if grant.operations.is_empty() {
                    return Err(Failure::usage(format!(
                        "role `{name}`: a grant names at least one operation"
                    )));
                }
                Ok(GrantShape::new(
                    &grant.operations,
                    &grant.selector,
                    &grant.types,
                    grant.expires,
                ))
            })
            .collect::<Result<_, _>>()?;
        wanted.insert(
            name,
            WantedRole {
                description: role.description,
                members,
                grants,
            },
        );
    }
    Ok(wanted)
}

/// The wanted roles as the Host holds them, and the roles it holds that the file does not name.
fn held(
    backend: &dyn Host,
    wanted: &BTreeMap<String, WantedRole>,
) -> Result<(BTreeMap<String, HeldRole>, Vec<String>), Failure> {
    let listed = backend.roles().map_err(client)?;
    let mut held = BTreeMap::new();
    let mut undeclared = Vec::new();
    for summary in listed.roles {
        if !wanted.contains_key(&summary.name) {
            undeclared.push(summary.name);
            continue;
        }
        let detail = backend.role(&summary.name).map_err(client)?;
        let mut grants: BTreeMap<GrantShape, Vec<(String, u64)>> = BTreeMap::new();
        for grant in detail
            .grants
            .iter()
            .filter(|grant| grant.status == "active")
        {
            grants
                .entry(GrantShape::new(
                    &grant.operations,
                    &grant.selector,
                    &grant.resource_types,
                    grant.expires_at.clone(),
                ))
                .or_default()
                .push((grant.grant_id.clone(), grant.revision));
        }
        held.insert(
            summary.name,
            HeldRole {
                description: detail.description,
                members: detail.members.into_iter().collect(),
                grants,
            },
        );
    }
    Ok((held, undeclared))
}

/// What converges `held` to `wanted`, widening first: sorted by kind, then by role.
fn changes(
    wanted: &BTreeMap<String, WantedRole>,
    held: &BTreeMap<String, HeldRole>,
) -> Vec<Change> {
    let mut changes = Vec::new();
    for (role, want) in wanted {
        let Some(have) = held.get(role) else {
            changes.push(Change::CreateRole {
                role: role.clone(),
                description: want.description.clone(),
            });
            changes.extend(want.members.iter().map(|member| Change::AddMember {
                role: role.clone(),
                member: member.clone(),
            }));
            changes.extend(want.grants.iter().map(|grant| Change::IssueGrant {
                role: role.clone(),
                grant: grant.clone(),
            }));
            continue;
        };
        if have.description != want.description {
            changes.push(Change::DescribeRole {
                role: role.clone(),
                description: want.description.clone(),
            });
        }
        for member in want.members.difference(&have.members) {
            changes.push(Change::AddMember {
                role: role.clone(),
                member: member.clone(),
            });
        }
        for member in have.members.difference(&want.members) {
            changes.push(Change::RemoveMember {
                role: role.clone(),
                member: member.clone(),
            });
        }
        for grant in &want.grants {
            if !have.grants.contains_key(grant) {
                changes.push(Change::IssueGrant {
                    role: role.clone(),
                    grant: grant.clone(),
                });
            }
        }
        for (grant, ids) in &have.grants {
            // A shape the file holds keeps one grant; its duplicates and every other shape go.
            let kept = usize::from(want.grants.contains(grant));
            for (grant_id, _) in ids.iter().skip(kept) {
                changes.push(Change::RevokeGrant {
                    role: role.clone(),
                    grant_id: grant_id.clone(),
                    grant: grant.clone(),
                });
            }
        }
    }
    changes.sort();
    changes
}

fn run(backend: &dyn Host, change: &Change) -> Result<(), Failure> {
    let member = |member: &str| MemberBody {
        request_id: request_id(),
        expected_revision: None,
        member: member.to_owned(),
    };
    match change {
        Change::CreateRole { role, description } => backend
            .create_role(&CreateRole {
                request_id: request_id(),
                expected_revision: None,
                name: role.clone(),
                description: description.clone(),
            })
            .map(|_| ()),
        Change::DescribeRole { role, description } => backend
            .update_role(
                role,
                &UpdateRole {
                    request_id: request_id(),
                    expected_revision: None,
                    description: description.clone(),
                },
            )
            .map(|_| ()),
        Change::AddMember { role, member: who } => {
            backend.add_member(role, &member(who)).map(|_| ())
        }
        Change::RemoveMember { role, member: who } => {
            backend.remove_member(role, &member(who)).map(|_| ())
        }
        Change::IssueGrant { role, grant } => backend
            .create_grant(&permguard_host::api::CreateGrant {
                request_id: request_id(),
                expected_revision: None,
                principal: format!("role:{role}"),
                operations: grant.operations.clone(),
                selector: grant.selector.clone(),
                resource_types: grant.types.clone(),
                constraints: BTreeMap::default(),
                expires_at: grant.expires.clone(),
            })
            .map(|_| ()),
        Change::RevokeGrant { grant_id, .. } => backend
            .plan_grant_revoke(
                grant_id,
                &permguard_host::api::PlanRevoke {
                    request_id: request_id(),
                    expected_revision: None,
                },
            )
            .and_then(|planned| {
                backend.run_grant_revoke(
                    grant_id,
                    &permguard_host::api::RunRevoke {
                        request_id: request_id(),
                        receipt: planned.receipt,
                    },
                )
            })
            .map(|_| ()),
    }
    .map_err(client)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn wanted(members: &[&str], grants: &[GrantShape]) -> WantedRole {
        WantedRole {
            description: "ops".to_owned(),
            members: members.iter().map(|member| (*member).to_owned()).collect(),
            grants: grants.iter().cloned().collect(),
        }
    }

    fn admin() -> GrantShape {
        GrantShape::new(&["authz.admin".to_owned()], "host", &[], None)
    }

    fn read() -> GrantShape {
        GrantShape::new(&["catalog.read".to_owned()], "plane/control/*", &[], None)
    }

    #[test]
    fn a_role_the_host_lacks_is_created_with_its_members_and_grants() {
        let wanted = BTreeMap::from([("ops".to_owned(), wanted(&["user:paperino"], &[admin()]))]);
        assert_eq!(
            changes(&wanted, &BTreeMap::new()),
            vec![
                Change::CreateRole {
                    role: "ops".to_owned(),
                    description: "ops".to_owned()
                },
                Change::AddMember {
                    role: "ops".to_owned(),
                    member: "user:paperino".to_owned()
                },
                Change::IssueGrant {
                    role: "ops".to_owned(),
                    grant: admin()
                },
            ]
        );
    }

    #[test]
    fn widening_comes_before_narrowing_and_a_converged_role_changes_nothing() {
        let wanted_roles =
            BTreeMap::from([("ops".to_owned(), wanted(&["user:paperino"], &[admin()]))]);
        let held = BTreeMap::from([(
            "ops".to_owned(),
            HeldRole {
                description: "ops".to_owned(),
                members: BTreeSet::from(["user:gastone".to_owned()]),
                grants: BTreeMap::from([(read(), vec![("g1".to_owned(), 3)])]),
            },
        )]);
        let planned = changes(&wanted_roles, &held);
        let kinds: Vec<&str> = planned
            .iter()
            .map(|change| match change {
                Change::CreateRole { .. } => "create",
                Change::DescribeRole { .. } => "describe",
                Change::AddMember { .. } => "add",
                Change::IssueGrant { .. } => "issue",
                Change::RemoveMember { .. } => "remove",
                Change::RevokeGrant { .. } => "revoke",
            })
            .collect();
        assert_eq!(kinds, ["add", "issue", "remove", "revoke"]);

        let converged = BTreeMap::from([(
            "ops".to_owned(),
            HeldRole {
                description: "ops".to_owned(),
                members: BTreeSet::from(["user:paperino".to_owned()]),
                grants: BTreeMap::from([(admin(), vec![("g2".to_owned(), 4)])]),
            },
        )]);
        assert!(changes(&wanted_roles, &converged).is_empty());
    }

    #[test]
    fn a_duplicate_grant_is_revoked_and_one_is_kept() {
        let wanted_roles = BTreeMap::from([("ops".to_owned(), wanted(&[], &[admin()]))]);
        let held = BTreeMap::from([(
            "ops".to_owned(),
            HeldRole {
                description: "ops".to_owned(),
                members: BTreeSet::new(),
                grants: BTreeMap::from([(
                    admin(),
                    vec![("g1".to_owned(), 1), ("g2".to_owned(), 2)],
                )]),
            },
        )]);
        assert_eq!(
            changes(&wanted_roles, &held),
            vec![Change::RevokeGrant {
                role: "ops".to_owned(),
                grant_id: "g2".to_owned(),
                grant: admin()
            }]
        );
    }

    #[test]
    fn a_grant_compares_by_what_it_allows_not_by_spelling() {
        assert_eq!(
            GrantShape::new(
                &["b".to_owned(), "a".to_owned(), "a".to_owned()],
                "host",
                &["*".to_owned()],
                None
            ),
            GrantShape::new(&["a".to_owned(), "b".to_owned()], "host", &[], None)
        );
    }

    #[test]
    fn the_roles_file_reads_members_as_the_command_line_names_them() {
        let file: RolesFile = serde_norway::from_str(
            "roles:\n  ops:\n    description: run it\n    members:\n      - local: paperino\n      - user: entra:alice@acme.com\n      - issuer: entra\n      - principal: spiffe://acme/ops\n    grants:\n      - operations: [authz.admin]\n        selector: host\n",
        )
        .expect("a roles file");
        let ops = &file.roles["ops"];
        assert_eq!(ops.members.len(), 4);
        assert!(ops.members[1].user.as_deref() == Some("entra:alice@acme.com"));
        assert_eq!(ops.grants[0].selector, "host");
        assert!(
            serde_norway::from_str::<RolesFile>("roles:\n  ops:\n    owner: x\n").is_err(),
            "an unknown key is refused"
        );
    }
}
