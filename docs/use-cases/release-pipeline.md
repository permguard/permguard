<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release and deployment operations

**The domain:** an enterprise software delivery platform. Teams cut releases, a
pipeline builds and signs them, somebody approves them, a controller deploys them,
and when production breaks somebody rolls them back.

**The question this use case answers:** every one of those steps is a decision
somebody could get wrong, or could be talked into. Who is allowed to take each
step, under what conditions, and how do you prove afterwards what was allowed and
why?

This page describes the domain and the controls in plain terms — no Permguard
knowledge assumed. The runnable version, with policies you can apply and requests
you can send, is in
**[examples/release-pipeline](../../examples/release-pipeline)**.

---

## 1. The organisation

Three kinds of thing, and that is all the structure the controls need.

**People**, each in a team, each with a role:

| Person | Team | Role |
| --- | --- | --- |
| Alice | Payments | Developer |
| Bob | Payments | Release Manager |
| Charlie | Platform | Platform Administrator |

**Teams**, each owning services:

| Team | Owns |
| --- | --- |
| Payments | `payments-api` |
| Platform | `platform-api` |

**Machines** — the automation, which acts on its own and needs permission just as
people do:

| Workload | Its one job |
| --- | --- |
| `ci-pipeline` | builds a release and uploads the artifact |
| `artifact-signer` | signs the artifact, and nothing else |
| `deployment-controller` | performs the deployment |

That last table is the part most access models leave out. A pipeline that can do
whatever the engineer who wrote it could do is a pipeline that is a way around
every control below.

---

## 2. The lifecycle

```text
   a release is opened          release:create        Alice
            │
            ▼
   the build uploads it         artifact:upload       ci-pipeline
            │
            ▼
   it is signed                 artifact:sign         artifact-signer
            │
            ▼
   it is approved               release:signoff       Bob
            │
            ▼
   it is deployed               deployment:execute    deployment-controller
            │
            ▼
   it breaks, and goes back     deployment:rollback   whoever is on call
```

Six steps, six different actors, and six different reasons somebody might not be
allowed to take the step. The platform asks before each one; nothing below changes
how the platform *performs* the step, only whether it is permitted to.

---

## 3. The controls

Each control is written here the way a policy reads: what is allowed, and the
condition. This is pseudocode — the real Cedar and Rego are in the lab.

### Only the owning team opens a release

```text
ALLOW  release:create  on a service
WHEN   the person is in the team that owns that service
```

Alice may cut a release of `payments-api`, because Payments owns it. The same
request for `platform-api` is refused — not because Alice is untrusted, but because
ownership is where the responsibility sits.

### Only a Release Manager of the owning team approves one

```text
ALLOW  release:signoff  on a release
WHEN   the person is a Release Manager
AND    the person is in the team that owns the release's service
```

### But an approval by its own author is not an approval

```text
REFUSE release:signoff
WHEN   the person approving is the person who created the release
```

This is **separation of duties**, and it is the single most valuable rule on the
page. Note its shape: it does not grant anything, it takes something away, and it
takes it away from somebody who was otherwise entitled. Bob is a Release Manager;
Bob may approve releases; Bob may not approve *his own*.

Two more refusals of the same kind:

```text
REFUSE release:signoff   WHEN the tests did not pass
REFUSE release:signoff   WHEN the artifact is not signed
```

Approving an untested release is not a thing anybody should be *able* to do, no
matter their role. Expressing that as a refusal rather than as a condition on the
grant is what keeps it true when somebody later adds another way to approve.

### Each machine may do its one job, and only for what it built

```text
ALLOW  artifact:upload
WHEN   the caller is the build pipeline
AND    its identity is verified
AND    it is the pipeline of the service the release belongs to

ALLOW  artifact:sign
WHEN   the caller is the signing workload
AND    its identity is verified

ALLOW  deployment:execute
WHEN   the caller is the deployment controller
AND    its identity is verified
AND    the release was approved
AND    the artifact is signed
AND    the security scan passed
```

The build asking to *sign* is refused. Not by a rule against it — by there being
no rule for it. Nothing permits it, so the answer is no.

### A production rollback is an incident action

```text
ALLOW  deployment:rollback  on a service
WHEN   the person is in the team that owns it

REFUSE deployment:rollback
WHEN   the environment is production
AND    NOT (the person is on call AND an incident is open)
```

Read those two together, because they are the point. Alice is in Payments, so she
is *entitled* to roll `payments-api` back. On an ordinary afternoon she is refused
anyway. At three in the morning, on call, with an incident open, the same request
is allowed.

Nothing about Alice changed. That is why this cannot be solved with roles alone: a
role is a property of a person, and this control is a property of the moment.

---

## 4. Two shapes of rule, and why both

Look back over section 3 and the controls fall into two groups.

| | Entitlement | Guardrail |
| --- | --- | --- |
| Asks | is this person, structurally, the right person? | is this action, right now, safe? |
| Reads | teams, ownership, roles | tests, signatures, scans, incidents, who is on call |
| Changes | when the organisation changes | through the day |
| Says | yes | no |

They are kept apart deliberately, and a **refusal from a guardrail overrides a
grant from an entitlement**. That is the mechanism behind every interesting case
above: Bob is entitled and refused; Alice is entitled and refused, until the
incident opens.

Mixing them into one rulebook loses this. The moment "may approve releases" and
"but not their own" live in the same condition, the second is one edit away from
being dropped by somebody who only meant to widen the first.

There is also a quieter kind of no. **Nothing permitting** is a refusal too — it is
what stops the build from signing. A system that distinguishes the two can tell an
auditor the difference between *a control refused this* and *nobody ever granted
it*.

---

## 5. Why the platform asks instead of deciding

Every step above is performed by the delivery platform. What the platform does not
do is decide whether it may.

```text
      somebody, or something, asks for a step
                      │
                      ▼
          the delivery platform
                      │
                      │  who is asking, for what, on what, under which conditions
                      ▼
                  Permguard
                      │
       ┌──────────────┴──────────────┐
       ▼                             ▼
     ALLOW                         DENY
  take the step                 refuse it
```

Three things follow from the split, and they are the reason to bother:

**The rules are one thing, not eleven.** The same control applies whether the
release was cut from the web console, the CLI, an API call or a pipeline. There is
no fourth copy of the separation-of-duties rule that somebody forgot to update.

**Changing a control does not mean shipping the platform.** "Production rollbacks
now also require a second on-call engineer" is a change to a policy, reviewed and
released like any other change, without a deployment of the delivery platform
itself.

**The decision is written down.** Which brings us to the part that matters most in
a regulated environment.

---

## 6. What it leaves behind

Six months after the fact, the question is never "is Bob allowed to approve
releases". It is:

> Who approved `v2.4.0`, when, and under which version of the rules?

Every decision is recorded, and each record carries the exact version of the
policies that produced it, plus the identity of the specific policy that decided.
So the answer is not a reconstruction from log lines — it is a record that says:

- this person, at this time, asked to approve this release;
- the answer was yes;
- it was **this** approval rule that permitted it;
- and the rules in force were **this** exact version.

The refusals are evidence too, and often better evidence. A record showing that
self-approval was attempted and refused, naming the control that refused it, is
what demonstrates the control exists and works — which is what an audit is actually
asking.

The records are signed by the component that produced them and can be verified
independently, without trusting the server that hands them over.

---

## 7. Where the controls live in the delivery flow

Nothing here replaces the pipeline. It sits beside each step:

| Step | Asked before | If refused |
| --- | --- | --- |
| Open a release | the release exists | the request fails; nothing is created |
| Upload an artifact | the artifact is accepted | the upload is rejected |
| Sign an artifact | the signature is made | no signature is produced |
| Approve a release | the release is marked approved | the approval does not happen |
| Deploy | anything is changed in production | the deployment does not start |
| Roll back | the previous version is restored | the rollback is refused, and recorded |

The failure mode of a missing check is the interesting column. A deployment that
starts and is then found to have been unauthorised is an incident; a deployment
that never starts is a refused request. The ask comes first for that reason.

---

## Run it

```bash
task run:all
```

then follow **[examples/release-pipeline/README.md](../../examples/release-pipeline/README.md)**,
which applies these policies and sends twenty-three requests — including the two that
matter most: Bob refused his own approval, and Alice allowed to roll back only once
the incident is open.
