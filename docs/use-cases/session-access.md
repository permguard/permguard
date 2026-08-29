<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Session access, and decisions that depend on what already happened

**The domain:** a gateway in front of documents. People sign in, read things, and
sign out again. An agent or an integration does the same, on somebody's behalf.

**The question this use case answers:** *may this user read this document?* is not
the whole question. The one the business actually asks is *may this user read this
document **given that** they signed in recently and have not signed out since?* —
and the answer is not in the request.

This page describes the domain and the controls in plain terms — no Permguard,
Cedar or Dogwood knowledge assumed. The runnable version, with policies you can
apply and events you can submit, is in
**[examples/dogwood-session-access](../../examples/dogwood-session-access)**.

---

## 1. Why this is a different kind of question

Every control in [release and deployment operations](release-pipeline.md) can be
decided from the request in front of you. *Is Alice on the Payments team? Is this
a production environment? Is there an open incident?* — the request, or something
the request can carry, says.

Session access cannot be decided that way:

> Alice may read a document if she logged in within the last hour and has not
> logged out since.

Nothing in a `Read` request says whether a `Login` happened. Only the *history*
says, and the history is a sequence of things that happened at particular times.

The usual answers are all bad in a way that takes a while to notice:

| The usual answer | What goes wrong |
| --- | --- |
| Put a `logged_in_at` claim in the token | the token is now a cache of a fact that changed after it was minted — a logout does not reach it |
| Have the gateway look up the session and pass it in | the *gateway* now decides what "logged in recently" means, in code, per gateway |
| Have the policy call the session service | the decision now depends on a network hop that can be slow, down, or lying |

Each of them moves the rule out of the policy and into something that is neither
reviewed nor audited as policy. The rule stops being a sentence somebody can read
and becomes a property of an integration.

## 2. The organisation

Very little structure is needed, which is part of the point.

**People and machines**, each an identity the gateway already knows:

| Identity | What it is |
| --- | --- |
| alice | a person, signing in through the gateway |
| bob | another person, who has not signed in |

**Things that happen**, each with a time:

| Occurrence | Kind | What it means |
| --- | --- | --- |
| `Login` | request, then response | somebody asked to sign in, and it succeeded |
| `Read` | request | somebody is asking to read a document |
| `Logout` | request, then response | somebody signed out |

**The thing being protected:** documents, behind one gateway.

## 3. The control

One rule, and it is the whole use case:

> **Permit a read** when a successful `Login` for *this same user* happened within
> the last hour, and no `Logout` for them has happened since.

Read it twice and notice what it does *not* say. It does not say "if the token
claims a login". It does not say "ask the session service". It says what has to
have happened, and the platform's job is to know whether it did.

## 4. Whose history is it?

The subtle half of the control is the phrase *this same user*.

Alice's login must not permit Bob's read. That is obvious to a person and is
exactly the sort of thing a policy gets wrong, because the natural way to write it
is to add a condition — *and the login's user equals the read's user* — which is a
condition somebody can forget, get backwards, or leave off one branch of.

So it is not written as a condition. The event schema declares that occurrences
are **partitioned by the caller's identity**, and a temporal question then ranges
over one identity's history by construction:

```text
alice's history:  Login·request  Login·response  Read·request  …
bob's history:    Read·request   …
```

Bob's read cannot see Alice's login because it is not in the history being asked.
Not "because the policy checks" — because the two are different histories.

The value is never taken from the caller. The platform derives it from the
request's authoritative root, and a caller that also sends a disagreeing copy is
**refused** rather than having one of the two picked: whoever chooses which history
an event belongs to controls who its login permits.

## 5. Why the platform asks instead of deciding

Everything in section 1 fails for one reason: the fact the rule depends on lives
somewhere that is not the policy.

Putting the history *under* the decision point fixes that, and it costs something
honest:

- **The occurrence is recorded before it is decided.** A decision that depended on
  history the process then lost would be a decision nobody can reproduce, so the
  event is durable — on disk, in a hash chain — before any engine sees it and
  before an answer is returned.
- **Recording is not free.** One disk barrier per submission is the floor, and it
  is the price of an authorization trail that survives the process.
- **A restart is not a fresh start.** The history is on disk; the engine that
  decides against it starts empty, so it is replayed before it answers. A platform
  that skipped that would return a `deny` indistinguishable from a correct one.
- **Two data centres are two histories until they are shipped.** Which history a
  decision ranged over is a deployment's explicit choice, and it travels in every
  answer — because the same request, decided in two places, can legitimately
  differ, and nothing else explains why.

## 6. What it leaves behind

Every occurrence is a record, and the records are the audit:

| The record carries | Why somebody wants it |
| --- | --- |
| the exact commit of the policies | what the rule *was* when it decided, months later |
| the policy that decided | which sentence, not "some policy" |
| the history key | whose history it was in |
| its position in a hash chain | that it has not been altered, and that none before it is missing |
| the mode and watermark of the history | exactly what was visible, so the decision can be replayed |

A reviewer asking "why was Bob refused on the 3rd?" gets the sentence, the
history, and the proof that neither has been edited since.

## 7. What is refused, and why that matters here

An event store whose contents can be shaped by a caller is not evidence. So a
submission is refused — never accepted with the offending part quietly dropped —
when it names an action the schema does not declare, carries a field nobody
declared, contradicts a pin, or reuses an identifier under different content.

The last one is worth stating plainly: one identifier carrying two different
occurrences is a client bug or a replay, and picking either would be the platform
deciding which of the two happened.

## Run it

```sh
task cp-dogwood       # copy the example into the current directory
task run:experimental      # both planes in one process, with the event path on
```

Then follow **[examples/dogwood-session-access](../../examples/dogwood-session-access)**,
which submits five occurrences in order and shows what each answers — including the
one that returns *no verdict at all*, because it recorded something rather than
deciding it.
