---
layout: page
pageClass: pg-page-concepts
title: How Permguard works
description: Authorization leaves the code. Applications and AI agents ask Permguard, and every answer names the policy that decided it.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup>
import { onBeforeUnmount, onMounted } from 'vue'
import { withBase } from 'vitepress'

// "Follow one request": the step nearest the middle of the window lights its part of the picture.
// Without JavaScript, or before it runs, every step and every part stay lit.
let observer
onMounted(() => {
  const root = document.querySelector('.pgx-follow')
  if (!root || !('IntersectionObserver' in window)) return
  const steps = [...root.querySelectorAll('.pgx-follow__steps li')]
  const show = (step) => {
    root.dataset.step = step.dataset.step
    for (const li of steps) li.classList.toggle('is-active', li === step)
  }
  observer = new IntersectionObserver((entries) => {
    for (const entry of entries) if (entry.isIntersecting) show(entry.target)
  }, { rootMargin: '-45% 0px -45% 0px' })
  for (const li of steps) observer.observe(li)
})
onBeforeUnmount(() => observer?.disconnect())
</script>

<main class="pgx-page">
  <section class="pgx-hero pgx-hero--center">
    <div class="pgx-kicker">How it works</div>
    <h1>Authorization leaves the code.</h1>
    <p>Identity left your applications years ago. Authorization stayed inside them, different in every one. Permguard takes it out, gives it an owner and keeps every decision on record.</p>
    <div class="pgx-hero-visual">
      <div class="pgx-hero-visual__art" role="img" aria-label="The Control Plane distributes signed policy to a Policy Decision Point beside every workload, in three clusters. Applications and AI agents ask their PDP through the Permguard SDKs, for Go, Java, .NET, Node.js, Python and Rust, their Policy Enforcement Point; identities come from your Identity Provider. Every decision becomes a signed, chained record, exported to your own SIEM and cyber threat intelligence.">
        <svg class="pgx-hv pgx-hv--wide" viewBox="0 0 1040 420" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-hv-wide-flow" gradientUnits="userSpaceOnUse" x1="0" y1="84" x2="0" y2="186"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-wide-flow)" d="M520 84 V120 H349 V186"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-wide-flow)" d="M520 84 V186"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-wide-flow)" d="M520 84 V120 H799 V186"/>
            <path class="pgx-hv__flow pgx-hv__flow--identity" d="M170 212 H200"/>
            <path class="pgx-hv__flow pgx-hv__flow--identity" d="M860 210 H840"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M295 270 V336"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M520 270 V336"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M745 270 V336"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M840 360 H870"/>
          </g>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="400" y="20" width="240" height="64" rx="14"/>
            <text class="pgx-hv__k" x="520" y="46" text-anchor="middle">CONTROL PLANE</text>
            <text class="pgx-hv__s" x="520" y="68" text-anchor="middle">versioned · signed policy</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--idp">
            <rect x="20" y="180" width="150" height="64" rx="14"/>
            <text class="pgx-hv__k" x="95" y="206" text-anchor="middle">IDENTITY</text>
            <text class="pgx-hv__s" x="95" y="228" text-anchor="middle">Your IdP</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="200" y="150" width="190" height="120" rx="16"/>
            <text class="pgx-hv__m" x="216" y="172">cluster · eu-west</text>
            <rect class="pgx-hv__pod" x="216" y="186" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="267" y="205" text-anchor="middle">orders · app</text>
            <rect class="pgx-hv__pdp" x="324" y="186" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="349" y="205" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="216" y="226" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="267" y="245" text-anchor="middle">planner · agent</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--2" x="324" y="226" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="349" y="245" text-anchor="middle">PDP</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="425" y="150" width="190" height="120" rx="16"/>
            <text class="pgx-hv__m" x="441" y="172">cluster · us-east</text>
            <rect class="pgx-hv__pod" x="441" y="186" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="492" y="205" text-anchor="middle">billing · api</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--3" x="549" y="186" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="574" y="205" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="441" y="226" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="492" y="245" text-anchor="middle">support · agent</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--4" x="549" y="226" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="574" y="245" text-anchor="middle">PDP</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="650" y="150" width="190" height="120" rx="16"/>
            <text class="pgx-hv__m" x="666" y="172">edge</text>
            <rect class="pgx-hv__pod" x="666" y="186" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="717" y="205" text-anchor="middle">gateway</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--5" x="774" y="186" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="799" y="205" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="666" y="226" width="102" height="30" rx="8"/><text class="pgx-hv__p" x="717" y="245" text-anchor="middle">worker · agent</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--6" x="774" y="226" width="50" height="30" rx="8"/><text class="pgx-hv__d" x="799" y="245" text-anchor="middle">PDP</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--sdk">
            <rect x="860" y="150" width="160" height="120" rx="14"/>
            <text class="pgx-hv__k" x="940" y="170" text-anchor="middle">PEP · SDKS</text>
          <g class="pgx-hv__lang"><rect x="873" y="180" width="64" height="20" rx="10"/><text x="905" y="194" text-anchor="middle">Go</text></g>
          <g class="pgx-hv__lang"><rect x="943" y="180" width="64" height="20" rx="10"/><text x="975" y="194" text-anchor="middle">Java</text></g>
          <g class="pgx-hv__lang"><rect x="873" y="204" width="64" height="20" rx="10"/><text x="905" y="218" text-anchor="middle">.NET</text></g>
          <g class="pgx-hv__lang"><rect x="943" y="204" width="64" height="20" rx="10"/><text x="975" y="218" text-anchor="middle">Node.js</text></g>
          <g class="pgx-hv__lang"><rect x="873" y="228" width="64" height="20" rx="10"/><text x="905" y="242" text-anchor="middle">Python</text></g>
          <g class="pgx-hv__lang"><rect x="943" y="228" width="64" height="20" rx="10"/><text x="975" y="242" text-anchor="middle">Rust</text></g>
            <text class="pgx-hv__m" x="940" y="261" text-anchor="middle">in every workload</text>
          </g>
          <text class="pgx-hv__k" x="200" y="326">EVIDENCE · SIGNED · CHAINED</text>
          <g class="pgx-hv__chain">
            <path class="pgx-hv__link" d="M290 360 H310 M400 360 H420 M510 360 H530 M620 360 H640 M730 360 H750"/>
            <rect class="pgx-hv__block pgx-hv__block--1" x="200" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="245" y="365" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--2" x="310" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="355" y="365" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--3" x="420" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="465" y="365" text-anchor="middle">deny</text>
            <rect class="pgx-hv__block pgx-hv__block--4" x="530" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="575" y="365" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--5" x="640" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="685" y="365" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--6" x="750" y="340" width="90" height="40" rx="8"/><text class="pgx-hv__p" x="795" y="365" text-anchor="middle">deny</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--siem">
            <rect x="870" y="328" width="150" height="64" rx="14"/>
            <text class="pgx-hv__k" x="945" y="354" text-anchor="middle">EXPORT</text>
            <text class="pgx-hv__s" x="945" y="376" text-anchor="middle">Your SIEM · CTI</text>
          </g>
        </svg>
        <svg class="pgx-hv pgx-hv--compact" viewBox="0 0 360 676" aria-hidden="true" focusable="false">
          <defs>
            <linearGradient id="pgx-hv-compact-flow" gradientUnits="userSpaceOnUse" x1="0" y1="74" x2="0" y2="332"><stop offset="0" stop-color="#f05c80"/><stop offset="1" stop-color="#cc34df"/></linearGradient>
          </defs>
          <g class="pgx-hv__flows">
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-compact-flow)" d="M180 74 V112"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-compact-flow)" d="M180 204 V222"/>
            <path class="pgx-hv__flow pgx-hv__flow--policy" stroke="url(#pgx-hv-compact-flow)" d="M180 314 V332"/>
            <path class="pgx-hv__flow pgx-hv__flow--identity" d="M180 424 V440"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M180 516 V534"/>
            <path class="pgx-hv__flow pgx-hv__flow--evidence" d="M180 574 V606"/>
          </g>
          <g class="pgx-hv__node pgx-hv__node--cp">
            <rect x="70" y="14" width="220" height="60" rx="14"/>
            <text class="pgx-hv__k" x="180" y="38" text-anchor="middle">CONTROL PLANE</text>
            <text class="pgx-hv__s" x="180" y="60" text-anchor="middle">versioned · signed policy</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="16" y="112" width="328" height="92" rx="16"/>
            <text class="pgx-hv__m" x="32" y="134">cluster · eu-west</text>
            <rect class="pgx-hv__pod" x="32" y="152" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="80" y="174" text-anchor="middle">orders</text>
            <rect class="pgx-hv__pdp" x="134" y="152" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="154" y="174" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="186" y="152" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="234" y="174" text-anchor="middle">planner</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--2" x="288" y="152" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="308" y="174" text-anchor="middle">PDP</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="16" y="222" width="328" height="92" rx="16"/>
            <text class="pgx-hv__m" x="32" y="244">cluster · us-east</text>
            <rect class="pgx-hv__pod" x="32" y="262" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="80" y="284" text-anchor="middle">billing</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--3" x="134" y="262" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="154" y="284" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="186" y="262" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="234" y="284" text-anchor="middle">support</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--4" x="288" y="262" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="308" y="284" text-anchor="middle">PDP</text>
          </g>
          <g class="pgx-hv__cluster">
            <rect class="pgx-hv__frame" x="16" y="332" width="328" height="92" rx="16"/>
            <text class="pgx-hv__m" x="32" y="354">edge</text>
            <rect class="pgx-hv__pod" x="32" y="372" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="80" y="394" text-anchor="middle">gateway</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--5" x="134" y="372" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="154" y="394" text-anchor="middle">PDP</text>
            <rect class="pgx-hv__pod" x="186" y="372" width="96" height="34" rx="8"/><text class="pgx-hv__p" x="234" y="394" text-anchor="middle">worker</text>
            <rect class="pgx-hv__pdp pgx-hv__pdp--6" x="288" y="372" width="40" height="34" rx="8"/><text class="pgx-hv__d" x="308" y="394" text-anchor="middle">PDP</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--sdk">
            <rect x="16" y="440" width="328" height="76" rx="14"/>
            <text class="pgx-hv__k" x="180" y="460" text-anchor="middle">PEP · SDKS IN EVERY WORKLOAD</text>
          <g class="pgx-hv__lang"><rect x="32" y="469" width="92" height="19" rx="9"/><text x="78" y="483" text-anchor="middle">Go</text></g>
          <g class="pgx-hv__lang"><rect x="134" y="469" width="92" height="19" rx="9"/><text x="180" y="483" text-anchor="middle">Java</text></g>
          <g class="pgx-hv__lang"><rect x="236" y="469" width="92" height="19" rx="9"/><text x="282" y="483" text-anchor="middle">.NET</text></g>
          <g class="pgx-hv__lang"><rect x="32" y="492" width="92" height="19" rx="9"/><text x="78" y="506" text-anchor="middle">Node.js</text></g>
          <g class="pgx-hv__lang"><rect x="134" y="492" width="92" height="19" rx="9"/><text x="180" y="506" text-anchor="middle">Python</text></g>
          <g class="pgx-hv__lang"><rect x="236" y="492" width="92" height="19" rx="9"/><text x="282" y="506" text-anchor="middle">Rust</text></g>
          </g>
          <g class="pgx-hv__chain">
            <path class="pgx-hv__link" d="M95 554 H109 M173 554 H187 M251 554 H265"/>
            <rect class="pgx-hv__block pgx-hv__block--1" x="31" y="534" width="64" height="40" rx="8"/><text class="pgx-hv__p" x="63" y="559" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--2" x="109" y="534" width="64" height="40" rx="8"/><text class="pgx-hv__p" x="141" y="559" text-anchor="middle">permit</text>
            <rect class="pgx-hv__block pgx-hv__block--3" x="187" y="534" width="64" height="40" rx="8"/><text class="pgx-hv__p" x="219" y="559" text-anchor="middle">deny</text>
            <rect class="pgx-hv__block pgx-hv__block--4" x="265" y="534" width="64" height="40" rx="8"/><text class="pgx-hv__p" x="297" y="559" text-anchor="middle">permit</text>
          </g>
          <g class="pgx-hv__node pgx-hv__node--siem">
            <rect x="90" y="606" width="180" height="56" rx="14"/>
            <text class="pgx-hv__k" x="180" y="628" text-anchor="middle">EXPORT</text>
            <text class="pgx-hv__s" x="180" y="650" text-anchor="middle">Your SIEM · CTI</text>
          </g>
        </svg>
      </div>
      <dl class="pgx-legend">
        <div data-term="cp"><dt><a :href="withBase('/how-it-works/glossary#control-plane')">Control Plane</a></dt><dd>Where policies are written, versioned and signed.</dd></div>
        <div data-term="pdp"><dt><a :href="withBase('/how-it-works/glossary#pdp')">PDP</a></dt><dd>Policy Decision Point: answers permit or deny, beside each workload.</dd></div>
        <div data-term="pep"><dt><a :href="withBase('/how-it-works/glossary#pep')">PEP · SDK</a></dt><dd>Policy Enforcement Point: the line in your code that asks, and obeys.</dd></div>
        <div data-term="idp"><dt><a :href="withBase('/how-it-works/glossary#identity-provider')">Your IdP</a></dt><dd>Says who the user is. Permguard decides what they may do.</dd></div>
        <div data-term="evidence"><dt><a :href="withBase('/how-it-works/glossary#evidence')">Evidence</a></dt><dd>A signed record of every decision, chained to the one before.</dd></div>
        <div data-term="siem"><dt><a :href="withBase('/how-it-works/glossary#siem')">Your SIEM · CTI</a></dt><dd>Your own security tools: analyse the records beside your other logs and cross them with your cyber threat intelligence.</dd></div>
      </dl>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The gap</div><h2>Identity moved out. Authorization did not.</h2></div><p>Inside the applications, who may do what is still decided by code.</p></div>
    <div class="pgx-principles">
      <article><span>Then</span><h3>Every application kept its passwords.</h3><p>In its own files and databases. Hashes and salts came later, but each application stayed an island.</p></article>
      <article><span>Later</span><h3>Identity left the application.</h3><p>An Identity Provider and standard protocols. Identity got an owner, a console and an audit.</p></article>
      <article><span>Today</span><h3>Authorization is still in the code.</h3><p>An <code>if</code> here, a role table there, and nobody holds the map. AI agents now act inside applications at machine speed: every forgotten rule is an open door.</p></article>
    </div>
    <div class="vp-doc pgx-compare">
      <div class="pgx-compare__col"><p class="pgx-compare__label"><b>Today</b>The rule is an <code>if</code>, copied into every handler that needs it.</p>

```go
func readBudget(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user.Role != "finance" && user.ID != "alice" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	serveBudget(w)
}
```

</div>
      <div class="pgx-compare__col pgx-compare__col--after"><p class="pgx-compare__label"><b>With Permguard</b>The code asks. The rule lives in a policy, out of the code.</p>

```go
func readBudget(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	answer, err := pdp.Evaluate(r.Context(), &permguard.EvaluateRequest{
		Zone:     "quickstart",
		Ledger:   "policies",
		Subject:  &permguard.Entity{Type: "User", ID: user.ID},
		Action:   &permguard.Action{Name: "read"},
		Resource: &permguard.Entity{Type: "Document", ID: "budget"},
	})
	if err != nil || !answer.Decision { // no answer is a no: fail closed
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	serveBudget(w)
}
```

</div>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The same turn</div><h2>Ask. Decide. Enforce.</h2></div><p>Every application and every AI agent asks Permguard the same question.</p></div>
    <div class="pgx-discovery pgx-discovery--decision" role="img" aria-label="An application or AI agent asks whether a subject may perform an action on a resource, the Policy Decision Point evaluates the published policy, and the application enforces the answer, which names the policy that decided it.">
      <article><small>PEP · ASK</small><strong>May alice read the budget?</strong><span>subject · action · resource</span></article><i>→</i>
      <article class="pgx-discovery__accent"><small>PDP · DECIDE</small><strong>Evaluate the published policy</strong><span>Permguard Data Plane</span></article><i>→</i>
      <article><small>PEP · ENFORCE</small><strong>Apply the answer</strong><span>permit or deny, naming its policy</span></article>
    </div>
    <p>The <strong>Policy Enforcement Point</strong> guards an action: it asks and it enforces. The <strong>Policy Decision Point</strong> decides, with the exact policy version it names in the answer.</p>
    <div class="pgx-parc">
      <article><small>SUBJECT</small><strong>Who</strong><span><code>User alice</code>, as your IdP knows her</span></article>
      <article><small>ACTION</small><strong>Does what</strong><span><code>read</code></span></article>
      <article><small>RESOURCE</small><strong>On what</strong><span><code>Document budget</code></span></article>
      <article><small>CONTEXT</small><strong>Under which facts</strong><span>time, network, risk: anything the policy reads</span></article>
    </div>
    <div class="vp-doc pgx-anatomy">
      <div class="pgx-anatomy__row"><div class="pgx-anatomy__label"><b>1 · The question</b><span>Your code sends who, does what, on what, in which zone and ledger.</span></div>

```json
{
  "zone": "quickstart",
  "ledger": "policies",
  "subject": { "type": "User", "id": "alice" },
  "action": { "name": "read" },
  "resource": { "type": "Document", "id": "budget" },
  "context": {}
}
```

</div>
      <div class="pgx-anatomy__row"><div class="pgx-anatomy__label"><b>2 · The rule</b><span>A Cedar policy in that ledger. It permits exactly this; whatever no policy permits is denied.</span></div>

```cedar
@alias("alice-can-read")
permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Document::"budget"
);
```

</div>
      <div class="pgx-anatomy__row"><div class="pgx-anatomy__label"><b>3 · The answer</b><span>Permit, the policy that decided and the id of this decision, already on record. Ask for <code>bob</code> and <code>decision</code> is <code>false</code>: “no policy permits this request”.</span></div>

```json
{
  "decision": true,
  "request_id": "quickstart-1",
  "context": {
    "id": "01a1f111-df65-77cf-b171-3facea0cbc27",
    "reason_admin": {
      "code": "200",
      "message": "permitted by 92efe24a-8620-8bcd-b026-a19c1f440c45"
    },
    "policies": ["92efe24a-8620-8bcd-b026-a19c1f440c45"],
    "evidence": { "mode": "required", "status": "durable" }
  }
}
```

</div>
    </div>
    <p class="pgx-anatomy__note">A real answer of the Data Plane, abridged: the full one also carries a message meant for the user and the position of the record. Run it yourself in <a :href="withBase('/how-it-works/getting-started')">Getting Started</a>.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">An analogy</div><h2>Think of an office building.</h2></div><p>Six things you already know, and what each one is in Permguard.</p></div>
    <div class="pgx-analogy" role="table" aria-label="An office building compared with Permguard">
      <div class="pgx-analogy__head" role="row"><span role="columnheader">In the building</span><span role="columnheader">What it does</span><span role="columnheader">In Permguard</span></div>
      <div role="row"><strong role="cell">Your badge</strong><span role="cell">Says who you are.</span><a role="cell" :href="withBase('/how-it-works/glossary#identity-provider')">Your Identity Provider</a></div>
      <div role="row"><strong role="cell">The door reader</strong><span role="cell">Asks before the door opens, and keeps it shut on a no.</span><a role="cell" :href="withBase('/how-it-works/glossary#pep')">PEP: the SDK in your code</a></div>
      <div role="row"><strong role="cell">The security desk</strong><span role="cell">Checks the rulebook and answers yes or no.</span><a role="cell" :href="withBase('/how-it-works/glossary#pdp')">PDP: the Data Plane</a></div>
      <div role="row"><strong role="cell">The rulebook</strong><span role="cell">Who may enter where, and when.</span><a role="cell" :href="withBase('/how-it-works/glossary#policy')">A policy</a></div>
      <div role="row"><strong role="cell">Head office</strong><span role="cell">Writes the rulebook and sends signed copies to every desk.</span><a role="cell" :href="withBase('/how-it-works/glossary#control-plane')">The Control Plane</a></div>
      <div role="row"><strong role="cell">The access log</strong><span role="cell">Every yes and every no, in a log nobody can rewrite.</span><a role="cell" :href="withBase('/how-it-works/glossary#evidence')">Evidence</a></div>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Step by step</div><h2>Follow one request.</h2></div><p>Scroll: the picture follows alice's request from her click to the open document.</p></div>
    <div class="pgx-follow">
      <div class="pgx-follow__stage" role="img" aria-label="alice uses an application; its Policy Enforcement Point asks the Data Plane, the PDP, which decides with a policy mirrored from the Control Plane, records the decision as evidence exported to the SIEM, and then answers.">
        <svg class="pgx-hv pgx-follow__art" viewBox="0 0 560 300" aria-hidden="true" focusable="false">
          <g class="pgx-hv__flows">
            <path class="f f-click pgx-hv__flow pgx-hv__flow--identity" d="M120 150 H150"/>
            <path class="f f-ask pgx-hv__flow pgx-hv__flow--evidence" d="M304 156 H380"/>
            <path class="f f-answer pgx-hv__flow pgx-hv__flow--evidence" d="M380 178 H304"/>
            <path class="f f-mirror pgx-hv__flow pgx-hv__flow--identity" d="M460 64 V110"/>
            <path class="f f-record pgx-hv__flow pgx-hv__flow--evidence" d="M430 194 V214 H330 V236"/>
            <path class="f f-export pgx-hv__flow pgx-hv__flow--evidence" d="M400 260 H430"/>
          </g>
          <g class="f f-user pgx-hv__node"><rect x="10" y="120" width="110" height="60" rx="14"/><text class="pgx-hv__k" x="65" y="144" text-anchor="middle">USER</text><text class="pgx-hv__s" x="65" y="166" text-anchor="middle">alice</text></g>
          <g class="f f-app pgx-hv__node"><rect x="150" y="100" width="170" height="100" rx="14"/><text class="pgx-hv__k" x="235" y="126" text-anchor="middle">APPLICATION</text></g>
          <g class="f f-pep pgx-hv__node pgx-hv__node--pep"><rect x="166" y="144" width="138" height="42" rx="10"/><text class="pgx-hv__d" x="235" y="170" text-anchor="middle">PEP · SDK</text></g>
          <g class="f f-cp pgx-hv__node pgx-hv__node--cp"><rect x="380" y="10" width="160" height="54" rx="14"/><text class="pgx-hv__k" x="460" y="32" text-anchor="middle">CONTROL PLANE</text><text class="pgx-hv__s" x="460" y="52" text-anchor="middle">signed policy</text></g>
          <g class="f f-pdp pgx-hv__node"><rect x="380" y="110" width="160" height="84" rx="14"/><text class="pgx-hv__k" x="460" y="136" text-anchor="middle">DATA PLANE</text><text class="pgx-hv__s" x="460" y="158" text-anchor="middle">PDP</text><text class="pgx-hv__m" x="460" y="178" text-anchor="middle">policy already here</text></g>
          <g class="f f-ev pgx-hv__node"><rect x="150" y="236" width="250" height="52" rx="14"/><text class="pgx-hv__k" x="275" y="258" text-anchor="middle">EVIDENCE</text><text class="pgx-hv__m" x="275" y="277" text-anchor="middle">signed · chained</text></g>
          <g class="f f-siem pgx-hv__node"><rect x="430" y="236" width="110" height="52" rx="14"/><text class="pgx-hv__k" x="485" y="258" text-anchor="middle">EXPORT</text><text class="pgx-hv__s" x="485" y="278" text-anchor="middle">SIEM</text></g>
        </svg>
      </div>
      <ol class="pgx-follow__steps">
        <li data-step="1"><b>01</b><h3>alice opens the budget.</h3><p>A handler in your application is about to serve the document. Before it does, the Permguard SDK, your Policy Enforcement Point, stops and asks.</p></li>
        <li data-step="2"><b>02</b><h3>The PEP asks its PDP.</h3><p>Subject <code>alice</code>, action <code>read</code>, resource <code>budget</code>. The PDP is the Data Plane: a sidecar beside the application, a remote service, or a library inside the process.</p></li>
        <li data-step="3"><b>03</b><h3>The PDP decides with the policy it already holds.</h3><p>The Control Plane published the policy as a signed version, and the Data Plane mirrored and verified it before this request. Deciding needs no call to the Control Plane.</p></li>
        <li data-step="4"><b>04</b><h3>The decision is on record.</h3><p>In the shipped configurations the answer leaves only once its record is durable: signed and chained to the ones before, so nobody can alter it unnoticed. Export the records to your SIEM.</p></li>
        <li data-step="5"><b>05</b><h3>The answer comes back.</h3><p>Permit, naming the policy that decided and the id of this decision. No policy that permits means deny; no answer at all, the PEP treats as a no.</p></li>
        <li data-step="6"><b>06</b><h3>The PEP enforces.</h3><p>The handler serves the budget to alice. For bob, the same line returns 403.</p></li>
      </ol>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The structure</div><h2>Govern centrally. Decide close.</h2></div><p>One Permguard Server: a Host and the planes you choose, together or apart.</p></div>
    <div class="pgx-system-map" role="img" aria-label="A Permguard Server Host provides identity, authorization, keys, audit, membership and streams to the Authority, Control and Data planes. Identities stay with your Identity Provider; decisions and audit become signed, chained records; one URL discovers the rest.">
      <div class="pgx-system-map__frame">
        <div class="pgx-system-map__label"><strong>Permguard Server</strong><span>one Host · the planes you deploy</span></div>
        <div class="pgx-system-map__host"><small>SERVER HOST</small><strong>Identity · Authorization · Keys · Audit · Membership · Streams</strong></div>
        <div class="pgx-system-map__bus" aria-hidden="true"></div>
        <div class="pgx-system-map__planes">
          <article><small>AUTHORITY PLANE</small><strong>Admit</strong><span>service accounts · access tokens</span></article>
          <article><small>CONTROL PLANE</small><strong>Publish</strong><span>versioned, signed policy</span></article>
          <article><small>DATA PLANE</small><strong>Decide</strong><span>sidecar · remote · embedded</span></article>
        </div>
      </div>
      <div class="pgx-system-map__protocols">
        <article><small>IDENTITY</small><strong>Your Identity Provider</strong><span>identities stay where they are</span></article>
        <article><small>EVIDENCE</small><strong>Signed records</strong><span>decisions · events · audit</span></article>
        <article><small>DISCOVERY</small><strong>One URL</strong><span>server → plane → interface</span></article>
      </div>
    </div>
    <p class="pgx-system-map__truth">Policies are written once, in the Control Plane: versioned, signed and distributed. The Data Plane decides beside the workload, as a sidecar or a remote service, or inside the process through the engine libraries. The <a :href="withBase('/trust-plane')">Trust Plane</a>, for authority continuity with PIC-X, is next on the roadmap.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Beyond authorization</div><h2>Authorization is the first question.</h2></div><p>Permguard governs the rules an execution follows: written once, answered where the execution runs, proven afterwards. Every dimension of execution is in its scope; each joins these pages when it ships.</p></div>
    <div class="pgx-dimensions" role="table" aria-label="One Control Plane governs every question. Application policies are answered by the PDP in the Data Plane, available today. Trust Anchors, a policy engine for PIC-like protocols with interfaces of its own, will answer in the Data Plane, next. Authority continuity, with PIC-X, is the Trust Plane's, next.">
      <div class="pgx-dimensions__govern" role="rowheader"><small>GOVERNED BY</small><strong>Control Plane</strong><span>one ledger model, signed versions, for every question</span></div>
      <div class="pgx-dimensions__rows">
        <div class="pgx-dimensions__head" role="row"><span role="columnheader">The question</span><span role="columnheader">Answered by</span><span role="columnheader">Proven by</span><span role="columnheader">Status</span></div>
        <div class="pgx-dimensions__row pgx-dimensions__row--live" role="row"><div role="cell"><strong>May alice read the budget?</strong><span>application policies</span></div><div role="cell"><strong>PDP</strong><span>Data Plane</span></div><div role="cell"><span>a signed decision record</span></div><div role="cell"><em class="pgx-status pgx-status--live">Available</em></div></div>
        <div class="pgx-dimensions__row" role="row"><div role="cell"><strong>May this hand-off cross the boundary?</strong><span>a policy engine for PIC-like protocols; its interfaces differ from the PDP's, so it has its own name</span></div><div role="cell"><strong>Trust Anchor</strong><span>Data Plane</span></div><div role="cell"><span>the same evidence chain</span></div><div role="cell"><em class="pgx-status pgx-status--next">Next</em></div></div>
        <div class="pgx-dimensions__row" role="row"><div role="cell"><strong>Does authority hold along the chain?</strong><span>authority continuity, with <a href="https://pic-protocol.org/pic-x">PIC-X</a>, the trust-plane component of PIC</span></div><div role="cell"><strong><a :href="withBase('/trust-plane')">Trust Plane</a></strong><span>its own plane</span></div><div role="cell"><span>the same evidence chain</span></div><div role="cell"><em class="pgx-status pgx-status--next">Next</em></div></div>
      </div>
    </div>
    <p class="pgx-dimensions__note">Each question arrives as its own interface, on the plane that answers it, and a server advertises only the interfaces it actually runs.</p>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Who does what</div><h2>Authorization gets an owner.</h2></div><p>The rules no longer start in the code.</p></div>
    <div class="pgx-principles">
      <article><span>Security</span><h3>Owns the rules.</h3><p>Application authorization becomes a first-level control, with every decision in view.</p></article>
      <article><span>Compliance</span><h3>Holds the proof.</h3><p>Policies aligned with regulation, decisions recorded and verifiable after the fact.</p></article>
      <article><span>Development</span><h3>Enforces.</h3><p>Only the Policy Enforcement Point, through SDKs for Go, Java, .NET, Node.js, Python and Rust.</p></article>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">The tools</div><h2>One server. Every role.</h2></div><p>The same policies and decisions, from a terminal, a desktop or your code.</p></div>
    <div class="pgx-cards pgx-cards--3">
      <a class="pgx-card" :href="withBase('/command-line')"><span>CLI</span><h3>Permguard CLI</h3><p>Author, validate, test offline and publish policy, from a terminal or a pipeline.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card pgx-card--accent" :href="withBase('/how-it-works/install#permguard-admin')"><span>Desktop</span><h3>Permguard Admin</h3><p>Ledgers where every change is a commit, decision logs, analytics and export.</p><b aria-hidden="true">→</b></a>
      <article class="pgx-card"><span>Code</span><h3>SDKs</h3><p>The Policy Enforcement Point in your application: Go, Java, .NET, Node.js, Python and Rust.</p></article>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Observable</div><h2>Every decision, on record.</h2></div><p>The new challenge: make the application security layer observable.</p></div>
    <div class="pgx-principles">
      <article><span>Recorded</span><h3>Who, what, on which resource, under which policy.</h3><p>Permitted or denied. Records are chained and signed, so anyone can verify that nobody touched them.</p></article>
      <article><span>Analysed</span><h3>Into your SIEM.</h3><p>Export decisions as JSON Lines or CSV, beside your firewall logs, and cross them with threat intelligence.</p></article>
      <article><span>Stable</span><h3>The policy stays. The context moves.</h3><p>When the threat changes, the policy is not rewritten: the information in the evaluation context changes.</p></article>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Mental model</div><h2>From policy to proof.</h2></div><p>Three rules are enough.</p></div>
    <div class="pgx-flow" role="img" aria-label="A policy moves from authoring to the control plane, then to the data plane, where a decision produces evidence.">
      <div class="pgx-flow__track"><i aria-hidden="true"></i></div>
      <div class="pgx-flow__step"><b>01</b><strong>Author</strong><span>policy as code</span></div>
      <div class="pgx-flow__step"><b>02</b><strong>Publish</strong><span>signed head</span></div>
      <div class="pgx-flow__step"><b>03</b><strong>Mirror</strong><span>verify first</span></div>
      <div class="pgx-flow__step"><b>04</b><strong>Decide</strong><span>fail closed</span></div>
      <div class="pgx-flow__step"><b>05</b><strong>Prove</strong><span>evidence</span></div>
    </div>
    <div class="pgx-principles">
      <article><span>Immutable</span><h3>A version never changes.</h3><p>Policies become content-addressed objects. A signed head selects the accepted commit.</p></article>
      <article><span>Local</span><h3>Decisions stay near the workload.</h3><p>The Data Plane already holds the verified policy: a decision never waits for the Control Plane.</p></article>
      <article><span>Traceable</span><h3>An answer leaves evidence.</h3><p>The signer, the decision and the exact policy version remain independently verifiable.</p></article>
    </div>
  </section>

  <section class="pgx-section" id="faq">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Questions</div><h2>What people ask first.</h2></div><p>Straight answers before you start.</p></div>
    <div class="pgx-faq">
      <details><summary>Does every check go over the network?</summary><p>Only as far as the PDP you choose. As a sidecar it is a local call beside your application; embedded, it is a function call in the process. The PDP never calls the Control Plane to decide: the policy is already there.</p></details>
      <details><summary>What happens if the Control Plane is down?</summary><p>The Data Plane keeps deciding with the policy it already mirrored and verified; only new versions wait until the Control Plane is back. If you set an expiry on a ledger, a copy older than that is refused rather than served.</p></details>
      <details><summary>What happens if the PDP does not answer?</summary><p>The SDK returns an error, not a deny: a deny is a normal answer with <code>decision</code> false. Treat an error as a no, as the code above does: fail closed.</p></details>
      <details><summary>Does Permguard replace my Identity Provider?</summary><p>No. Your IdP says who the user is; your code passes that subject to Permguard, which decides what it may do. The Authority Plane only issues the tokens that callers of Permguard itself present.</p></details>
      <details><summary>Which language are policies written in?</summary><p>Cedar or Rego, side by side in the same ledger. Dogwood, for decisions that depend on history, is experimental. See <a :href="withBase('/how-it-works/policy-languages')">Policy as Code</a>.</p></details>
      <details><summary>Can I test a policy without a server?</summary><p>Yes: <code>permguard test</code> runs the same engine and decision algebra as the Data Plane, offline. See <a :href="withBase('/how-it-works/getting-started')">Getting Started</a>.</p></details>
      <details><summary>Can anyone call my PDP?</summary><p>Only in development, where the configuration grants it publicly. In production every caller presents an access token of the Authority Plane, and each plane checks it itself. See <a :href="withBase('/authority-plane/access-tokens')">Access Tokens</a>.</p></details>
      <details><summary>Is it worth it for a small application?</summary><p>Yes: any application that decides who may do what gains from rules out of the code, tested offline and kept on record. The value grows with the stakes: enterprise and complex applications, AI agents acting on someone's behalf, rules that change without a redeploy, and the need to show who was allowed what, and why.</p></details>
    </div>
  </section>

  <section class="pgx-section">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Start</div><h2>See it working.</h2></div><p>The tools first. A real server next.</p></div>
    <div class="pgx-cards pgx-cards--3">
      <a class="pgx-card pgx-card--accent" :href="withBase('/how-it-works/install')"><span>01</span><h3>Install</h3><p>The Permguard CLI and Permguard Admin on your machine.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/container-images')"><span>02</span><h3>Containers</h3><p>The server images, verified before they run.</p><b aria-hidden="true">→</b></a>
      <a class="pgx-card" :href="withBase('/how-it-works/getting-started')"><span>03</span><h3>Getting Started</h3><p>Create, test, publish and ask a policy.</p><b aria-hidden="true">→</b></a>
    </div>
  </section>

  <section class="pgx-section pgx-section--tint">
    <div class="pgx-section-head"><div><div class="pgx-kicker">Concepts</div><h2>Go one layer deeper.</h2></div></div>
    <div class="pgx-link-grid">
      <a :href="withBase('/how-it-works/architecture')"><strong>Server, Host &amp; Planes</strong><span>one Host · the planes you deploy</span></a>
      <a :href="withBase('/how-it-works/policy-languages')"><strong>Policy as Code</strong><span>Cedar · Rego · Dogwood</span></a>
      <a :href="withBase('/how-it-works/zones-and-ledgers')"><strong>Zones &amp; Ledgers</strong><span>the security boundary · its ledgers</span></a>
      <a :href="withBase('/how-it-works/policy-storage')"><strong>Git-like Versioning</strong><span>commits · history · signed heads</span></a>
      <a :href="withBase('/how-it-works/notp')"><strong>NOTP Protocol</strong><span>how policy moves between planes</span></a>
      <a :href="withBase('/how-it-works/policy-lifecycle')"><strong>Policy Delivery</strong><span>commit → signed version → running PDP</span></a>
      <a :href="withBase('/how-it-works/decision-lifecycle')"><strong>Decision Path</strong><span>request → evaluation → answer</span></a>
      <a :href="withBase('/how-it-works/evidence')"><strong>Verifiable Evidence</strong><span>record → chain → proof</span></a>
      <a :href="withBase('/how-it-works/bring-your-own-data-plane')"><strong>Bring Your Own Data Plane</strong><span>Permguard policy → your runtime</span></a>
      <a :href="withBase('/how-it-works/temporal-authorization')"><strong>Temporal Authorization</strong><span>history becomes policy input</span></a>
      <a :href="withBase('/authority-plane')"><strong>Authority Plane</strong><span>who may call Permguard itself</span></a>
      <a :href="withBase('/how-it-works/glossary')"><strong>Glossary</strong><span>every term, in one line</span></a>
    </div>
    <nav class="pgx-pager pgx-pager--next-only" aria-label="Documentation pages">
      <a class="pgx-pager__next" :href="withBase('/how-it-works/install')"><span>Next</span><strong>Install <b aria-hidden="true">→</b></strong></a>
    </nav>
  </section>
</main>
