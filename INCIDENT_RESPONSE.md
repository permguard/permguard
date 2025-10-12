# Incident Response Plan

This document describes how the **Permguard** team manages and responds to
security incidents, critical bugs, or operational issues that may impact users
or the reliability of the project.

---

## 1. Purpose and Scope

This plan applies to all components of the
[permguard/permguard](https://github.com/permguard/permguard) repository,
including its source code, build pipelines, and published releases.

---

## 2. Roles and Contacts

- **Incident Coordinator:** [@os-permguard](https://github.com/os-permguard) (default contact)
- **Security Contact:**
  All incidents must be reported **confidentially** using
  [GitHub Security Advisories][gsa].

No other communication channels (issues, discussions, PRs, or email) should be used
to disclose security problems.

---

## 3. Detection and Reporting

All potential security vulnerabilities or incidents are treated as **sensitive information**.

If you suspect a vulnerability or security breach, please:

1. Report it privately through [GitHub Security Advisories][gsa].
2. Avoid discussing or disclosing it publicly until the team confirms resolution.

---

## 4. Initial Response

Upon receiving a report, the Permguard team will:

1. **Acknowledge** receipt and thank the reporter.
2. **Evaluate** the report for accuracy and severity. (See [CIA model][cia])
3. **Notify** relevant maintainers or contributors if needed.
4. **Contain** the problem quickly (e.g., revoke access tokens, disable compromised workflows).

---

## 5. Investigation and Mitigation

- **Identify** root cause and potential scope of impact.
- **Remediate** the issue by:
  - Applying or developing patches.
  - Rotating or revoking credentials if necessary.
- **Record** all actions taken for audit and transparency purposes.

---

## 6. Timeline for Resolution

A formal response or mitigation plan will generally be provided within **30 days**
from the initial acknowledgment of the report.
Critical vulnerabilities may be prioritized sooner.

---

## 7. Communication and Disclosure

All discussions about security incidents occur **privately** via GitHub Security Advisories.

Once a fix is deployed and validated:

- A public disclosure or summary will be coordinated with the reporter.
- A CVE may be requested when appropriate.
- A changelog or advisory will be published to inform users.

---

## 8. Post-Incident Review

After resolution, the team will:

1. **Review** the event and the effectiveness of the response.
2. **Improve** related documentation, tooling, or processes.
3. **Acknowledge** contributors or reporters (unless they request anonymity).
4. **Share** lessons learned internally to prevent recurrence.

---

## 9. Related Documents

- [SECURITY.md](./SECURITY.md)

---

[gsa]: https://github.com/permguard/permguard/security/advisories/new
[cia]: https://www.energy.gov/femp/operational-technology-cybersecurity-energy-systems#cia
