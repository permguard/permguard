<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Syntax highlighting grammars

Shiki, which VitePress uses to colour code blocks, ships no grammar for the policy languages, so the documentation registers these three in `.vitepress/config.mts` (`markdown.languages`).

| File                      | Language | Source                                                                                                                         | Licence    |
| ------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `cedar.tmLanguage.json`   | Cedar    | `syntaxes/cedar.tmLanguage.json` of [cedar-policy/vscode-cedar](https://github.com/cedar-policy/vscode-cedar), unmodified      | Apache-2.0 |
| `rego.tmLanguage.json`    | Rego     | `syntaxes/Rego.tmLanguage` of [open-policy-agent/vscode-opa](https://github.com/open-policy-agent/vscode-opa), at commit `9291e7c81d3656b1005e5a323834d837a321f979`, converted from plist to JSON | Apache-2.0 |
| `dogwood.tmLanguage.json` | Dogwood  | written for this site from the keywords of `dogwood-language` 1.1.0 (`src/extension/temporal/grammar.pest`) and `dogwood-syntax` 1.1.0 | Apache-2.0 |

`cedar.tmLanguage.json`: Copyright Cedar Contributors, licensed under the Apache License, Version 2.0.
`rego.tmLanguage.json`: Copyright the Open Policy Agent authors, licensed under the Apache License, Version 2.0; the only change is the format, plist to JSON, with the same rules.
The Apache License, Version 2.0 is at <https://www.apache.org/licenses/LICENSE-2.0>.

The grammars carry no logo or trademark: Cedar, Rego, Open Policy Agent and Dogwood are named in text only, as their owners' guidelines allow.
