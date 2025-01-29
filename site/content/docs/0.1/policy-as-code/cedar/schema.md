---
title: "Schema"
slug: "Schema"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "schema-f68ed4d511834c2db6a8d1055f56c807"
weight: 4102
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
The **schema** follows the official `JSON Schema` specification, available in the <a href="https://docs.cedarpolicy.com/schema/json-schema.html" target="_blank" rel="noopener noreferrer">official documentation</a>.

Permguard requires the file to be named `schema.json` and placed in the root of the workspace.

Below is an example of a directory structure that includes the schema file:

```plaintext
.
├── .permguard
├── schema.json
```

Below is a sample schema:

```yaml
{
    "MagicFarmacia::Platform": {
      "entityTypes": {
        "Branch": {
          "shape": {
            "type": "Record",
            "attributes": {
              "city": {
                "type": "String"
              }
            }
          },
          "memberOfTypes": [
            "Account"
          ]
        },
        "Account": {
          "shape": {
            "type": "Record",
            "attributes": {
              "active": {
                "type": "Boolean"
              }
            }
          },
          "memberOfTypes": []
        }
      },
      "actions": {
        "create": {
          "appliesTo": {
            "principalTypes": [
              "Permguard::IAM::User",
              "Permguard::IAM::Actor"
            ],
            "resourceTypes": [
              "Account",
              "Branch"
            ]
          }
        },
        "update": {
          "appliesTo": {
            "principalTypes": [
              "Permguard::IAM::User",
              "Permguard::IAM::Actor"
            ],
            "resourceTypes": [
              "Account",
              "Branch"
            ]
          }
        },
        "delete": {
          "appliesTo": {
            "principalTypes": [
              "Permguard::IAM::User",
              "Permguard::IAM::Actor"
            ],
            "resourceTypes": [
              "Account",
              "Branch"
            ]
          }
        },
        "view": {
          "appliesTo": {
            "principalTypes": [
              "Permguard::IAM::User",
              "Permguard::IAM::Actor"
            ],
            "resourceTypes": [
              "Account",
              "Branch"
            ],
            "context": {
              "type": "Record",
              "attributes": {
                "isSuperUser": {
                  "type": "Boolean",
                  "required": true
                }
              }
            }
          }
        }
      }
    }
  }
```
