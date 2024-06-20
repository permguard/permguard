---
title: "Schemas Management"
description: ""
summary: ""
date: 2023-08-17T11:47:15+01:00
lastmod: 2023-08-17T11:47:15+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "schemas-160cffa0b8b4cb23e5e742c85a475a4b"
weight: 6203
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Using the `Schemas` commands, it is possible to manage schemas.

```text
This command manages schemas.

Usage:
  PermGuard authz schemas [flags]
  PermGuard authz schemas [command]

Available Commands:
  list        List schemas
  update      Update a schema
  validate    Validate a schema

Flags:
      --account int   account id filter
  -h, --help          help for schemas

Global Flags:
  -o, --output string   output format (default "terminal")
  -v, --verbose         true for verbose output

Use "PermGuard authz schemas [command] --help" for more information about a command.
```

{{< callout context="caution" icon="alert-triangle" >}}
The output from your current version of PermGuard may differ from the example provided on this page.
{{< /callout >}}

## Validate a Schema

A schema can be modeled using either JSON or YAML,  and then validated using YAML format.

{{< tabs "permguard-schemas-validate" >}}
{{< tab "yaml" >}}

```yaml
---
name: car-rental
description: Car rental application
tag: 1.0.0
account_id: 581616507495
domains:
- name: backoffice
  resources:
  - name: car
    actions:
    - name: list
      description: List all cars
    - name: create
      description: Create a new car
    - name: delete
      description: Delete a car
- name: renting
  description: Car renting domain
  resources:
  - name: car
    description: Car resource
    actions:
    - name: list-available
      description: List available cars
    - name: show-details
      description: Show the car details
    - name: book
      description: Book a car
```

{{< /tab >}}
{{< tab "json" >}}

```json
{
  "name": "car-rental",
  "account_id": 581616507495,
  "domains": [
    {
      "name": "backoffice",
      "resources": [
        {
          "name": "car",
          "actions": [
            {
              "name": "list",
              "description": "List all cars"
            },
            {
              "name": "create",
              "description": "Create a new car"
            },
            {
              "name": "delete",
              "description": "Delete a car"
            }
          ]
        }
      ]
    },
    {
      "name": "renting",
      "description": "Car renting domain",
      "resources": [
        {
          "name": "car",
          "description": "Car resource",
          "actions": [
            {
              "name": "list-available",
              "description": "List available cars"
            },
            {
              "name": "show-details",
              "description": "Show the car details"
            },
            {
              "name": "book",
              "description": "Book a car"
            }
          ]
        }
      ]
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}

To validate the schema, use the following command:

```bash
permguard authz schemas validate -f ./car-rental/schema.yml --verbose
```

## Update an Schema

The `permguard authz schemas update` command allows to update a schema for the mandatory input account, schema id.

{{< tabs "permguard-schemas-create" >}}
{{< tab "terminal" >}}

```bash
❯ permguard authz schemas update --account 567269058122 -f ./car-rental/schema-001.yml -o json  --schemaid 8a753a7b-720c-4eb5-a22b-5e6eb83cf88b
```
output:
```
 8a753a7b-720c-4eb5-a22b-5e6eb83cf88b: car-rental
{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authz schemas update --account 567269058122 -f ./car-rental/schema-001.yml -o json  --schemaid 8a753a7b-720c-4eb5-a22b-5e6eb83cf88b --output json
{
  "schema": [
    {
      "schema_id": "442fddf2-4444-4b83-9b6f-ea91d3a25c8c",
      "created_at": "2023-03-21T23:08:52.476737Z",
      "updated_at": "2023-03-21T23:08:52.476737Z",
      "account_id": 567269058122,
      "name": "car-rental",
      "tag": "0.1",
      "description": "car rental",
      "domains": {
        "domains": [
          {
            "name": "backoffice",
            "description": "",
            "resources": [
              {
                "name": "car",
                "description": "",
                "actions": [
                  {
                    "name": "list",
                    "description": "List all cars"
                  }
                ]
              }
            ]
          }
        ]
      }
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}

## Get All Schema

The `permguard authz schemas list` command allows for the retrieval of all schemas.

{{< tabs "permguard-schemas-list" >}}
{{< tab "terminal" >}}

```bash
❯ permguard authz schemas list --account 567269058122
```
output:
```
 46968b2e-21df-4c1d-8606-f772a3f30b70: default
 6957ef83-6693-41c4-80b8-fe025a745f88: car-rental

{{< /tab >}}
{{< tab "json" >}}

```bash
❯ permguard authz schemas list --account 567269058122 --output json
{
  "schema": [
    {
      "schema_id": "46968b2e-21df-4c1d-8606-f772a3f30b70",
      "created_at": "2023-04-27T21:50:16.569511Z",
      "updated_at": "2023-04-27T21:50:16.569511Z",
      "account_id": 567269058122,
      "repository_id": "440e5c38-a403-497a-ac69-861f3789b01f",
      "repository_name": "default",
      "domains": {
        "domains": []
      }
    },
    {
      "schema_id": "6957ef83-6693-41c4-80b8-fe025a745f88",
      "created_at": "2023-04-27T21:50:16.663757Z",
      "updated_at": "2023-04-27T21:50:18.039045Z",
      "account_id": 567269058122,
      "repository_id": "b7bd0df8-3183-4dfb-9a29-c2d935be0d3d",
      "repository_name": "car-rental",
      "domains": {
        "domains": [
          {
            "name": "backoffice",
            "description": "",
            "resources": [
              {
                "name": "car",
                "description": "",
                "actions": [
                  {
                    "name": "list",
                    "description": "List all cars"
                  },
                  {
                    "name": "create",
                    "description": "Create a new car"
                  },
                  {
                    "name": "update",
                    "description": "Update a car"
                  },
                  {
                    "name": "delete",
                    "description": "Delete a car"
                  }
                ]
              }
            ]
          },
          {
            "name": "renting",
            "description": "Car renting domain",
            "resources": [
              {
                "name": "car",
                "description": "Car resource",
                "actions": [
                  {
                    "name": "list",
                    "description": "List cars"
                  },
                  {
                    "name": "show-detail",
                    "description": "Show the car details"
                  },
                  {
                    "name": "book",
                    "description": "Book a car"
                  }
                ]
              }
            ]
          }
        ]
      }
    }
  ]
}
```

{{< /tab >}}
{{< /tabs >}}
