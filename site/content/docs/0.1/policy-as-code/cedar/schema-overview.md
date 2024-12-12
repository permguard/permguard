---
title: "Schema Overview"
slug: "Schema Overview"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "schema-grammar-f68ed4d511834c2db6a8d1055f56c807"
weight: 4102
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
The **schema** follows the official `JSON Schema` specification, available in the <a href="https://docs.cedarpolicy.com/schema/json-schema.html" target="_blank" rel="noopener noreferrer">official documentation</a>.

PermGuard requires the file to be named `schema.json` and placed in the root of the workspace.

Below is an example of a directory structure that includes the schema file:

```plaintext
.
├── .permguard
├── schema.yml
```

Below is a sample schema:

```yaml
{
    "PhotoFlash": {
        "entityTypes": {
            "User": {
                "memberOfTypes": [ "UserGroup" ],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "department": { "type": "String" },
                        "jobLevel": { "type": "Long" }
                    }
                }
            },
            "UserGroup": { },
            "Photo": {
                "memberOfTypes": [ "Album" ],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "private": { "type": "Boolean" },
                        "account": {
                            "type": "Entity",
                            "name": "Account"
                        }
                    }
                }
            },
            "Album": {
                "memberOfTypes": [ "Album" ],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "private": { "type": "Boolean" },
                        "account": {
                            "type": "Entity",
                            "name": "Account"
                        }
                    }
                }
            },
            "Account": {
                "memberOfTypes": [],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "owner": {
                            "type": "Entity",
                            "name": "User"
                        },
                        "admins": {
                            "required": false,
                            "type": "Set",
                            "element": {
                                "type": "Entity",
                                "name": "User"
                            }
                        }
                    }
                }
            }
        },
        "actions": {
            "viewPhoto": {
                "appliesTo": {
                    "principalTypes": [ "User" ],
                    "resourceTypes": [ "Photo" ],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "authenticated": { "type": "Boolean" }
                        }
                    }
                }
            },
            "listAlbums": {
                "appliesTo": {
                    "principalTypes": [ "User" ],
                    "resourceTypes": [ "Account" ],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "authenticated": { "type": "Boolean" }
                        }
                    }
                }
            },
            "uploadPhoto": {
                "appliesTo": {
                    "principalTypes": [ "User" ],
                    "resourceTypes": [ "Album" ],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "authenticated": { "type": "Boolean" },
                            "photo": {
                                "type": "Record",
                                "attributes": {
                                    "file_size": { "type": "Long" },
                                    "file_type": { "type": "String" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```
