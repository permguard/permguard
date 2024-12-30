---
title: "Configuration Options"
slug: "Configuration Options"
description: ""
summary: ""
date: 2023-08-15T21:01:37+01:00
lastmod: 2023-08-15T21:01:37+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "configuration-options-85030aefbc53456496023ea81b6941f9"
weight: 6102
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
**PermGuard** consists of multiple services that make up the **Authorization Server**. These services can be deployed as a single `all-in-one` instance or separately.

For production environments, using the `all-in-one` distribution is not recommended. A distributed deployment is preferred as it allows each service to scale independently, improving both flexibility and performance.

Each server provides a set of CLI options to configure startup parameters, runtime behaviors, and integrations, ensuring flexibility for diverse use cases.

## Servers

Regardless of the chosen distribution, the binary accepts the following options:

---
**\--debug**: *enables debug mode (default `false`).*

---
**\--log.level**: *specifies the log level (default `INFO`, options: `DEBUG`, `INFO`, `WARN`, `ERROR`, `DPANIC`, `PANIC`, `FATAL`).*

<details>
  <summary>Options</summary>

| LEVEL     | MEANING                                                                                                          |
|-----------|------------------------------------------------------------------------------------------------------------------|
| DEBUG     | Debug logs are typically voluminous, and are usually disabled in production.                                     |
| INFO      | Info is the default logging priority.                                                                            |
| WARN      | Warn logs are more important than Info, but don't need individual human review.                                  |
| ERROR     | Error logs are high-priority. If an application is running smoothly, it shouldn't generate any error-level logs. |
| DPANIC    | DPanic logs are particularly important errors. In development the logger panics after writing the message.       |
| PANIC     | Panic logs a message, then panics.                                                                               |
| FATAL     | Fatal logs a message, then calls os.Exit(1).                                                                     |

</details>

---

**\--storage.engine.central**: *data storage engine to be used for central data (default `sqlite`).*

---

**Storage Engines**: storage engine options are used to configure the storage engine responsible for data persistence in the services.

<details>
  <summary>SQLITE</summary>

**\--storage.engine.sqlite.dbname**: *sqlite database name (default **permguard**).*

---

</details>

---

**\--server.appdata**: *directory to be used as application data (default `./`).*

---

### server-aap

{{< callout >}} Application Administration Point. {{< /callout >}}

**\--storage.aap.engine.central**: *data storage engine to be used for the AAP central data. This overrides the `--storage.engine.central` option. Default: `sqlite`.*

---

**\--server.aap.data.fetch.maxpagesize int**: *maximum number of items to fetch per request. (default `10000`).*

---

**\--server.aap.data.enable.default.creation bool**: *enables the creation of default entities (e.g., tenants, identity sources) during data creation. (default `false`).*

---

**\--server.aap.grpc.port int**: *port to be used for exposing the aap grpc services. (default `9091`).*

---

### server-pap

{{< callout >}} Policy Administration Point. {{< /callout >}}

**\--storage.pap.engine.central**: *data storage engine to be used for the PAP central data. This overrides the `--storage.engine.central` option. Default: `sqlite`.*

---

**\--server.pap.data.fetch.maxpagesize int**: *maximum number of items to fetch per request. (default `10000`).*

---

**\--server.pap.grpc.port int**: *port to be used for exposing the pap grpc services. (default `9092`).*

---

### server-pip

{{< callout >}} Policy Information Point. {{< /callout >}}

**\--storage.pip.engine.central**: *data storage engine to be used for the PIP central data. This overrides the `--storage.engine.central` option. Default: `sqlite`.*

---

**\--server.pip.data.fetch.maxpagesize int**: *maximum number of items to fetch per request. (default `10000`).*

---

**\--server.pip.grpc.port int**: *port to be used for exposing the pip grpc services. (default `9096`).*

---

### server-pdp

{{< callout >}} Policy Decision Point. {{< /callout >}}

**\--storage.pdp.engine.central**: *data storage engine to be used for the PDP central data. This overrides the `--storage.engine.central` option. Default: `sqlite`.*

---

**\--server.pdp.data.fetch.maxpagesize int**: *maximum number of items to fetch per request. (default `10000`).*

---

**\--server.pdp.grpc.port int**: *port to be used for exposing the pdp grpc services. (default `9096`).*

---

## Provisioners

Regardless of the chosen distribution, the binary accepts the following options:

---
**\--debug**: *enables debug mode (default `false`).*

---
**\--log.level**: *specifies log level (default `INFO`, options: `DEBUG`, `INFO`, `WARN`, `ERROR`, `DPANIC`, `PANIC`, `FATAL`).*

<details>
  <summary>Options</summary>

| LEVEL     | MEANING                                                                                                          |
|-----------|------------------------------------------------------------------------------------------------------------------|
| DEBUG     | Debug logs are typically voluminous, and are usually disabled in production.                                     |
| INFO      | Info is the default logging priority.                                                                            |
| WARN      | Warn logs are more important than Info, but don't need individual human review.                                  |
| ERROR     | Error logs are high-priority. If an application is running smoothly, it shouldn't generate any error-level logs. |
| DPANIC    | DPanic logs are particularly important errors. In development the logger panics after writing the message.       |
| PANIC     | Panic logs a message, then panics.                                                                               |
| FATAL     | Fatal logs a message, then calls os.Exit(1).                                                                     |

</details>

---

<details>
  <summary>SQLITE</summary>

**\--storage.engine.sqlite.filepath**: *sqlite database file path (default `.`).*

---

</details>
