---
title: "Cli Flags v0.2"
slug: "Cli Flags"
description: ""
summary: ""
date: 2023-08-15T21:01:37+01:00
lastmod: 2023-08-15T21:01:37+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "cli-flags-85030aefbc53456496023ea81b6941f9"
weight: 6006
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The CLI flags provide a method for executing the permguard binaries via the command line.
There are multiple executables that can be run, generally they can be divided between servers and provisioners.

## Servers

Irrespective of the chosen distribution, the binary supports the following flags:

---

**--debug**: _Enable debug mode (default `false`)._

---

**--log.level**: _Set log level (default `INFO`, options: `DEBUG`, `INFO`, `WARN`, `ERROR`, `DPANIC`, `PANIC`, `FATAL`)._

<details>
  <summary>Options</summary>

| LEVEL  | MEANING                                                                                                          |
| ------ | ---------------------------------------------------------------------------------------------------------------- |
| DEBUG  | Debug logs are typically voluminous, and are usually disabled in production.                                     |
| INFO   | Info is the default logging priority.                                                                            |
| WARN   | Warn logs are more important than Info, but don't need individual human review.                                  |
| ERROR  | Error logs are high-priority. If an application is running smoothly, it shouldn't generate any error-level logs. |
| DPANIC | DPanic logs are particularly important errors. In development the logger panics after writing the message.       |
| PANIC  | Panic logs a message, then panics.                                                                               |
| FATAL  | Fatal logs a message, then calls os.Exit(1).                                                                     |

</details>

---

**--storage.central.engine**: _Data storage engine to be used for central data (default `sqlite`)._

---

**--storage.proximity.engine**: _Data storage engine to be used for proximity data (default `sqlite`)._

---

**Storage Engines**: Storage engine flags are used to configure the storage engine to be used for the central and proximity data.

<details>
  <summary>SQLITE</summary>

**--storage.engine.sqlite.dbname**: _sqlite database name (default `permguard`)._

---

</details>

---

**--server.appdata**: _Directory to be used as application data (default `./`)._

---

### server-aap

{{< callout >}} Account Administration Point. {{< /callout >}}

**--server.aap.data.fetch.maxpagesize int**: _maximum number of items to fetch per request. (default `10000`)._

---

**--server.aap.enable.default.creation bool**: _the creation of default entities (e.g., tenants, identity sources) during data creation. (default `false`)._

---

**--server.aap.grpc.port int**: _port to be used for exposing the aap grpc services. (default `9091`)._

---

### server-pap

{{< callout >}} Policy Administration Point. {{< /callout >}}

**--server.pap.data.fetch.maxpagesize int**: _maximum number of items to fetch per request. (default `10000`)._

---

**--server.pap.grpc.port int**: _port to be used for exposing the pap grpc services. (default `9092`)._

---

### server-pdp

{{< callout >}} Policy Decision Point. {{< /callout >}}

**--server.pdp.data.fetch.maxpagesize int**: _maximum number of items to fetch per request. (default `10000`)._

---

**--server.pdp.grpc.port int**: _port to be used for exposing the pdp grpc services. (default `9096`)._

---

## Provisioners

Irrespective of the chosen distribution, the binary supports the following flags:

---

**--debug**: _Enable debug mode (default `false`)._

---

**--log.level**: _Set log level (default `INFO`, options: `DEBUG`, `INFO`, `WARN`, `ERROR`, `DPANIC`, `PANIC`, `FATAL`)._

<details>
  <summary>Options</summary>

| LEVEL  | MEANING                                                                                                          |
| ------ | ---------------------------------------------------------------------------------------------------------------- |
| DEBUG  | Debug logs are typically voluminous, and are usually disabled in production.                                     |
| INFO   | Info is the default logging priority.                                                                            |
| WARN   | Warn logs are more important than Info, but don't need individual human review.                                  |
| ERROR  | Error logs are high-priority. If an application is running smoothly, it shouldn't generate any error-level logs. |
| DPANIC | DPanic logs are particularly important errors. In development the logger panics after writing the message.       |
| PANIC  | Panic logs a message, then panics.                                                                               |
| FATAL  | Fatal logs a message, then calls os.Exit(1).                                                                     |

</details>

---

<details>
  <summary>SQLITE</summary>

**--storage.engine.sqlite.filepath**: _sqlite database file path (default `.`)._

---

</details>
