---
title: "Error Codes"
slug: "Error Codes"
description: ""
summary: ""
date: 2023-08-15T14:31:58+01:00
lastmod: 2023-08-15T14:31:58+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "error-codes-64a156e667534e54898895f676eead99"
weight: 8201
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

`PermGuard` divide errors into categories based on the error code. The error code is a 5 digit number that represents the error category.

## 00xxx Generic errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 00000      | core: unknown error               |

## 001xx Implementation Errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 00101      | code: feature not implemented     |

## 01xxx Configuration errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 01000      | config: generic error             |

## 04xxx Client errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 04000      | client: generic error             |

### 041xx Client Parameter Errors

| Error Code | Description                           |
|------------|---------------------------------------|
| 04100      | client: invalid client parameter      |
| 04101      | client: invalid pagination parameter  |

### 041xx Client Entity Errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 04110      | client: invalid entity            |
| 04111      | client: invalid ID                |
| 04112      | client: invalid UUID              |
| 04113      | client: invalid name              |

## 05xxx Server errors

| Error Code | Description                                      |
|------------|--------------------------------------------------|
| 05000      | server: generic error                            |
| 05001      | server: infrastructure error                     |

### 051xx Storage Errors

| Error Code | Description                                      |
|------------|--------------------------------------------------|
| 05100      | storage: generic error                           |
| 05101      | storage: entity mapping error                    |
| 05110      | storage: constraint error                        |
| 05111      | storage: foreign key constraint violation        |
| 05112      | storage: unique constraint violation             |
| 05120      | storage: entity not found in storage             |

## 08xxx: Command Line Interface Errors

| Error Code | Description                                      |
|------------|--------------------------------------------------|
| 08000      | cli: generic error                               |
| 08001      | cli: invalid arguments                           |
| 08002      | cli: invalid input                               |
| 08003      | cli: not a permguard workspace directory         |
| 08004      | cli: record already exists                       |
| 08005      | cli: record not found                            |

## 081xx: Command Line Interface File System Errors
| Error Code | Description                                      |
|------------|--------------------------------------------------|
| 08100      | cli: file system error                           |
| 08101      | cli: operation on directory failed               |
| 08102      | cli: operation on file failed                    |
| 08110      | cli: workspace operation failed                  |

## 09xxx Plugin errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 09000      | plugin: generic error             |
