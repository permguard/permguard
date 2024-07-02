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
| 00000      | generic unknown error             |
| 00101      | invalid input parameter           |

## 01xxx Configuration errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 01000      | generic configuration error       |

## 04xxx Client errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 04000      | generic client error              |
| 04100      | invalid entity                    |
| 04101      | invalid account id                |
| 04102      | invalid id                        |
| 04103      | invalid uuid                      |
| 04104      | invalid name                      |

## 05xxx Server errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 05000      | generic server error              |
| 05001      | infrastructural error             |
| 05100      | generic storage error             |
| 05101      | duplicate entity                  |
| 05102      | not found                         |

## 09xxx Plugin errors

| Error Code | Description                       |
|------------|-----------------------------------|
| 09000      | generic plugin error              |
