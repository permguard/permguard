# Contributing

By contributing to this project, you agree to follow our [code of conduct](https://github.com/permguard/.github/blob/main/CODE_OF_CONDUCT.md).

## Set up your machine

`permguard` is written in [Go](https://go.dev/).

Prerequisites:

- [Task](https://taskfile.dev/installation)
- [Go 1.25+](https://go.dev/doc/install)

Some development or test workflows may rely on external tools.
If these tools are not installed locally, the related tests will be skipped automatically:

- [cosign](https://github.com/sigstore/cosign)
- [Docker](https://www.docker.com/)
- [GPG](https://gnupg.org)
- [Syft](https://github.com/anchore/syft)

## Building

Clone `permguard` anywhere:

```sh
git clone git@github.com:permguard/permguard.git
```

`cd` into the directory and install the dependencies:

```bash
task mod
```

You should then be able to build the binaries:

```bash
task build
```

## Testing your changes

Create a new branch for your changes and build the project incrementally as you work:

```sh
task build
```

Once you’re satisfied with the results, run the full validation pipeline:

```sh
task ci
```

Before committing, ensure the codebase is properly formatted and consistent with the project’s style guidelines:

```sh
task fmt
```

## Creating a commit

Commit messages should be clear and consistent.
To maintain a common standard, we follow the Conventional Commits specification.
You can find the full documentation on [their website](https://www.conventionalcommits.org).

## Submitting a pull request

Push your branch to your `permguard` fork and open a pull request against the main branch.

Below are a few recommendations:

- Before submitting a pull request, please raise an issue to discuss the changes you wish to make. This will help us understand the context of your changes and provide feedback.
- Make sure sure each source file include the appropriate license header.

  ```go
  // Copyright (c) 2022 Nitro Agility S.r.l.
  // SPDX-License-Identifier: Apache-2.0
  ```

- Add test cases for your changes.
- Ensure the documentation is updated accordingly to reflect the changes you made.
- It is very important to commit only required files and not any unnecessary files, whenever necessary it is recommended to use `.gitignore` to exclude files.
- Code cannot be reverted if you by mistake commit any sensitive information, so please make sure to not commit any sensitive information.
- Do not add third-party content in-line without attribution. Use links where possible.
- Make sure the development guidance is followed.

## Platform Notes

Permguard is primarily developed and tested on macOS (Darwin) environments.
While Go’s cross-platform support allows the project to build and run on other operating systems such as Linux and Windows, most of our local development run on macOS.

If you experience any platform-specific issues, differences in behavior, or build failures on other systems, your feedback is highly appreciated.
You can either:

- pen a pull request with fixes or suggestions, or
- Contact us directly at 📧 **<opensource@permguard.com>**
