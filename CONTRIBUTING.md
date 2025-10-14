# Contributing

By contributing to this project, you agree to follow our [code of conduct](https://github.com/permguard/.github/blob/main/CODE_OF_CONDUCT.md).

## Set up your machine

**Permguard** is written in [Go](https://go.dev/).

Prerequisites:

- [Task](https://taskfile.dev/installation)
- [Go 1.25+](https://go.dev/doc/install)

Some development or test workflows may rely on external tools.
If these tools are not installed locally, the related tests will be skipped automatically:

- [Docker](https://www.docker.com/)
- [Protobuf](https://grpc.io/docs/protoc-installation/)
- [Add License](https://github.com/google/addlicense)
- [Gofumpt](https://github.com/mvdan/gofumpt)
- [Cosign](https://github.com/sigstore/cosign)
- [GPG](https://gnupg.org)
- [Syft](https://github.com/anchore/syft)

## Building

Clone `permguard` anywhere:

```bash
git clone git@github.com:permguard/permguard.git
```

`cd` into the directory and setup your environment:

```bash
task local
```

## Building and Running the local environment with Docker

First, build the project artifacts (binaries and Docker images) and create the local database:

```bash
task build:ci
task local:docker
```

Then, run the local environment using Docker. The task automatically detects your system architecture (amd64 or arm64) and starts the correct image:

```bash
task local:docker
```

## Testing your changes

Create a new branch for your changes and make your modifications.

Before committing, ensure the codebase is properly formatted and consistent with the project’s style guidelines:

```bash
task source:precommit
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

## Development Platform Notes

Permguard is primarily developed and tested on macOS (Darwin) environments.
While Go’s cross-platform support allows the project to build and run on other operating systems such as Linux and Windows, most of our local development runs on macOS.

If you experience any platform-specific issues, differences in behavior, or build failures on other systems, your feedback is highly appreciated.
You can either:

- Open a pull request with fixes or suggestions, or
- Contact us directly at 📧 **<opensource@permguard.com>**

## Legal and Licensing Compliance

All contributions to **Permguard** must fully comply must fully comply with the project’s Apache 2.0 License, our EULA, and any applicable third-party terms.
By submitting a contribution, you confirm that you have the right to do so and that your submission does not violate any intellectual property or contractual obligations.

If your contribution introduces third-party technologies, external dependencies, or materials under a different license:

- Provide clear attribution and include a reference to the corresponding license.
- Add a short note in your pull request description under a “Third-Party Notice” section.
- Ensure the license terms of any added dependency are compatible with the Apache 2.0 License.
- If you’re unsure about the licensing implications or compliance requirements, please contact us before submitting the PR.

📧 For any legal or licensing concerns, reach out to 📧 **<opensource@permguard.com>**

⚖️ Note: Contributions that introduce incompatible or unverified third-party materials may be declined to protect the integrity and legal safety of the project.
