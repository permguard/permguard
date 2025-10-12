# Bump the version number

This section describes how to bump the version number of the Permguard project.

## Permguard

Navigate to `./www/content/docs/` and copy the latest version directory to create a new version directory. For example, to create version `v0.1.0`, copy the `v0.0.0` directory and rename it to `v0.1.0`.

Find and replace all the occurence of `docs/0.0.x` with `docs/0.1.x` in the new version directory as well as in the go files.

Review the READEM.md file into the www directory.

## Permguard*

Navigate to each component to be deployed and create the new initial tag.

```bash
git tag -d v0.0.1
git push --delete origin v0.0.1
git tag -a v0.0.1 -m "v0.0.1"
git push origin v0.0.1
```

Here the list of the components to be deployed:

- permguard/permguard
- permguard/sdk-go
- permguard/sdk-python
- permguard/sdk-node
- permguard/sdk-java
- permguard/sdk-netcore
