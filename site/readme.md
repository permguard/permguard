# Permguard Doks

# Adding a new version

The default version in the base project is 0.1, but in case of need you may adjust this value and add other versions.

## Create a new version

Let's add a new 0.2 version,
For creation of a new version, follow next steps:

1. Add new version into `docsVersions` in the `config\_default\params.toml` file

   docsVersions = ["0.1", "0.2"]

2. Add new folder with version (ex. `0.2`) in the `content\docs` folder and fill it with markdown files
3. Adjust the value of docs enry page `url = "/docs/0.3/overview/introduction-to-permguard/"` in file `config\_default\menus\menus.en.toml`

App will select automatically latest value from `docsVersions` array as the docs last version
