# Permguard Documentation

## Adding a New Version

The base project uses version `0.1` by default. If needed, you can update this value and add additional versions.

### Steps to Create a New Version

To create a new version (e.g., `0.2`), follow these steps:

1. **Update the `docsVersions` in the `config_default/params.toml` file**  
   Add the new version to the `docsVersions` array as shown below:

   ```toml
   docsVersions = ["0.1", "0.2"]
   ```

2. **Create a new folder for the new version**  
   In the `content/docs` directory, create a new folder with the version number (e.g., `0.2`). Populate this folder with the necessary Markdown files.

3. **Update the docs entry page**  
   Modify the `url` in the `config_default/menus/menus.en.toml` file to point to the new version, for example:

   ```toml
   url = "/docs/0.2/overview/introduction-to-permguard/"
   ```

The application will automatically select the latest version from the docsVersions array as the default version of the documentation.
