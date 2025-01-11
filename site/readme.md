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
   url = "/docs/0.2/getting-started/introduction-to-permguard/"
   ```

The application will automatically select the latest version from the docsVersions array as the default version of the documentation.

3. **Update the docsearch**
   Modify the `FALLBACK_VERSION` in the `site\assets\js\docsearch.js` file to point to the new version when performing a search in the documentation.

   ```toml
   const FALLBACK_VERSION = "0.2";
   ```

   _Note_: You should re-crawl all the pages in the algolia dashboard to take into account the new version pages when performing a search.

# Algolia config

[Algolia](https://www.algolia.com/) crawler cofig:

```code
new Crawler({
  appId: "12ZDGY7DFM",
  apiKey: "f2f64521df6af721cda9b5f1d48e6ab5",
  maxUrls: 5000,
  indexPrefix: "",
  rateLimit: 8,
  renderJavaScript: false,
  startUrls: [
    "https://www.permguard.com/docs/",
    "https://www.permguard.com/blog/",
    "https://www.permguard.com/",
  ],
  discoveryPatterns: [
    "https://www.permguard.com/docs/**",
    "https://www.permguard.com/blog/**",
    "https://www.permguard.com/",
  ],
  schedule: "at 16:17 on Wednesday",
  maxDepth: 10,
  actions: [
    {
      indexName: "permguard_index",
      pathsToMatch: [
        "https://www.permguard.com/docs/**",
        "https://www.permguard.com/blog/**",
        "https://www.permguard.com/",
      ],
      recordExtractor: ({ helpers, url }) => {
        const versionMatch = url.toString().match(/\/docs\/([^/]+)/);
        const version = versionMatch ? versionMatch[1] : "non-versionable";

        const records = helpers.docsearch({
          recordProps: {
            lvl1: ["header h1", "article h1", "main h1", "h1", "head > title"],
            content: ["article p, article li", "main p, main li", "p, li"],
            lvl0: {
              selectors: "",
              defaultValue: "General Content",
            },
            lvl2: ["article h2", "main h2", "h2"],
            lvl3: ["article h3", "main h3", "h3"],
            lvl4: ["article h4", "main h4", "h4"],
            lvl5: ["article h5", "main h5", "h5"],
            lvl6: ["article h6", "main h6", "h6"],
          },
          aggregateContent: true,
          recordVersion: "v3",
        });

        records.forEach((record) => {
          record.version = version;
        });

        return records;
      },
    },
  ],
  sitemaps: ["https://www.permguard.com/sitemap.xml"],
  initialIndexSettings: {
    permguard_index: {
      advancedSyntax: true,
      allowTyposOnNumericTokens: false,
      attributeCriteriaComputedByMinProximity: true,
      attributeForDistinct: "url",
      attributesForFaceting: ["type", "lang", "version"],
      attributesToHighlight: ["hierarchy", "content", "version"],
      attributesToRetrieve: [
        "hierarchy",
        "content",
        "anchor",
        "url",
        "url_without_anchor",
        "type",
        "version",
      ],
      attributesToSnippet: ["content:10"],
      camelCaseAttributes: ["hierarchy", "content"],
      customRanking: [
        "desc(weight.pageRank)",
        "desc(weight.level)",
        "asc(weight.position)",
      ],
      highlightPostTag: "</span>",
      highlightPreTag: '<span class="algolia-docsearch-suggestion--highlight">',
      ignorePlurals: true,
      minProximity: 1,
      minWordSizefor1Typo: 3,
      minWordSizefor2Typos: 7,
      ranking: [
        "words",
        "filters",
        "typo",
        "attribute",
        "proximity",
        "exact",
        "custom",
      ],
      searchableAttributes: [
        "unordered(hierarchy.lvl0)",
        "unordered(hierarchy.lvl1)",
        "unordered(hierarchy.lvl2)",
        "unordered(hierarchy.lvl3)",
        "unordered(hierarchy.lvl4)",
        "unordered(hierarchy.lvl5)",
        "unordered(hierarchy.lvl6)",
        "content",
      ],
    },
  },
  ignoreCanonicalTo: false,
  safetyChecks: { beforeIndexPublishing: { maxLostRecordsPercentage: 10 } },
});
```
