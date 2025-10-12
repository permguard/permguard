import docsearch from "@docsearch/js";

var FALLBACK_VERSION = "0.0.x";

function getVersion() {
  var versionMatch = window.location.href.toString().match(/\/docs\/([^/]+)/);
  var version = versionMatch ? versionMatch[1] : FALLBACK_VERSION;

  return version;
}

docsearch({
  container: "#docsearch",
  appId: "Y97Q3IU6YH",
  apiKey: "6bbb1f533a692e69f5c66a5e4ee33604",
  indexName: "permguard_index",
  debug: false,
  insights: true,
  searchParameters: {
    filters: `version:${getVersion()} OR version:non-versionable`,
  },
});

var onClick = function () {
  document.getElementsByClassName("DocSearch-Button")[0].click();
};

document.getElementById("searchToggleMobile").onclick = onClick;
document.getElementById("searchToggleDesktop").onclick = onClick;
