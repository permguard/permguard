import docsearch from "@docsearch/js";

var FALLBACK_VERSION = "0.2";

function getVersion() {
  var versionMatch = window.location.href.toString().match(/\/docs\/([^/]+)/);
  var version = versionMatch ? versionMatch[1] : FALLBACK_VERSION;

  return version;
}

docsearch({
  container: "#docsearch",
  appId: "12ZDGY7DFM",
  apiKey: "f8906cf9282829730e92917673da2199",
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
