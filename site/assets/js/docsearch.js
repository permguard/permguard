import docsearch from "@docsearch/js";

docsearch({
  container: "#docsearch",
  appId: "YOUR_APP_ID",
  indexName: "YOUR_INDEX_NAME",
  apiKey: "YOUR_SEARCH_API_KEY",
  insights: true,
});

const onClick = function () {
  document.getElementsByClassName("DocSearch-Button")[0].click();
};

document.getElementById("searchToggleMobile").onclick = onClick;
document.getElementById("searchToggleDesktop").onclick = onClick;
