import docsearch from "@docsearch/js";

docsearch({
  container: "#docsearch",
  appId: "12ZDGY7DFM",
  apiKey: "5efc65320edcbb3b963c363925374d52",
  indexName: "permguard",
  debug: false,
  insights: true,
  start_urls: [
    {
      url: "https://www.permguard.com/docs/",
      tags: ["version:0.2"],
    },
    {
      url: "https://www.permguard.com/docs/0.1/",
      tags: ["version:0.1"],
    },
    {
      url: "https://www.permguard.com/docs/0.2/",
      tags: ["version:0.2"],
    },
  ],
});

const onClick = function () {
  document.getElementsByClassName("DocSearch-Button")[0].click();
};

document.getElementById("searchToggleMobile").onclick = onClick;
document.getElementById("searchToggleDesktop").onclick = onClick;
