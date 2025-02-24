function highlightSyntax() {
  if (window.location.pathname === "/") {
    // eslint-disable-next-line no-undef
    hljs.highlightAll();
  } else {
    var languages = [
      "cedar",
      //   "python",
      //   "go",
      //   "java",
      //   "json",
      //   "yaml",
      //   "rego",
      //   "bash",
    ];
    languages.forEach((language) => {
      document
        .querySelectorAll(`pre code.language-${language}`)
        .forEach((block) => {
          // eslint-disable-next-line no-undef
          hljs.highlightElement(block);
        });
    });
  }
}
highlightSyntax();
