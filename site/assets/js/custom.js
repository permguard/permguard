/**
 * Copyright 2024 Nitro Agility S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Put your custom JS code here
import Clipboard from "clipboard";
import { LANGUAGES_CODE } from "./code";

// Language switch
let selectedLanguage = "go";
let isPermguard = false;

const handleSelectedLanguageChange = (element) => {
  const hasSeparator = window.innerWidth >= 768;

  const languageElements = document.querySelectorAll(".code__language");
  languageElements.forEach((el) => {
    el.classList.remove("code__language--active");
  });

  element.classList.add("code__language--active");

  const oldLanguage = selectedLanguage;
  selectedLanguage = element.getAttribute("data-language");
  console.log(selectedLanguage);

  let codeBoxes = [];

  if (hasSeparator) {
    codeBoxes = document.querySelectorAll("img-comparison-slider pre code");

    codeBoxes[0].innerHTML = LANGUAGES_CODE[selectedLanguage].before;
    codeBoxes[1].innerHTML = LANGUAGES_CODE[selectedLanguage].after;
  } else {
    codeBoxes = document.querySelectorAll(".code__img--small pre code");

    codeBoxes[0].innerHTML =
      LANGUAGES_CODE[selectedLanguage][isPermguard ? "after" : "before"];
  }

  codeBoxes.forEach((codeBox) => {
    codeBox.classList.remove(`language-${oldLanguage}`);
    codeBox.classList.add(`language-${selectedLanguage}`);
    codeBox.removeAttribute("data-highlighted");
  });

  // eslint-disable-next-line no-undef
  hljs.highlightAll();
};

const languageElements = document.querySelectorAll(".code__language");
const switchInput = document.querySelector("#switchInput");

const toggleIsPermguard = () => {
  isPermguard = !isPermguard;

  const codeBoxes = document.querySelectorAll(".code__img--small pre code");

  codeBoxes[0].innerHTML =
    LANGUAGES_CODE[selectedLanguage][isPermguard ? "after" : "before"];

  codeBoxes.forEach((codeBox) => {
    codeBox.removeAttribute("data-highlighted");
  });

  // eslint-disable-next-line no-undef
  hljs.highlightAll();
};

languageElements.forEach((el) => {
  el.addEventListener("click", () => handleSelectedLanguageChange(el));
});

if (switchInput) {
  switchInput.addEventListener("change", toggleIsPermguard);
}

// Detect forced dark mode
function detectForcedDarkMode() {
  if (
    !navigator.userAgent.match(/Samsung/i) ||
    !window.matchMedia ||
    window.matchMedia("(prefers-color-scheme:dark)").matches
  )
    return new Promise((resolve) => {
      resolve(false);
    });

  return new Promise((resolve) => {
    const ctx = document.createElement("canvas").getContext("2d");
    const svg = `
          <svg width="1" height="1" xmlns="http://www.w3.org/2000/svg">
              <rect width="1" height="1" fill="white"  />
          </svg>
      `;

    const blob = new Blob([svg], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);

    const img = new Image();
    img.src = url;

    img.onload = () => {
      ctx.drawImage(img, 0, 0);
      const [r, g, b] = ctx.getImageData(0, 0, 1, 1).data;
      URL.revokeObjectURL(url); // Clean up the object URL to avoid memory leaks
      resolve((r & b & g) < 255);
    };

    img.onerror = () => {
      URL.revokeObjectURL(url); // Clean up on error as well
      resolve(false);
    };
  });
}

detectForcedDarkMode().then(function (isDarkModeForced) {
  if (isDarkModeForced) {
    document.querySelector("body").classList.add("forced-dark");
  }
});

// Cedar copy to clipboard
function addCopyToClipboardCedar() {
  "use strict";

  var cb = document.getElementsByClassName("language-cedar");

  for (var i = 0; i < cb.length; ++i) {
    var element = cb[i];
    element.insertAdjacentHTML(
      "afterbegin",
      '<div class="copy"><button title="Copy to clipboard" class="btn-copy" aria-label="Clipboard button"><div></div></button></div>'
    );
  }

  var clipboard = new Clipboard(".btn-copy", {
    target: function (trigger) {
      return trigger.parentNode.parentNode;
    },
  });

  clipboard.on("success", function (e) {
    /*
      console.info('Action:', e.action);
      console.info('Text:', e.text);
      console.info('Trigger:', e.trigger);
      */

    e.clearSelection();
  });

  clipboard.on("error", function (e) {
    console.error("Action:", e.action);
    console.error("Trigger:", e.trigger);
  });
}

addCopyToClipboardCedar();
