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

const autoprefixer = require("autoprefixer");
const purgecss = require("@fullhuman/postcss-purgecss");
const whitelister = require("purgecss-whitelister");

module.exports = {
  plugins: [
    autoprefixer(),
    purgecss({
      content: ["./hugo_stats.json"],
      extractors: [
        {
          extractor: (content) => {
            const els = JSON.parse(content).htmlElements;
            return els.tags.concat(els.classes, els.ids);
          },
          extensions: ["json"],
        },
      ],
      dynamicAttributes: [
        "aria-expanded",
        "data-bs-popper",
        "data-bs-target",
        "data-bs-theme",
        "data-dark-mode",
        "data-global-alert",
        "data-pane", // tabs.js
        "data-popper-placement",
        "data-sizes",
        "data-toggle-tab", // tabs.js
        "id",
        "size",
        "type",
      ],
      safelist: [
        "active",
        "btn-clipboard", // clipboards.js
        "clipboard", // clipboards.js
        "disabled",
        "hidden",
        "modal-backdrop", // search-modal.js
        "selected", // search-modal.js
        "show",
        "img-fluid",
        "blur-up",
        "lazyload",
        "lazyloaded",
        "alert-link",
        "container-fw ",
        "container-lg",
        "container-fluid",
        "offcanvas-backdrop",
        "figcaption",
        "dt",
        "dd",
        "showing",
        "hiding",
        "page-item",
        "page-link",
        ...whitelister([
          "./assets/scss/**/*.scss",
          "./node_modules/@hyas/doks-core/assets/scss/components/_code.scss",
          "./node_modules/@hyas/doks-core/assets/scss/components/_expressive-code.scss",
          "./node_modules/@hyas/doks-core/assets/scss/common/_syntax.scss",
        ]),
      ],
    }),
  ],
};
