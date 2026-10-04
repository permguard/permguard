// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

import { copyFile, mkdir, readdir } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

const root = resolve(process.argv[2] ?? ".vitepress/dist");
let aliases = 0;

async function addAliases(directory) {
  const entries = await readdir(directory, { withFileTypes: true });

  for (const entry of entries) {
    const path = join(directory, entry.name);

    if (entry.isDirectory()) {
      await addAliases(path);
      continue;
    }

    if (
      !entry.isFile() ||
      !entry.name.endsWith(".html") ||
      entry.name === "index.html" ||
      entry.name === "404.html"
    ) {
      continue;
    }

    const aliasDirectory = join(dirname(path), basename(entry.name, ".html"));
    await mkdir(aliasDirectory, { recursive: true });
    await copyFile(path, join(aliasDirectory, "index.html"));
    aliases += 1;
  }
}

await addAliases(root);
console.log(`created ${aliases} trailing-slash aliases in ${root}`);
