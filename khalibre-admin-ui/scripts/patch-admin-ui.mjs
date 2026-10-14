#!/usr/bin/env node
// Adds the EDC MFA channels page to the Keycloak admin console.
//
// This is a scripted patch rather than a fork. The admin console is a React app whose routes live in
// one array and whose sidebar is a JSX tree, and Keycloak publishes no plugin hook to extend either
// (checked: no registry in the built bundle, and the npm package ships internals as types only, so
// `lib/routes.js` does not exist). So a new page means patching the two files that own the route
// table and the sidebar, and taking the rest of the console from the pinned upstream checkout.
//
// The page's own source is *copied into* the checkout rather than aliased in. An alias would leave
// the files outside the Vite root, and Vite resolves bare specifiers by walking up from the
// importing file - `khalibre-admin-ui/node_modules` is never consulted, because nothing there is
// installed: the build runs inside the checkout, so `apps/admin-ui/node_modules` is what has to be
// found, and only a file under that tree can find it. In-tree also means the console's own tsconfig
// covers the page, so `vite build` type-checks it (`vite-plugin-checker`) under `strict: true`
// without any config of ours.
//
// Upstream lives in a pinned checkout, never in this repository, so it cannot drift on its own: an
// upgrade is a version bump plus re-running this script.
//
// Every edit replaces an exact anchor and asserts it was found. A silent no-op here would build a
// console that looks unchanged and has no ICT page, which is the failure mode this file exists to
// prevent. Every edit is also idempotent, because the task that runs this is expected to be run
// again on every change.

import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUR_ROOT = resolve(HERE, "..");

/**
 * Where the pinned Keycloak checkout lives.
 *
 * Resolved from this script rather than from the working directory, so it can be run from anywhere;
 * `mise run build:khalibre-admin-ui` is the usual way, and it fetches the checkout first.
 * KEYCLOAK_JS_DIR overrides the location.
 */
const KC_JS = process.env.KEYCLOAK_JS_DIR
  ? resolve(process.env.KEYCLOAK_JS_DIR)
  : resolve(OUR_ROOT, "..", "build", "keycloak-26.1.3", "js");
const ADMIN_UI = join(KC_JS, "apps/admin-ui");
const OUR_SRC = join(OUR_ROOT, "src/mfa");

/** Where our built console lands, before the Maven build copies it into the theme jar. */
const OUT_DIR = join(OUR_ROOT, "target/console");

/** In-tree landing spot for the page. Under `src`, so the console's tsconfig picks it up. */
const IN_TREE = join(ADMIN_UI, "src/khalibre");

/** Bumping this makes every patch below re-apply to an already-patched checkout. */
const MARKER = "khalibre-admin-ui";

function fail(message) {
  console.error(`\n  patch-admin-ui: ${message}\n`);
  console.error(
    "  Upstream moved. Open the file, find the equivalent anchor, and update this script.\n" +
      "  Do not remove the assertion to make it pass - a silent no-op builds a console\n" +
      "  with no EDC section in it.\n",
  );
  process.exit(1);
}

/** Replaces `needle` exactly once, or fails loudly. Returns the new content. */
function replaceOnce(content, needle, replacement, what) {
  const first = content.indexOf(needle);
  if (first === -1) {
    fail(`anchor not found for ${what}`);
  }
  if (content.indexOf(needle, first + 1) !== -1) {
    fail(`anchor found more than once for ${what}`);
  }
  return content.slice(0, first) + replacement + content.slice(first + needle.length);
}

/**
 * Applies `edits` to a file, skipping any whose inserted text is already there.
 *
 * Per edit rather than per file: PageNav.tsx carries two independent edits, and a single
 * file-level "already patched" check would skip the second on a checkout that already has the first
 * - which is a silent no-op, the exact thing this script exists to prevent.
 *
 * The test is "is this exact replacement already in the file", which the marker makes cheap: bump the
 * marker and every edit re-applies.
 *
 * @param {string} relativePath
 * @param {{find: string, insert: (marker: string) => string, why: string}[]} edits
 */
function patch(relativePath, edits) {
  const path = join(ADMIN_UI, relativePath);
  if (!existsSync(path)) {
    fail(`no ${relativePath} at ${path}`);
  }
  let content = readFileSync(path, "utf8");
  let applied = 0;

  for (const edit of edits) {
    const replacement = edit.insert(MARKER);
    if (content.includes(replacement)) {
      console.log(`  unchanged ${relativePath} (${edit.why})`);
      continue;
    }
    content = replaceOnce(content, edit.find, replacement, `${relativePath}: ${edit.why}`);
    applied++;
  }

  if (applied === 0) {
    return;
  }
  writeFileSync(path, content);
  console.log(`  patched ${relativePath} (${applied} edit${applied === 1 ? "" : "s"})`);
}

if (!existsSync(ADMIN_UI)) {
  fail(
    `no Keycloak admin-ui checkout at ${ADMIN_UI}.\n` +
      "  Run `mise run build:khalibre-admin-ui`, which fetches the pinned source into build/,\n" +
      "  or set KEYCLOAK_JS_DIR to the js/ directory of a checkout you already have.",
  );
}

// ------------------------------------------------------------------- the page

// Recreated wholesale rather than merged, so a file deleted here is deleted there too.
rmSync(IN_TREE, { recursive: true, force: true });
mkdirSync(IN_TREE, { recursive: true });
cpSync(OUR_SRC, IN_TREE, { recursive: true });
console.log(`  copied src/mfa -> ${IN_TREE}`);

// ---------------------------------------------------------------- routes.tsx

patch("src/routes.tsx", [
  {
    why: "the routes.tsx import block",
    find: `import pageRoutes from "./page/routes";`,
    insert: (marker) =>
      `import pageRoutes from "./page/routes";
import edcMfaRoutes from "./khalibre/routes"; // ${marker}`,
  },
  {
    why: "the routes array",
    find: `  ...pageRoutes,
  NotFoundRoute,`,
    insert: (marker) =>
      `  ...pageRoutes,
  ...edcMfaRoutes, // ${marker}
  NotFoundRoute,`,
  },
]);

// --------------------------------------------------------------- PageNav.tsx
//
// The sidebar is a JSX tree of NavGroup elements, not a data array. MFA channels belongs in the
// Configure group beside Authentication, since it is a realm-wide authentication setting rather than
// a Manage item. An earlier draft of this script appended to the last "];" in the file, which would
// have landed in an arbitrary array and built a console with a mangled nav - the reason every edit
// here asserts its anchor.
//
// `path` is matched against the route with its `/:param` segments stripped, and an entry that
// matches nothing renders nothing at all: it must be `/edc-mfa` for the route `/:realm/edc-mfa`.

patch("src/PageNav.tsx", [
  {
    why: "the Configure nav group",
    find: `              <LeftNav title="authentication" path="/authentication" />
`,
    insert: (marker) =>
      `              <LeftNav title="authentication" path="/authentication" />
              <LeftNav title="edcMfaChannels" path="/edc-mfa" /> {/* ${marker} */}
`,
  },
  {
    // The one that is not obvious, and the one that made the page unreachable.
    //
    // Both nav groups are hidden behind a `hasSomeAccess(...)` that names only *view*-ish roles, and
    // `hasAccess` is a flat membership test with no implication between roles - so an account holding
    // only `manage-realm`, which is all our page needs, renders **no sidebar at all**, not even an
    // empty Configure group. Adding our row alone could therefore never be seen by the person it was
    // written for.
    //
    // `manage-realm` is added to the Configure gate only. The Manage group is left alone: our page
    // administers no users, clients or events, so widening that one would be claiming authority the
    // page does not need.
    why: "the Configure group gate",
    find: `  const showConfigure = hasSomeAccess(
    "view-realm",
    "query-clients",
    "view-identity-providers",
  );`,
    insert: (marker) => `  const showConfigure = hasSomeAccess(
    "view-realm",
    "query-clients",
    "view-identity-providers",
    "manage-realm", // ${marker}: keeps this group reachable for the EDC MFA page's own gate
  );`,
  },
]);

// ------------------------------------------------------------ vite.config.ts

// Ours has to land in its own theme directory: the stock outDir writes into the checkout, which would
// overwrite keycloak.v2's own resources and leave nothing for the theme jar to ship. It also sits
// outside the Vite root, where the default is to warn and keep whatever was there, so emptying it is
// stated rather than left to chance - a stale chunk from a previous build is a page that half works.
patch("vite.config.ts", [
  {
    why: "the library outDir",
    find: `        outDir: "target/classes/theme/keycloak.v2/admin/resources",`,
    insert: () =>
      `        outDir: ${JSON.stringify(OUT_DIR.replace(/\\/g, "/"))},
        emptyOutDir: true,`,
  },
  {
    why: "the returned vite config object",
    find: `  return {
    base: "",`,
    insert: (marker) =>
      `  return {
    // ${marker}: the console is built into this theme's jar, not into the checkout.
    base: "",`,
  },
]);

console.log(`\n  done. page: ${join(IN_TREE, "MfaChannels.tsx")}`);
console.log(`  console output: ${OUT_DIR}`);