import { defineConfig } from "tsup";

// Bundle the server + CLI to a single ESM file with a node shebang so that
// `npx codeinspectus` starts fast. Data files (data/, detection-db/) are shipped
// alongside dist/ and resolved at runtime relative to the package root.
export default defineConfig({
  entry: { index: "src/index.ts" },
  format: ["esm"],
  target: "node18",
  platform: "node",
  outDir: "dist",
  clean: true,
  splitting: false,
  minify: false,
  sourcemap: false,
  shims: true,
  // Keep the SDK external so we don't re-bundle express/hono/etc.; resolved from
  // node_modules at runtime. `npx codeinspectus` installs deps before running.
  noExternal: [],
  banner: { js: "#!/usr/bin/env node" },
});
