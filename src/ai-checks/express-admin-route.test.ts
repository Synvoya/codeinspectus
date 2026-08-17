import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { mkdtemp, mkdir, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  runExpressAdminRouteAnalysis,
  runExpressAdminRouteCheck,
} from "./express-admin-route.js";

let root: string;

async function source(path: string, content: string): Promise<void> {
  const absolute = join(root, path);
  await mkdir(join(absolute, ".."), { recursive: true });
  await writeFile(absolute, content);
}

describe("Express admin route access-control boundary", () => {
  beforeAll(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), "codeinspectus-express-admin-")));
    await Promise.all([
      source("tp/esm.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get(\"/api/admin/users\", (_req, res) => {",
        "  return res.json({ ok: true });",
        "});",
      ].join("\n")),
      source("tp/cjs.js", [
        'const { Router } = require("express");',
        "const router = Router();",
        "router.delete('/v1/admin/users', function (_req, res) {",
        "  res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("tp/dead-evidence.ts", [
        'import express from "express";',
        "const app = express();",
        "function unusedAuthHelper() { requireAuth(); requireRole('admin'); }",
        "app.post('/admin/jobs', (_req, res) => {",
        "  // requireAuth and role=admin are comments, not guards.",
        "  const label = 'authorization role admin';",
        "  return res.json({ label });",
        "});",
      ].join("\n")),
      source("tp/nonmatching-use.ts", [
        'import express from "express";',
        "const app = express();",
        "app.use('/public', publicMiddleware);",
        "app.patch('/admin/settings', (_req, res) => res.sendStatus(204));",
      ].join("\n")),
      source("tp/standard-use.ts", [
        'import express from "express";',
        "const app = express();",
        "app.use(express.json());",
        "app.use('/admin', express.urlencoded({ extended: false }));",
        "app.use('/assets', express.static('public'));",
        "app.put('/admin/settings', (_req, res) => res.sendStatus(204));",
      ].join("\n")),
      source("tp/typed-naked.ts", [
        'import express from "express";',
        "const app = express();",
        "function naked(_req: unknown, res: any): Promise<{ ok: boolean }> {",
        "  return res.json({ ok: true });",
        "}",
        "app.get('/admin/typed', naked);",
      ].join("\n")),
      source("tp/conditional-and-guards.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/conditional-and', (req, res) => {",
        "  if (!req.user && strict) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin' && strict) return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/reversed-authz.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/reversed', (req, res) => {",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role === 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/double-negation-auth.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/double-negation', (req, res) => {",
        "  if (!!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/aliased-late-sink.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/aliased-late', async (req, res) => {",
        "  const records = db.records;",
        "  await records.deleteMany();",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("tp/privileged-utility.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/status', async (_req, res) => {",
        "  await db.records.deleteMany();",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("tp/standard-route-middleware.ts", [
        'import express from "express";',
        "const app = express();",
        "app.post('/admin/standard-route', express.json(), (_req, res) => res.json([]));",
      ].join("\n")),
      source("tp/status-with-next.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/status-next', (req, res, next) => {",
        "  if (!req.user) { res.sendStatus(401); return next(); }",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/status-without-send.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/status-only', (req, res) => {",
        "  if (!req.user) { res.status(401); return; }",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/helper-before-guards.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/helper-before', async (req, res) => {",
        "  async function purge() { await db.records.deleteMany(); }",
        "  await purge();",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("tp/expression-arrow-before.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/arrow-before', async (req, res) => {",
        "  const purge = () => db.records.deleteMany();",
        "  await purge();",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("tp/auth-denial-privileged-sink.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/auth-denial-sink', async (req, res) => {",
        "  if (!req.user) { res.sendStatus(401); await db.records.deleteMany(); return; }",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("tp/authz-denial-privileged-sink.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/authz-denial-sink', async (req, res) => {",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') { res.sendStatus(403); await adminService.deleteUser(); return; }",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("tp/throw-argument-privileged-sink.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/throw-sink', async (req, res) => {",
        "  if (!req.user) throw new UnauthorizedError(await db.records.deleteMany());",
        "  if (req.user.role !== 'admin') throw new ForbiddenError();",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("tp/authz-throw-argument-sink.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/authz-throw-sink', async (req, res) => {",
        "  if (!req.user) throw new UnauthorizedError();",
        "  if (req.user.role !== 'admin') throw new ForbiddenError(await adminService.deleteUser());",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("tp/mixed-router-mount.ts", [
        'import express from "express";',
        "const app = express();",
        "const router = express.Router();",
        "router.get('/admin/mixed-mount', (_req, res) => res.json([]));",
        "app.use('/safe', requireAuth, requireAdmin, router);",
        "app.use('/public', router);",
      ].join("\n")),
      source("tp/mixed-router-alias-mount.ts", [
        'import express from "express";',
        "const app = express();",
        "const router = express.Router();",
        "const mounted = router;",
        "router.get('/admin/mixed-alias-mount', (_req, res) => res.json([]));",
        "app.use('/safe', requireAuth, requireAdmin, mounted);",
        "app.use('/public', mounted);",
      ].join("\n")),
      source("tp/identity-direct-write.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/identity-write', (req, res) => {",
        "  req.user = req.body.user;",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/identity-computed-write.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/computed-write', (req, res) => {",
        "  req['user']['role'] = req.body.role;",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/identity-object-assign.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/object-assign-write', (req, res) => {",
        "  Object.assign(req.user, { role: req.body.role });",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/identity-reflect-set.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/reflect-set-write', (req, res) => {",
        "  Reflect.set(req.user, 'role', req.body.role);",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/identity-conditional-write.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/conditional-write', (req, res) => {",
        "  if (override) req.user.role = req.body.role;",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/identity-between-guards-write.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/between-guards-write', (req, res) => {",
        "  if (!req.user) return res.sendStatus(401);",
        "  req.user.role = req.body.role;",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fp/route-middleware.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/users', requireAuth, (_req, res) => res.json([]));",
      ].join("\n")),
      source("fp/use-guard.ts", [
        'const express = require("express");',
        "const app = express();",
        "app.use('/admin', requireAuth);",
        "app.get('/admin/users', (_req, res) => res.json([]));",
      ].join("\n")),
      source("fp/computed-use.ts", [
        'import express from "express";',
        "const app = express();",
        "app.use(maybeAdminPrefix, maybeGuard);",
        "app.get('/admin/users', (_req, res) => res.json([]));",
      ].join("\n")),
      source("fp/metachar-use.ts", [
        'import express from "express";',
        "const app = express();",
        "app.use('/:scope', maybeGuard);",
        "app.get('/admin/users', (_req, res) => res.json([]));",
      ].join("\n")),
      source("fp/case-insensitive-use.ts", [
        'import express from "express";',
        "const app = express();",
        "app.use('/ADMIN', maybeGuard);",
        "app.get('/admin/users', (_req, res) => res.json([]));",
      ].join("\n")),
      source("fixed/in-handler.ts", [
        'import { Router } from "express";',
        "const router = Router();",
        "router.post('/admin/reports', (req, res) => {",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json({ ok: true });",
        "});",
      ].join("\n")),
      source("fixed/typed-handler.ts", [
        'import express from "express";',
        "const app = express();",
        "function handler(req: any, res: any): Promise<{ ok: boolean }> {",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json({ ok: true });",
        "}",
        "app.get('/admin/typed-safe', handler);",
      ].join("\n")),
      source("fixed/conditional-typed-handler.ts", [
        'import express from "express";',
        "const app = express();",
        "function handler(req: any, res: any): Mode extends 'ok' ? { ok: true } : { ok: false } {",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json({ ok: true });",
        "}",
        "app.get('/admin/conditional-type', handler);",
      ].join("\n")),
      source("fixed/renamed-typed-parameters.ts", [
        'import express, { type Request, type Response } from "express";',
        "const app = express();",
        "app.get('/admin/renamed', (r: Request<Record<string, unknown>>, s: Response) => {",
        "  if (!r.user) return s.sendStatus(401);",
        "  if (r.user.role !== 'admin') return s.sendStatus(403);",
        "  return s.json([]);",
        "});",
      ].join("\n")),
      source("fixed/braced-direct-denials.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/braced', (req, res) => {",
        "  if (!req.user) { res.sendStatus(401); return; }",
        "  if (req.user.role !== 'admin') { res.sendStatus(403); return; }",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fixed/nested-unused-sink.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/nested-unused', (req, res) => {",
        "  function unused() { return db.records.deleteMany(); }",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fixed/direct-throws.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/throws', (req, res) => {",
        "  if (!req.user) throw new UnauthorizedError();",
        "  if (req.user.role !== 'admin') throw new ForbiddenError();",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fixed/helper-after-guards.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/helper-after', async (req, res) => {",
        "  async function purge() { await db.records.deleteMany(); }",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  await purge();",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("fixed/helper-conditional.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/helper-conditional', async (req, res) => {",
        "  async function purge() { await db.records.deleteMany(); }",
        "  if (maintenance) await purge();",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("fixed/unused-expression-arrow.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/unused-arrow', (req, res) => {",
        "  const unused = () => db.records.deleteMany();",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fixed/or-guards.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/or-guards', (req, res) => {",
        "  if (!req.user || req.user.disabled) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin' || req.user.suspended) return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fixed/null-undefined-guards.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/null-guard', (req, res) => {",
        "  if (req.user == null) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
        "app.get('/admin/undefined-guard', (req, res) => {",
        "  if (undefined === req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fixed/asi-denials.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/asi', (req, res) => {",
        "  if (!req.user) return res.sendStatus(401)",
        "  if (req.user.role !== 'admin') return res.sendStatus(403)",
        "  return res.json([])",
        "})",
      ].join("\n")),
      source("fixed/post-guard-identity-write.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/post-guard-write', (req, res) => {",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  req.user.role = req.body.role;",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fp/guarded-router-alias.ts", [
        'import express from "express";',
        "const app = express();",
        "const router = express.Router();",
        "const mounted = router;",
        "router.get('/admin/mounted-alias', (_req, res) => res.json([]));",
        "app.use('/', requireAuth, requireAdmin, mounted);",
      ].join("\n")),
      source("fp/ambiguous-router-alias.ts", [
        'import express from "express";',
        "const app = express();",
        "const router = express.Router();",
        "let mounted = router;",
        "mounted = chooseRouter();",
        "router.get('/admin/ambiguous-mount', (_req, res) => res.json([]));",
        "app.use('/', requireAuth, requireAdmin, mounted);",
      ].join("\n")),
      source("fp/ambiguous-mixed-router-alias.ts", [
        'import express from "express";',
        "const app = express();",
        "const router = express.Router();",
        "let mounted = router;",
        "router.get('/admin/ambiguous-mixed', (_req, res) => res.json([]));",
        "app.use('/safe', requireAuth, requireAdmin, router);",
        "mounted = chooseRouter();",
        "app.use('/maybe', mounted);",
      ].join("\n")),
      source("fp/unsupported-plausible-guard.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/plausible', (req, res) => {",
        "  if (mustRejectPrincipal(req.user)) return res.sendStatus(401);",
        "  if (mustRejectPrivilege(req.user)) return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fp/guarded-router-mount.ts", [
        'import express from "express";',
        "const app = express();",
        "const router = express.Router();",
        "router.get('/admin/mounted', (_req, res) => res.json([]));",
        "app.use('/', requireAuth, requireAdmin, router);",
      ].join("\n")),
      source("fp/wrapped-handler.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/wrapped', withAuth((_req, res) => res.json([])));",
      ].join("\n")),
      source("fp/conditional-handler.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/conditional', enabled ? ((_req, res) => res.json([])) : fallback);",
      ].join("\n")),
      source("fp/composed-definition.ts", [
        'import express from "express";',
        "const app = express();",
        "const handler = compose((_req, res) => res.json([]));",
        "app.get('/admin/composed', handler);",
      ].join("\n")),
      source("tp/nested-guards.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/nested', (req, res) => {",
        "  if (featureEnabled) {",
        "    if (!req.user) return res.sendStatus(401);",
        "    if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  }",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/dead-helper-guards.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/dead-helper', (req, res) => {",
        "  function unused() {",
        "    if (!req.user) return res.sendStatus(401);",
        "    if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  }",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/late-guards.ts", [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/late', async (req, res) => {",
        "  await db.records.deleteMany();",
        "  if (!req.user) return res.sendStatus(401);",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n")),
      source("fp/unresolved-direct-guard.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/unresolved', (req, res) => {",
        "  requireAdminAccess(req);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("tp/nested-status-unrelated-return.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/nested-status', (req, res) => {",
        "  if (!req.user) {",
        "    if (verbose) res.sendStatus(401);",
        "    return next();",
        "  }",
        "  if (req.user.role !== 'admin') return res.sendStatus(403);",
        "  return res.json([]);",
        "});",
      ].join("\n")),
      source("fp/public-admin-utility.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/login', (_req, res) => res.render('login'));",
        "app.get('/admin/callback', (_req, res) => res.redirect('/'));",
        "app.get('/admin/health', (_req, res) => res.json({ ok: true }));",
        "app.get('/admin/status', (_req, res) => res.json({ ok: true }));",
      ].join("\n")),
      source("fp/ambiguous-handler.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/audit', importedHandler);",
      ].join("\n")),
      source("fp/computed-path.ts", [
        'import express from "express";',
        "const app = express();",
        "const path = '/admin/users';",
        "app.get(path, (_req, res) => res.json([]));",
      ].join("\n")),
      source("fp/lookalike.ts", [
        "function express() { return { get() {} }; }",
        "const app = express();",
        "app.get('/admin/users', (_req, res) => res.json([]));",
      ].join("\n")),
      source("fp/not-express.ts", [
        'import express from "express-lookalike";',
        "const app = express();",
        "app.get('/admin/users', (_req, res) => res.json([]));",
      ].join("\n")),
      source("malformed/broken.ts", [
        'import express from "express";',
        "const app = express();",
        "app.get('/admin/users', (_req, res) => {",
      ].join("\n")),
    ]);
  });

  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  test("finds only statically-proven, clearly naked Express admin routes", async () => {
    const { findings, notes } = await runExpressAdminRouteAnalysis(root);
    expect(findings.map((item) => [item.location.file, item.location.start_line])).toEqual([
      ["tp/aliased-late-sink.ts", 3],
      ["tp/auth-denial-privileged-sink.ts", 3],
      ["tp/authz-denial-privileged-sink.ts", 3],
      ["tp/authz-throw-argument-sink.ts", 3],
      ["tp/cjs.js", 3],
      ["tp/conditional-and-guards.ts", 3],
      ["tp/dead-evidence.ts", 4],
      ["tp/dead-helper-guards.ts", 3],
      ["tp/double-negation-auth.ts", 3],
      ["tp/esm.ts", 3],
      ["tp/expression-arrow-before.ts", 3],
      ["tp/helper-before-guards.ts", 3],
      ["tp/identity-between-guards-write.ts", 3],
      ["tp/identity-computed-write.ts", 3],
      ["tp/identity-conditional-write.ts", 3],
      ["tp/identity-direct-write.ts", 3],
      ["tp/identity-object-assign.ts", 3],
      ["tp/identity-reflect-set.ts", 3],
      ["tp/late-guards.ts", 3],
      ["tp/mixed-router-alias-mount.ts", 5],
      ["tp/mixed-router-mount.ts", 4],
      ["tp/nested-guards.ts", 3],
      ["tp/nested-status-unrelated-return.ts", 3],
      ["tp/nonmatching-use.ts", 4],
      ["tp/privileged-utility.ts", 3],
      ["tp/reversed-authz.ts", 3],
      ["tp/standard-route-middleware.ts", 3],
      ["tp/standard-use.ts", 6],
      ["tp/status-with-next.ts", 3],
      ["tp/status-without-send.ts", 3],
      ["tp/throw-argument-privileged-sink.ts", 3],
      ["tp/typed-naked.ts", 6],
    ]);
    for (const item of findings) {
      expect(item).toMatchObject({
        rule_id: "ci-ai-express-admin-route-no-authz",
        severity: "high",
        confidence: "medium",
        cwe: ["CWE-862", "CWE-863"],
        engine: "codeinspectus-ai",
      });
      expect(item.location.snippet).toMatch(/\.(?:get|post|put|patch|delete)\(/);
    }
    expect(notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/malformed.*malformed\/broken\.ts/i),
      expect.stringMatching(/computed-use\.ts.*prior app\/router\.use middleware/i),
      expect.stringMatching(/metachar-use\.ts.*prior app\/router\.use middleware/i),
      expect.stringMatching(/case-insensitive-use\.ts.*prior app\/router\.use middleware/i),
      expect.stringMatching(/public-looking login\/callback\/health\/status.*public-admin-utility\.ts/i),
      expect.stringMatching(/guarded-router-mount\.ts.*router is mounted behind unresolved middleware/i),
      expect.stringMatching(/route-middleware\.ts.*route middleware could not be proven/i),
      expect.stringMatching(/ambiguous-handler\.ts.*final route handler body was not statically available/i),
      expect.stringMatching(/guarded-router-alias\.ts.*router is mounted behind unresolved middleware/i),
      expect.stringMatching(/ambiguous-router-alias\.ts.*mount alias was reassigned or otherwise ambiguous/i),
      expect.stringMatching(/ambiguous-mixed-router-alias\.ts.*mount alias was reassigned or otherwise ambiguous/i),
      expect.stringMatching(/unsupported-plausible-guard\.ts.*plausible in-handler access-control guard/i),
    ]));
  });

  test("compatibility wrapper returns only findings", async () => {
    const findings = await runExpressAdminRouteCheck(root);
    expect(findings).toHaveLength(32);
  });

  test("caps route candidates and reports the unevaluated remainder", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "codeinspectus-express-routes-")));
    try {
      const routes = Array.from({ length: 520 }, (_, index) =>
        `app.get('/admin/item-${index}', (_req, res) => res.sendStatus(204));`
      );
      await writeFile(join(directory, "routes.ts"), [
        'import express from "express";',
        "const app = express();",
        ...routes,
      ].join("\n"));
      const result = await runExpressAdminRouteAnalysis(directory);
      expect(result.findings).toHaveLength(512);
      expect(result.notes).toEqual(expect.arrayContaining([
        expect.stringMatching(/skipped 8 route candidate.*512-route file bound/i),
      ]));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("caps findings across files and never drops the omission note", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "codeinspectus-express-findings-")));
    try {
      const routes = (offset: number) => Array.from({ length: 300 }, (_, index) =>
        `app.get('/admin/item-${offset + index}', (_req, res) => res.sendStatus(204));`
      );
      await Promise.all([
        writeFile(join(directory, "routes-a.ts"), [
          'import express from "express";',
          "const app = express();",
          ...routes(0),
        ].join("\n")),
        writeFile(join(directory, "routes-b.ts"), [
          'import express from "express";',
          "const app = express();",
          ...routes(300),
        ].join("\n")),
        ...Array.from({ length: 30 }, (_, index) =>
          writeFile(join(directory, `unknown-${String(index).padStart(2, "0")}.ts`), [
            'import express from "express";',
            "const app = express();",
            "app.use(maybePrefix, maybeGuard);",
            `app.get('/admin/unknown-${index}', (_req, res) => res.sendStatus(204));`,
          ].join("\n"))
        ),
      ]);
      const result = await runExpressAdminRouteAnalysis(directory);
      expect(result.findings).toHaveLength(512);
      expect(result.notes).toHaveLength(24);
      expect(result.notes.at(-1)).toMatch(/omitted 88 finding.*512-finding bound/i);
      expect(result.notes.at(-2)).toMatch(/additional Express admin-route analysis notes omitted/i);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("skips call-heavy files at the explicit bound", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "codeinspectus-express-calls-")));
    try {
      const calls = Array.from({ length: 2_049 }, () => "noop();");
      await writeFile(join(directory, "calls.ts"), [
        'import express from "express";',
        "const app = express();",
        ...calls,
        "app.get('/admin/after-bound', (_req, res) => res.sendStatus(204));",
      ].join("\n"));
      const result = await runExpressAdminRouteAnalysis(directory);
      expect(result.findings).toHaveLength(0);
      expect(result.notes).toEqual(expect.arrayContaining([
        expect.stringMatching(/calls\.ts.*exceed.*2048-call file bound/i),
      ]));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("excludes minified and vendored assets without making application-route coverage partial", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "codeinspectus-express-vendor-")));
    try {
      await mkdir(join(directory, "app", "assets", "vendor"), { recursive: true });
      await writeFile(
        join(directory, "app", "assets", "vendor", "jquery.min.js"),
        Array.from({ length: 2_049 }, () => "noop();").join(""),
      );
      await writeFile(join(directory, "server.ts"), [
        'import express from "express";',
        "const app = express();",
        "app.delete('/admin/users', async (_req, res) => {",
        "  await db.users.deleteMany();",
        "  return res.sendStatus(204);",
        "});",
      ].join("\n"));

      const result = await runExpressAdminRouteAnalysis(directory);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.location.file).toBe("server.ts");
      expect(result.notes).not.toEqual(expect.arrayContaining([
        expect.stringMatching(/jquery\.min\.js|2048-call file bound/i),
      ]));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("bounds notes and reports the omitted count", async () => {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "codeinspectus-express-notes-")));
    try {
      await Promise.all(Array.from({ length: 30 }, (_, index) =>
        writeFile(join(directory, `unknown-${String(index).padStart(2, "0")}.ts`), [
          'import express from "express";',
          "const app = express();",
          "app.use(maybePrefix, maybeGuard);",
          `app.get('/admin/item-${index}', (_req, res) => res.sendStatus(204));`,
        ].join("\n"))
      ));
      const result = await runExpressAdminRouteAnalysis(directory);
      expect(result.findings).toHaveLength(0);
      expect(result.notes).toHaveLength(24);
      expect(result.notes.at(-1)).toMatch(/7 additional Express admin-route analysis notes omitted/i);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
