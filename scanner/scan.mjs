#!/usr/bin/env node
/**
 * blastradius scanner -- emits the micro (code) graph as JSON.
 *
 * Regex and lightweight AST parsers cannot answer the question we need, which
 * is "does a call in controllers/auth.ts reach a symbol exported from
 * 'vulnerable-pkg'". That needs real symbol resolution across files, so this
 * uses ts-morph, which wraps the TypeScript compiler API.
 *
 * Output shape (all keys are stable strings the Python loader turns into ids):
 *
 *   {
 *     service, root,
 *     files:           [{ key, path, lang }],
 *     functions:       [{ key, name, file, line, exported }],
 *     calls:           [[callerKey, calleeKey]],
 *     externalImports: [{ key, specifier, file, names }],
 *     callsExternal:   [[functionKey, importKey]],
 *     routes:          [{ key, method, pattern, file, line, handler }],
 *     stats:           { ... }
 *   }
 *
 * Usage: node scan.mjs <project-dir> [--service NAME] [--out FILE]
 */

import { Project, SyntaxKind, Node } from "ts-morph";
import path from "node:path";
import fs from "node:fs";
import { pathToFileURL } from "node:url";

const FUNCTION_KINDS = new Set([
  SyntaxKind.FunctionDeclaration,
  SyntaxKind.FunctionExpression,
  SyntaxKind.ArrowFunction,
  SyntaxKind.MethodDeclaration,
  SyntaxKind.GetAccessor,
  SyntaxKind.SetAccessor,
  SyntaxKind.Constructor,
]);

const ROUTE_METHODS = new Set([
  "get", "post", "put", "patch", "delete", "head", "options", "all", "use",
]);

/** Express-ish router receivers. Heuristic, and reported as such in stats. */
const ROUTER_NAMES = /^(app|router|server|api|r)$/i;

const SOURCE_GLOBS = [
  "**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts}",
  "!**/node_modules/**",
  "!**/dist/**",
  "!**/build/**",
  "!**/.next/**",
  "!**/coverage/**",
  "!**/*.d.ts",
  "!**/*.min.js",
];

/** Stable, human-readable keys. The Python side maps these to graph ids. */
const fileKey = (service, rel) => `${service}::${rel}`;
const funcKey = (service, rel, name, line) => `${service}::${rel}::${name}::${line}`;
const importKey = (service, specifier) => `${service}::${specifier}`;
const routeKey = (service, method, pattern, rel, line) =>
  `${service}::${method} ${pattern}::${rel}::${line}`;

const isRelative = (spec) => spec.startsWith(".") || spec.startsWith("/");

/** "@scope/pkg/sub/path" -> "@scope/pkg";  "lodash/merge" -> "lodash". */
function packageNameOf(specifier) {
  if (specifier.startsWith("@")) {
    const parts = specifier.split("/");
    return parts.slice(0, 2).join("/");
  }
  return specifier.split("/")[0];
}

/**
 * A readable name for any function-like node.
 *
 * Arrow functions and function expressions are usually anonymous in the AST
 * but named by whatever they are assigned to, which is what a human would
 * call them. Falling back to the assignment target keeps the graph legible;
 * without it half the call graph reads "anonymous".
 */
function functionName(node) {
  const own = typeof node.getName === "function" ? node.getName() : undefined;
  if (own) return own;

  const parent = node.getParent();
  if (!parent) return `anonymous@${node.getStartLineNumber()}`;

  if (Node.isVariableDeclaration(parent)) return parent.getName();
  if (Node.isPropertyAssignment(parent)) return parent.getName();
  if (Node.isPropertyDeclaration(parent)) return parent.getName();
  if (Node.isExportAssignment(parent)) return "default";

  // Handler passed straight into a call: app.get("/x", (req, res) => {...})
  if (Node.isCallExpression(parent)) {
    const callee = parent.getExpression().getText().split(".").pop();
    return `${callee}:handler@${node.getStartLineNumber()}`;
  }
  return `anonymous@${node.getStartLineNumber()}`;
}

/** Nearest enclosing function-like ancestor that we registered, or null. */
function enclosingFunction(node, keyByNode) {
  let current = node.getParent();
  while (current) {
    if (FUNCTION_KINDS.has(current.getKind())) {
      const key = keyByNode.get(current);
      if (key) return key;
    }
    current = current.getParent();
  }
  return null;
}

/**
 * Resolve what an identifier refers to.
 *
 * Returns { kind: "external", specifier } when the identifier came from an
 * import of a non-relative module, or { kind: "local", node } when it resolves
 * to a function declared in this project. Everything else is null -- globals,
 * types, and dynamic dispatch we cannot follow.
 */
function resolveIdentifier(identifier) {
  let symbol = identifier.getSymbol();
  if (!symbol) return null;

  const aliased = symbol.getAliasedSymbol?.();
  const declarations = (aliased ?? symbol).getDeclarations?.() ?? [];
  const originalDeclarations = symbol.getDeclarations?.() ?? [];

  // Check the pre-alias declarations for an import: that is where the module
  // specifier lives, and following the alias would take us into node_modules
  // type stubs instead.
  for (const decl of originalDeclarations) {
    const specifier = importSpecifierOf(decl);
    if (specifier && !isRelative(specifier)) {
      return { kind: "external", specifier };
    }
  }

  for (const decl of declarations) {
    if (FUNCTION_KINDS.has(decl.getKind())) return { kind: "local", node: decl };
    // `const handler = () => {}` -- the symbol is the variable, the function
    // is its initialiser.
    if (Node.isVariableDeclaration(decl)) {
      const init = decl.getInitializer();
      if (init && FUNCTION_KINDS.has(init.getKind())) {
        return { kind: "local", node: init };
      }
    }
  }
  return null;
}

/** Module specifier if this declaration is part of an import, else null. */
function importSpecifierOf(decl) {
  const importDecl =
    decl.getFirstAncestorByKind?.(SyntaxKind.ImportDeclaration) ??
    (Node.isImportDeclaration(decl) ? decl : undefined);
  if (importDecl) return importDecl.getModuleSpecifierValue();

  // const x = require("pkg")
  if (Node.isVariableDeclaration(decl)) {
    const init = decl.getInitializer();
    if (init && Node.isCallExpression(init)) {
      const spec = requireTarget(init);
      if (spec) return spec;
    }
  }
  return null;
}

/** The module string of a `require("...")` call, or null. */
function requireTarget(call) {
  if (call.getExpression().getText() !== "require") return null;
  const [arg] = call.getArguments();
  if (arg && Node.isStringLiteral(arg)) return arg.getLiteralValue();
  return null;
}

/** Leftmost identifier of `a.b.c()` -- the thing that was imported. */
function rootIdentifier(expression) {
  let current = expression;
  while (Node.isPropertyAccessExpression(current)) current = current.getExpression();
  return Node.isIdentifier(current) ? current : null;
}

export function scan(root, serviceName) {
  const service = serviceName || path.basename(root);
  const tsconfig = ["tsconfig.json", "jsconfig.json"]
    .map((f) => path.join(root, f))
    .find((f) => fs.existsSync(f));

  // A tsconfig gives real path mappings and lib resolution. Without one we
  // still get full symbol resolution across files, just with defaults.
  const project = tsconfig
    ? new Project({ tsConfigFilePath: tsconfig, skipAddingFilesFromTsConfig: true })
    : new Project({ compilerOptions: { allowJs: true, checkJs: false } });

  project.addSourceFilesAtPaths(SOURCE_GLOBS.map((g) => path.join(root, g)));

  const files = [];
  const functions = [];
  const calls = new Set();
  const externalImports = new Map();
  const callsExternal = new Set();
  const routes = [];
  const keyByNode = new Map();
  const stats = { unresolvedCalls: 0, dynamicCalls: 0, sourceFiles: 0 };

  const sourceFiles = project.getSourceFiles();
  stats.sourceFiles = sourceFiles.length;

  const relOf = (sf) => path.relative(root, sf.getFilePath()).split(path.sep).join("/");

  const noteImport = (specifier, rel, names) => {
    const pkg = packageNameOf(specifier);
    const key = importKey(service, pkg);
    const existing = externalImports.get(key);
    if (existing) {
      for (const n of names) existing.names.add(n);
      existing.files.add(rel);
    } else {
      externalImports.set(key, {
        key,
        specifier: pkg,
        raw: specifier,
        file: rel,
        names: new Set(names),
        files: new Set([rel]),
      });
    }
    return key;
  };

  // Pass 1 -- register every file and every function-like node, so that pass 2
  // can resolve a call target to something that already has a key.
  for (const sf of sourceFiles) {
    const rel = relOf(sf);
    const ext = path.extname(rel).replace(".", "");
    files.push({ key: fileKey(service, rel), path: rel, lang: ext });

    // Top-level code is real code. `const app = express()` and
    // `app.post(...)` run at module scope, and without somewhere to attribute
    // them a framework initialised at the top of a file looks unused -- which
    // would report it as "installed, never called" and understate the risk.
    functions.push({
      key: funcKey(service, rel, "<module>", 0),
      name: "<module>",
      file: rel,
      line: 0,
      exported: false,
    });

    for (const node of sf.getDescendants()) {
      if (!FUNCTION_KINDS.has(node.getKind())) continue;
      const line = node.getStartLineNumber();
      const name = functionName(node);
      const key = funcKey(service, rel, name, line);
      keyByNode.set(node, key);
      functions.push({
        key,
        name,
        file: rel,
        line,
        exported: typeof node.isExported === "function" ? node.isExported() : false,
      });
    }
  }

  // Pass 2 -- imports, calls, and routes.
  for (const sf of sourceFiles) {
    const rel = relOf(sf);

    for (const decl of sf.getImportDeclarations()) {
      const specifier = decl.getModuleSpecifierValue();
      if (isRelative(specifier)) continue;
      const names = [];
      const def = decl.getDefaultImport();
      if (def) names.push(def.getText());
      const ns = decl.getNamespaceImport();
      if (ns) names.push(`* as ${ns.getText()}`);
      for (const named of decl.getNamedImports()) names.push(named.getName());
      noteImport(specifier, rel, names);
    }

    const moduleKey = funcKey(service, rel, "<module>", 0);

    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const caller = enclosingFunction(call, keyByNode) ?? moduleKey;

      // require("pkg") -- record the import even at module top level.
      const required = requireTarget(call);
      if (required && !isRelative(required)) {
        const key = noteImport(required, rel, []);
        if (caller) callsExternal.add(JSON.stringify([caller, key]));
        continue;
      }

      const expression = call.getExpression();
      const root = rootIdentifier(expression);
      if (!root) {
        stats.dynamicCalls += 1; // computed member access, IIFE, etc.
        continue;
      }

      const resolved = resolveIdentifier(root);
      if (!resolved) {
        stats.unresolvedCalls += 1;
        continue;
      }

      if (resolved.kind === "external") {
        const key = noteImport(resolved.specifier, rel, [root.getText()]);
        callsExternal.add(JSON.stringify([caller, key]));
        continue;
      }

      // Local call. For `obj.method()` the root identifier resolves to the
      // object, so prefer resolving the property itself when we can.
      let targetNode = resolved.node;
      if (Node.isPropertyAccessExpression(expression)) {
        const viaProperty = resolveIdentifier(expression.getNameNode());
        if (viaProperty && viaProperty.kind === "local") targetNode = viaProperty.node;
      }

      const calleeKey = keyByNode.get(targetNode);
      if (calleeKey && calleeKey !== caller) {
        calls.add(JSON.stringify([caller, calleeKey]));
      } else if (!calleeKey) {
        stats.unresolvedCalls += 1;
      }
    }

    collectRoutes(sf, rel, service, keyByNode, routes, stats);
  }

  return {
    service,
    root,
    files,
    functions,
    calls: [...calls].map((s) => JSON.parse(s)),
    externalImports: [...externalImports.values()].map((e) => ({
      key: e.key,
      specifier: e.specifier,
      file: e.file,
      names: [...e.names],
      file_count: e.files.size,
    })),
    callsExternal: [...callsExternal].map((s) => JSON.parse(s)),
    routes,
    stats: {
      ...stats,
      files: files.length,
      functions: functions.length,
      calls: calls.size,
      externalImports: externalImports.size,
      callsExternal: callsExternal.size,
      routes: routes.length,
    },
  };
}

/**
 * Find HTTP route registrations and the function each one dispatches to.
 *
 * These are the entry points that turn "the package is installed" into "the
 * package is reachable from the internet", so they carry most of the severity
 * signal. Detection is deliberately Express/Fastify-shaped and pattern-based;
 * a route registered through a decorator or a dynamic table will be missed,
 * which is why the count is reported in stats rather than presented as
 * exhaustive.
 */
function collectRoutes(sf, rel, service, keyByNode, routes, stats) {
  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const expression = call.getExpression();
    if (!Node.isPropertyAccessExpression(expression)) continue;

    const method = expression.getName().toLowerCase();
    if (!ROUTE_METHODS.has(method)) continue;

    const receiver = rootIdentifier(expression.getExpression());
    if (!receiver || !ROUTER_NAMES.test(receiver.getText())) continue;

    const args = call.getArguments();
    if (args.length < 2) continue;
    const [first] = args;
    if (!Node.isStringLiteral(first)) continue;

    const pattern = first.getLiteralValue();
    const line = call.getStartLineNumber();

    // Every argument after the path can be a handler -- middleware chains are
    // normal, and middleware is just as reachable as the final handler.
    for (const arg of args.slice(1)) {
      let handlerKey = null;
      if (FUNCTION_KINDS.has(arg.getKind())) {
        handlerKey = keyByNode.get(arg) ?? null;
      } else if (Node.isIdentifier(arg)) {
        const resolved = resolveIdentifier(arg);
        if (resolved && resolved.kind === "local") {
          handlerKey = keyByNode.get(resolved.node) ?? null;
        }
      }
      if (!handlerKey) continue;
      routes.push({
        key: routeKey(service, method.toUpperCase(), pattern, rel, line),
        method: method.toUpperCase(),
        pattern,
        file: rel,
        line,
        handler: handlerKey,
      });
    }
  }
}

function main() {
  const argv = process.argv.slice(2);
  if (!argv.length) {
    console.error("usage: node scan.mjs <project-dir> [--service NAME] [--out FILE]");
    process.exit(2);
  }
  const root = path.resolve(argv[0]);
  const serviceIdx = argv.indexOf("--service");
  const outIdx = argv.indexOf("--out");
  const service = serviceIdx >= 0 ? argv[serviceIdx + 1] : path.basename(root);
  const out = outIdx >= 0 ? argv[outIdx + 1] : null;

  if (!fs.existsSync(root)) {
    console.error(`no such directory: ${root}`);
    process.exit(1);
  }

  const result = scan(root, service);
  const json = JSON.stringify(result, null, 2);
  if (out) {
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, json, "utf8");
    console.error(`${service}: ${JSON.stringify(result.stats)}`);
    console.error(`wrote ${out}`);
  } else {
    process.stdout.write(json);
  }
}

// Only run when invoked as a script, not when imported by a test.
const entry = process.argv[1] ? pathToFileURL(process.argv[1]).href : null;
if (entry && import.meta.url === entry) main();
