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

    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const caller = enclosingFunction(call, keyByNode);

      // require("pkg") -- record the import even at module top level.
      const required = requireTarget(call);
      if (required && !isRelative(required)) {
        const key = noteImport(required, rel, []);
        if (caller) callsExternal.add(JSON.stringify([caller, key]));
        continue;
      }

      if (!caller) continue; // a call at module scope reaches no function

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
