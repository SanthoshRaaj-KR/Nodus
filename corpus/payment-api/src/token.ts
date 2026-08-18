import { UAParser } from "ua-parser-js";

/**
 * Reached from POST /login -> handleLogin -> verify -> here.
 *
 * The point of this fixture is the call below: application code on a
 * request-handling path invokes a symbol from the compromised package, which
 * is what separates "it is in the lockfile" from "a request runs it".
 */
export function verify(token: string): boolean {
  const parsed = new UAParser(token).getResult();
  return Boolean(parsed.browser.name);
}

export function unusedHelper(x: number): number {
  return x * 2;
}
