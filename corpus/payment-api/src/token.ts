import { sign } from "vulnerable-pkg";

/** Reached from POST /login -> handleLogin -> verify -> here. */
export function verify(token: string): boolean {
  return sign(token).length > 0;
}

export function unusedHelper(x: number): number {
  return x * 2;
}
