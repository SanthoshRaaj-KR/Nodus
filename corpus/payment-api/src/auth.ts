import { verify } from "./token";

export function handleLogin(req: any, res: any) {
  if (verify(req.body.token)) {
    res.json({ ok: true });
  } else {
    res.status(401).end();
  }
}

export function handleHealth(req: any, res: any) {
  res.json({ status: "up" });
}
