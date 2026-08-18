import express from "express";
import { handleLogin, handleHealth } from "./auth";

const app = express();

app.post("/login", handleLogin);
app.get("/health", handleHealth);
app.get("/inline", (req: any, res: any) => {
  res.json({ inline: true });
});

app.listen(3000);
