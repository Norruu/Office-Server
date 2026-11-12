import express from "express";
import cors from "cors";
import { z } from "zod";
import path from "node:path";
import { createBackup, startBackupSchedule } from "./backup";
import { adminRouter, accountRouter, signupRouter } from "./admin";
import installersRouter from "./installers";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { randomUUID, X509Certificate } from "node:crypto";
import updatesRouter from "./updates";
import locationsRouter from "./locations";
import { healthRouter, startHealthLog } from "./health";
import fleetRouter from "./fleet";
import modulesRouter from "./modules/hello";
import db from "./db";
import {
  checkCredentials,
  clearFailures,
  createSession,
  deleteSession,
  getToken,
  logAudit,
  recordFailure,
  requireSupervisor,
  requireLogin,
  tooManyAttempts,
} from "./auth";

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json({ limit: "100kb" }));
app.use("/api/admin", adminRouter);
app.use("/api/me", accountRouter);
app.use("/api", updatesRouter);
app.use("/api", locationsRouter);
app.use("/api/admin", healthRouter);
app.use("/api", fleetRouter);
app.use("/api/modules", modulesRouter);

// ---------- Public ----------

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/api/categories", requireLogin, (_req, res) => {
  const rows = db.prepare("SELECT id, name FROM categories ORDER BY name").all();
  res.json(rows);
});

app.get("/api/systems", requireLogin, (_req, res) => {
  const user = res.locals.user;
  const base = `SELECT s.id, s.name, s.description, s.category_id AS categoryId,
                       s.system_type AS systemType, s.status
                FROM systems s`;
  const rows =
      user.role === "master" || user.role === "admin"
      ? db.prepare(`${base} WHERE s.status != 'archived' ORDER BY s.name`).all()
      : db
          .prepare(
            `${base}
             JOIN job_systems js ON js.system_id = s.id
             JOIN users u ON u.job_id = js.job_id
             WHERE u.id = ? AND s.status != 'archived'
             ORDER BY s.name`
          )
          .all(user.id);
  res.json(rows);
});

// ---------- Login ----------

const loginSchema = z.object({
  username: z.string().min(1).max(100),
  password: z.string().min(1).max(200),
});

app.post("/api/login", (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Enter a username and password" });
    return;
  }
  const { username, password } = parsed.data;
  const key = `${req.ip}:${username.toLowerCase()}`;

  if (tooManyAttempts(key)) {
    res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
    return;
  }

  const user = checkCredentials(username, password);
  if (!user) {
    recordFailure(key);
    logAudit(null, "login_failed", null, { username: username.slice(0, 50) });
    res.status(401).json({ error: "Wrong username or password" });
    return;
  }

  clearFailures(key);
  const token = createSession(user.id);
  logAudit(user.id, "login", null);
  res.json({ token, user: { username: user.username, role: user.role } });
});

app.post("/api/logout", (req, res) => {
  const token = getToken(req);
  if (token) deleteSession(token);
  res.json({ ok: true });
});

app.get("/api/me", requireLogin, (_req, res) => {
  const { username, role } = res.locals.user;
  res.json({ username, role });
});

// ---------- Admin only ----------

const systemSchema = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().trim().max(500).default(""),
  categoryId: z.string().nullable().optional(),
  systemType: z.enum(["desktop", "web", "file", "module"]),
  status: z.enum(["active", "planned"]).default("active"),
});

function categoryExists(categoryId: string | null): boolean {
  if (!categoryId) return true;
  return !!db.prepare("SELECT 1 FROM categories WHERE id = ?").get(categoryId);
}

app.post("/api/systems", requireSupervisor, (req, res) => {
  const parsed = systemSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid input", issues: parsed.error.issues });
    return;
  }
  const d = parsed.data;
  const categoryId = d.categoryId || null;
  if (!categoryExists(categoryId)) {
    res.status(400).json({ error: "Unknown category" });
    return;
  }

  const id = randomUUID();
  db.prepare(
    `INSERT INTO systems (id, name, description, category_id, system_type, status)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(id, d.name, d.description, categoryId, d.systemType, d.status);

  logAudit(res.locals.user.id, "system_created", id, { name: d.name });
  res.status(201).json({ id });
});

app.patch("/api/systems/:id", requireSupervisor, (req, res) => {
  const id = String(req.params.id);
  const parsed = systemSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid input", issues: parsed.error.issues });
    return;
  }
  const d = parsed.data;
  const categoryId = d.categoryId || null;
  if (!categoryExists(categoryId)) {
    res.status(400).json({ error: "Unknown category" });
    return;
  }

  const result = db
    .prepare(
      `UPDATE systems
       SET name = ?, description = ?, category_id = ?, system_type = ?, status = ?
       WHERE id = ?`
    )
    .run(d.name, d.description, categoryId, d.systemType, d.status, req.params.id);

  if (result.changes === 0) {
    res.status(404).json({ error: "System not found" });
    return;
  }
  logAudit(res.locals.user.id, "system_updated", id, { name: d.name });
  res.json({ ok: true });
});

app.post("/api/systems/:id/archive", requireSupervisor, (req, res) => {
  const id = String(req.params.id);
  const result = db
    .prepare("UPDATE systems SET status = 'archived' WHERE id = ?")
    .run(id);

  if (result.changes === 0) {
    res.status(404).json({ error: "System not found" });
    return;
  }
  logAudit(res.locals.user.id, "system_archived", id);
  res.json({ ok: true });
});

app.get("/api/audit", requireSupervisor, (_req, res) => {
  const rows = db
    .prepare(
      `SELECT a.id, a.action, a.system_id AS systemId, a.details_json AS details,
              a.created_at AS createdAt, u.username AS actor
       FROM audit_logs a
       LEFT JOIN users u ON u.id = a.actor_id
       ORDER BY a.created_at DESC, a.rowid DESC
       LIMIT 100`
    )
    .all();
  res.json(rows);
});

app.post("/api/backup", requireSupervisor, async (_req, res) => {
  try {
    const file = await createBackup();
    logAudit(res.locals.user.id, "backup_created", null, { file: path.basename(file) });
    res.json({ ok: true, file: path.basename(file) });
  } catch (err) {
    console.error("Manual backup failed:", err);
    res.status(500).json({ error: "Backup failed" });
  }
});

app.use("/api/signup", signupRouter);

app.use("/api", installersRouter);

const CERT_DIR = process.env.CERT_DIR ?? "certs";
const keyFile = path.join(CERT_DIR, "server.key.pem");
const certFile = path.join(CERT_DIR, "server.cert.pem");
const useHttps = fs.existsSync(keyFile) && fs.existsSync(certFile);

const server = useHttps
  ? https.createServer(
      { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile), minVersion: "TLSv1.2" },
      app
    )
  : http.createServer(app);

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT} (${useHttps ? "HTTPS" : "plain HTTP, NOT encrypted"})`);
  if (useHttps) {
    const expires = Date.parse(new X509Certificate(fs.readFileSync(certFile)).validTo);
    const days = Math.floor((expires - Date.now()) / 86_400_000);
    console.log(`Server certificate expires in ${days} days`);
    if (days < 60) console.warn("WARNING: renew the server certificate soon (run make-certs again).");
  }
  startBackupSchedule();
  startHealthLog();
});
server.requestTimeout = 30 * 60 * 1000; // allow large installer uploads