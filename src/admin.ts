import { Router } from "express";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import db from "./db";
import {
  checkCredentials,
  createSession,
  hashPassword,
  logAudit,
  requireLogin,
  requireSupervisor,
} from "./auth";

function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as { code?: string }).code === "SQLITE_CONSTRAINT_UNIQUE"
  );
}

type Actor = { id: string; username: string; role: string };

const usernameRule = z
  .string()
  .trim()
  .min(3)
  .max(50)
  .regex(/^[A-Za-z0-9._-]+$/, "Use letters, numbers, dots, dashes or underscores");

export const adminRouter = Router();

// ---------- Jobs ----------

adminRouter.get("/jobs", requireSupervisor, (_req, res) => {
  const jobs = db
    .prepare(
      `SELECT j.id, j.name,
              (SELECT COUNT(*) FROM users u WHERE u.job_id = j.id) AS employeeCount
       FROM jobs j ORDER BY j.name`
    )
    .all() as { id: string; name: string; employeeCount: number }[];
  const links = db
    .prepare("SELECT job_id AS jobId, system_id AS systemId FROM job_systems")
    .all() as { jobId: string; systemId: string }[];
  res.json(
    jobs.map((j) => ({
      ...j,
      systemIds: links.filter((l) => l.jobId === j.id).map((l) => l.systemId),
    }))
  );
});

adminRouter.post("/jobs", requireSupervisor, (req, res) => {
  const parsed = z.object({ name: z.string().trim().min(1).max(60) }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Enter a job name" });
    return;
  }
  const id = randomUUID();
  try {
    db.prepare("INSERT INTO jobs (id, name) VALUES (?, ?)").run(id, parsed.data.name);
  } catch (err) {
    if (isUniqueViolation(err)) {
      res.status(409).json({ error: "A job with that name already exists" });
      return;
    }
    throw err;
  }
  logAudit(res.locals.user.id, "job_created", null, { jobId: id, name: parsed.data.name });
  res.status(201).json({ id });
});

adminRouter.put("/jobs/:id/systems", requireSupervisor, (req, res) => {
  const parsed = z
    .object({ systemIds: z.array(z.string().max(100)).max(500) })
    .safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid input" });
    return;
  }
  const id = String(req.params.id);
  if (!db.prepare("SELECT 1 FROM jobs WHERE id = ?").get(id)) {
    res.status(404).json({ error: "Job not found" });
    return;
  }
  const ids = [...new Set(parsed.data.systemIds)];
  const exists = db.prepare("SELECT 1 FROM systems WHERE id = ?");
  if (!ids.every((s) => exists.get(s))) {
    res.status(400).json({ error: "Unknown system" });
    return;
  }

  db.transaction(() => {
    db.prepare("DELETE FROM job_systems WHERE job_id = ?").run(id);
    const insert = db.prepare("INSERT INTO job_systems (job_id, system_id) VALUES (?, ?)");
    for (const s of ids) insert.run(id, s);
  })();

  logAudit(res.locals.user.id, "job_systems_updated", null, { jobId: id, count: ids.length });
  res.json({ ok: true });
});

adminRouter.delete("/jobs/:id", requireSupervisor, (req, res) => {
  const id = String(req.params.id);
  const used = db.prepare("SELECT COUNT(*) AS n FROM users WHERE job_id = ?").get(id) as { n: number };
  if (used.n > 0) {
    res.status(409).json({ error: `Move the ${used.n} account(s) with this job to another job first` });
    return;
  }
  const result = db.prepare("DELETE FROM jobs WHERE id = ?").run(id);
  if (result.changes === 0) {
    res.status(404).json({ error: "Job not found" });
    return;
  }
  logAudit(res.locals.user.id, "job_deleted", null, { jobId: id });
  res.json({ ok: true });
});

// ---------- Accounts: supervisors manage employees, the master manages everyone ----------

adminRouter.get("/users", requireSupervisor, (_req, res) => {
  const actor = res.locals.user as Actor;
  const where = actor.role === "master" ? "" : "WHERE role = 'user'";
  const rows = db
    .prepare(
      `SELECT id, username, role, job_id AS jobId, active, pending, created_at AS createdAt
       FROM users ${where} ORDER BY username`
    )
    .all();
  res.json(rows);
});

const newUserSchema = z.object({
  username: usernameRule,
  password: z.string().min(10).max(200),
  role: z.enum(["master", "admin", "user"]).default("user"),
  jobId: z.string().max(100).nullable().optional(),
});

adminRouter.post("/users", requireSupervisor, (req, res) => {
  const actor = res.locals.user as Actor;
  const parsed = newUserSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: "Username needs 3+ characters (letters, numbers, . - _) and the password 10+ characters",
    });
    return;
  }
  const d = parsed.data;
  if (actor.role !== "master" && d.role !== "user") {
    res.status(403).json({ error: "Only the master can create supervisors" });
    return;
  }
  const jobId = d.jobId || null;
  if (jobId && !db.prepare("SELECT 1 FROM jobs WHERE id = ?").get(jobId)) {
    res.status(400).json({ error: "Unknown job" });
    return;
  }

  const id = randomUUID();
  try {
    db.prepare(
      "INSERT INTO users (id, username, password_hash, role, job_id) VALUES (?, ?, ?, ?, ?)"
    ).run(id, d.username, hashPassword(d.password), d.role, jobId);
  } catch (err) {
    if (isUniqueViolation(err)) {
      res.status(409).json({ error: "That username is already taken" });
      return;
    }
    throw err;
  }
  logAudit(actor.id, "user_created", null, { username: d.username, role: d.role });
  res.status(201).json({ id });
});

const patchUserSchema = z.object({
  role: z.enum(["master", "admin", "user"]).optional(),
  jobId: z.string().max(100).nullable().optional(),
  active: z.boolean().optional(),
});

adminRouter.patch("/users/:id", requireSupervisor, (req, res) => {
  const actor = res.locals.user as Actor;
  const parsed = patchUserSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid input" });
    return;
  }
  const id = String(req.params.id);
  const current = db
    .prepare("SELECT id, role, job_id AS jobId, active, pending FROM users WHERE id = ?")
    .get(id) as
    | { id: string; role: string; jobId: string | null; active: number; pending: number }
    | undefined;
  if (!current) {
    res.status(404).json({ error: "Account not found" });
    return;
  }
  if (current.pending === 1) {
    res.status(400).json({ error: "Approve or reject this request first" });
    return;
  }

  if (actor.role !== "master") {
    if (current.role !== "user") {
      res.status(403).json({ error: "Supervisors can only manage employees" });
      return;
    }
    if (parsed.data.role !== undefined) {
      res.status(403).json({ error: "Only the master can change roles" });
      return;
    }
  }

  const role = parsed.data.role ?? current.role;
  const jobId = parsed.data.jobId === undefined ? current.jobId : parsed.data.jobId || null;
  const active =
    parsed.data.active === undefined ? current.active : parsed.data.active ? 1 : 0;

  if (jobId && !db.prepare("SELECT 1 FROM jobs WHERE id = ?").get(jobId)) {
    res.status(400).json({ error: "Unknown job" });
    return;
  }

  // Never lock everyone out
  const losesMaster =
    current.role === "master" && current.active === 1 && (role !== "master" || active === 0);
  if (losesMaster) {
    const others = db
      .prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'master' AND active = 1 AND id != ?")
      .get(id) as { n: number };
    if (others.n === 0) {
      res.status(400).json({ error: "There must always be at least one active master account" });
      return;
    }
  }

  db.prepare("UPDATE users SET role = ?, job_id = ?, active = ? WHERE id = ?").run(
    role,
    jobId,
    active,
    id
  );
  if (active === 0) db.prepare("DELETE FROM sessions WHERE user_id = ?").run(id);

  logAudit(actor.id, "user_updated", null, { userId: id, role, jobId, active });
  res.json({ ok: true });
});

adminRouter.post("/users/:id/password", requireSupervisor, (req, res) => {
  const actor = res.locals.user as Actor;
  const parsed = z.object({ password: z.string().min(10).max(200) }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "The password needs at least 10 characters" });
    return;
  }
  const id = String(req.params.id);
  const target = db.prepare("SELECT role, pending FROM users WHERE id = ?").get(id) as
    | { role: string; pending: number }
    | undefined;
  if (!target) {
    res.status(404).json({ error: "Account not found" });
    return;
  }
  if (target.pending === 1) {
    res.status(400).json({ error: "Approve or reject this request first" });
    return;
  }
  if (actor.role !== "master" && target.role !== "user") {
    res.status(403).json({ error: "Supervisors can only manage employees" });
    return;
  }

  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(
    hashPassword(parsed.data.password),
    id
  );
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(id);
  logAudit(actor.id, "password_reset", null, { userId: id });
  res.json({ ok: true });
});

// Account requests: approve (and pick a job) or reject

adminRouter.post("/users/:id/approve", requireSupervisor, (req, res) => {
  const parsed = z
    .object({ jobId: z.string().max(100).nullable().optional() })
    .safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid input" });
    return;
  }
  const id = String(req.params.id);
  const target = db.prepare("SELECT username, pending FROM users WHERE id = ?").get(id) as
    | { username: string; pending: number }
    | undefined;
  if (!target || target.pending !== 1) {
    res.status(404).json({ error: "No waiting request found" });
    return;
  }
  const jobId = parsed.data.jobId || null;
  if (jobId && !db.prepare("SELECT 1 FROM jobs WHERE id = ?").get(jobId)) {
    res.status(400).json({ error: "Unknown job" });
    return;
  }

  db.prepare("UPDATE users SET active = 1, pending = 0, job_id = ? WHERE id = ?").run(jobId, id);
  logAudit(res.locals.user.id, "signup_approved", null, { username: target.username, jobId });
  res.json({ ok: true });
});

adminRouter.post("/users/:id/reject", requireSupervisor, (req, res) => {
  const id = String(req.params.id);
  const target = db.prepare("SELECT username, pending FROM users WHERE id = ?").get(id) as
    | { username: string; pending: number }
    | undefined;
  if (!target || target.pending !== 1) {
    res.status(404).json({ error: "No waiting request found" });
    return;
  }
  db.prepare("DELETE FROM users WHERE id = ? AND pending = 1").run(id);
  logAudit(res.locals.user.id, "signup_rejected", null, { username: target.username });
  res.json({ ok: true });
});

// ---------- Anyone: ask for an account (stays locked until approved) ----------
export const signupRouter = Router();

const signupAttempts = new Map<string, { count: number; first: number }>();
const SIGNUP_WINDOW_MS = 10 * 60 * 1000;
const SIGNUP_MAX_PER_WINDOW = 5;
const MAX_WAITING = 50;

function signupThrottled(key: string): boolean {
  const now = Date.now();
  const entry = signupAttempts.get(key);
  if (!entry || now - entry.first > SIGNUP_WINDOW_MS) {
    signupAttempts.set(key, { count: 1, first: now });
    return false;
  }
  entry.count += 1;
  return entry.count > SIGNUP_MAX_PER_WINDOW;
}

signupRouter.post("/", (req, res) => {
  if (signupThrottled(req.ip ?? "unknown")) {
    res.status(429).json({ error: "Too many requests from this computer. Try again in a few minutes." });
    return;
  }
  const parsed = z
    .object({ username: usernameRule, password: z.string().min(10).max(200) })
    .safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: "Username needs 3+ characters (letters, numbers, . - _) and the password 10+ characters",
    });
    return;
  }
  const waiting = db.prepare("SELECT COUNT(*) AS n FROM users WHERE pending = 1").get() as { n: number };
  if (waiting.n >= MAX_WAITING) {
    res.status(503).json({ error: "Too many requests are waiting. Please ask your supervisor." });
    return;
  }

  try {
    db.prepare(
      "INSERT INTO users (id, username, password_hash, role, active, pending) VALUES (?, ?, ?, 'user', 0, 1)"
    ).run(randomUUID(), parsed.data.username, hashPassword(parsed.data.password));
  } catch (err) {
    if (isUniqueViolation(err)) {
      res.status(409).json({ error: "That username is already taken or already requested" });
      return;
    }
    throw err;
  }
  logAudit(null, "signup_requested", null, { username: parsed.data.username });
  res.status(201).json({ ok: true });
});

// ---------- Any logged-in person ----------
export const accountRouter = Router();

accountRouter.post("/password", requireLogin, (req, res) => {
  const parsed = z
    .object({
      currentPassword: z.string().min(1).max(200),
      newPassword: z.string().min(10).max(200),
    })
    .safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "The new password needs at least 10 characters" });
    return;
  }
  const user = res.locals.user;
  if (!checkCredentials(user.username, parsed.data.currentPassword)) {
    res.status(400).json({ error: "Your current password is wrong" });
    return;
  }

  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(
    hashPassword(parsed.data.newPassword),
    user.id
  );
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(user.id);
  const token = createSession(user.id);
  logAudit(user.id, "password_changed", null);
  res.json({ token });
});