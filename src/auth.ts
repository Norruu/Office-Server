import {
  randomBytes,
  scryptSync,
  timingSafeEqual,
  createHash,
  randomUUID,
} from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import db from "./db";

const SESSION_HOURS = 24;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

function verifyPassword(password: string, stored: string): boolean {
  const [saltHex, hashHex] = stored.split(":");
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  const actual = scryptSync(
    password,
    Buffer.from(saltHex, "hex"),
    expected.length,
  );
  return timingSafeEqual(actual, expected);
}

// Used when the username doesn't exist, so the check takes the same time either way
const DUMMY_HASH = hashPassword("dummy-password-for-timing");

type User = { id: string; username: string; role: string };

export function checkCredentials(
  username: string,
  password: string,
): User | null {
  const row = db
    .prepare(
      "SELECT id, username, password_hash, role, active FROM users WHERE username = ?",
    )
    .get(username) as
    | (User & { password_hash: string; active: number })
    | undefined;
  const valid = verifyPassword(password, row ? row.password_hash : DUMMY_HASH);
  return row && row.active === 1 && valid
    ? { id: row.id, username: row.username, role: row.role }
    : null;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createSession(userId: string): string {
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(
    new Date().toISOString(),
  );
  const token = randomBytes(32).toString("hex");
  const expires = new Date(
    Date.now() + SESSION_HOURS * 3600 * 1000,
  ).toISOString();
  db.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
  ).run(sha256(token), userId, expires);
  return token;
}

export function getToken(req: Request): string | null {
  const header = req.headers.authorization ?? "";
  return header.startsWith("Bearer ") ? header.slice(7) : null;
}

export function deleteSession(token: string) {
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(sha256(token));
}

function getUser(req: Request): User | null {
  const token = getToken(req);
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT u.id, u.username, u.role
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1`,
    )
    .get(sha256(token), new Date().toISOString()) as User | undefined;
  return row ?? null;
}

export function requireLogin(req: Request, res: Response, next: NextFunction) {
  const user = getUser(req);
  if (!user) {
    res.status(401).json({ error: "Login required" });
    return;
  }
  res.locals.user = user;
  next();
}

export function requireRole(...allowed: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = getUser(req);
    if (!user) {
      res.status(401).json({ error: "Login required" });
      return;
    }
    if (!allowed.includes(user.role)) {
      res.status(403).json({ error: "You don't have permission to do that" });
      return;
    }
    res.locals.user = user;
    next();
  };
}

export const requireMaster = requireRole("master");
export const requireSupervisor = requireRole("master", "admin");

// Old name, kept so nothing breaks: it now means "master only"
export const requireAdmin = requireMaster;

export function logAudit(
  actorId: string | null,
  action: string,
  systemId: string | null,
  details?: unknown,
) {
  db.prepare(
    "INSERT INTO audit_logs (id, actor_id, action, system_id, details_json) VALUES (?, ?, ?, ?, ?)",
  ).run(
    randomUUID(),
    actorId,
    action,
    systemId,
    details ? JSON.stringify(details) : null,
  );
}

// Simple login throttle: 5 failures per 10 minutes for the same address and username
const failures = new Map<string, { count: number; first: number }>();
const WINDOW_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

export function tooManyAttempts(key: string): boolean {
  const entry = failures.get(key);
  if (!entry) return false;
  if (Date.now() - entry.first > WINDOW_MS) {
    failures.delete(key);
    return false;
  }
  return entry.count >= MAX_FAILURES;
}

export function recordFailure(key: string) {
  const entry = failures.get(key);
  if (!entry || Date.now() - entry.first > WINDOW_MS) {
    failures.set(key, { count: 1, first: Date.now() });
  } else {
    entry.count += 1;
  }
}

export function clearFailures(key: string) {
  failures.delete(key);
}
