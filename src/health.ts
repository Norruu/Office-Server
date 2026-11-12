import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import db from "./db";
import { requireSupervisor } from "./auth";
import { BACKUP_DIR, backupStatus, listBackups } from "./backup";

type Level = "ok" | "warning" | "critical" | "info";
type Check = { id: string; label: string; level: Level; detail: string };

const CERT_DIR = process.env.CERT_DIR ?? "certs";
const INSTALLER_DIR = process.env.INSTALLER_DIR ?? "installers";
const UPDATE_DIR = process.env.UPDATE_DIR ?? "updates";
const DB_FILE = "office-hub.db";
const GB = 1024 ** 3;
const HOUR = 60 * 60 * 1000;

function fmtBytes(n: number): string {
  if (n >= GB) return `${(n / GB).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(n / 1024))} KB`;
}

function fmtAge(ms: number): string {
  const m = Math.floor(ms / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} minute${m === 1 ? "" : "s"} ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} hour${h === 1 ? "" : "s"} ago`;
  return `${Math.floor(h / 24)} days ago`;
}

function fmtUptime(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

function dirInfo(dir: string): { files: number; bytes: number } {
  let files = 0;
  let bytes = 0;
  const walk = (d: string) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, entry.name);
      if (entry.isDirectory()) walk(p);
      else {
        files += 1;
        bytes += fs.statSync(p).size;
      }
    }
  };
  try {
    if (fs.existsSync(dir)) walk(dir);
  } catch {
    // a file may disappear while we count; partial numbers are fine
  }
  return { files, bytes };
}

export function collectChecks(): { status: Level; checks: Check[] } {
  const checks: Check[] = [];
  const add = (id: string, label: string, level: Level, detail: string) =>
    checks.push({ id, label, level, detail });

  // Disk space on the drive that holds the database
  try {
    const s = fs.statfsSync(".");
    const free = Number(s.bavail) * Number(s.bsize);
    const total = Number(s.blocks) * Number(s.bsize);
    const pct = total ? (free / total) * 100 : 0;
    const level: Level = free < 2 * GB || pct < 5 ? "critical" : free < 10 * GB || pct < 15 ? "warning" : "ok";
    add("disk", "Disk space", level, `${fmtBytes(free)} free of ${fmtBytes(total)} (${pct.toFixed(0)}%).`);
  } catch {
    add("disk", "Disk space", "info", "Could not read the free space on this system.");
  }

  // Backups
  const backups = listBackups();
  if (backups.length === 0) {
    add("backups", "Backups", "critical", "No backups exist yet. Press Back up now.");
  } else {
    const newest = backups[backups.length - 1];
    const age = Date.now() - fs.statSync(path.join(BACKUP_DIR, newest)).mtimeMs;
    const total = backups.reduce((sum, f) => sum + fs.statSync(path.join(BACKUP_DIR, f)).size, 0);
    const level: Level = age > 24 * HOUR ? "critical" : age > 12 * HOUR ? "warning" : "ok";
    add("backups", "Backups", level, `Newest backup was made ${fmtAge(age)}. ${backups.length} kept (${fmtBytes(total)}).`);
  }
  if (backupStatus.lastError && backupStatus.lastErrorAt) {
    add(
      "backup-run",
      "Last backup attempt",
      "critical",
      `Failed ${fmtAge(Date.now() - backupStatus.lastErrorAt)}: ${backupStatus.lastError}`
    );
  }

  // Are backups on the same drive as the database?
  try {
    if (fs.existsSync(BACKUP_DIR) && fs.existsSync(DB_FILE)) {
      const same = fs.statSync(BACKUP_DIR).dev === fs.statSync(DB_FILE).dev;
      add(
        "backup-location",
        "Backup location",
        same ? "warning" : "ok",
        same
          ? `${path.resolve(BACKUP_DIR)} is on the same drive as the database. If that drive fails, both are lost. Copy backups to another drive or computer.`
          : `${path.resolve(BACKUP_DIR)} (a different drive from the database).`
      );
    }
  } catch {
    // skip this check if the drives can't be compared
  }

  // Encryption and certificate
  const certFile = path.join(CERT_DIR, "server.cert.pem");
  const keyFile = path.join(CERT_DIR, "server.key.pem");
  if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
    add("tls", "Encryption (HTTPS)", "warning", "Not set up. Passwords travel as plain text on the network.");
  } else {
    try {
      const cert = new X509Certificate(fs.readFileSync(certFile));
      const expires = Date.parse(cert.validTo);
      const days = Math.floor((expires - Date.now()) / 86_400_000);
      const level: Level = days < 14 ? "critical" : days < 60 ? "warning" : "ok";
      add(
        "tls",
        "Encryption (HTTPS)",
        level,
        days < 0
          ? "The server certificate has EXPIRED. Run make-certs and restart the server."
          : `The certificate expires on ${new Date(expires).toLocaleDateString()} (${days} days).`
      );
    } catch {
      add("tls", "Encryption (HTTPS)", "critical", "The certificate file could not be read.");
    }
  }

  // Database
  try {
    const size = fs.statSync(DB_FILE).size;
    const result = db.pragma("quick_check", { simple: true });
    add(
      "database",
      "Database",
      result === "ok" ? "ok" : "critical",
      result === "ok"
        ? `Healthy (${fmtBytes(size)}).`
        : `A problem was found: ${String(result)}. Restore from a backup.`
    );
  } catch {
    add("database", "Database", "critical", "The database could not be checked.");
  }

  // Files that the database backup does not include
  const inst = dirInfo(INSTALLER_DIR);
  const upd = dirInfo(UPDATE_DIR);
  add(
    "files",
    "Installer and update files",
    "info",
    `${inst.files} installer file(s), ${fmtBytes(inst.bytes)}; ${upd.files} app update file(s), ${fmtBytes(upd.bytes)}. These are not part of the database backup.`
  );

  const pending = (db.prepare("SELECT COUNT(*) AS n FROM users WHERE pending = 1").get() as { n: number }).n;
  if (pending > 0) add("pending", "Account requests", "info", `${pending} waiting for approval.`);

  const sessions = (
    db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE expires_at > ?").get(new Date().toISOString()) as { n: number }
  ).n;
  add("server", "Server", "info", `Running for ${fmtUptime(process.uptime())} on Node ${process.version}. ${sessions} active login(s).`);

  const status: Level = checks.some((c) => c.level === "critical")
    ? "critical"
    : checks.some((c) => c.level === "warning")
      ? "warning"
      : "ok";
  return { status, checks };
}

export const healthRouter = Router();

healthRouter.get("/health", requireSupervisor, (_req, res) => {
  res.json(collectChecks());
});

// Write problems to server.log once a day, so they are visible even if nobody opens the app
export function startHealthLog() {
  const run = () => {
    try {
      const { status, checks } = collectChecks();
      for (const c of checks) {
        if (c.level === "warning" || c.level === "critical") {
          console.warn(`[health] ${c.level.toUpperCase()}: ${c.label}: ${c.detail}`);
        }
      }
      if (status === "ok") console.log("[health] All checks passed.");
    } catch (err) {
      console.error("[health] check failed:", err);
    }
  };
  setTimeout(run, 10_000);
  setInterval(run, 24 * HOUR);
}