import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import db from "./db";

export const BACKUP_DIR = process.env.BACKUP_DIR ?? "backups";
const KEEP = 14;
const EVERY_MS = 6 * 60 * 60 * 1000;

export const backupStatus: {
  lastOkAt: number | null;
  lastError: string | null;
  lastErrorAt: number | null;
} = { lastOkAt: null, lastError: null, lastErrorAt: null };

export function listBackups(): string[] {
  if (!fs.existsSync(BACKUP_DIR)) return [];
  return fs
    .readdirSync(BACKUP_DIR)
    .filter((f) => /^office-hub-.*\.db$/.test(f))
    .sort(); // oldest first, because the names contain the date
}

export async function createBackup(): Promise<string> {
  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const file = path.join(BACKUP_DIR, `office-hub-${stamp}.db`);

    await db.backup(file);

    // Open the copy and check it is healthy
    const copy = new Database(file, { readonly: true });
    try {
      const result = copy.pragma("integrity_check", { simple: true });
      if (result !== "ok") throw new Error(`Backup failed its integrity check: ${result}`);
    } finally {
      copy.close();
    }

    // Keep only the newest backups
    const all = listBackups();
    for (const old of all.slice(0, Math.max(0, all.length - KEEP))) {
      fs.unlinkSync(path.join(BACKUP_DIR, old));
    }

    backupStatus.lastOkAt = Date.now();
    backupStatus.lastError = null;
    return file;
  } catch (err) {
    backupStatus.lastError = err instanceof Error ? err.message : String(err);
    backupStatus.lastErrorAt = Date.now();
    throw err;
  }
}

export function startBackupSchedule() {
  const run = () =>
    createBackup()
      .then((f) => console.log("Backup created:", f))
      .catch((e) => console.error("Backup failed:", e));

  // The server restarts often while you develop, so skip the startup backup if a recent one exists
  const newest = listBackups().pop();
  const newestAge = newest
    ? Date.now() - fs.statSync(path.join(BACKUP_DIR, newest)).mtimeMs
    : Infinity;
  if (newestAge > EVERY_MS) run();

  setInterval(run, EVERY_MS);
}