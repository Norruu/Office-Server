import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";

const BACKUP_DIR = process.env.BACKUP_DIR ?? "backups";
const LIVE = "office-hub.db";

const name = process.argv[2];
if (!name) {
  console.log("Usage: npx tsx src/restore.ts <backup file name>\n");
  console.log("Available backups:");
  if (fs.existsSync(BACKUP_DIR)) {
    for (const f of fs.readdirSync(BACKUP_DIR).sort()) console.log("  " + f);
  }
  process.exit(1);
}

const source = path.join(BACKUP_DIR, path.basename(name));
if (!fs.existsSync(source)) {
  console.log("Backup not found:", source);
  process.exit(1);
}

// Make sure the backup is healthy before touching anything
const check = new Database(source, { readonly: true });
const result = check.pragma("integrity_check", { simple: true });
check.close();
if (result !== "ok") {
  console.log("That backup is damaged. Nothing was changed.");
  process.exit(1);
}

// Keep a safety copy of the current database
if (fs.existsSync(LIVE)) {
  const safety = `${LIVE}.before-restore-${Date.now()}`;
  fs.copyFileSync(LIVE, safety);
  console.log("Saved the current database as", safety);
}

// Remove leftover side files, then restore
for (const ext of ["-wal", "-shm", "-journal"]) fs.rmSync(LIVE + ext, { force: true });
fs.copyFileSync(source, LIVE);
console.log("Restored from", source, "\nNow start the server again.");