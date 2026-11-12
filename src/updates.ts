import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import db from "./db";
import { logAudit, requireMaster } from "./auth";

const DIR = process.env.UPDATE_DIR ?? "updates";
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB
const EXT: Record<string, string> = { windows: ".exe", linux: ".appimage" };
const VERSION = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/;

db.exec(`
  CREATE TABLE IF NOT EXISTS app_releases (
    platform TEXT PRIMARY KEY CHECK (platform IN ('windows', 'linux')),
    version TEXT NOT NULL,
    filename TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    uploaded_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

function isNewer(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] > pb[i];
  }
  return false;
}

type Row = {
  version: string;
  filename: string;
  stored_name: string;
  size: number;
  sha256: string;
  notes: string;
};

const router = Router();

// Public: any copy of Office Hub can ask for the newest version
router.get("/app-update", (req, res) => {
  const platform = String(req.query.platform ?? "");
  const row = db
    .prepare("SELECT version, filename, size, sha256, notes FROM app_releases WHERE platform = ?")
    .get(platform);
  if (!row) {
    res.status(404).json({ error: "No update has been published" });
    return;
  }
  res.json(row);
});

// Public: download the newest version
router.get("/app-update/download", (req, res) => {
  const platform = String(req.query.platform ?? "");
  const row = db
    .prepare("SELECT stored_name, size, sha256 FROM app_releases WHERE platform = ?")
    .get(platform) as Pick<Row, "stored_name" | "size" | "sha256"> | undefined;
  if (!row) {
    res.status(404).json({ error: "No update has been published" });
    return;
  }
  const file = path.join(DIR, path.basename(row.stored_name));
  if (!fs.existsSync(file)) {
    res.status(404).json({ error: "The update file is missing on the server" });
    return;
  }
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Length", String(row.size));
  res.setHeader("X-Installer-Sha256", row.sha256);
  fs.createReadStream(file)
    .on("error", () => res.destroy())
    .pipe(res);
});

// Master only: list what is published
router.get("/app-updates", requireMaster, (_req, res) => {
  const rows = db
    .prepare(
      `SELECT platform, version, filename, size, sha256, notes, created_at AS createdAt
       FROM app_releases ORDER BY platform`
    )
    .all();
  res.json(rows);
});

// Master only: publish a release. The file is the raw request body, streamed to disk.
router.put("/app-update", requireMaster, (req, res) => {
  const reject = (status: number, error: string) => {
    res.set("Connection", "close");
    res.status(status).json({ error });
  };

  const platform = String(req.query.platform ?? "");
  const version = String(req.query.version ?? "");
  const notes = String(req.query.notes ?? "").slice(0, 200);
  const filename = path
    .basename(String(req.query.filename ?? ""))
    .replace(/[^\w.\- ()]/g, "_")
    .slice(0, 120);

  if (!EXT[platform]) return reject(400, "Platform must be windows or linux");
  if (!VERSION.test(version)) return reject(400, "The version must look like 1.0.1");
  if (!filename.toLowerCase().endsWith(EXT[platform])) {
    return reject(400, `A ${platform} update must be a ${EXT[platform]} file`);
  }
  if (!filename.includes(version)) {
    return reject(400, "The file name must contain the version number (this catches mix-ups)");
  }
  const existing = db
    .prepare("SELECT version, stored_name FROM app_releases WHERE platform = ?")
    .get(platform) as { version: string; stored_name: string } | undefined;
  if (existing && !isNewer(version, existing.version)) {
    return reject(409, `The version must be higher than the published one (${existing.version})`);
  }
  const length = Number(req.headers["content-length"] ?? 0);
  if (!length) return reject(411, "The file size is missing");
  if (length > MAX_BYTES) return reject(413, "File is too large (2 GB maximum)");

  fs.mkdirSync(DIR, { recursive: true });
  const storedName = `${randomUUID()}.bin`;
  const finalPath = path.join(DIR, storedName);
  const tmpPath = finalPath + ".part";
  const hash = createHash("sha256");
  let size = 0;
  let failed = false;
  const out = fs.createWriteStream(tmpPath);

  function fail(status: number, error: string) {
    if (failed) return;
    failed = true;
    req.unpipe(out);
    out.destroy();
    fs.rm(tmpPath, { force: true }, () => {});
    if (!res.headersSent) reject(status, error);
  }

  req.on("data", (chunk: Buffer) => {
    size += chunk.length;
    if (size > MAX_BYTES) {
      fail(413, "File is too large (2 GB maximum)");
      return;
    }
    hash.update(chunk);
  });
  req.on("error", () => fail(400, "Upload failed"));
  req.on("close", () => {
    if (!req.complete) fail(400, "Upload cancelled");
  });
  out.on("error", () => fail(500, "Could not save the file"));

  out.on("finish", () => {
    if (failed) return;
    if (size === 0 || size !== length) {
      fail(400, "The upload was incomplete");
      return;
    }
    try {
      fs.renameSync(tmpPath, finalPath);
      const sha256 = hash.digest("hex");
      db.prepare(
        `INSERT INTO app_releases (platform, version, filename, stored_name, size, sha256, notes, uploaded_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(platform) DO UPDATE SET
           version = excluded.version, filename = excluded.filename,
           stored_name = excluded.stored_name, size = excluded.size,
           sha256 = excluded.sha256, notes = excluded.notes,
           uploaded_by = excluded.uploaded_by, created_at = CURRENT_TIMESTAMP`
      ).run(platform, version, filename, storedName, size, sha256, notes, res.locals.user.id);

      if (existing) fs.rm(path.join(DIR, path.basename(existing.stored_name)), { force: true }, () => {});
      logAudit(res.locals.user.id, "app_release_published", null, { platform, version, filename, size, sha256 });
      res.status(201).json({ ok: true, sha256, size });
    } catch (err) {
      console.error("Release upload failed:", err);
      fail(500, "Could not save the file");
    }
  });

  req.pipe(out);
});

// Master only: withdraw a release
router.delete("/app-update", requireMaster, (req, res) => {
  const platform = String(req.query.platform ?? "");
  const row = db
    .prepare("SELECT version, stored_name FROM app_releases WHERE platform = ?")
    .get(platform) as { version: string; stored_name: string } | undefined;
  if (!row) {
    res.status(404).json({ error: "Nothing is published for that platform" });
    return;
  }
  db.prepare("DELETE FROM app_releases WHERE platform = ?").run(platform);
  fs.rm(path.join(DIR, path.basename(row.stored_name)), { force: true }, () => {});
  logAudit(res.locals.user.id, "app_release_removed", null, { platform, version: row.version });
  res.json({ ok: true });
});

export default router;