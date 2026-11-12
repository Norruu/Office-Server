import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import db from "./db";
import { logAudit, requireLogin, requireMaster } from "./auth";

const DIR = process.env.INSTALLER_DIR ?? "installers";
const MAX_BYTES = 4 * 1024 * 1024 * 1024; // 4 GB per file

const ALLOWED: Record<string, string[]> = {
  windows: [".exe", ".msi"],
  linux: [".appimage", ".deb", ".rpm", ".tar.gz"],
};

db.exec(`
  CREATE TABLE IF NOT EXISTS system_installers (
    id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(id),
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'linux')),
    filename TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    uploaded_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (system_id, platform)
  );
`);

type Actor = { id: string; username: string; role: string };

// Who may download for a system: masters and supervisors for all, employees only for their job
function canAccessSystem(user: Actor, systemId: string): boolean {
  const exists = db.prepare("SELECT 1 FROM systems WHERE id = ? AND status != 'archived'").get(systemId);
  if (!exists) return false;
  if (user.role === "master" || user.role === "admin") return true;
  return !!db
    .prepare(
      `SELECT 1 FROM job_systems js
       JOIN users u ON u.job_id = js.job_id
       WHERE u.id = ? AND js.system_id = ?`
    )
    .get(user.id, systemId);
}

const router = Router();

// List the installers the person is allowed to see
router.get("/installers", requireLogin, (_req, res) => {
  const user = res.locals.user as Actor;
  const base = `SELECT i.system_id AS systemId, i.platform, i.filename, i.size, i.sha256,
                       i.created_at AS uploadedAt
                FROM system_installers i
                JOIN systems s ON s.id = i.system_id`;
  const rows =
    user.role === "master" || user.role === "admin"
      ? db.prepare(`${base} WHERE s.status != 'archived'`).all()
      : db
          .prepare(
            `${base}
             JOIN job_systems js ON js.system_id = i.system_id
             JOIN users u ON u.job_id = js.job_id
             WHERE u.id = ? AND s.status != 'archived'`
          )
          .all(user.id);
  res.json(rows);
});

// Upload (master only). The file is the raw request body, streamed to disk.
router.put("/systems/:id/installer", requireMaster, (req, res) => {
  const systemId = String(req.params.id);
  const platform = String(req.query.platform ?? "");
  const filename = path
    .basename(String(req.query.filename ?? ""))
    .replace(/[^\w.\- ()]/g, "_")
    .slice(0, 120);
  const lower = filename.toLowerCase();

  if (!ALLOWED[platform]) {
    res.status(400).json({ error: "Platform must be windows or linux" });
    return;
  }
  if (!ALLOWED[platform].some((ext) => lower.endsWith(ext))) {
    res.status(400).json({ error: `That file type is not allowed for ${platform}` });
    return;
  }
  if (!db.prepare("SELECT 1 FROM systems WHERE id = ? AND status != 'archived'").get(systemId)) {
    res.status(404).json({ error: "System not found" });
    return;
  }
  const length = Number(req.headers["content-length"] ?? 0);
  if (!length) {
    res.status(411).json({ error: "The file size is missing" });
    return;
  }
  if (length > MAX_BYTES) {
    res.status(413).json({ error: "File is too large (4 GB maximum)" });
    return;
  }

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
    if (!res.headersSent) res.status(status).json({ error });
  }

  req.on("data", (chunk: Buffer) => {
    size += chunk.length;
    if (size > MAX_BYTES) {
      fail(413, "File is too large (4 GB maximum)");
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
      const old = db
        .prepare("SELECT stored_name FROM system_installers WHERE system_id = ? AND platform = ?")
        .get(systemId, platform) as { stored_name: string } | undefined;

      db.prepare(
        `INSERT INTO system_installers (id, system_id, platform, filename, stored_name, size, sha256, uploaded_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(system_id, platform) DO UPDATE SET
           filename = excluded.filename, stored_name = excluded.stored_name,
           size = excluded.size, sha256 = excluded.sha256,
           uploaded_by = excluded.uploaded_by, created_at = CURRENT_TIMESTAMP`
      ).run(randomUUID(), systemId, platform, filename, storedName, size, sha256, res.locals.user.id);

      if (old) fs.rm(path.join(DIR, path.basename(old.stored_name)), { force: true }, () => {});
      logAudit(res.locals.user.id, "installer_uploaded", systemId, { platform, filename, size, sha256 });
      res.status(201).json({ ok: true, sha256, size });
    } catch (err) {
      console.error("Installer upload failed:", err);
      fail(500, "Could not save the file");
    }
  });

  req.pipe(out);
});

// Remove (master only)
router.delete("/systems/:id/installer", requireMaster, (req, res) => {
  const systemId = String(req.params.id);
  const platform = String(req.query.platform ?? "");
  const row = db
    .prepare("SELECT stored_name, filename FROM system_installers WHERE system_id = ? AND platform = ?")
    .get(systemId, platform) as { stored_name: string; filename: string } | undefined;
  if (!row) {
    res.status(404).json({ error: "No installer found" });
    return;
  }
  db.prepare("DELETE FROM system_installers WHERE system_id = ? AND platform = ?").run(systemId, platform);
  fs.rm(path.join(DIR, path.basename(row.stored_name)), { force: true }, () => {});
  logAudit(res.locals.user.id, "installer_removed", systemId, { platform, filename: row.filename });
  res.json({ ok: true });
});

// Download (anyone who may use that system)
router.get("/systems/:id/installer/download", requireLogin, (req, res) => {
  const user = res.locals.user as Actor;
  const systemId = String(req.params.id);
  const platform = String(req.query.platform ?? "");

  if (!canAccessSystem(user, systemId)) {
    res.status(404).json({ error: "System not found" });
    return;
  }
  const row = db
    .prepare(
      "SELECT filename, stored_name, size, sha256 FROM system_installers WHERE system_id = ? AND platform = ?"
    )
    .get(systemId, platform) as
    | { filename: string; stored_name: string; size: number; sha256: string }
    | undefined;
  if (!row) {
    res.status(404).json({ error: "No installer has been uploaded for this computer type" });
    return;
  }
  const file = path.join(DIR, path.basename(row.stored_name));
  if (!fs.existsSync(file)) {
    res.status(404).json({ error: "The installer file is missing on the server" });
    return;
  }

  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Length", String(row.size));
  res.setHeader("X-Installer-Sha256", row.sha256);
  res.setHeader("X-Installer-Filename", encodeURIComponent(row.filename));
  logAudit(user.id, "installer_downloaded", systemId, { platform, filename: row.filename });
  fs.createReadStream(file)
    .on("error", () => res.destroy())
    .pipe(res);
});

export default router;