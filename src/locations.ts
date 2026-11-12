import { Router } from "express";
import { z } from "zod";
import db from "./db";
import { logAudit, requireLogin, requireMaster } from "./auth";

db.exec(`
  CREATE TABLE IF NOT EXISTS system_locations (
    system_id TEXT NOT NULL REFERENCES systems(id),
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'linux')),
    paths_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (system_id, platform)
  );
`);

const WIN_VARS = [
  "LOCALAPPDATA",
  "APPDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "PROGRAMDATA",
  "USERPROFILE",
  "SYSTEMDRIVE",
];

function pathProblem(platform: string, p: string): string | null {
  if (p.length > 260) return "A path is too long";
  if (/[\u0000-\u001f<>"|?*]/.test(p)) return "A path contains characters that are not allowed";
  if (p.split(/[\\/]+/).includes("..")) return "Paths may not contain '..'";

  if (platform === "windows") {
    const m = p.match(/^%([^%]+)%[\\/]/);
    if (m) {
      if (!WIN_VARS.includes(m[1].toUpperCase())) {
        return `%${m[1]}% is not allowed. Use one of: ${WIN_VARS.map((v) => `%${v}%`).join(", ")}`;
      }
      if (p.slice(m[0].length).includes("%")) return "Only one % variable is allowed, at the start";
    } else if (/^[A-Za-z]:[\\/]/.test(p)) {
      if (p.includes("%")) return "Only one % variable is allowed, at the start";
    } else {
      return "Start with a drive (C:\\...) or a variable like %ProgramFiles%\\";
    }
    if (!p.toLowerCase().endsWith(".exe")) return "Windows programs must end in .exe";
  } else if (!p.startsWith("/") && !p.startsWith("~/")) {
    return "Start with / or ~/";
  }
  return null;
}

const router = Router();

// Everyone logged in gets the hints for systems they may use
router.get("/locations", requireLogin, (_req, res) => {
  const user = res.locals.user as { id: string; role: string };
  const base = `SELECT l.system_id AS systemId, l.platform, l.paths_json AS pathsJson
                FROM system_locations l
                JOIN systems s ON s.id = l.system_id`;
  const rows = (
    user.role === "master" || user.role === "admin"
      ? db.prepare(`${base} WHERE s.status != 'archived'`).all()
      : db
          .prepare(
            `${base}
             JOIN job_systems js ON js.system_id = l.system_id
             JOIN users u ON u.job_id = js.job_id
             WHERE u.id = ? AND s.status != 'archived'`
          )
          .all(user.id)
  ) as { systemId: string; platform: string; pathsJson: string }[];

  res.json(
    rows.map((r) => ({ systemId: r.systemId, platform: r.platform, paths: JSON.parse(r.pathsJson) }))
  );
});

router.put("/systems/:id/location", requireMaster, (req, res) => {
  const parsed = z
    .object({
      platform: z.enum(["windows", "linux"]),
      paths: z.array(z.string().trim().min(1).max(260)).min(1).max(5),
    })
    .safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Enter 1 to 5 paths" });
    return;
  }
  const systemId = String(req.params.id);
  if (!db.prepare("SELECT 1 FROM systems WHERE id = ? AND status != 'archived'").get(systemId)) {
    res.status(404).json({ error: "System not found" });
    return;
  }
  const { platform } = parsed.data;
  const paths = [...new Set(parsed.data.paths)];
  for (const p of paths) {
    const problem = pathProblem(platform, p);
    if (problem) {
      res.status(400).json({ error: problem });
      return;
    }
  }

  db.prepare(
    `INSERT INTO system_locations (system_id, platform, paths_json)
     VALUES (?, ?, ?)
     ON CONFLICT(system_id, platform) DO UPDATE SET
       paths_json = excluded.paths_json, updated_at = CURRENT_TIMESTAMP`
  ).run(systemId, platform, JSON.stringify(paths));
  logAudit(res.locals.user.id, "install_location_set", systemId, { platform, paths });
  res.json({ ok: true });
});

router.delete("/systems/:id/location", requireMaster, (req, res) => {
  const systemId = String(req.params.id);
  const platform = String(req.query.platform ?? "");
  const result = db
    .prepare("DELETE FROM system_locations WHERE system_id = ? AND platform = ?")
    .run(systemId, platform);
  if (result.changes === 0) {
    res.status(404).json({ error: "Nothing to remove" });
    return;
  }
  logAudit(res.locals.user.id, "install_location_removed", systemId, { platform });
  res.json({ ok: true });
});

export default router;