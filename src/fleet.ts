import { Router } from "express";
import { z } from "zod";
import db from "./db";
import { logAudit, requireLogin, requireMaster } from "./auth";

const MAX_COMPUTERS_PER_USER = 20;

db.exec(`
  CREATE TABLE IF NOT EXISTS installations (
    device_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    app_version TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (device_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS installation_systems (
    device_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    system_id TEXT NOT NULL REFERENCES systems(id),
    state TEXT NOT NULL CHECK (state IN ('ready', 'broken', 'found', 'missing')),
    PRIMARY KEY (device_id, user_id, system_id),
    FOREIGN KEY (device_id, user_id) REFERENCES installations(device_id, user_id) ON DELETE CASCADE
  );
`);

type Actor = { id: string; username: string; role: string };

const reportSchema = z.object({
  deviceId: z.string().uuid(),
  hostname: z.string().trim().min(1).max(64),
  platform: z.enum(["windows", "linux", "other"]),
  appVersion: z.string().regex(/^\d{1,4}\.\d{1,4}\.\d{1,4}$/),
  systems: z
    .array(
      z.object({
        systemId: z.string().max(100),
        state: z.enum(["ready", "broken", "found", "missing"]),
      })
    )
    .max(300),
});

// The systems this person is allowed to have
function accessibleIds(user: Actor): Set<string> {
  const rows = (
    user.role === "master" || user.role === "admin"
      ? db.prepare("SELECT id FROM systems WHERE status = 'active'").all()
      : db
          .prepare(
            `SELECT s.id FROM systems s
             JOIN job_systems js ON js.system_id = s.id
             JOIN users u ON u.job_id = js.job_id
             WHERE u.id = ? AND s.status = 'active'`
          )
          .all(user.id)
  ) as { id: string }[];
  return new Set(rows.map((r) => r.id));
}

const router = Router();

// Any logged-in copy of the app reports in. The account comes from the login, not from the body.
router.post("/report", requireLogin, (req, res) => {
  const parsed = reportSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid report" });
    return;
  }
  const user = res.locals.user as Actor;
  const d = parsed.data;
  const hostname = d.hostname.replace(/[\u0000-\u001f]/g, "");

  const others = db
    .prepare("SELECT COUNT(*) AS n FROM installations WHERE user_id = ? AND device_id != ?")
    .get(user.id, d.deviceId) as { n: number };
  if (others.n >= MAX_COMPUTERS_PER_USER) {
    res.status(409).json({ error: "Too many computers are registered for this account" });
    return;
  }

  const allowed = accessibleIds(user);
  const states = d.systems.filter((s) => allowed.has(s.systemId));

  db.transaction(() => {
    db.prepare(
      `INSERT INTO installations (device_id, user_id, hostname, platform, app_version, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(device_id, user_id) DO UPDATE SET
         hostname = excluded.hostname, platform = excluded.platform,
         app_version = excluded.app_version, last_seen_at = excluded.last_seen_at`
    ).run(d.deviceId, user.id, hostname, d.platform, d.appVersion, new Date().toISOString());

    db.prepare("DELETE FROM installation_systems WHERE device_id = ? AND user_id = ?").run(d.deviceId, user.id);
    const insert = db.prepare(
      "INSERT OR REPLACE INTO installation_systems (device_id, user_id, system_id, state) VALUES (?, ?, ?, ?)"
    );
    for (const s of states) insert.run(d.deviceId, user.id, s.systemId, s.state);
  })();

  res.json({ ok: true });
});

type ComputerRow = {
  deviceId: string;
  userId: string;
  hostname: string;
  platform: string;
  appVersion: string;
  lastSeenAt: string;
  username: string;
  role: string;
  jobName: string | null;
};

// Master only: everything in one go
router.get("/admin/fleet", requireMaster, (_req, res) => {
  const systems = db
    .prepare("SELECT id, name FROM systems WHERE status = 'active' ORDER BY name")
    .all() as { id: string; name: string }[];
  const activeIds = new Set(systems.map((s) => s.id));

  const latest: Record<string, string> = {};
  try {
    const rows = db.prepare("SELECT platform, version FROM app_releases").all() as {
      platform: string;
      version: string;
    }[];
    for (const r of rows) latest[r.platform] = r.version;
  } catch {
    // no releases table yet
  }

  const computers = db
    .prepare(
      `SELECT i.device_id AS deviceId, i.user_id AS userId, i.hostname, i.platform,
              i.app_version AS appVersion, i.last_seen_at AS lastSeenAt,
              u.username, u.role, j.name AS jobName
       FROM installations i
       JOIN users u ON u.id = i.user_id
       LEFT JOIN jobs j ON j.id = u.job_id
       ORDER BY i.last_seen_at DESC`
    )
    .all() as ComputerRow[];

  const stateRows = db
    .prepare("SELECT device_id AS deviceId, user_id AS userId, system_id AS systemId, state FROM installation_systems")
    .all() as { deviceId: string; userId: string; systemId: string; state: string }[];
  const statesByKey = new Map<string, Record<string, string>>();
  for (const r of stateRows) {
    const key = `${r.deviceId}|${r.userId}`;
    const entry = statesByKey.get(key) ?? {};
    entry[r.systemId] = r.state;
    statesByKey.set(key, entry);
  }

  const jobRows = db
    .prepare("SELECT u.id AS userId, js.system_id AS systemId FROM users u JOIN job_systems js ON js.job_id = u.job_id")
    .all() as { userId: string; systemId: string }[];
  const jobAssigned = new Map<string, string[]>();
  for (const r of jobRows) jobAssigned.set(r.userId, [...(jobAssigned.get(r.userId) ?? []), r.systemId]);

  const result = computers.map((c) => {
    const states = statesByKey.get(`${c.deviceId}|${c.userId}`) ?? {};
    const assigned =
      c.role === "master" || c.role === "admin"
        ? Object.keys(states)
        : (jobAssigned.get(c.userId) ?? []).filter((id) => activeIds.has(id));
    return { ...c, states, assigned };
  });

  const neverSeen = db
    .prepare(
      `SELECT u.id AS userId, u.username, j.name AS jobName
       FROM users u LEFT JOIN jobs j ON j.id = u.job_id
       WHERE u.active = 1 AND u.pending = 0 AND u.role = 'user'
         AND NOT EXISTS (SELECT 1 FROM installations i WHERE i.user_id = u.id)
       ORDER BY u.username`
    )
    .all();

  res.json({ latest, systems, computers: result, neverSeen });
});

// Master only: forget a computer (for example, one that was retired)
router.delete("/admin/fleet/:deviceId/:userId", requireMaster, (req, res) => {
  const deviceId = String(req.params.deviceId);
  const userId = String(req.params.userId);
  const result = db
    .prepare("DELETE FROM installations WHERE device_id = ? AND user_id = ?")
    .run(deviceId, userId);
  if (result.changes === 0) {
    res.status(404).json({ error: "Computer not found" });
    return;
  }
  logAudit(res.locals.user.id, "computer_forgotten", null, { deviceId, userId });
  res.json({ ok: true });
});

export default router;