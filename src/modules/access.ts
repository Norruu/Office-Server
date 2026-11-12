import { Router } from "express";
import db from "../db";
import { requireLogin } from "../auth";

type Actor = { id: string; role: string };

export function canUseModule(user: Actor, moduleId: string): boolean {
  const active = db
    .prepare("SELECT 1 FROM systems WHERE id = ? AND system_type = 'module' AND status = 'active'")
    .get(moduleId);
  if (!active) return false;
  if (user.role === "master" || user.role === "admin") return true;
  return !!db
    .prepare(
      `SELECT 1 FROM job_systems js
       JOIN users u ON u.job_id = js.job_id
       WHERE u.id = ? AND js.system_id = ?`
    )
    .get(user.id, moduleId);
}

// Every module builds its routes on top of this router.
export function moduleRouter(moduleId: string) {
  const router = Router();
  router.use(requireLogin, (_req, res, next) => {
    if (!canUseModule(res.locals.user, moduleId)) {
      res.status(404).json({ error: "Module not found" });
      return;
    }
    next();
  });
  return router;
}