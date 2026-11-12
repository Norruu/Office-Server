import Database from "better-sqlite3";

const db = new Database("office-hub.db");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
  );

  CREATE TABLE IF NOT EXISTS systems (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category_id TEXT REFERENCES categories(id),
    system_type TEXT NOT NULL CHECK (system_type IN ('desktop', 'web', 'file', 'module')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'planned', 'archived'))
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'user')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_id TEXT,
    action TEXT NOT NULL,
    system_id TEXT,
    details_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

// Sample data, only added once
const count = db.prepare("SELECT COUNT(*) AS n FROM categories").get() as { n: number };
if (count.n === 0) {
  db.exec(`
    INSERT INTO categories (id, name) VALUES
      ('operations', 'Operations'),
      ('people', 'People & Admin');

    INSERT INTO systems (id, name, description, category_id, system_type, status) VALUES
      ('inventory-001', 'Inventory System', 'Manage office stock and assets', 'operations', 'module', 'active'),
      ('hr-001', 'HR Management', 'People and administration', 'people', 'module', 'active'),
      ('docs-001', 'Documents', 'Forms and records', 'operations', 'module', 'planned');
  `);
}

// Test module for Milestone 1 (we remove this later)
db.prepare(
  `INSERT OR IGNORE INTO systems (id, name, description, category_id, system_type, status)
   VALUES ('hello-001', 'Hello', 'Test module', NULL, 'module', 'active')`
).run();

// Migration: jobs, and which systems each job can use
db.exec(`
  CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS job_systems (
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    PRIMARY KEY (job_id, system_id)
  );
`);

const userCols = db.prepare("PRAGMA table_info(users)").all() as { name: string }[];
if (!userCols.some((c) => c.name === "job_id")) {
  db.exec("ALTER TABLE users ADD COLUMN job_id TEXT REFERENCES jobs(id)");
}
if (!userCols.some((c) => c.name === "active")) {
  db.exec("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1");
}

const userColsNow = db.prepare("PRAGMA table_info(users)").all() as { name: string }[];
if (!userColsNow.some((c) => c.name === "pending")) {
  db.exec("ALTER TABLE users ADD COLUMN pending INTEGER NOT NULL DEFAULT 0");
}

// Migration: add the "master" role (SQLite can't edit a CHECK rule, so rebuild the table)
const usersSql = (
  db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").get() as {
    sql: string;
  }
).sql;

if (!usersSql.includes("'master'")) {
  db.pragma("foreign_keys = OFF");
  try {
    db.transaction(() => {
      db.exec(`
        CREATE TABLE users_new (
          id TEXT PRIMARY KEY,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('master', 'admin', 'user')),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          job_id TEXT REFERENCES jobs(id),
          active INTEGER NOT NULL DEFAULT 1
        );
        INSERT INTO users_new (id, username, password_hash, role, created_at, job_id, active)
          SELECT id, username, password_hash, role, created_at, job_id, active FROM users;
        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;
        UPDATE users SET role = 'master' WHERE role = 'admin';
      `);
      if ((db.pragma("foreign_key_check") as unknown[]).length > 0) {
        throw new Error("Users table migration left broken references");
      }
    })();
  } finally {
    db.pragma("foreign_keys = ON");
  }
}

export default db;