import Database from "better-sqlite3";

const file = process.argv[2];
if (!file) {
  console.log("Usage: npx tsx src/check-backup.ts <path to backup file>");
  process.exit(1);
}

const db = new Database(file, { readonly: true });
const integrity = db.pragma("integrity_check", { simple: true });
const count = (table: string) =>
  (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;

console.log("Integrity:", integrity);
console.log("Systems:", count("systems"));
console.log("Categories:", count("categories"));
console.log("Users:", count("users"));
console.log("Audit log entries:", count("audit_logs"));
db.close();