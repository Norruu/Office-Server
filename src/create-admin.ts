import readline from "node:readline/promises";
import { randomUUID } from "node:crypto";
import db from "./db";
import { hashPassword } from "./auth";

async function main() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const username = (await rl.question("Admin username: ")).trim();
  const password = await rl.question("Password (at least 10 characters): ");
  rl.close();

  if (username.length < 3 || password.length < 10) {
    console.log("Username needs 3+ characters and password needs 10+. Nothing was created.");
    process.exit(1);
  }
  if (db.prepare("SELECT 1 FROM users WHERE username = ?").get(username)) {
    console.log("That username already exists. Nothing was created.");
    process.exit(1);
  }

  db.prepare("INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, 'master')").run(
    randomUUID(),
    username,
    hashPassword(password)
  );
  console.log(`Admin "${username}" created.`);
}

main();