import forge from "node-forge";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline/promises";

const DIR = process.env.CERT_DIR ?? "certs";
const caKeyFile = path.join(DIR, "ca.key.pem");
const caCertFile = path.join(DIR, "ca.cert.pem");

function serial(): string {
  return "01" + forge.util.bytesToHex(forge.random.getBytesSync(15));
}

function yearsFromNow(n: number): Date {
  const d = new Date();
  d.setFullYear(d.getFullYear() + n);
  return d;
}

function makeCa() {
  console.log("Creating the private certificate authority (this can take a few seconds)...");
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serial();
  cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
  cert.validity.notAfter = yearsFromNow(10);
  const attrs = [
    { name: "commonName", value: "Office Hub Private CA" },
    { name: "organizationName", value: "Office Hub" },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, pathLenConstraint: 0 },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, digitalSignature: true },
    { name: "subjectKeyIdentifier" },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  fs.writeFileSync(caKeyFile, forge.pki.privateKeyToPem(keys.privateKey), { mode: 0o600 });
  fs.writeFileSync(caCertFile, forge.pki.certificateToPem(cert));
  return { key: keys.privateKey, cert };
}

function loadCa() {
  return {
    key: forge.pki.privateKeyFromPem(fs.readFileSync(caKeyFile, "utf-8")),
    cert: forge.pki.certificateFromPem(fs.readFileSync(caCertFile, "utf-8")),
  };
}

async function main() {
  fs.mkdirSync(DIR, { recursive: true });
  const haveCa = fs.existsSync(caKeyFile) && fs.existsSync(caCertFile);
  const ca = haveCa ? loadCa() : makeCa();
  if (haveCa) console.log("Using the existing certificate authority.");

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question(
    "Addresses people use to reach this server, separated by commas\n(for example 192.168.1.20, 100.64.1.5): "
  );
  rl.close();

  const names = [
    ...new Set(["localhost", "127.0.0.1", ...answer.split(",").map((s) => s.trim()).filter(Boolean)]),
  ];
  if (names.some((n) => !/^[A-Za-z0-9.-]+$/.test(n))) {
    console.log("Addresses may only contain letters, numbers, dots and dashes. Nothing was created.");
    process.exit(1);
  }
  const isIp = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
  const altNames = names.map((n) => (isIp(n) ? { type: 7, ip: n } : { type: 2, value: n }));

  console.log("Creating the server certificate...");
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serial();
  cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
  cert.validity.notAfter = yearsFromNow(3);
  cert.setSubject([{ name: "commonName", value: "Office Hub Server" }]);
  cert.setIssuer(ca.cert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", serverAuth: true },
    { name: "subjectAltName", altNames },
  ]);
  cert.sign(ca.key, forge.md.sha256.create());

  fs.writeFileSync(path.join(DIR, "server.key.pem"), forge.pki.privateKeyToPem(keys.privateKey), { mode: 0o600 });
  fs.writeFileSync(path.join(DIR, "server.cert.pem"), forge.pki.certificateToPem(cert));

  console.log(`\nDone. Valid for: ${names.join(", ")}`);
  console.log("The server certificate is valid for 3 years.\n");
  console.log("What to do with the files in the '" + DIR + "' folder:");
  console.log("  server.key.pem + server.cert.pem -> stay on the server computer");
  console.log("  ca.cert.pem   -> copy into the app as build-resources/office-ca.pem (public, safe to share)");
  console.log("  ca.key.pem    -> SECRET. Move it to a USB drive kept somewhere safe, and delete it from the server.");
}

main();