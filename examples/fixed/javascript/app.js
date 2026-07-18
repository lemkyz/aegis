const { execFile } = require("child_process");
const fs = require("fs");
const path = require("path");

function runCommand(host) {
  if (!/^[A-Za-z0-9.-]+$/.test(host)) {
    throw new Error("Invalid host");
  }

  return execFile("ping", ["-c", "1", host]);
}

function findUser(db, username) {
  return db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
  );
}

function readUserFile(filename) {
  const base = path.resolve("/srv/uploads");
  const target = path.resolve(base, filename);

  if (!target.startsWith(`${base}${path.sep}`)) {
    throw new Error("Invalid path");
  }

  return fs.readFileSync(target, "utf8");
}

async function fetchRemote(url) {
  const parsed = new URL(url);

  if (
    parsed.protocol !== "https:" ||
    parsed.hostname !== "api.example.com"
  ) {
    throw new Error("Unapproved destination");
  }

  return fetch(parsed);
}

const apiKey = process.env.DEMO_JAVASCRIPT_API_KEY;
