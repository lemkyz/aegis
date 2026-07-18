import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export function runCommand(host: string): void {
  if (!/^[A-Za-z0-9.-]+$/.test(host)) {
    throw new Error("Invalid host");
  }

  execFile("ping", ["-c", "1", host]);
}

export function loadFile(filename: string): string {
  const base = path.resolve("/srv/uploads");
  const target = path.resolve(base, filename);

  if (!target.startsWith(`${base}${path.sep}`)) {
    throw new Error("Invalid path");
  }

  return fs.readFileSync(target, "utf8");
}

export async function fetchRemote(
  url: string,
): Promise<Response> {
  const parsed = new URL(url);

  if (
    parsed.protocol !== "https:" ||
    parsed.hostname !== "api.example.com"
  ) {
    throw new Error("Unapproved destination");
  }

  return fetch(parsed);
}

const secretKey =
  process.env.DEMO_TYPESCRIPT_SECRET;
