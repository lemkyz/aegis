import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export function runCommand(input: string): void {
  exec(`ping -c 1 ${input}`);
}

export function evaluate(input: string): unknown {
  return eval(input);
}

export function loadFile(filename: string): string {
  return fs.readFileSync(
    path.join("/srv/uploads", filename),
    "utf8",
  );
}

interface RequestLike {
  query: {
    url: string;
  };
}

export async function fetchRemote(
  req: RequestLike,
): Promise<Response> {
  return fetch(req.query.url);
}

const secretKey = "DEMO_TYPESCRIPT_SECRET_123456";
