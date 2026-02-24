import { execSync, execFileSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { pbkdf2Sync, createDecipheriv } from "node:crypto";
import { homedir, platform } from "node:os";
import { join } from "node:path";

type ChromeExtractedTeam = { url: string; name?: string; token: string };

export type ChromeExtracted = {
  cookie_d: string;
  teams: ChromeExtractedTeam[];
};

const IS_MACOS = platform() === "darwin";
const CHROME_BASE_DIR = join(homedir(), "Library", "Application Support", "Google", "Chrome");

function escapeOsaScript(script: string): string {
  // osascript -e '...'
  return script.replace(/'/g, `'"'"'`);
}

function osascript(script: string): string {
  return execSync(`osascript -e '${escapeOsaScript(script)}'`, {
    encoding: "utf8",
    timeout: 7000,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

const TEAM_JSON_PATHS = [
  "JSON.stringify(JSON.parse(localStorage.localConfig_v2).teams)",
  "JSON.stringify(JSON.parse(localStorage.localConfig_v3).teams)",
  "JSON.stringify(JSON.parse(localStorage.getItem('reduxPersist:localConfig'))?.teams || {})",
  "JSON.stringify(window.boot_data?.teams || {})",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function toChromeTeam(value: unknown): ChromeExtractedTeam | null {
  if (!isRecord(value)) {
    return null;
  }
  const token = typeof value.token === "string" ? value.token : null;
  const url = typeof value.url === "string" ? value.url : null;
  if (!token || !url || !token.startsWith("xoxc-")) {
    return null;
  }
  const name = typeof value.name === "string" ? value.name : undefined;
  return { url, name, token };
}

function teamsScript(): string {
  const tryPaths = TEAM_JSON_PATHS.map(
    (expr) => `try { var v = ${expr}; if (v && v !== '{}' && v !== 'null') return v; } catch(e) {}`,
  );
  return `
    tell application "Google Chrome"
      repeat with w in windows
        repeat with t in tabs of w
          set u to URL of t
          if (u starts with "https://") and ((u contains "://app.slack.com/") or (u contains ".slack.com/")) then
            return execute t javascript "(function(){ ${tryPaths.join(" ")} return '{}'; })()"
          end if
        end repeat
      end repeat
      return "{}"
    end tell
  `;
}

function extractTeamsFromChromeTab(): ChromeExtractedTeam[] {
  const teamsRaw = osascript(teamsScript());
  let teamsObj: unknown = {};
  try {
    teamsObj = JSON.parse(teamsRaw || "{}");
  } catch {
    teamsObj = {};
  }

  const teamsRecord = isRecord(teamsObj) ? teamsObj : {};
  return Object.values(teamsRecord)
    .map((t) => toChromeTeam(t))
    .filter((t): t is ChromeExtractedTeam => t !== null);
}

function isMissingBunSqliteModule(error: unknown): boolean {
  if (!error || typeof error !== "object") {
    return false;
  }
  const err = error as { code?: unknown; message?: unknown };
  const code = typeof err.code === "string" ? err.code : "";
  const message = typeof err.message === "string" ? err.message : "";

  if (code === "ERR_MODULE_NOT_FOUND" || code === "ERR_UNSUPPORTED_ESM_URL_SCHEME") {
    return true;
  }
  if (!message.includes("bun:sqlite")) {
    return false;
  }
  return (
    message.includes("Cannot find module") ||
    message.includes("Unknown builtin module") ||
    message.includes("unsupported URL scheme") ||
    message.includes("Only URLs with a scheme in")
  );
}

type SqliteRow = Record<string, unknown>;

async function queryReadonlySqlite(dbPath: string, sql: string): Promise<SqliteRow[]> {
  try {
    const { Database } = await import("bun:sqlite");
    const db = new Database(dbPath, { readonly: true });
    try {
      return db.query(sql).all() as SqliteRow[];
    } finally {
      db.close();
    }
  } catch (error) {
    if (!isMissingBunSqliteModule(error)) {
      throw error;
    }
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      return db.prepare(sql).all() as SqliteRow[];
    } finally {
      db.close();
    }
  }
}

function getChromeCookiesDbPaths(): string[] {
  if (!existsSync(CHROME_BASE_DIR)) {
    return [];
  }

  const profileNames = new Set<string>(["Default"]);
  for (const name of readdirSync(CHROME_BASE_DIR)) {
    if (/^Profile \d+$/i.test(name)) {
      profileNames.add(name);
    }
  }

  const paths: string[] = [];
  for (const profile of profileNames) {
    const direct = join(CHROME_BASE_DIR, profile, "Cookies");
    const network = join(CHROME_BASE_DIR, profile, "Network", "Cookies");
    if (existsSync(direct)) {
      paths.push(direct);
    }
    if (existsSync(network)) {
      paths.push(network);
    }
  }
  return [...new Set(paths)];
}

function getSafeStoragePasswords(): string[] {
  const services = ["Chrome Safe Storage", "Chromium Safe Storage"];
  const passwords: string[] = [];
  for (const service of services) {
    try {
      const out = execFileSync("security", ["find-generic-password", "-w", "-s", service], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim();
      if (out) {
        passwords.push(out);
      }
    } catch {
      // continue
    }
  }
  return passwords;
}

function decryptChromiumCookieValue(data: Buffer, password: string): string {
  if (!data || data.length === 0) {
    return "";
  }

  const salt = Buffer.from("saltysalt", "utf8");
  const iv = Buffer.alloc(16, " ");
  const key = pbkdf2Sync(password, salt, 1003, 16, "sha1");

  const decipher = createDecipheriv("aes-128-cbc", key, iv);
  decipher.setAutoPadding(true);
  const plain = Buffer.concat([decipher.update(data), decipher.final()]);
  const marker = Buffer.from("xoxd-");
  const idx = plain.indexOf(marker);
  if (idx === -1) {
    return plain.toString("utf8");
  }

  let end = idx;
  while (end < plain.length) {
    const b = plain[end]!;
    if (b < 0x21 || b > 0x7e) {
      break;
    }
    end++;
  }
  const rawToken = plain.subarray(idx, end).toString("utf8");
  try {
    return decodeURIComponent(rawToken);
  } catch {
    return rawToken;
  }
}

function extractXoxdToken(text: string): string | null {
  if (!text) {
    return null;
  }
  const direct = text.match(/xoxd-[A-Za-z0-9%/+_=.-]+/);
  if (direct) {
    return direct[0]!;
  }
  try {
    const decoded = decodeURIComponent(text);
    const decodedMatch = decoded.match(/xoxd-[A-Za-z0-9%/+_=.-]+/);
    if (decodedMatch) {
      return decodedMatch[0]!;
    }
  } catch {
    // ignore
  }
  return null;
}

function extractCookieCandidate(text: string): string | null {
  if (!text) {
    return null;
  }

  const xoxd = extractXoxdToken(text);
  if (xoxd) {
    return xoxd;
  }

  const trimmed = text.trim();
  const likelyCookie = /^[A-Za-z0-9%/+_=.-]{20,}$/.test(trimmed);
  if (likelyCookie) {
    return trimmed;
  }

  try {
    const decoded = decodeURIComponent(trimmed);
    if (/^[A-Za-z0-9%/+_=.-]{20,}$/.test(decoded)) {
      return decoded;
    }
  } catch {
    // ignore
  }
  return null;
}

async function extractCookieDFromChromeCookies(): Promise<string> {
  const cookieDbPaths = getChromeCookiesDbPaths();
  if (cookieDbPaths.length === 0) {
    throw new Error("Chrome Cookies DB not found");
  }

  const passwords = getSafeStoragePasswords();
  if (passwords.length === 0) {
    throw new Error("Could not read Chrome Safe Storage password from keychain");
  }

  const fallbackCandidates: string[] = [];
  for (const dbPath of cookieDbPaths) {
    const rows = (await queryReadonlySqlite(
      dbPath,
      "select host_key, name, value, encrypted_value from cookies where name = 'd' and host_key like '%slack.com' order by length(encrypted_value) desc",
    )) as {
      host_key: string;
      name: string;
      value: string;
      encrypted_value: Uint8Array;
    }[];

    for (const row of rows) {
      const plain = extractCookieCandidate(typeof row.value === "string" ? row.value : "");
      if (plain) {
        if (plain.startsWith("xoxd-")) {
          return plain;
        }
        fallbackCandidates.push(plain);
      }

      const encrypted = Buffer.from(row.encrypted_value || []);
      if (encrypted.length === 0) {
        continue;
      }

      const prefix = encrypted.subarray(0, 3).toString("utf8");
      const data = prefix === "v10" || prefix === "v11" ? encrypted.subarray(3) : encrypted;

      for (const password of passwords) {
        try {
          const decrypted = decryptChromiumCookieValue(data, password);
          const token = extractCookieCandidate(decrypted);
          if (token) {
            if (token.startsWith("xoxd-")) {
              return token;
            }
            fallbackCandidates.push(token);
          }
        } catch {
          // continue
        }
      }
    }
  }

  if (fallbackCandidates.length > 0) {
    fallbackCandidates.sort((a, b) => b.length - a.length);
    return fallbackCandidates[0]!;
  }

  throw new Error("Could not decrypt Slack 'd' cookie from Chrome");
}

export async function extractFromChrome(): Promise<ChromeExtracted | null> {
  if (!IS_MACOS) {
    return null;
  }
  try {
    const teams = extractTeamsFromChromeTab();
    if (teams.length === 0) {
      return null;
    }

    const cookie_d = await extractCookieDFromChromeCookies();
    if (!cookie_d) {
      return null;
    }

    return { cookie_d, teams };
  } catch {
    return null;
  }
}
