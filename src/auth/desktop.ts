// Desktop auth extraction approach inspired by:
// - slacktokens: https://github.com/hraftery/slacktokens
import { cp, mkdir, rm, unlink } from "node:fs/promises";
import { existsSync, readdirSync, copyFileSync, unlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { homedir, platform, tmpdir } from "node:os";
import { join } from "node:path";
import { findKeysContaining } from "../lib/leveldb-reader.js";
import { isRecord } from "../lib/object-type-guards.ts";
import { queryReadonlySqlite } from "./firefox-profile.ts";
import { decryptChromiumCookieValue } from "./chromium-cookie.ts";
import { getSafeStoragePasswords, decryptCookieWindows } from "./desktop-crypto.ts";

type DesktopTeam = { url: string; name?: string; token: string };

export type DesktopExtracted = {
  cookie_d: string;
  teams: DesktopTeam[];
  source: { leveldb_path: string; cookies_path: string };
};

const PLATFORM = platform();
const IS_MACOS = PLATFORM === "darwin";
const IS_LINUX = PLATFORM === "linux";
const IS_WIN32 = PLATFORM === "win32";

// Electron (direct download) paths
const SLACK_SUPPORT_DIR_ELECTRON = join(homedir(), "Library", "Application Support", "Slack");
// Mac App Store paths (sandboxed container)
const SLACK_SUPPORT_DIR_APPSTORE = join(
  homedir(),
  "Library",
  "Containers",
  "com.tinyspeck.slackmacgap",
  "Data",
  "Library",
  "Application Support",
  "Slack",
);

const SLACK_SUPPORT_DIR_LINUX = join(homedir(), ".config", "Slack");

const SLACK_SUPPORT_DIR_LINUX_FLATPAK = join(
  homedir(),
  ".var",
  "app",
  "com.slack.Slack",
  "config",
  "Slack",
);

type SlackPathCandidate = {
  baseDir: string;
  leveldbDir: string;
  cookiesDb: string;
};

// Windows: regular installer stores data in %APPDATA%\Slack
const SLACK_SUPPORT_DIR_WIN_APPDATA = join(
  process.env.APPDATA || join(homedir(), "AppData", "Roaming"),
  "Slack",
);

/**
 * Find the Microsoft Store Slack app data directory.
 * The package folder name includes a publisher hash suffix that varies per machine,
 * so we search for the matching prefix.
 */
function getWindowsStoreSlackPath(): string | null {
  const pkgBase = join(process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "Packages");
  try {
    const entries = readdirSync(pkgBase);
    const slackPkg = entries.find((e) => e.startsWith("com.tinyspeck.slackdesktop_"));
    if (slackPkg) {
      return join(pkgBase, slackPkg, "LocalCache", "Roaming", "Slack");
    }
  } catch {
    // directory may not exist
  }
  return null;
}

function getSlackPathCandidates(): SlackPathCandidate[] {
  let candidates: string[];
  if (IS_MACOS) {
    candidates = [SLACK_SUPPORT_DIR_ELECTRON, SLACK_SUPPORT_DIR_APPSTORE];
  } else if (IS_LINUX) {
    candidates = [SLACK_SUPPORT_DIR_LINUX_FLATPAK, SLACK_SUPPORT_DIR_LINUX];
  } else if (IS_WIN32) {
    candidates = [SLACK_SUPPORT_DIR_WIN_APPDATA];
    const storePath = getWindowsStoreSlackPath();
    if (storePath) {
      candidates.push(storePath);
    }
  } else {
    candidates = [];
  }

  if (candidates.length === 0) {
    throw new Error(`Slack Desktop extraction is not supported on ${PLATFORM}.`);
  }

  const out: SlackPathCandidate[] = [];
  for (const dir of candidates) {
    const leveldbDir = join(dir, "Local Storage", "leveldb");
    if (existsSync(leveldbDir)) {
      const cookiesDbCandidates = [join(dir, "Network", "Cookies"), join(dir, "Cookies")];
      const cookiesDb =
        cookiesDbCandidates.find((candidate) => existsSync(candidate)) || cookiesDbCandidates[0]!;
      out.push({ baseDir: dir, leveldbDir, cookiesDb });
    }
  }

  if (out.length > 0) {
    return out;
  }

  throw new Error(
    `Slack Desktop data not found. Checked:\n  - ${candidates.map((d) => join(d, "Local Storage", "leveldb")).join("\n  - ")}`,
  );
}

function toDesktopTeam(value: unknown): DesktopTeam | null {
  if (!isRecord(value)) {
    return null;
  }
  const url = typeof value.url === "string" ? value.url : null;
  const token = typeof value.token === "string" ? value.token : null;
  if (!url || !token) {
    return null;
  }
  const name = typeof value.name === "string" ? value.name : undefined;
  return { url, name, token };
}

async function snapshotLevelDb(srcDir: string): Promise<string> {
  const base = join(homedir(), ".config", "agent-slack", "cache", "leveldb-snapshots");
  const dest = join(base, `${Date.now()}`);
  await mkdir(base, { recursive: true });
  let copiedWithShell = false;
  if (IS_MACOS) {
    try {
      execFileSync("cp", ["-cR", srcDir, dest], {
        stdio: ["ignore", "ignore", "ignore"],
      });
      copiedWithShell = true;
    } catch {
      // clonefile can fail with EPERM on some protected app-data directories.
      // Force plain byte copy mode to avoid macOS copyfile/clonefile paths.
      execFileSync("cp", ["-R", srcDir, dest], {
        env: { ...process.env, COPYFILE_DISABLE: "1" },
        stdio: ["ignore", "ignore", "ignore"],
      });
      copiedWithShell = true;
    }
  }
  if (!copiedWithShell) {
    await cp(srcDir, dest, { recursive: true, force: true });
  }

  try {
    await unlink(join(dest, "LOCK"));
  } catch {
    // ignore
  }
  return dest;
}

function parseLocalConfig(raw: Buffer): unknown {
  if (!raw || raw.length === 0) {
    throw new Error("localConfig is empty");
  }

  const [first] = raw;
  const data = first === 0x00 || first === 0x01 || first === 0x02 ? raw.subarray(1) : raw;

  let nulCount = 0;
  for (const b of data) {
    if (b === 0) {
      nulCount++;
    }
  }

  const encodings: BufferEncoding[] =
    nulCount > data.length / 4 ? (["utf16le", "utf8"] as const) : (["utf8", "utf16le"] as const);

  let lastErr: unknown;
  for (const enc of encodings) {
    try {
      const text = data.toString(enc);
      try {
        return JSON.parse(text);
      } catch (err1) {
        lastErr = err1;
      }

      const start = text.indexOf("{");
      const end = text.lastIndexOf("}");
      if (start !== -1 && end !== -1 && end > start) {
        try {
          return JSON.parse(text.slice(start, end + 1));
        } catch (err2) {
          lastErr = err2;
        }
      }
    } catch (err) {
      lastErr = err;
    }
  }

  throw lastErr || new Error("localConfig not parseable");
}

async function extractTeamsFromSlackLevelDb(leveldbDir: string): Promise<DesktopTeam[]> {
  if (!existsSync(leveldbDir)) {
    throw new Error(`Slack LevelDB not found: ${leveldbDir}`);
  }

  let readDir = leveldbDir;
  let snap: string | null = null;
  let snapshotError: unknown;
  try {
    snap = await snapshotLevelDb(leveldbDir);
    readDir = snap;
  } catch (error) {
    snapshotError = error;
  }

  try {
    // Use pure JS LevelDB reader - search for localConfig entries
    const localConfigV2 = Buffer.from("localConfig_v2");
    const localConfigV3 = Buffer.from("localConfig_v3");

    const entries = await findKeysContaining(readDir, Buffer.from("localConfig_v"));

    let configBuf: Buffer | null = null;
    let configRank = -1n;
    for (const entry of entries) {
      if (entry.key.includes(localConfigV2) || entry.key.includes(localConfigV3)) {
        if (entry.value && entry.value.length > 0) {
          let rank = 0n;
          if (entry.key.length >= 8) {
            rank = entry.key.readBigUInt64LE(entry.key.length - 8);
          }
          if (!configBuf || rank >= configRank) {
            configBuf = entry.value;
            configRank = rank;
          }
        }
      }
    }

    if (!configBuf) {
      throw new Error("Slack LevelDB did not contain localConfig_v2/v3");
    }

    const cfg = parseLocalConfig(configBuf);
    const teamsValue = isRecord(cfg) ? cfg.teams : undefined;
    const teamsObj = isRecord(teamsValue) ? teamsValue : {};
    const teams: DesktopTeam[] = Object.values(teamsObj)
      .map((t) => toDesktopTeam(t))
      .filter((t): t is DesktopTeam => t !== null)
      .filter((t) => t.token.startsWith("xoxc-"));

    if (teams.length === 0) {
      throw new Error("No xoxc tokens found in Slack localConfig");
    }
    return teams;
  } catch (error) {
    if (snapshotError) {
      const reason =
        snapshotError instanceof Error
          ? snapshotError.message
          : "unknown snapshot error while copying LevelDB";
      throw new Error(
        `Failed to snapshot Slack LevelDB (${reason}) and fallback read also failed: ${error instanceof Error ? error.message : "unknown error"}`,
      );
    }
    throw error;
  } finally {
    if (snap) {
      try {
        await rm(snap, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
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

async function extractCookieDFromSlackCookiesDb(
  cookiesPath: string,
  slackDataDir: string,
): Promise<string> {
  if (!existsSync(cookiesPath)) {
    throw new Error(`Slack Cookies DB not found: ${cookiesPath}`);
  }

  // On Windows, Slack holds an exclusive lock on the Cookies DB while running.
  // Copy it to a temp location before reading.
  let dbPathToQuery = cookiesPath;
  if (IS_WIN32) {
    const tmpCopy = join(tmpdir(), `agent-slack-cookies-${Date.now()}`);
    copyFileSync(cookiesPath, tmpCopy);
    dbPathToQuery = tmpCopy;
  }

  let rows: {
    host_key: string;
    name: string;
    value: string;
    encrypted_value: Uint8Array;
  }[];
  try {
    rows = (await queryReadonlySqlite(
      dbPathToQuery,
      "select host_key, name, value, encrypted_value from cookies where name = 'd' and host_key like '%slack.com' order by length(encrypted_value) desc",
    )) as typeof rows;
  } finally {
    if (IS_WIN32 && dbPathToQuery !== cookiesPath) {
      try {
        unlinkSync(dbPathToQuery);
      } catch {
        /* ignore */
      }
    }
  }

  if (!rows || rows.length === 0) {
    throw new Error("No Slack 'd' cookie found");
  }
  const fallbackCandidates: string[] = [];

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

    if (IS_WIN32) {
      if (prefix === "v10" || prefix === "v11") {
        try {
          const decrypted = decryptCookieWindows(encrypted, slackDataDir);
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
      continue;
    }

    const data = prefix === "v10" || prefix === "v11" ? encrypted.subarray(3) : encrypted;
    const passwords = getSafeStoragePasswords(prefix);

    for (const password of passwords) {
      try {
        const decrypted = decryptChromiumCookieValue(data, {
          password,
          iterations: IS_LINUX ? 1 : 1003,
        });
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

  if (fallbackCandidates.length > 0) {
    // Prefer the most information-rich value if xoxd prefix is absent.
    fallbackCandidates.sort((a, b) => b.length - a.length);
    return fallbackCandidates[0]!;
  }

  throw new Error("Could not locate xoxd-* in decrypted Slack cookie");
}

export async function extractFromSlackDesktop(): Promise<DesktopExtracted> {
  const candidates = getSlackPathCandidates();

  let teams: DesktopTeam[] | null = null;
  let leveldbPath = "";
  const leveldbErrors: string[] = [];
  for (const candidate of candidates) {
    try {
      teams = await extractTeamsFromSlackLevelDb(candidate.leveldbDir);
      leveldbPath = candidate.leveldbDir;
      break;
    } catch (error) {
      leveldbErrors.push(
        `${candidate.leveldbDir}: ${error instanceof Error ? error.message : "unknown error"}`,
      );
    }
  }

  if (!teams) {
    throw new Error(
      `Failed to extract Slack teams from LevelDB:\n  - ${leveldbErrors.join("\n  - ")}`,
    );
  }

  let cookie_d = "";
  let cookiesPath = "";
  const cookieErrors: string[] = [];
  for (const candidate of candidates) {
    try {
      cookie_d = await extractCookieDFromSlackCookiesDb(candidate.cookiesDb, candidate.baseDir);
      cookiesPath = candidate.cookiesDb;
      break;
    } catch (error) {
      cookieErrors.push(
        `${candidate.cookiesDb}: ${error instanceof Error ? error.message : "unknown error"}`,
      );
    }
  }

  if (!cookie_d) {
    throw new Error(
      `Failed to extract Slack cookie 'd' from Desktop cookies DB:\n  - ${cookieErrors.join("\n  - ")}`,
    );
  }

  return {
    cookie_d,
    teams,
    source: { leveldb_path: leveldbPath, cookies_path: cookiesPath },
  };
}
