import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

/**
 * Persisted state for the Oase client — one identity per machine, in one
 * config file.
 *
 * The identity is a single Promise-backed Oase account established via the
 * login flow. We only persist the long-lived refresh token + person_id; access
 * tokens are short-lived (~2 days) and kept in memory, refreshed on demand.
 */
export interface JoinedOase {
  /** Oase UUID. */
  id: string;
  /** Decrypted display name, if we managed to resolve one. */
  name?: string;
  /** ISO timestamp we joined. */
  joinedAt: string;
}

export interface OaseConfig {
  /** Mainframe REST API root, e.g. https://api.oase.app */
  apiRoot: string;
  /** KMS root, e.g. https://kms.oase.app/ (note trailing slash) */
  kmsRoot: string;
  /** person_id of our account, once bootstrapped. */
  personId?: string;
  /** Long-lived refresh token for our account. */
  refreshToken?: string;
  /**
   * Last-issued access token (~2 days). Persisted so concurrent server
   * processes reuse it instead of each hitting oauth2/refresh: the backend
   * rotates the refresh token on every refresh and treats a stale one as
   * replay, deleting the whole session.
   */
  accessToken?: string;
  /** The display name we present as inside oases. */
  displayName: string;
  /** Oases we've joined, keyed by oase id. */
  oases: Record<string, JoinedOase>;
  /** Default oase id to target when a tool omits one. */
  defaultOaseId?: string;
}

const DEFAULT_CONFIG: OaseConfig = {
  apiRoot: "https://api.oase.app",
  kmsRoot: "https://kms.oase.app/",
  displayName: "Claude",
  oases: {},
};

export function configDir(): string {
  return process.env.OASE_MCP_CONFIG_DIR || path.join(homedir(), ".oase-mcp");
}

function configPath(): string {
  return path.join(configDir(), "config.json");
}

export async function loadConfig(): Promise<OaseConfig> {
  try {
    const raw = await fs.readFile(configPath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<OaseConfig>;
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      // Env overrides win, so a user can point at staging without editing files.
      apiRoot: process.env.OASE_API_ROOT || parsed.apiRoot || DEFAULT_CONFIG.apiRoot,
      kmsRoot: process.env.OASE_KMS_ROOT || parsed.kmsRoot || DEFAULT_CONFIG.kmsRoot,
      oases: parsed.oases || {},
    };
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        ...DEFAULT_CONFIG,
        apiRoot: process.env.OASE_API_ROOT || DEFAULT_CONFIG.apiRoot,
        kmsRoot: process.env.OASE_KMS_ROOT || DEFAULT_CONFIG.kmsRoot,
      };
    }
    throw err;
  }
}

export async function saveConfig(config: OaseConfig): Promise<void> {
  const dir = configDir();
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = configPath() + ".tmp";
  await fs.writeFile(tmp, JSON.stringify(config, null, 2), { mode: 0o600 });
  await fs.rename(tmp, configPath());
}

// ---- Cross-process auth lock ------------------------------------------------
//
// oauth2/refresh rotates the refresh token and deletes the session if it ever
// sees an already-rotated token (anti-replay). With several server processes
// sharing one identity, two concurrent refreshes would race exactly into
// that. Serialize refreshes across processes with a mkdir-based lock; holders
// re-read config.json under the lock to adopt a sibling's fresh tokens.

const LOCK_STALE_MS = 30_000;

export async function withAuthLock<T>(fn: () => Promise<T>): Promise<T> {
  const lockDir = path.join(configDir(), "auth.lock");
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + 20_000;
  for (;;) {
    try {
      await fs.mkdir(lockDir);
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      // Steal locks left behind by crashed processes.
      const stat = await fs.stat(lockDir).catch(() => null);
      if (stat && Date.now() - stat.mtimeMs > LOCK_STALE_MS) {
        await fs.rmdir(lockDir).catch(() => {});
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error("Timed out waiting for the auth lock.");
      }
      await new Promise((r) => setTimeout(r, 150 + Math.random() * 150));
    }
  }
  try {
    return await fn();
  } finally {
    await fs.rmdir(lockDir).catch(() => {});
  }
}
