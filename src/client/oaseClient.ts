import crypto from "node:crypto";
import {
  OaseConfig,
  JoinedOase,
  loadConfig,
  saveConfig,
  withAuthLock,
} from "./config.js";

/**
 * A cipher bundle is the encrypted-payload envelope the Oase backend stores
 * opaquely and the app decrypts client-side. We produce the exact same shape
 * the app produces (see oase-app `src/app/lib/encrypt.ts`):
 *   { oaseId, alg: 'AES-GCM', kid, ivBase64, cipherBase64 }
 * where cipherBase64 = base64(ciphertext || 16-byte GCM tag).
 */
export interface CipherBundle {
  oaseId: string;
  alg: "AES-GCM";
  kid: string;
  ivBase64: string;
  cipherBase64: string;
}

/**
 * Media blobs (images, voice messages, files) are uploaded by the app as an
 * encrypted ".oase" container with this outer mime; the real mime/name travel
 * as cipher bundles on the media item. See oase-app `src/app/lib/encryptedFile.ts`:
 *   [4-byte uint32 LE metadata length][metadata JSON][ciphertext][16-byte GCM tag]
 * where metadata = { version: 1, alg: 'AES-GCM', kid, oaseId, ivBase64 }.
 */
const OASE_ENCRYPTED_MIME = "application/x.oase-encrypted";

/** Backend caps uploads around 51 MB; refuse anything wildly beyond that. */
const MAX_MEDIA_BYTES = 64 * 1024 * 1024;

interface EncryptedBlobMetadata {
  version?: number;
  alg?: string;
  kid: string;
  oaseId: string;
  ivBase64: string;
}

/**
 * Parse the app's encrypted-blob container. Returns null when the bytes are
 * not a container (legacy plaintext media), so callers can fall through.
 */
function parseEncryptedContainer(
  data: Buffer,
): { metadata: EncryptedBlobMetadata; cipherWithTag: Buffer } | null {
  if (data.length < 4 + 2 + 16) return null;
  const metadataLength = data.readUInt32LE(0);
  if (metadataLength < 2 || 4 + metadataLength + 16 > data.length) return null;
  try {
    const metadata = JSON.parse(
      data.subarray(4, 4 + metadataLength).toString("utf8"),
    ) as EncryptedBlobMetadata;
    if (metadata.alg !== "AES-GCM" || !metadata.kid || !metadata.ivBase64) {
      return null;
    }
    return { metadata, cipherWithTag: data.subarray(4 + metadataLength) };
  } catch {
    return null;
  }
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" && v ? v : undefined;
}

/** Uploads are anonymized as "<uuid>.oase_enc" — hide that suffix like the app does. */
function stripOaseSuffix(name: string): string {
  return name.replace(/\.oase_enc$/, "");
}

/** Best-effort content sniffing for blobs whose mime we couldn't recover. */
function sniffMime(data: Buffer): string | undefined {
  if (data.length < 12) return undefined;
  const tag = (start: number, end: number) =>
    data.subarray(start, end).toString("latin1");
  if (data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff) return "image/jpeg";
  if (data.readUInt32BE(0) === 0x89504e47) return "image/png";
  if (tag(0, 4) === "GIF8") return "image/gif";
  if (tag(0, 4) === "RIFF" && tag(8, 12) === "WEBP") return "image/webp";
  if (tag(0, 4) === "%PDF") return "application/pdf";
  if (tag(0, 4) === "OggS") return "audio/ogg";
  if (tag(0, 3) === "ID3") return "audio/mpeg";
  if (tag(4, 8) === "ftyp") {
    return tag(8, 11) === "M4A" ? "audio/mp4" : "video/mp4";
  }
  return undefined;
}

/**
 * First http(s) URL anywhere in a decrypted giphy object (preferring the
 * original rendition) — giphy attachments carry no storage URL of their own.
 */
function findFirstUrl(value: unknown): string | undefined {
  if (typeof value === "string") {
    return /^https?:\/\//.test(value) ? value : undefined;
  }
  if (Array.isArray(value)) {
    for (const v of value) {
      const url = findFirstUrl(v);
      if (url) return url;
    }
    return undefined;
  }
  if (value && typeof value === "object") {
    const original = (value as { images?: { original?: { url?: unknown } } })
      .images?.original?.url;
    if (typeof original === "string" && /^https?:\/\//.test(original)) {
      return original;
    }
    for (const v of Object.values(value)) {
      const url = findFirstUrl(v);
      if (url) return url;
    }
  }
  return undefined;
}

interface KeyProof {
  jwt: string;
  key_url: string;
}

interface RawKey {
  kid: string;
  base64: string;
}

interface JoinPreview {
  oase?: {
    uuid?: string;
    is_member?: boolean;
    realm_oase_id?: string | null;
    join_url_enabled?: boolean;
    name_cipher_bundle?: CipherBundle;
  };
}

export class OaseError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "OaseError";
  }
}

/** Log to stderr — stdout is reserved for the MCP protocol stream. */
function log(...args: unknown[]): void {
  console.error("[oase-mcp]", ...args);
}

function jwtExpMs(jwt: string): number | null {
  try {
    const payload = jwt.split(".")[1];
    if (!payload) return null;
    const json = Buffer.from(payload, "base64url").toString("utf8");
    const { exp } = JSON.parse(json) as { exp?: number };
    return typeof exp === "number" ? exp * 1000 : null;
  } catch {
    return null;
  }
}

/** One attachment on a chat message, described (metadata decrypted). */
export interface MediaAttachment {
  /** Position in the message's attachment list — pass as media_index. */
  index: number;
  id?: string;
  /** Server-side kind: "image" | "video" | "file" | "external" | … */
  kind?: string;
  /** Effective content type (the decrypted original mime for encrypted blobs). */
  mime?: string;
  /** Decrypted original filename, when available. */
  name?: string;
  /** True if the blob is an encrypted .oase container. */
  encrypted: boolean;
}

/** A downloaded (and if needed decrypted) attachment blob. */
export interface FetchedMedia {
  data: Buffer;
  mime?: string;
  name?: string;
  /** True if the blob was an encrypted container we decrypted. */
  encrypted: boolean;
}

/** A feed post ("opslag"), decoded and (where possible) decrypted. */
export interface OasePost {
  id: string;
  version: string;
  /** Author's participant_id. */
  from: string;
  /** True if this agent posted it. */
  mine: boolean;
  /** Decrypted title, or undefined if empty / undecryptable. */
  title?: string;
  /** Decrypted markdown body, or undefined if it couldn't be decrypted. */
  text?: string;
  at?: string;
  deleted: boolean;
  /** Attachments — fetch via fetchMedia with the post id. */
  media: MediaAttachment[];
}

/** A chat message, decoded and (where possible) decrypted. */
export interface ChatMessage {
  id: string;
  version: string;
  /** Sender's participant_id. */
  from: string;
  /** True if this agent sent it. */
  mine: boolean;
  /** Decrypted text, or undefined if it couldn't be decrypted / isn't text. */
  text?: string;
  bodyType?: string;
  at?: string;
  type: string;
  deleted: boolean;
  /** Full chat_id, e.g. "<oaseId>" (group) or "<oaseId>/m/<parentId>" (a reply). */
  chatId: string;
  /** True if this agent has reacted to the message. */
  reactedByMe: boolean;
  /** Reactions on the message, emojis decrypted where possible. */
  reactions: MessageReaction[];
  /** Attachments (images, voice messages, files) — fetch via fetchMedia. */
  media: MediaAttachment[];
}

export interface MessageReaction {
  /** Reacting participant_id. */
  by: string;
  /** True if this agent left it. */
  mine: boolean;
  /** Decrypted emoji, or undefined if it couldn't be decrypted. */
  emoji?: string;
}

export class OaseClient {
  private accessToken: string | null = null;
  private accessTokenExpMs = 0;
  /** Raw oase keys cached by `${oaseId}:${kid}` — keys are stable, proofs aren't. */
  private keyCache = new Map<string, RawKey>();
  /** My participant_id per oase. */
  private participantCache = new Map<string, string>();
  /** Message id → root id of the thread it lives in (itself for main-chat messages). */
  private threadRoots = new Map<string, string>();
  /** Message id → raw media items (with signed URLs) from the latest read. */
  private rawMediaByMessage = new Map<string, Array<Record<string, unknown>>>();

  constructor(private config: OaseConfig) {}

  private async persist(): Promise<void> {
    await saveConfig(this.config);
  }

  // ---- HTTP helpers -------------------------------------------------------

  private async raw(
    url: string,
    init: RequestInit & { bearer?: string } = {},
  ): Promise<Response> {
    const { bearer, headers, ...rest } = init;
    const h = new Headers(headers);
    h.set("accept", "application/json");
    if (bearer) h.set("authorization", `Bearer ${bearer}`);
    return fetch(url, { ...rest, headers: h });
  }

  private async json<T>(res: Response, context: string): Promise<T> {
    const text = await res.text();
    let body: unknown = text;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        /* leave as text */
      }
    }
    if (!res.ok) {
      throw new OaseError(
        `${context} failed (${res.status})${
          typeof body === "object" ? ": " + JSON.stringify(body) : text ? ": " + text : ""
        }`,
        res.status,
        body,
      );
    }
    return body as T;
  }

  private api(path: string): string {
    return `${this.config.apiRoot.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
  }

  /** REST API root (e.g. https://api.oase.app). */
  get apiRoot(): string {
    return this.config.apiRoot;
  }

  // ---- Auth ---------------------------------------------------------------

  /**
   * Exchange an external Promise id_token for an Oase token pair. The Oase
   * refresh token is long-lived, so Promise is only ever hit once.
   */
  private async exchange(idToken: string): Promise<{
    person_id: string;
    access_token: string;
    refresh_token: string;
  }> {
    return this.json(
      await this.raw(this.api("oauth2/token"), {
        method: "POST",
        bearer: idToken,
      }),
      "oauth2/token",
    );
  }

  private applyIdentity(token: {
    person_id: string;
    access_token: string;
    refresh_token: string;
  }): void {
    this.config.personId = token.person_id;
    this.config.refreshToken = token.refresh_token;
    this.config.accessToken = token.access_token;
    this.accessToken = token.access_token;
    this.accessTokenExpMs = jwtExpMs(token.access_token) ?? Date.now() + 60_000;
  }

  /** True once a Promise identity has been established. */
  get isLoggedIn(): boolean {
    return !!this.config.refreshToken;
  }

  /** Guard for operations that need an authenticated identity. */
  private ensureLoggedIn(): void {
    if (!this.config.refreshToken) {
      throw new OaseError(
        "Not logged in. Sign in as a Promise user first: run promise_login_start, " +
          "open the URL, then promise_login_finish.",
      );
    }
  }

  /**
   * Establish (or replace) the Promise-backed identity by exchanging a fresh
   * Promise id_token. Since memberships are per-person, joined oases from a
   * *different* prior identity are dropped (they belonged to another account).
   */
  async loginWithPromise(idToken: string): Promise<string> {
    const previousPerson = this.config.personId;
    const token = await this.exchange(idToken.trim());
    this.applyIdentity(token);
    if (token.person_id !== previousPerson) {
      // Old memberships belong to the old account; start fresh.
      this.config.oases = {};
      this.config.defaultOaseId = undefined;
    }
    await this.persist();
    log("Logged in as Promise identity", token.person_id);
    return token.person_id;
  }

  /** True if the in-memory access token is good for at least another minute. */
  private hasFreshAccessToken(): boolean {
    // 60s of slack so we never send an almost-expired token.
    return !!this.accessToken && Date.now() < this.accessTokenExpMs - 60_000;
  }

  /**
   * Re-read config.json and adopt any newer tokens a sibling server process
   * persisted — sharing their access token avoids a refresh of our own, and
   * taking their rotated refresh token avoids the fatal replay path.
   */
  private async adoptPersistedTokens(): Promise<void> {
    try {
      const disk = await loadConfig();
      if (disk.refreshToken && disk.refreshToken !== this.config.refreshToken) {
        this.config.refreshToken = disk.refreshToken;
      }
      if (disk.personId) this.config.personId = disk.personId;
      if (disk.accessToken) {
        const exp = jwtExpMs(disk.accessToken);
        if (exp && Date.now() < exp - 60_000) {
          this.accessToken = disk.accessToken;
          this.accessTokenExpMs = exp;
        }
      }
    } catch (e) {
      log("could not re-read config for tokens:", (e as Error).message);
    }
  }

  /** A valid bearer access token, refreshed if needed. */
  async getAccessToken(): Promise<string> {
    this.ensureLoggedIn();
    if (this.hasFreshAccessToken()) return this.accessToken!;

    // A sibling process may have refreshed already — reuse its access token.
    await this.adoptPersistedTokens();
    if (this.hasFreshAccessToken()) return this.accessToken!;

    // Refreshing rotates the refresh token, and the backend deletes the whole
    // session if it sees a stale one (anti-replay) — so refreshes must be
    // serialized across processes, with a re-check once the lock is held.
    return withAuthLock(async () => {
      await this.adoptPersistedTokens();
      if (this.hasFreshAccessToken()) return this.accessToken!;

      let token: { access_token: string; refresh_token: string };
      try {
        token = await this.json<{ access_token: string; refresh_token: string }>(
          await this.raw(this.api("oauth2/refresh"), {
            method: "POST",
            bearer: this.config.refreshToken,
          }),
          "oauth2/refresh",
        );
      } catch (e) {
        if (e instanceof OaseError && e.status === 401) {
          throw new OaseError(
            "The Oase session was revoked (refresh token no longer valid). " +
              "Log in again: run promise_login_start, open the URL, then " +
              "promise_login_finish.",
            e.status,
            e.body,
          );
        }
        throw e;
      }
      this.accessToken = token.access_token;
      this.accessTokenExpMs = jwtExpMs(token.access_token) ?? Date.now() + 60_000;
      this.config.accessToken = token.access_token;
      if (token.refresh_token) this.config.refreshToken = token.refresh_token;
      await this.persist();
      return this.accessToken;
    });
  }

  /** Authenticated request against the mainframe REST API. */
  private async authed<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const bearer = await this.getAccessToken();
    const init: RequestInit & { bearer: string } = { method, bearer };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
      init.headers = { "content-type": "application/json" };
    }
    return this.json<T>(await this.raw(this.api(path), init), `${method} ${path}`);
  }

  // ---- Invite links & joining --------------------------------------------

  /**
   * Parse an Oase invite link or bare "oaseId/phrase" into its parts.
   * Accepts e.g. https://oase.app/oase/<oase_id>/join/<phrase> (with or
   * without scheme/host/query), or "<oase_id> <phrase>".
   */
  static parseInvite(input: string): { oaseId: string; phrase: string } {
    const trimmed = input.trim();
    const m = trimmed.match(/oase\/([^/\s?#]+)\/join\/([^/\s?#]+)/i);
    if (m) return { oaseId: m[1]!, phrase: m[2]! };

    // Fallback: two whitespace- or slash-separated tokens.
    const parts = trimmed.split(/[\s/]+/).filter(Boolean);
    if (parts.length === 2) return { oaseId: parts[0]!, phrase: parts[1]! };

    throw new OaseError(
      `Could not parse invite link. Expected something like ` +
        `https://oase.app/oase/<oase_id>/join/<phrase>, got: ${input}`,
    );
  }

  async joinPreview(oaseId: string, phrase: string): Promise<JoinPreview> {
    return this.authed<JoinPreview>(
      "GET",
      `v1/iam/oases/${oaseId}/join/${phrase}`,
    );
  }

  /**
   * Join an oase via an invite link. Idempotent-ish: if already a member the
   * backend still succeeds. Returns the record we persist.
   */
  async join(
    inviteLink: string,
    displayName?: string,
  ): Promise<JoinedOase> {
    const { oaseId, phrase } = OaseClient.parseInvite(inviteLink);
    this.ensureLoggedIn();

    const preview = await this.joinPreview(oaseId, phrase).catch((e) => {
      log("join preview failed (continuing):", (e as Error).message);
      return undefined;
    });
    if (preview?.oase?.join_url_enabled === false) {
      throw new OaseError(
        "This oase's join URL is currently disabled by an admin.",
      );
    }

    await this.authed("PUT", `v1/iam/oases/${oaseId}/join/${phrase}`, {});

    const record: JoinedOase = {
      id: oaseId,
      joinedAt: new Date().toISOString(),
    };
    this.config.oases[oaseId] = record;
    this.config.defaultOaseId = oaseId;
    await this.persist();

    // Set our display name so we don't show up blank. For a sub-oase the
    // profile is owned by the realm, so target the realm when present.
    const profileOaseId = preview?.oase?.realm_oase_id || oaseId;
    const name = displayName || this.config.displayName;
    try {
      await this.waitForParticipation(profileOaseId);
      await this.setDisplayName(profileOaseId, name);
    } catch (e) {
      log("Could not set display name after join:", (e as Error).message);
    }

    return record;
  }

  // ---- Encryption ---------------------------------------------------------

  private async keyProof(oaseId: string, kid = "current"): Promise<KeyProof> {
    return this.authed<KeyProof>(
      "GET",
      `v1/oases/${oaseId}/security/key_requests/${kid}`,
    );
  }

  /**
   * Membership is eventually consistent: right after joining, the participant
   * projection (which gates key access) may not be live yet. Poll the key-proof
   * endpoint until it succeeds or we time out.
   */
  private async waitForParticipation(oaseId: string, timeoutMs = 10_000): Promise<void> {
    const start = Date.now();
    let delay = 300;
    for (;;) {
      try {
        await this.keyProof(oaseId, "current");
        return;
      } catch (e) {
        const status = e instanceof OaseError ? e.status : undefined;
        const transient = status === 403 || status === 404;
        if (!transient || Date.now() - start > timeoutMs) throw e;
        await new Promise((r) => setTimeout(r, delay));
        delay = Math.min(delay * 1.5, 2000);
      }
    }
  }

  /** Fetch the raw symmetric key material for an oase from the KMS (cached). */
  private async fetchRawKey(oaseId: string, kid = "current"): Promise<RawKey> {
    const cacheKey = `${oaseId}:${kid}`;
    const cached = this.keyCache.get(cacheKey);
    if (cached) return cached;
    const proof = await this.keyProof(oaseId, kid);
    const res = await this.raw(proof.key_url, { bearer: proof.jwt });
    const key = await this.json<RawKey>(res, "KMS get key");
    this.keyCache.set(cacheKey, key);
    // Also cache under the resolved kid so bundle-specific lookups hit.
    this.keyCache.set(`${oaseId}:${key.kid}`, key);
    return key;
  }

  /** Encrypt plaintext into a cipher bundle the Oase app can decrypt. */
  async encrypt(oaseId: string, clearText: string): Promise<CipherBundle> {
    const key = await this.fetchRawKey(oaseId, "current");
    const keyBuf = Buffer.from(key.base64, "base64");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", keyBuf, iv);
    const enc = Buffer.concat([
      cipher.update(clearText, "utf8"),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return {
      oaseId,
      alg: "AES-GCM",
      kid: key.kid,
      ivBase64: iv.toString("base64"),
      // ciphertext || tag, matching the app's encrypt.ts
      cipherBase64: Buffer.concat([enc, tag]).toString("base64"),
    };
  }

  // ---- Profile & messaging ------------------------------------------------

  async setDisplayName(oaseId: string, name: string): Promise<void> {
    const nameCipherBundle = await this.encrypt(oaseId, name);
    await this.authed("PUT", `v1/oases/${oaseId}/feel/me`, {
      name_cipher_bundle: nameCipherBundle,
    });
  }

  /**
   * Threads in Oase are one level deep — you cannot reply to a reply. Posting
   * to `<oaseId>/m/<replyId>` would create a nested chat the app never shows,
   * making the message invisible. So: if `messageId` is itself a reply,
   * return the root id of the thread it lives in; otherwise return it
   * unchanged. Roots are learned from every chat read; for an id we've never
   * seen, one baseline read is tried, then the id is assumed to be a root
   * (and cached as such so it isn't re-fetched).
   */
  async resolveThreadRoot(oaseId: string, messageId: string): Promise<string> {
    const cached = this.threadRoots.get(messageId);
    if (cached) return cached;
    try {
      await this.chatEvolve(oaseId, ""); // populates threadRoots from the latest page
    } catch (e) {
      log("thread-root lookup failed (using id as-is):", (e as Error).message);
    }
    const root = this.threadRoots.get(messageId) ?? messageId;
    this.threadRoots.set(messageId, root);
    return root;
  }

  /**
   * Send a markdown message. With no `threadMessageId` it posts to the oase's
   * group chat; with one it posts into that message's reply thread (chat_id
   * `<oaseId>/m/<threadMessageId>`), keeping a conversation together. A
   * `threadMessageId` that is itself a reply is resolved to its thread root
   * (replies can't be nested — see resolveThreadRoot). Returns the new
   * message id.
   */
  async sendMessage(
    oaseId: string,
    message: string,
    threadMessageId?: string,
  ): Promise<string> {
    if (threadMessageId) {
      threadMessageId = await this.resolveThreadRoot(oaseId, threadMessageId);
    }
    const bundle = await this.encrypt(oaseId, message);
    const chatId = threadMessageId ? `${oaseId}/m/${threadMessageId}` : oaseId;
    const res = await this.authed<{ id: string }>(
      "POST",
      `v1/oases/${oaseId}/messaging/messages`,
      {
        chat_id: chatId,
        body_cipher_bundle: bundle,
        body_type: "markdown",
        media: [],
      },
    );
    return res.id;
  }

  /**
   * React to a message with an emoji (or short text). Reactions are encrypted
   * exactly like message bodies. The backend allows one reaction per
   * participant per message and rejects a second with "already reacted".
   */
  async react(
    oaseId: string,
    messageId: string,
    reaction: string,
  ): Promise<void> {
    const bundle = await this.encrypt(oaseId, reaction);
    await this.authed(
      "POST",
      `v1/oases/${oaseId}/messaging/messages/${messageId}/reactions`,
      { reaction_cipher_bundle: bundle },
    );
  }

  /**
   * Edit one of this agent's own chat messages: re-encrypt the new text and
   * PUT it to the message. Mirrors the app's edit (same endpoint and payload):
   * the edited body is a fresh cipher bundle under the same oase key, and the
   * message's existing attachments are sent back unchanged so the edit doesn't
   * drop them (the backend overwrites media on edit). The message must be in
   * the recent chat history so its chat_id and attachments can be recovered.
   * The backend only lets you edit your OWN messages (it rejects others).
   * Returns the message id.
   */
  async updateMessage(
    oaseId: string,
    messageId: string,
    newText: string,
  ): Promise<string> {
    const { messages } = await this.chatEvolve(oaseId, "");
    const msg = messages.find((m) => m.id === messageId);
    if (!msg) {
      throw new OaseError(
        `Message ${messageId} isn't in the recent chat history, so it can't ` +
          `be edited (it may be too old, deleted, or in a different oase).`,
      );
    }
    const bundle = await this.encrypt(oaseId, newText);
    const media = this.rawMediaByMessage.get(messageId) ?? [];
    await this.authed("PUT", `v1/oases/${oaseId}/messaging/messages/${messageId}`, {
      oase_id: oaseId,
      chat_id: msg.chatId,
      body_cipher_bundle: bundle,
      media,
    });
    return messageId;
  }

  /**
   * Delete a chat message. Soft-deletes it (the app shows a tombstone and the
   * client's reads mark it `deleted`). The backend allows deleting your own
   * message, or any message if you're an oase admin/owner; otherwise it
   * rejects with a requires-own-or-admin error.
   */
  async deleteMessage(oaseId: string, messageId: string): Promise<void> {
    await this.authed(
      "DELETE",
      `v1/oases/${oaseId}/messaging/messages/${messageId}`,
    );
  }

  // ---- Posts (feed/"opslag") ----------------------------------------------

  /**
   * Publish a post to an oase's feed. Posts are the wall/feed items the app
   * shows on the oase's front page — distinct from chat messages, but stored
   * in the same messaging projection (type "post") and encrypted identically:
   * title and body are separate cipher bundles under the same oase key. The
   * backend requires a title bundle even for an empty title (the app encrypts
   * "" too), so we always send one. Returns the new post id. Comments on a
   * post are ordinary thread replies (chat_id `<oaseId>/m/<postId>`), so
   * sendMessage with the post id as threadMessageId comments on it.
   *
   * A 403 with reason "posting_restricted" means an admin limited posting to
   * admins in this oase.
   */
  async sendPost(
    oaseId: string,
    body: string,
    title = "",
  ): Promise<string> {
    const [titleBundle, bodyBundle] = await Promise.all([
      this.encrypt(oaseId, title.trim()),
      this.encrypt(oaseId, body.trim()),
    ]);
    const res = await this.authed<{ id: string }>(
      "POST",
      `v1/oases/${oaseId}/messaging/posts`,
      {
        chat_id: oaseId,
        body_cipher_bundle: bodyBundle,
        body_type: "markdown",
        media: [],
        type: "post",
        title_cipher_bundle: titleBundle,
      },
    );
    return res.id;
  }

  /**
   * The most recent `limit` feed posts, decrypted, oldest→newest. Reads the
   * posts projection (`projections/posts/evolve`, the posts-only view of the
   * chat projection) with an empty from_version, which returns the latest
   * page. Raw media items and thread roots are registered like a chat read,
   * so fetchMedia works on post attachments and sendMessage can thread
   * comments under a post id.
   */
  async readRecentPosts(oaseId: string, limit = 10): Promise<OasePost[]> {
    const res = await this.authed<{
      collection: Array<Record<string, unknown>>;
    }>(
      "GET",
      `v1/oases/${oaseId}/messaging/projections/posts/evolve` +
        `?chat_id=${encodeURIComponent(oaseId)}&from_version=`,
    );
    const me = await this.getMyParticipantId(oaseId);
    const posts: OasePost[] = [];
    for (const m of res.collection || []) {
      if (String(m.type ?? "") !== "post") continue;
      const deleted = m.deleted_by_participant_id != null;
      const id = String(m.id ?? "");
      if (!id || deleted) continue;
      // A post's comments live in its thread — register it as a thread root.
      this.threadRoots.set(id, id);
      const rawAttachments = ([] as Array<Record<string, unknown>>).concat(
        Array.isArray(m.media) ? (m.media as Array<Record<string, unknown>>) : [],
        Array.isArray(m.files) ? (m.files as Array<Record<string, unknown>>) : [],
      );
      let media: MediaAttachment[] = [];
      if (rawAttachments.length) {
        this.rawMediaByMessage.set(id, rawAttachments);
        media = await Promise.all(
          rawAttachments.map((item, i) => this.describeMediaItem(oaseId, item, i)),
        );
      }
      const from = String(m.participant_id ?? "");
      posts.push({
        id,
        version: String(m.version ?? ""),
        from,
        mine: from === me,
        title: await this.decryptBundleSafe(oaseId, m.post_title_cipher_bundle),
        text: await this.decryptBundleSafe(oaseId, m.body_cipher_bundle),
        at: m.created_at ? String(m.created_at) : undefined,
        deleted,
        media,
      });
    }
    posts.sort((a, b) => (a.version < b.version ? -1 : a.version > b.version ? 1 : 0));
    return posts.slice(-limit);
  }

  /**
   * Edit a feed post: re-encrypt the new body (and title) and PUT it. Mirrors
   * the app's edit — title and body are separate cipher bundles under the oase
   * key, and the post's existing attachments are sent back unchanged so the
   * edit doesn't drop them (the backend overwrites body, title, and media on
   * update). Because a missing title bundle would clear the title, when `title`
   * is omitted the post's current title is read and preserved. The post must be
   * in the recent feed so its title and attachments can be recovered. The
   * backend allows editing your own post (or any, if you're an admin/owner).
   * Returns the post id.
   */
  async updatePost(
    oaseId: string,
    postId: string,
    body: string,
    title?: string,
  ): Promise<string> {
    const posts = await this.readRecentPosts(oaseId, 100);
    const existing = posts.find((p) => p.id === postId);
    if (!existing) {
      throw new OaseError(
        `Post ${postId} isn't in the recent feed, so it can't be edited ` +
          `(it may be too old, deleted, or in a different oase).`,
      );
    }
    const newTitle = title !== undefined ? title : existing.title ?? "";
    const [titleBundle, bodyBundle] = await Promise.all([
      this.encrypt(oaseId, newTitle.trim()),
      this.encrypt(oaseId, body.trim()),
    ]);
    const media = this.rawMediaByMessage.get(postId) ?? [];
    await this.authed("PUT", `v1/oases/${oaseId}/messaging/posts/${postId}`, {
      oase_id: oaseId,
      chat_id: oaseId,
      body_cipher_bundle: bodyBundle,
      body_type: "markdown",
      media,
      type: "post",
      title_cipher_bundle: titleBundle,
    });
    return postId;
  }

  /**
   * Delete a feed post. The backend allows deleting your own post, or any post
   * if you're an oase admin/owner; otherwise it rejects with a
   * requires-own-or-admin error.
   */
  async deletePost(oaseId: string, postId: string): Promise<void> {
    await this.authed("DELETE", `v1/oases/${oaseId}/messaging/posts/${postId}`);
  }

  // ---- Reading chat -------------------------------------------------------

  /** This agent's participant_id in an oase (cached). */
  async getMyParticipantId(oaseId: string): Promise<string> {
    const cached = this.participantCache.get(oaseId);
    if (cached) return cached;
    const me = await this.authed<{ id?: string; uuid?: string }>(
      "GET",
      `v1/oases/${oaseId}/feel/me`,
    );
    const pid = me.id || me.uuid;
    if (!pid) throw new OaseError("Could not resolve my participant_id.");
    this.participantCache.set(oaseId, pid);
    return pid;
  }

  /**
   * Fetch chat messages newer than `fromVersion` (pass "" for a baseline that
   * returns the latest page and the current cursor). Returns decoded, decrypted
   * messages sorted oldest→newest, plus the new cursor.
   *
   * `chatId` scopes the read: the oase id for the group chat, or a resource path
   * like `<oaseId>/m/<messageId>` for the reply thread under one message. The
   * server matches the exact chat_id plus any deeper sub-paths.
   */
  async chatEvolve(
    oaseId: string,
    fromVersion: string,
    chatId: string = oaseId,
  ): Promise<{ toVersion: string; messages: ChatMessage[] }> {
    const res = await this.authed<{
      to_version: string;
      collection: Array<Record<string, unknown>>;
    }>(
      "GET",
      `v1/oases/${oaseId}/messaging/projections/chat/evolve` +
        `?chat_id=${encodeURIComponent(chatId)}&from_version=${encodeURIComponent(fromVersion)}`,
    );
    const me = await this.getMyParticipantId(oaseId);
    const raw = res.collection || [];
    const decoded: ChatMessage[] = [];
    for (const m of raw) {
      const type = String(m.type ?? "");
      const from = String(m.participant_id ?? "");
      const deleted = m.deleted_by_participant_id != null;
      const bundle = m.body_cipher_bundle as CipherBundle | undefined;
      let text: string | undefined;
      if (type === "message" && bundle && !deleted) {
        try {
          text = await this.decrypt(bundle);
        } catch (e) {
          log("decrypt failed for message", m.id, (e as Error).message);
        }
      }
      const id = String(m.id ?? "");
      const chatId = String(m.chat_id ?? "");
      if (id) {
        this.threadRoots.set(id, chatId.match(/\/m\/([^/]+)/)?.[1] ?? id);
      }
      // Attachments live in `media` (images/video/external) and `files`
      // (everything the backend re-uploaded as an opaque file — which is
      // where modern client-side-encrypted blobs land). Keep the raw items
      // (they carry the signed download URLs) and describe them for callers.
      const rawAttachments = ([] as Array<Record<string, unknown>>).concat(
        Array.isArray(m.media) ? (m.media as Array<Record<string, unknown>>) : [],
        Array.isArray(m.files) ? (m.files as Array<Record<string, unknown>>) : [],
      );
      let media: MediaAttachment[] = [];
      if (id && rawAttachments.length && !deleted) {
        this.rawMediaByMessage.set(id, rawAttachments);
        media = await Promise.all(
          rawAttachments.map((item, i) =>
            this.describeMediaItem(oaseId, item, i),
          ),
        );
      }
      const reactions = Array.isArray(m.reactions)
        ? (m.reactions as Array<Record<string, unknown>>)
        : [];
      // Reaction bodies are encrypted exactly like message bodies. Decrypt
      // them so callers can actually read what people reacted with — a
      // reaction is often the whole answer (👍 as approval, a colour code
      // as a vote), and dropping it loses that signal entirely.
      const decodedReactions: MessageReaction[] = [];
      for (const r of reactions) {
        const by = String(r.participant_id ?? "");
        let emoji: string | undefined;
        if (r.reaction != null) {
          emoji = String(r.reaction);
        } else if (r.reaction_cipher_bundle) {
          try {
            emoji = await this.decrypt(r.reaction_cipher_bundle as CipherBundle);
          } catch (e) {
            log("decrypt failed for reaction on", id, (e as Error).message);
          }
        }
        decodedReactions.push({ by, mine: by === me, emoji });
      }
      decoded.push({
        id,
        version: String(m.version ?? ""),
        from,
        mine: from === me,
        text,
        bodyType: m.body_type ? String(m.body_type) : undefined,
        at: m.created_at ? String(m.created_at) : undefined,
        type,
        deleted,
        chatId,
        reactedByMe: reactions.some(
          (r) => String(r.participant_id ?? "") === me,
        ),
        reactions: decodedReactions,
        media,
      });
    }
    decoded.sort((a, b) => (a.version < b.version ? -1 : a.version > b.version ? 1 : 0));
    return { toVersion: res.to_version ?? fromVersion, messages: decoded };
  }

  /** The most recent `limit` chat messages, decrypted, oldest→newest. */
  async readRecentMessages(
    oaseId: string,
    limit = 20,
  ): Promise<{ messages: ChatMessage[] }> {
    const { messages: all } = await this.chatEvolve(oaseId, "");
    const textual = all.filter((m) => m.type === "message" && !m.deleted);
    return { messages: textual.slice(-limit) };
  }

  // ---- Media attachments ---------------------------------------------------

  /** Decrypt a `*_cipher_bundle` field, tolerating absence and bad bundles. */
  private async decryptBundleSafe(
    oaseId: string,
    bundle: unknown,
  ): Promise<string | undefined> {
    if (!bundle || typeof bundle !== "object") return undefined;
    try {
      const b = bundle as CipherBundle;
      const text = await this.decrypt({ ...b, oaseId: b.oaseId || oaseId });
      return text || undefined;
    } catch (e) {
      log("attachment metadata decrypt failed:", (e as Error).message);
      return undefined;
    }
  }

  /**
   * Describe one raw media item: recover the original filename and mime from
   * their cipher bundles (modern uploads hide both — the outer mime is the
   * opaque application/x.oase-encrypted wrapper and the stored filename is an
   * anonymized UUID).
   */
  private async describeMediaItem(
    oaseId: string,
    item: Record<string, unknown>,
    index: number,
  ): Promise<MediaAttachment> {
    const outerMime = asString(item.mime);
    const encrypted = outerMime === OASE_ENCRYPTED_MIME;
    const name =
      (await this.decryptBundleSafe(
        oaseId,
        item.original_file_name_cipher_bundle,
      )) ?? asString(item.original_file_name);
    const mime =
      (await this.decryptBundleSafe(
        oaseId,
        item.original_file_mime_cipher_bundle,
      )) ??
      asString(item.original_file_mime) ??
      (encrypted ? undefined : outerMime);
    return {
      index,
      id: asString(item.id),
      kind: asString(item.type),
      mime,
      name: name ? stripOaseSuffix(name) : undefined,
      encrypted,
    };
  }

  /** Download one attachment's blob from its signed storage URL. */
  private async downloadMediaItem(
    oaseId: string,
    item: Record<string, unknown>,
  ): Promise<Buffer> {
    let url = asString(item.url) ?? asString(item.original_url);
    if (!url) {
      // Giphy attachments have no storage URL — the CDN link lives inside
      // the encrypted giphy object.
      const giphy = await this.decryptBundleSafe(
        oaseId,
        item.giphy_object_cipher_bundle,
      );
      if (giphy) {
        try {
          url = findFirstUrl(JSON.parse(giphy));
        } catch {
          /* not JSON — fall through */
        }
      }
    }
    if (!url) {
      throw new OaseError("This attachment has no downloadable URL.");
    }
    const res = await fetch(url);
    if (!res.ok) {
      throw new OaseError(`Attachment download failed (${res.status}).`, res.status);
    }
    const declared = Number(res.headers.get("content-length") || 0);
    if (declared > MAX_MEDIA_BYTES) {
      throw new OaseError(
        `Attachment too large (${declared} bytes; limit ${MAX_MEDIA_BYTES}).`,
      );
    }
    const data = Buffer.from(await res.arrayBuffer());
    if (data.length > MAX_MEDIA_BYTES) {
      throw new OaseError(
        `Attachment too large (${data.length} bytes; limit ${MAX_MEDIA_BYTES}).`,
      );
    }
    return data;
  }

  /**
   * Download and, when needed, decrypt one attachment of a message. Modern
   * uploads are an encrypted container (see parseEncryptedContainer) keyed by
   * the same oase key as text; legacy image/video items are plaintext blobs
   * behind signed CDN URLs and pass through unchanged.
   *
   * Raw media items (with their signed URLs) are remembered from every chat
   * read; a message not seen yet triggers one baseline read. Signed URLs
   * expire after ~2 days, so a failed download refreshes the chat page and
   * retries once.
   */
  async fetchMedia(
    oaseId: string,
    messageId: string,
    index = 0,
  ): Promise<FetchedMedia> {
    let items = this.rawMediaByMessage.get(messageId);
    if (!items) {
      await this.chatEvolve(oaseId, "");
      items = this.rawMediaByMessage.get(messageId);
    }
    if (!items || items.length === 0) {
      throw new OaseError(
        `No attachments found for message ${messageId}. It may have none, ` +
          `be deleted, or be older than the latest chat page.`,
      );
    }
    if (index < 0 || index >= items.length) {
      throw new OaseError(
        `Message ${messageId} has ${items.length} attachment(s); ` +
          `index ${index} is out of range.`,
      );
    }

    let item = items[index]!;
    let data: Buffer;
    try {
      data = await this.downloadMediaItem(oaseId, item);
    } catch (e) {
      // The signed URL may simply have expired — refresh the projection
      // (which re-signs URLs) and retry once.
      this.rawMediaByMessage.delete(messageId);
      await this.chatEvolve(oaseId, "");
      const fresh = this.rawMediaByMessage.get(messageId)?.[index];
      if (!fresh) throw e;
      item = fresh;
      data = await this.downloadMediaItem(oaseId, item);
    }

    const desc = await this.describeMediaItem(oaseId, item, index);
    const container = parseEncryptedContainer(data);
    if (container) {
      const { metadata, cipherWithTag } = container;
      const key = await this.fetchRawKey(
        metadata.oaseId || oaseId,
        metadata.kid,
      );
      const keyBuf = Buffer.from(key.base64, "base64");
      const iv = Buffer.from(metadata.ivBase64, "base64");
      const tag = cipherWithTag.subarray(cipherWithTag.length - 16);
      const enc = cipherWithTag.subarray(0, cipherWithTag.length - 16);
      const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, iv);
      decipher.setAuthTag(tag);
      const plain = Buffer.concat([decipher.update(enc), decipher.final()]);
      return {
        data: plain,
        mime: desc.mime ?? sniffMime(plain),
        name: desc.name,
        encrypted: true,
      };
    }
    if (desc.encrypted) {
      throw new OaseError(
        "Attachment is marked encrypted but is not a valid .oase container.",
      );
    }
    return {
      data,
      mime: desc.mime ?? sniffMime(data),
      name: desc.name,
      encrypted: false,
    };
  }

  /** Decrypt a cipher bundle produced for an oase we're a member of. */
  async decrypt(bundle: CipherBundle): Promise<string> {
    const key = await this.fetchRawKey(bundle.oaseId, bundle.kid || "current");
    const keyBuf = Buffer.from(key.base64, "base64");
    const iv = Buffer.from(bundle.ivBase64, "base64");
    const combined = Buffer.from(bundle.cipherBase64, "base64");
    const tag = combined.subarray(combined.length - 16);
    const data = combined.subarray(0, combined.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString(
      "utf8",
    );
  }

  get identity(): {
    personId?: string;
    displayName: string;
    loggedIn: boolean;
  } {
    return {
      personId: this.config.personId,
      displayName: this.config.displayName,
      loggedIn: this.isLoggedIn,
    };
  }

  listOases(): JoinedOase[] {
    return Object.values(this.config.oases);
  }

  get defaultOaseId(): string | undefined {
    return this.config.defaultOaseId;
  }

  resolveTargetOase(oaseId?: string): string {
    if (oaseId) {
      if (!this.config.oases[oaseId]) {
        throw new OaseError(
          `Not a member of oase ${oaseId}. Join it first with join_oase.`,
        );
      }
      return oaseId;
    }
    const ids = Object.keys(this.config.oases);
    if (ids.length === 0) {
      throw new OaseError(
        "Not a member of any oase yet. Use join_oase with an invite link first.",
      );
    }
    if (this.config.defaultOaseId && this.config.oases[this.config.defaultOaseId]) {
      return this.config.defaultOaseId;
    }
    if (ids.length === 1) return ids[0]!;
    throw new OaseError(
      `Multiple oases joined; specify oase_id. Options: ${ids.join(", ")}`,
    );
  }
}
