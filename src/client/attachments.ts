import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Outgoing attachment support: local-file validation, the `.oase` encrypted
 * container the apps upload, and image dimension sniffing. Pure helpers with
 * no network access — the upload itself lives in OaseClient.
 */

/** Outer mime of every encrypted upload (oase-app `OASE_FILES.MIME_TYPE`). */
export const OASE_ENCRYPTED_MIME = "application/x.oase-encrypted";

/** Default per-file cap. The backend default is 51 MB (an oase admin may lower it). */
export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

/** Most attachments allowed on one message or post. */
export const MAX_ATTACHMENTS = 10;

/** A local file to send as an encrypted attachment. */
export interface AttachmentInput {
  /** Path to a file on this machine (absolute, or relative to the cwd; `~/` ok). */
  path: string;
  /** Filename shown to recipients. Defaults to the file's basename. */
  name?: string;
  /** Mime type. Defaults to a guess from the extension / file content. */
  mime?: string;
}

/** A validated, read-in attachment ready to encrypt. */
export interface LoadedAttachment {
  data: Buffer;
  name: string;
  mime: string;
  width?: number;
  height?: number;
}

export class AttachmentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttachmentError";
  }
}

const MIME_BY_EXT: Record<string, string> = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".heic": "image/heic",
  ".heif": "image/heif",
  ".svg": "image/svg+xml",
  ".pdf": "application/pdf",
  ".txt": "text/plain",
  ".md": "text/markdown",
  ".csv": "text/csv",
  ".json": "application/json",
  ".zip": "application/zip",
  ".mp4": "video/mp4",
  ".mov": "video/quicktime",
  ".m4a": "audio/mp4",
  ".mp3": "audio/mpeg",
  ".ogg": "audio/ogg",
  ".wav": "audio/wav",
  ".doc": "application/msword",
  ".docx":
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xls": "application/vnd.ms-excel",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".ppt": "application/vnd.ms-powerpoint",
  ".pptx":
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
};

/** Sniff a mime from magic bytes (images and a few common containers). */
export function sniffMimeFromBytes(data: Buffer): string | undefined {
  if (data.length < 12) return undefined;
  const tag = (s: number, e: number) => data.subarray(s, e).toString("latin1");
  if (data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff) return "image/jpeg";
  if (data.readUInt32BE(0) === 0x89504e47) return "image/png";
  if (tag(0, 4) === "GIF8") return "image/gif";
  if (tag(0, 4) === "RIFF" && tag(8, 12) === "WEBP") return "image/webp";
  if (tag(0, 4) === "%PDF") return "application/pdf";
  return undefined;
}

/** Pixel dimensions of a PNG, GIF, JPEG or WebP, or undefined if unknown. */
export function imageSize(
  data: Buffer,
): { width: number; height: number } | undefined {
  try {
    if (data.length > 24 && data.readUInt32BE(0) === 0x89504e47) {
      return { width: data.readUInt32BE(16), height: data.readUInt32BE(20) };
    }
    if (data.length > 10 && data.subarray(0, 3).toString("latin1") === "GIF") {
      return { width: data.readUInt16LE(6), height: data.readUInt16LE(8) };
    }
    if (data.length > 30 && data.subarray(8, 12).toString("latin1") === "WEBP") {
      const kind = data.subarray(12, 16).toString("latin1");
      if (kind === "VP8X") {
        return {
          width: 1 + data.readUIntLE(24, 3),
          height: 1 + data.readUIntLE(27, 3),
        };
      }
      if (kind === "VP8 ") {
        return {
          width: data.readUInt16LE(26) & 0x3fff,
          height: data.readUInt16LE(28) & 0x3fff,
        };
      }
      if (kind === "VP8L") {
        const b = data.readUInt32LE(21);
        return { width: (b & 0x3fff) + 1, height: ((b >> 14) & 0x3fff) + 1 };
      }
      return undefined;
    }
    if (data[0] === 0xff && data[1] === 0xd8) {
      let i = 2;
      while (i + 9 < data.length) {
        if (data[i] !== 0xff) {
          i++;
          continue;
        }
        const marker = data[i + 1]!;
        if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) {
          i += 2;
          continue;
        }
        const len = data.readUInt16BE(i + 2);
        // SOF0..SOF15 except DHT (c4), JPG (c8), DAC (cc)
        if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) {
          return {
            height: data.readUInt16BE(i + 5),
            width: data.readUInt16BE(i + 7),
          };
        }
        i += 2 + len;
      }
    }
  } catch {
    /* fall through */
  }
  return undefined;
}

/** Directories (under $HOME) an agent must never be able to upload from. */
const BLOCKED_HOME_DIRS = [".oase-mcp", ".ssh", ".aws", ".gnupg", ".config/gcloud", ".kube"];

function expandHome(p: string): string {
  return p === "~" || p.startsWith("~/") ? path.join(os.homedir(), p.slice(1)) : p;
}

function isSecretLooking(base: string): boolean {
  return (
    /^\.env(\..*)?$/i.test(base) ||
    /^id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/.test(base) ||
    /(^|[._-])(token|secret|credentials)s?([._-]|$)/i.test(base) ||
    base === ".npmrc" ||
    base === ".netrc"
  );
}

/**
 * Validate a local file and read it into memory. Rejects URLs, directories,
 * empty and oversized files, and credential-looking locations (the MCP
 * config dir, ~/.ssh, .env files, …) so a prompt-injected agent can't
 * exfiltrate them into a chat. Resolves symlinks before checking.
 */
export async function loadAttachment(
  input: AttachmentInput,
  maxBytes = MAX_UPLOAD_BYTES,
): Promise<LoadedAttachment> {
  const raw = input.path?.trim();
  if (!raw) throw new AttachmentError("Attachment path is empty.");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    throw new AttachmentError(
      `Only local file paths are accepted, not URLs (got "${raw}").`,
    );
  }
  let real: string;
  try {
    real = await fs.realpath(path.resolve(expandHome(raw)));
  } catch {
    throw new AttachmentError(`File not found: ${raw}`);
  }
  const home = await fs.realpath(os.homedir()).catch(() => os.homedir());
  for (const d of BLOCKED_HOME_DIRS) {
    const blocked = path.join(home, d);
    if (real === blocked || real.startsWith(blocked + path.sep)) {
      throw new AttachmentError(
        `Refusing to send ${raw}: it is inside ~/${d}, which holds credentials.`,
      );
    }
  }
  if (isSecretLooking(path.basename(real))) {
    throw new AttachmentError(
      `Refusing to send ${raw}: the filename looks like a credentials file.`,
    );
  }
  const stat = await fs.stat(real);
  if (!stat.isFile()) throw new AttachmentError(`Not a regular file: ${raw}`);
  if (stat.size === 0) throw new AttachmentError(`File is empty: ${raw}`);
  if (stat.size > maxBytes) {
    throw new AttachmentError(
      `File too large: ${raw} is ${stat.size} bytes (limit ${maxBytes}).`,
    );
  }
  const data = await fs.readFile(real);
  const name = (input.name?.trim() || path.basename(real)).replace(/[\\/]/g, "_");
  const mime =
    input.mime?.trim() ||
    sniffMimeFromBytes(data) ||
    MIME_BY_EXT[path.extname(real).toLowerCase()] ||
    "application/octet-stream";
  if (!/^[\w.+-]+\/[\w.+-]+$/.test(mime)) {
    throw new AttachmentError(`Invalid mime type: ${mime}`);
  }
  const dims = mime.startsWith("image/") ? imageSize(data) : undefined;
  return { data, name, mime, width: dims?.width, height: dims?.height };
}

export interface EncryptedContainerMeta {
  version?: number;
  alg?: string;
  kid: string;
  oaseId: string;
  ivBase64: string;
}

/**
 * Build the `.oase` container the apps upload:
 *   [uint32 LE metadata length][metadata JSON][AES-256-GCM ciphertext][16-byte tag]
 * metadata = { version: 1, alg: 'AES-GCM', kid, oaseId, ivBase64 }. The whole
 * file is one GCM message with a fresh random 12-byte IV, keyed by the oase's
 * current key (the same key that encrypts message text).
 */
export function encryptContainer(
  plain: Buffer,
  key: Buffer,
  oaseId: string,
  kid: string,
): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  const meta: EncryptedContainerMeta = {
    version: 1,
    alg: "AES-GCM",
    kid,
    oaseId,
    ivBase64: iv.toString("base64"),
  };
  const metaBytes = Buffer.from(JSON.stringify(meta), "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(metaBytes.length, 0);
  return Buffer.concat([len, metaBytes, enc, tag]);
}
