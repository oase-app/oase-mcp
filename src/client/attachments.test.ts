import assert from "node:assert/strict";
import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { OaseClient } from "./oaseClient.js";
import { loadConfig } from "./config.js";
import {
  AttachmentError,
  imageSize,
  loadAttachment,
} from "./attachments.js";

/** A valid 3x2 RGB PNG generated in-process (no real image content). */
function makePng(width = 3, height = 2): Buffer {
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (b: Buffer) => {
    let c = 0xffffffff;
    for (const x of b) c = crcTable[(c ^ x) & 0xff]! ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const c = Buffer.alloc(4);
    c.writeUInt32BE(crc(td));
    return Buffer.concat([len, td, c]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const row = Buffer.concat([Buffer.from([0]), crypto.randomBytes(width * 3)]);
  const raw = Buffer.concat(Array.from({ length: height }, () => row));
  const zlib = require_zlib().deflateSync(raw);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}
import zlibModule from "node:zlib";
function require_zlib() {
  return zlibModule;
}

async function tmpFile(name: string, data: Buffer): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "oase-att-"));
  const p = path.join(dir, name);
  await fs.writeFile(p, data);
  return p;
}

test("imageSize reads PNG dimensions", () => {
  assert.deepEqual(imageSize(makePng(7, 5)), { width: 7, height: 5 });
});

test("loadAttachment: validates and describes a PNG", async () => {
  const png = makePng(4, 3);
  const a = await loadAttachment({ path: await tmpFile("pic.png", png) });
  assert.equal(a.mime, "image/png");
  assert.equal(a.name, "pic.png");
  assert.equal(a.width, 4);
  assert.equal(a.height, 3);
  assert.ok(a.data.equals(png));
});

test("loadAttachment: rejects bad input", async () => {
  await assert.rejects(loadAttachment({ path: "/nope/missing.png" }), AttachmentError);
  await assert.rejects(loadAttachment({ path: "https://x.test/a.png" }), /URL/);
  await assert.rejects(loadAttachment({ path: os.tmpdir() }), /regular file/);
  await assert.rejects(loadAttachment({ path: await tmpFile("e.bin", Buffer.alloc(0)) }), /empty/);
  await assert.rejects(
    loadAttachment({ path: await tmpFile("big.bin", Buffer.alloc(100)) }, 50),
    /too large/,
  );
  await assert.rejects(loadAttachment({ path: await tmpFile(".env", Buffer.from("A=1")) }), /credentials/);
  await assert.rejects(
    loadAttachment({ path: path.join(os.homedir(), ".oase-mcp", "config.json") }),
    AttachmentError,
  );
});

test("send then read_media round trip: bytes identical", async () => {
  process.env.OASE_TRANSLOADIT_KEY = "test-key";
  process.env.OASE_TRANSLOADIT_TEMPLATE = "test-template";
  const oaseId = "oase-1";
  const key = crypto.randomBytes(32);
  const png = makePng(8, 6);
  const file = await tmpFile("generated.png", png);

  const client = new OaseClient(await loadConfig());
  const c = client as any;
  c.fetchRawKey = async () => ({ kid: "k1", base64: key.toString("base64") });

  const uploaded: Buffer[] = [];
  let sentBody: any;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: any, init: any = {}) => {
    const u = String(url);
    const method = init.method ?? "GET";
    if (u.endsWith("/assemblies")) {
      const params = JSON.parse((init.body as FormData).get("params") as string);
      assert.ok(params.auth.key && params.template_id);
      return Response.json({
        assembly_id: "asm1",
        assembly_ssl_url: "https://t.test/assemblies/asm1",
        tus_url: "https://t.test/resumable/files/",
      });
    }
    if (u === "https://t.test/resumable/files/" && method === "POST") {
      const meta = new Headers(init.headers).get("upload-metadata")!;
      assert.match(meta, /^assembly_url /);
      return new Response(null, {
        status: 201,
        headers: { location: "/resumable/files/abc" },
      });
    }
    if (u === "https://t.test/resumable/files/abc" && method === "PATCH") {
      uploaded.push(Buffer.from(init.body));
      return new Response(null, {
        status: 204,
        headers: { "upload-offset": String(uploaded[0]!.length) },
      });
    }
    if (u.endsWith("/messaging/messages")) {
      sentBody = JSON.parse(init.body);
      return Response.json({ id: "msg1" });
    }
    if (u === "https://blob.test/x") return new Response(uploaded[0]);
    throw new Error(`unexpected fetch ${method} ${u}`);
  }) as typeof fetch;
  c.authed = async (_m: string, p: string, body: any) => {
    const r = await globalThis.fetch(`https://api.test/${p}`, { method: "POST", body: JSON.stringify(body) });
    return r.json();
  };

  try {
    const id = await client.sendMessage(oaseId, "", undefined, [{ path: file }]);
    assert.equal(id, "msg1");
    const item = sentBody.media[0];
    assert.equal(item.provider, "transloadit");
    assert.equal(item.id, "asm1");
    assert.equal(item.file.uploadURL, "https://t.test/resumable/files/abc");
    assert.equal(item.mime, "application/x.oase-encrypted");
    assert.equal(item.originalFile.width, 8);
    assert.equal(item.originalFile.height, 6);
    assert.equal(item.originalFile.size, png.length);
    assert.equal(item.originalFile.name, undefined);
    assert.ok(!uploaded[0]!.includes(png), "uploaded bytes must not contain plaintext");

    // Backend's view of the stored item, then the existing read_media path.
    c.rawMediaByMessage.set("msg1", [
      {
        id: "m1",
        type: "file",
        mime: item.mime,
        url: "https://blob.test/x",
        original_file_name_cipher_bundle: item.originalFile.name_cipher_bundle,
        original_file_mime_cipher_bundle: item.originalFile.mime_cipher_bundle,
      },
    ]);
    c.decrypt = OaseClient.prototype.decrypt;
    const got = await client.fetchMedia(oaseId, "msg1", 0);
    assert.ok(got.data.equals(png), "decrypted bytes identical");
    assert.equal(got.mime, "image/png");
    assert.equal(got.name, "generated.png");
    assert.equal(got.encrypted, true);
  } finally {
    globalThis.fetch = realFetch;
  }
});
