# oase-mcp

An MCP server that lets Claude chat inside an [Oase](https://oase.app). Give
Claude an invite link and it can post into that oase's group chat, publish
posts (opslag) to the oase's feed, read the conversation, and react — handy
for status updates, "I finished X", or dropping a note where you'll see it.

It's a **REST client**: every tool is a plain request/response HTTP call.

📖 **Documentation:** https://dev.oase.app/mcp/

## Status / disclaimer

This is **experimental** and provided **as-is**. It builds on Oase's
internal API, which can change without notice — so it may break, change, or
be discontinued at any time, and there's no guarantee it works today or will
keep working tomorrow. There's **no support commitment**: issues are welcome
(see [SUPPORT.md](SUPPORT.md)) but may go unanswered. If you need a supported
integration path, use the [identity & SCIM integration](https://dev.oase.app/identity/)
instead.

Talks to the production Oase backend (`api.oase.app`) exactly like the app does:
sign in → join via invite link → fetch the oase key from KMS → AES-256-GCM
encrypt → `POST .../messaging/messages`. Messages are encrypted client-side
with the oase's symmetric AES-256-GCM key (fetched from the KMS via a
mainframe-signed proof), so they render normally in the app.

## Architecture

The codebase is a passive REST client with an MCP server on top:

- **Passive REST client — `src/client/`.** Everything that knows *how to talk
  to Oase over HTTP*: Promise login/auth (`promiseLogin.ts`), token refresh
  and the shared config file (`config.ts`), and the full REST client
  (`oaseClient.ts`) — joining via invite link, KMS key fetching, AES-256-GCM
  encrypt/decrypt, and sending/reading messages and feed posts, reactions, and
  media. No agent behavior, no MCP dependency: it does something only when called.
  Importable by other consumers via the package root or `oase-mcp/client`
  (`import { OaseClient, loadConfig } from "oase-mcp"`), without pulling
  in the MCP layer.
- **MCP server — `src/mcp/`.** The MCP tool surface over the REST client
  (`server.ts`). Every tool is an on-demand request/response wrapper. Entry
  point: `dist/index.js` (`claude mcp add oase -- node /path/to/dist/index.js`).

## How it works

- **Identity.** Claude signs in as a persistent
  [Promise](https://promiseauthentication.org) user (the identity provider the
  Oase app uses) via a one-time browser login — see [Logging in](#logging-in).
  The resulting long-lived Oase refresh token is stored in
  `~/.oase-mcp/config.json` (mode 0600); short-lived access tokens are kept in
  memory and refreshed automatically.
- **Encryption.** Oase encrypts message content with a per-oase symmetric
  AES-256-GCM key held in escrow by the backend. Any participant can fetch the
  raw oase key from the KMS via a mainframe-signed proof, so encrypting/decrypting
  is straightforward — no device keypairs or enrollment. We produce the exact
  cipher-bundle shape the app expects.
- **No message is sent in plaintext** — the send endpoint requires a cipher bundle.

## Setup

```bash
npm install
npm run build
```

Register it with Claude Code (use the absolute path to this checkout):

```bash
claude mcp add oase -- node /path/to/oase-mcp/dist/index.js
```

Or add to your MCP client config manually:

```json
{
  "mcpServers": {
    "oase": {
      "command": "node",
      "args": ["/path/to/oase-mcp/dist/index.js"]
    }
  }
}
```

## Logging in

Claude signs in as a persistent Promise user — a one-time setup:

1. Call **`promise_login_start`** — it returns a URL. Open it in a browser
   (incognito is safest so an existing Promise session isn't reused).
2. Sign in to (or create) the Promise account for Claude. The page will say
   "Token captured".
3. Call **`promise_login_finish`** — it exchanges the token for a persistent
   Oase identity.

Under the hood the server hosts a localhost OIDC callback and captures the
single-use `id_token` from the redirect — no copy-pasting. (If you already have
an `id_token`, `login_with_promise` takes it directly.)

The exchange returns Oase's own long-lived refresh token (keyed to the Promise
`person_id`), so **Promise is never contacted again** — no Promise credentials
are stored, only the resulting Oase refresh token.

Login is required: every other tool (join, send, read, ask) refuses until a
Promise identity is established.

## Tools

| Tool | Args | What it does |
|---|---|---|
| `promise_login_start` | — | Start the one-time browser login for a persistent Promise identity; returns a URL to open. |
| `promise_login_finish` | — | Complete the Promise login after signing in in the browser. |
| `login_with_promise` | `id_token` | Exchange a Promise `id_token` you already have. |
| `join_oase` | `invite_link`, `display_name?` | Join an oase from an invite link (`https://oase.app/oase/<id>/join/<phrase>`). Sets the display name (default `Claude`) and makes this oase the default target. |
| `send_message` | `message`, `oase_id?`, `thread_id?` | Post a markdown message. With `thread_id` it posts inside that message's reply thread; otherwise the main chat. |
| `update_message` | `message_id`, `message`, `oase_id?` | Edit the text of a message you sent (only your own). Attachments are kept; only the text changes. |
| `delete_message` | `message_id`, `oase_id?` | Delete a message (soft delete). Your own, or anyone's if you're an oase admin/owner. |
| `send_post` | `body`, `title?`, `oase_id?` | Publish a **post** (opslag) to the oase's feed/wall — the front-page items in the app, distinct from chat. Markdown body, optional title (shown as the headline). Comments on the post are thread replies: `send_message` with `thread_id=<post id>`. Fails with `posting_restricted` if an admin limited posting to admins. |
| `update_post` | `post_id`, `body`, `title?`, `oase_id?` | Edit a feed post's body (and optionally title; omit `title` to keep it). Attachments are kept. Your own, or anyone's if you're an oase admin/owner. |
| `delete_post` | `post_id`, `oase_id?` | Delete a feed post. Your own, or anyone's if you're an oase admin/owner. |
| `read_posts` | `oase_id?`, `limit?` | Read recent feed posts (decrypted), oldest first, each line prefixed with the post id and tagged `(you)`/`(them)`, with title and attachment tags. Post attachments work with `read_media`. |
| `react_to_message` | `message_id`, `reaction`, `oase_id?` | Add an emoji reaction to a message (one per participant per message). |
| `read_media` | `message_id`, `media_index?`, `oase_id?` | Download and decrypt a message attachment (image, voice message / sound bite, file). Images are returned inline so the agent can view and analyze them; every attachment is also saved to a local temp file whose path is returned (e.g. for transcribing audio). |
| `read_messages` | `oase_id?`, `limit?` | Read recent messages (decrypted), oldest first, each line prefixed with its message id and tagged `(you)`/`(them)`; replies are marked `(in thread <rootId>)`. Attachments show as `[attachment <n>: <mime> "<name>"]` tags — fetch them with `read_media`. |
| `list_oases` | — | Show Claude's Oase identity and joined oases. |
| `set_name` | `display_name`, `oase_id?` | Change the display name Claude posts under. |

### Threads and replies

Threads in Oase are one level: every reply to a message lives under that
message's resource id (chat_id `<oaseId>/m/<messageId>`), and **you cannot reply
to a reply** — a nested thread would never be shown in the app. The server
enforces this: a `thread_id` that points at a reply is auto-resolved to the
thread's root message, so nothing ever lands in an invisible nested chat. To
reply to a message, pass its id as `thread_id` to `send_message`; use
`read_messages` to catch up on context and get the ids.

### Attachments (images, voice messages, files)

Messages with attachments show them as `[attachment <n>: <mime> "<name>"]`
tags in every read result (a voice message is simply an `audio/*`
attachment, usually `audio/mp4`). `read_media` downloads the blob and, for
modern uploads, decrypts it: the app uploads media as an encrypted `.oase`
container — `[4-byte length][metadata JSON {alg, kid, oaseId, ivBase64}]
[ciphertext][16-byte GCM tag]` — encrypted with the same server-escrowed oase
key as text, while the original filename/mime travel as cipher bundles on the
media item (legacy attachments are plaintext blobs behind signed CDN URLs and
pass through unchanged; giphy attachments resolve via their encrypted giphy
object).

What the agent gets back:

- **Images** (jpeg/png/gif/webp up to 3 MB) are returned inline as MCP image
  content, so the agent can look at them directly and use what it sees in its
  response. Larger images fall back to the saved file.
- **Everything** is also written to `<tmpdir>/oase-mcp/media/<messageId>-<n>-<name>`
  and the path returned. For audio (Claude can't listen natively) the agent is
  nudged to transcribe the saved file with a local speech-to-text tool (e.g.
  `hear` on macOS or `whisper`) and work from the transcript; documents can be
  opened with normal file tools.

Blob download URLs are provider-signed and expire after ~2 days; `read_media`
refreshes the chat projection and retries once if a URL has gone stale. Voice
messages / media-only messages have an empty text body and are shown by
`read_messages` like any other message.

### Typical flow

1. Log Claude in: `promise_login_start` → open the URL → `promise_login_finish`.
2. In the Oase app, open your oase → invite → copy the join link.
3. Ask Claude: *"Join this oase: https://oase.app/oase/…/join/…"* → `join_oase`.
4. Ask Claude to *"send a message to the oase saying …"* → `send_message`,
   *"post an update to the feed"* → `send_post`, or *"what's new in the oase?"*
   → `read_messages` / `read_posts`.

## Configuration

Environment variables (all optional):

- `OASE_MCP_CONFIG_DIR` — where to store `config.json` (default `~/.oase-mcp`).
- `OASE_API_ROOT` — mainframe API root (default `https://api.oase.app`), e.g. point at staging.
- `OASE_KMS_ROOT` — KMS root (default `https://kms.oase.app/`, trailing slash required).

## Notes & limitations

- Works on an oase's **group chat** (and per-message reply threads) and its
  **feed posts** (`send_post`/`read_posts` — text only when sending; a post's
  title and body are separate cipher bundles under the same oase key). It can
  read/decrypt media attachments (`read_media`) but not send them; it doesn't
  handle private 1:1 chats or realm join-approval flows.
- **Replies can't be nested** — threads are one level deep. A `thread_id` that
  is itself a reply is silently resolved to the thread's root message (best
  effort: for a message older than the latest chat page the id is used as-is).
- Signing in as a different Promise account clears joined oases, since
  memberships are per-person — re-invite Claude afterward.
- Deleting `~/.oase-mcp/config.json` forgets the identity (Claude must log in and
  be re-invited).
- Many server processes (one per Claude session) share the identity in
  `~/.oase-mcp/config.json`. The backend rotates the refresh token on every
  `oauth2/refresh` and **deletes the session if it ever sees a stale one**
  (anti-replay) — so the access token is persisted for reuse, and refreshes
  are serialized across processes via `~/.oase-mcp/auth.lock` with a re-read
  under the lock. Don't hit `oauth2/refresh` out-of-band while servers are
  running; if the session does get revoked, tools will say so — log in again
  with `promise_login_start`.

## License

MIT — see [LICENSE](LICENSE).
