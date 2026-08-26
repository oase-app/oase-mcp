import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  ChatMessage,
  FetchedMedia,
  OaseClient,
  OaseError,
  PromiseLogin,
  loadConfig,
  saveConfig,
} from "../client/index.js";

function textResult(text: string, isError = false) {
  return { content: [{ type: "text" as const, text }], isError };
}

/** Open a URL in the user's default browser (best-effort, never throws). */
function openInBrowser(url: string): void {
  const [cmd, args]: [string, string[]] =
    process.platform === "darwin"
      ? ["open", [url]]
      : process.platform === "win32"
        ? ["cmd", ["/c", "start", "", url]]
        : ["xdg-open", [url]];
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    /* the returned text includes the URL as fallback */
  }
}

/** "[attachment 0: image/jpeg "photo.jpg"]" tags for a message's media. */
function attachmentTags(m: ChatMessage): string[] {
  return m.media.map(
    (a) =>
      `[attachment ${a.index}: ${a.mime ?? a.kind ?? "file"}` +
      `${a.name ? ` "${a.name}"` : ""}]`,
  );
}

/** Message text plus attachment tags, as shown in tool output. */
function messageBody(m: ChatMessage): string {
  const parts = [m.text, ...attachmentTags(m)].filter(Boolean);
  if (parts.length) return parts.join(" ");
  return m.text === undefined ? "[undecryptable]" : "";
}

/** A hint appended when any listed message carries attachments. */
function mediaHint(messages: ChatMessage[]): string {
  return messages.some((m) => m.media.length)
    ? "\n(Some messages have attachments — use read_media with the " +
        "message_id and attachment index to download/decrypt them: images " +
        "are returned for you to view, audio/voice messages and other files " +
        "are saved locally for you to transcribe or inspect.)"
    : "";
}

/**
 * One chat message as a tool-output line. chat_id is "<oaseId>" for the main
 * chat or "<oaseId>/m/<rootId>" for a reply thread; surface the root so
 * agents thread correctly.
 */
function chatLine(m: ChatMessage): string {
  const root = m.chatId.match(/\/m\/([^/]+)/)?.[1];
  const where = root ? ` (in thread ${root})` : "";
  return `[${m.id}]${where} ${m.mine ? "(you)" : "(them)"}${reactionTag(m)} ${messageBody(m)}`;
}

/**
 * Reactions others left on a message, e.g. " {reactions: 🟢}". A reaction is
 * often the entire reply — someone voting with an emoji instead of typing —
 * so it belongs on the line. Own reactions are marked so the agent can tell
 * its own acknowledgements apart from real answers.
 */
function reactionTag(m: ChatMessage): string {
  const rs = (m.reactions ?? []).filter((r) => r.emoji);
  if (!rs.length) return "";
  const shown = rs.map((r) => (r.mine ? `${r.emoji}(you)` : r.emoji));
  return ` {reactions: ${shown.join(" ")}}`;
}

const EXT_BY_MIME: Record<string, string> = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/gif": "gif",
  "image/webp": "webp",
  "image/heic": "heic",
  "audio/mp4": "m4a",
  "audio/webm": "webm",
  "audio/mpeg": "mp3",
  "audio/ogg": "ogg",
  "audio/wav": "wav",
  "video/mp4": "mp4",
  "video/quicktime": "mov",
  "application/pdf": "pdf",
  "text/plain": "txt",
};

/** Write a fetched attachment to a temp file the agent's tools can open. */
async function saveMediaFile(
  messageId: string,
  index: number,
  media: FetchedMedia,
): Promise<string> {
  const dir = path.join(os.tmpdir(), "oase-mcp", "media");
  await fs.mkdir(dir, { recursive: true });
  let name = (media.name ?? "attachment").replace(/[^\w.-]+/g, "_");
  if (!/\.[A-Za-z0-9]{1,5}$/.test(name)) {
    const ext = media.mime ? EXT_BY_MIME[media.mime] : undefined;
    if (ext) name += `.${ext}`;
  }
  const file = path.join(dir, `${messageId}-${index}-${name}`);
  await fs.writeFile(file, media.data);
  return file;
}

/** Image types Claude can view inline, and the size we're willing to inline. */
const INLINE_IMAGE_MIMES = new Set([
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
]);
const INLINE_IMAGE_LIMIT = 3 * 1024 * 1024;

function errText(e: unknown): string {
  if (e instanceof OaseError) return e.message;
  return e instanceof Error ? e.message : String(e);
}

/**
 * Build and run the Oase MCP server over stdio. Every tool is a REST
 * request/response wrapper around the passive client layer (../client).
 * Resolves once the server is connected; it then serves until the process
 * exits.
 */
export async function runMcpServer(): Promise<void> {
  const config = await loadConfig();
  const client = new OaseClient(config);
  const promiseLogin = new PromiseLogin();

  const server = new McpServer({
    name: "oase-mcp",
    version: "0.1.0",
  });

  server.registerTool(
    "promise_login_start",
    {
      title: "Start Promise login (browser)",
      description:
        "Begin logging Claude in as a persistent Promise identity. Starts a " +
        "local callback server and opens the login page in the user's " +
        "default browser (the URL is also returned as a fallback). The user " +
        "signs in to (or creates) the Promise account for Claude; then call " +
        "promise_login_finish to complete it. Recommended over pasting a raw " +
        "id_token.",
      inputSchema: {},
    },
    async () => {
      try {
        const url = await promiseLogin.start();
        openInBrowser(url);
        return textResult(
          `Opened the Promise login page in the user's browser. Ask them to ` +
            `sign in as the Oase/Claude account and wait for "Token captured". ` +
            `If no browser window appeared, they can open it manually ` +
            `(an incognito window is safest so an existing Promise session ` +
            `isn't reused):\n\n${url}\n\n` +
            `Then call promise_login_finish.`,
        );
      } catch (e) {
        return textResult(`Could not start Promise login: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "promise_login_finish",
    {
      title: "Finish Promise login",
      description:
        "Complete the login started by promise_login_start: waits for the " +
        "browser redirect to deliver the token, exchanges it for a persistent " +
        "Oase identity, and shuts down the callback server.",
      inputSchema: {},
    },
    async () => {
      if (!promiseLogin.isRunning) {
        return textResult(
          "No Promise login in progress. Call promise_login_start first.",
          true,
        );
      }
      try {
        const idToken = await promiseLogin.waitForToken();
        const personId = await client.loginWithPromise(idToken);
        promiseLogin.stop();
        return textResult(
          `Logged in as Promise identity ${personId}. This is now Claude's ` +
            `persistent Oase account. Next, join an oase with join_oase.`,
        );
      } catch (e) {
        return textResult(
          `Promise login did not complete: ${errText(e)}`,
          true,
        );
      }
    },
  );

  server.registerTool(
    "join_oase",
    {
      title: "Join an Oase",
      description:
        "Join an oase using an invite link (e.g. https://oase.app/oase/<id>/join/<phrase>). " +
        "Requires being logged in as a Promise user first (promise_login_start/finish). " +
        "Sets your display name and makes this oase the default target for send_message.",
      inputSchema: {
        invite_link: z
          .string()
          .describe(
            "The full Oase invite link, or '<oase_id> <phrase>'.",
          ),
        display_name: z
          .string()
          .optional()
          .describe("Name to show in the oase. Defaults to 'Claude'."),
      },
    },
    async ({ invite_link, display_name }) => {
      try {
        const record = await client.join(invite_link, display_name);
        return textResult(
          `Joined oase ${record.id} as ` +
            `"${display_name || config.displayName}". It's now the default for send_message.`,
        );
      } catch (e) {
        return textResult(`Failed to join: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "login_with_promise",
    {
      title: "Log in with a Promise identity",
      description:
        "Exchange a fresh Promise id_token (OIDC, audience 'oase.app') for a " +
        "persistent Promise-backed Oase identity. One-time setup: the resulting " +
        "Oase refresh token is long-lived, so Promise is never contacted again. " +
        "Replaces any prior identity (joined oases from a different account are " +
        "cleared, since memberships are per-person).",
      inputSchema: {
        id_token: z
          .string()
          .describe(
            "A fresh Promise-issued id_token (JWT). Single-use and short-lived — exchange it promptly.",
          ),
      },
    },
    async ({ id_token }) => {
      try {
        const personId = await client.loginWithPromise(id_token);
        return textResult(
          `Logged in as Promise identity ${personId}. This is now Claude's ` +
            `persistent Oase account; re-invite it to any oases you want it in.`,
        );
      } catch (e) {
        return textResult(
          `Promise login failed: ${errText(e)}\n` +
            `The id_token may be expired or already used — Promise tokens are single-use. ` +
            `Grab a fresh one and try again.`,
          true,
        );
      }
    },
  );

  server.registerTool(
    "send_message",
    {
      title: "Send a message to an Oase",
      description:
        "Send a markdown chat message into an oase. Omit oase_id to use the " +
        "default (last joined) oase. Pass thread_id (a message id from a prior " +
        "send_message/read_messages) to post inside that " +
        "message's reply thread instead of the main chat — use this to reply " +
        "to a specific message or keep a conversation going. Threads are one " +
        "level deep: you cannot reply to a reply. To continue a conversation, " +
        "always thread under the root message; a reply's own id passed as " +
        "thread_id is auto-resolved to its thread root.",
      inputSchema: {
        message: z.string().describe("The message text (markdown supported)."),
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
        thread_id: z
          .string()
          .optional()
          .describe(
            "Root message id to reply under (keeps the conversation threaded). " +
              "Must be a main-chat message, not a reply — replies can't be " +
              "nested. Omit to post to the main chat.",
          ),
      },
    },
    async ({ message, oase_id, thread_id }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        // Resolve here (sendMessage would too) so a redirect can be reported.
        const thread = thread_id
          ? await client.resolveThreadRoot(target, thread_id)
          : undefined;
        const id = await client.sendMessage(target, message, thread);
        const where = thread ? `thread ${thread}` : "main chat";
        const note =
          thread && thread !== thread_id
            ? `\n(Note: ${thread_id} is itself a reply and replies can't be ` +
              `nested — posted to its thread root instead. Use ` +
              `thread_id="${thread}" for this conversation from now on.)`
            : "";
        return textResult(
          `Sent message ${id} to ${where} of oase ${target}.${note}`,
        );
      } catch (e) {
        return textResult(`Failed to send: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "update_message",
    {
      title: "Edit a message you sent",
      description:
        "Edit the text of a chat message this agent sent earlier, replacing " +
        "its body with new markdown. Get the message_id from send_message or " +
        "read_messages output. Omit oase_id to use the default (last joined) " +
        "oase. Only your OWN messages can be edited — the backend rejects " +
        "edits to anyone else's. Any attachments on the message are kept as-is; " +
        "only the text changes. The message must be in the recent chat history.",
      inputSchema: {
        message_id: z.string().describe("Id of the message to edit."),
        message: z
          .string()
          .describe("The new message text (markdown supported)."),
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
      },
    },
    async ({ message_id, message, oase_id }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        await client.updateMessage(target, message_id, message);
        return textResult(`Edited message ${message_id} in oase ${target}.`);
      } catch (e) {
        return textResult(`Failed to edit message: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "delete_message",
    {
      title: "Delete a message",
      description:
        "Delete a chat message (soft delete — it shows as removed in the app). " +
        "Get the message_id from send_message or read_messages output. Omit " +
        "oase_id to use the default (last joined) oase. You can delete your " +
        "own messages; deleting someone else's requires being an oase " +
        "admin/owner, otherwise the backend rejects it.",
      inputSchema: {
        message_id: z.string().describe("Id of the message to delete."),
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
      },
    },
    async ({ message_id, oase_id }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        await client.deleteMessage(target, message_id);
        return textResult(`Deleted message ${message_id} in oase ${target}.`);
      } catch (e) {
        return textResult(`Failed to delete message: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "send_post",
    {
      title: "Publish a post to an Oase's feed",
      description:
        "Publish a post (Danish: opslag/indlæg) to an oase's feed/wall — the " +
        "front-page items in the app, distinct from chat messages. Use for " +
        "announcements and longer write-ups; use send_message for chat. Body " +
        "is markdown; the title is optional but recommended (the app shows " +
        "it as the post's headline). Omit oase_id to use the default (last " +
        "joined) oase. Returns the post id — comments on a post are ordinary " +
        "thread replies, so send_message with thread_id=<post id> comments " +
        "on it, and react_to_message works on post ids too. Fails with " +
        "'posting_restricted' if an admin limited posting to admins.",
      inputSchema: {
        body: z.string().describe("The post body (markdown supported)."),
        title: z
          .string()
          .optional()
          .describe("Post title/headline. Optional; shown above the body."),
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
      },
    },
    async ({ body, title, oase_id }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        const id = await client.sendPost(target, body, title ?? "");
        return textResult(
          `Published post ${id} to the feed of oase ${target}.` +
            ` (To follow up: send_message with thread_id="${id}" comments on ` +
            `it; read_posts lists recent posts.)`,
        );
      } catch (e) {
        const restricted =
          e instanceof OaseError && e.status === 403
            ? " Posting in this oase is restricted to admins."
            : "";
        return textResult(`Failed to post: ${errText(e)}${restricted}`, true);
      }
    },
  );

  server.registerTool(
    "update_post",
    {
      title: "Edit a feed post",
      description:
        "Edit a post (opslag) on an oase's feed, replacing its body (and " +
        "optionally its title) with new markdown. Get the post_id from " +
        "send_post or read_posts output. Omit oase_id to use the default (last " +
        "joined) oase. If you omit title, the post's current title is kept; " +
        "pass title to change it (pass an empty string to clear it). Any " +
        "attachments on the post are kept as-is. You can edit your own post; " +
        "editing someone else's requires being an oase admin/owner. The post " +
        "must be in the recent feed.",
      inputSchema: {
        post_id: z.string().describe("Id of the post to edit."),
        body: z.string().describe("The new post body (markdown supported)."),
        title: z
          .string()
          .optional()
          .describe(
            "New title/headline. Omit to keep the current title; empty string " +
              "clears it.",
          ),
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
      },
    },
    async ({ post_id, body, title, oase_id }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        await client.updatePost(target, post_id, body, title);
        return textResult(`Edited post ${post_id} in oase ${target}.`);
      } catch (e) {
        return textResult(`Failed to edit post: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "delete_post",
    {
      title: "Delete a feed post",
      description:
        "Delete a post (opslag) from an oase's feed. Get the post_id from " +
        "send_post or read_posts output. Omit oase_id to use the default (last " +
        "joined) oase. You can delete your own post; deleting someone else's " +
        "requires being an oase admin/owner, otherwise the backend rejects it.",
      inputSchema: {
        post_id: z.string().describe("Id of the post to delete."),
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
      },
    },
    async ({ post_id, oase_id }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        await client.deletePost(target, post_id);
        return textResult(`Deleted post ${post_id} in oase ${target}.`);
      } catch (e) {
        return textResult(`Failed to delete post: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "read_posts",
    {
      title: "Read recent Oase feed posts",
      description:
        "Read the most recent posts (opslag) in an oase's feed, decrypted, " +
        "oldest first. Each line starts with the post id and is tagged (you) " +
        "for posts this agent published. Attachments show as [attachment " +
        "<n>: …] tags — download them with read_media using the post id. To " +
        "comment on a post, use send_message with thread_id=<post id>; to " +
        "react, react_to_message with message_id=<post id>.",
      inputSchema: {
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(50)
          .optional()
          .describe("How many recent posts to return. Default 10."),
      },
    },
    async ({ oase_id, limit }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        const posts = await client.readRecentPosts(target, limit ?? 10);
        if (posts.length === 0) return textResult("No posts yet.");
        const lines = posts.map((p) => {
          const tags = p.media.map(
            (a) =>
              `[attachment ${a.index}: ${a.mime ?? a.kind ?? "file"}` +
              `${a.name ? ` "${a.name}"` : ""}]`,
          );
          const headline = p.title ? `“${p.title}” — ` : "";
          const bodyParts = [p.text, ...tags].filter(Boolean);
          const bodyText = bodyParts.length
            ? bodyParts.join(" ")
            : p.text === undefined
              ? "[undecryptable]"
              : "";
          return `[${p.id}] ${p.mine ? "(you)" : "(them)"} ${headline}${bodyText}`;
        });
        const hint = posts.some((p) => p.media.length)
          ? "\n(Some posts have attachments — use read_media with the post " +
            "id and attachment index to download/decrypt them.)"
          : "";
        return textResult(lines.join("\n") + hint);
      } catch (e) {
        return textResult(`read_posts failed: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "react_to_message",
    {
      title: "React to a message",
      description:
        "Add an emoji reaction to a message in an oase. Get the message_id " +
        "from read_messages output. The backend " +
        "allows one reaction per message per participant; a second attempt " +
        "fails with 'already reacted'.",
      inputSchema: {
        message_id: z.string().describe("Id of the message to react to."),
        reaction: z
          .string()
          .describe("The reaction — an emoji like 👍 (short text also works)."),
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
      },
    },
    async ({ message_id, reaction, oase_id }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        await client.react(target, message_id, reaction);
        return textResult(
          `Reacted ${reaction} to message ${message_id} in oase ${target}.`,
        );
      } catch (e) {
        return textResult(`Failed to react: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "read_messages",
    {
      title: "Read recent Oase messages",
      description:
        "Read the most recent chat messages in an oase (decrypted), oldest " +
        "first. Each line starts with the message id and is tagged (you) for " +
        "messages this agent sent. To reply to a main-chat message, call " +
        "send_message with thread_id=<its id>. Messages marked " +
        "'in thread <rootId>' are replies — to continue that conversation, " +
        "use thread_id=<rootId>, not the reply's own id. Any id also works " +
        "as react_to_message's message_id. Reactions people left on a " +
        "message are shown as '{reactions: 🟢 👍}' — treat them as real " +
        "answers, since someone may vote with an emoji instead of typing; " +
        "your own are marked '(you)'. Attachments (images, voice " +
        "messages, files) show as [attachment <n>: …] tags — download and " +
        "decrypt them with read_media.",
      inputSchema: {
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe("How many recent messages to return. Default 20."),
      },
    },
    async ({ oase_id, limit }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        const { messages } = await client.readRecentMessages(
          target,
          limit ?? 20,
        );
        if (messages.length === 0) return textResult("No messages yet.");
        const lines = messages.map((m) => chatLine(m));
        return textResult(lines.join("\n") + mediaHint(messages));
      } catch (e) {
        return textResult(`read_messages failed: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "read_media",
    {
      title: "Read a message attachment (image/audio/file)",
      description:
        "Download and decrypt an attachment from a chat message — images, " +
        "voice messages (sound bites), videos, documents. Messages list " +
        'attachments as [attachment <n>: <type> "name"]; pass the message ' +
        "id and that index. Images are returned inline so you can view and " +
        "analyze them directly. Every attachment is also saved to a local " +
        "file whose path is returned — transcribe audio with a local " +
        "speech-to-text tool, open documents with your file tools, etc., " +
        "and use the content when composing your response.",
      inputSchema: {
        message_id: z
          .string()
          .describe("Id of the message carrying the attachment."),
        media_index: z
          .number()
          .int()
          .min(0)
          .optional()
          .describe(
            "Which attachment — the <n> in [attachment <n>: …]. Default 0.",
          ),
        oase_id: z
          .string()
          .optional()
          .describe("Target oase id. Defaults to the last joined oase."),
      },
    },
    async ({ message_id, media_index, oase_id }) => {
      const index = media_index ?? 0;
      try {
        const target = client.resolveTargetOase(oase_id);
        const media = await client.fetchMedia(target, message_id, index);
        const savedPath = await saveMediaFile(message_id, index, media);
        const lines = [
          `Attachment ${index} of message ${message_id}: ` +
            `${media.name ?? "(unnamed)"} — ${media.mime ?? "unknown type"}, ` +
            `${Math.max(1, Math.round(media.data.length / 1024))} KB` +
            `${media.encrypted ? ", decrypted" : ""}.`,
          `Saved to: ${savedPath}`,
        ];
        const content: Array<
          | { type: "text"; text: string }
          | { type: "image"; data: string; mimeType: string }
        > = [];
        if (media.mime && INLINE_IMAGE_MIMES.has(media.mime)) {
          if (media.data.length <= INLINE_IMAGE_LIMIT) {
            content.push({
              type: "image",
              data: media.data.toString("base64"),
              mimeType: media.mime,
            });
          } else {
            lines.push(
              "The image is too large to return inline — open the saved " +
                "file instead (e.g. with your Read tool, which resizes).",
            );
          }
        } else if (media.mime?.startsWith("audio/")) {
          lines.push(
            "This is an audio clip (voice message). To analyze it, " +
              "transcribe the saved file with a local speech-to-text tool " +
              "(e.g. `hear -i <path>` on macOS, or `whisper <path>`), then " +
              "use the transcript.",
          );
        } else if (media.mime?.startsWith("video/")) {
          lines.push(
            "This is a video. If you need its content, extract frames or " +
              "audio from the saved file with ffmpeg.",
          );
        }
        content.unshift({ type: "text", text: lines.join("\n") });
        return { content };
      } catch (e) {
        return textResult(`read_media failed: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "list_oases",
    {
      title: "List joined Oases",
      description:
        "Show this agent's Oase identity and the oases it has joined.",
      inputSchema: {},
    },
    async () => {
      try {
        const id = client.identity;
        if (!id.loggedIn) {
          return textResult(
            "Not logged in. Run promise_login_start, open the URL, then promise_login_finish.",
          );
        }
        const oases = client.listOases();
        const lines = [
          `Identity: ${id.displayName} (${id.personId ?? "unknown"})`,
          oases.length
            ? `Joined oases:`
            : `No oases joined yet — use join_oase with an invite link.`,
          ...oases.map(
            (o) =>
              `  • ${o.name ? `"${o.name}" ` : ""}${o.id}` +
              (o.id === client.defaultOaseId ? "  (default)" : ""),
          ),
        ];
        return textResult(lines.join("\n"));
      } catch (e) {
        return textResult(`Failed: ${errText(e)}`, true);
      }
    },
  );

  server.registerTool(
    "set_name",
    {
      title: "Set display name in an Oase",
      description:
        "Change the display name this agent shows under in an oase. " +
        "Omit oase_id to use the default oase. Also updates the default name for future joins.",
      inputSchema: {
        display_name: z.string().describe("New display name."),
        oase_id: z.string().optional().describe("Target oase id."),
      },
    },
    async ({ display_name, oase_id }) => {
      try {
        const target = client.resolveTargetOase(oase_id);
        await client.setDisplayName(target, display_name);
        config.displayName = display_name;
        await saveConfig(config);
        return textResult(`Display name set to "${display_name}" in oase ${target}.`);
      } catch (e) {
        return textResult(`Failed: ${errText(e)}`, true);
      }
    },
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[oase-mcp] server ready");
}
