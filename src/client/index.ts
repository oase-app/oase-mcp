/**
 * The passive Oase REST client layer: everything needed to talk to the Oase
 * backend over HTTP the way the app does — Promise login/auth, joining via
 * invite link, KMS key fetching, AES-256-GCM encryption/decryption, and
 * sending/reading (decrypted) messages and feed posts.
 *
 * Request/response only, no agent behavior, and no MCP dependency. It is safe
 * to import from other consumers — the MCP server in ../mcp builds on it, and
 * so can your own integration — via the package root or `oase-mcp/client`.
 */
export {
  OaseClient,
  OaseError,
  type ChatMessage,
  type CipherBundle,
  type FetchedMedia,
  type MediaAttachment,
  type MessageReaction,
  type OasePost,
} from "./oaseClient.js";
export { PromiseLogin } from "./promiseLogin.js";
export {
  configDir,
  loadConfig,
  saveConfig,
  withAuthLock,
  type JoinedOase,
  type OaseConfig,
} from "./config.js";
