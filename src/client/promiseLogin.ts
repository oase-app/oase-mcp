import http from "node:http";
import { AddressInfo } from "node:net";

const PROMISE_AUTHORIZE = "https://promiseauthentication.org/a/oase.app";

/**
 * Hosts a localhost OIDC callback so a Promise `id_token` can be captured
 * without the user copy-pasting a JWT. Promise redirects the browser back to
 * `http://localhost:<port>/authenticate#id_token=...`; the served page reads the
 * fragment (which never reaches a server on its own) and POSTs the token here.
 *
 * The MCP server is one long-lived process, so we keep the running server and
 * the captured token in memory between the `start` and `finish` tool calls.
 */
export class PromiseLogin {
  private server: http.Server | null = null;
  private port = 0;
  private token: string | null = null;
  private waiters: Array<(t: string) => void> = [];

  get isRunning(): boolean {
    return this.server !== null;
  }

  get loginUrl(): string {
    const redirect = `http://localhost:${this.port}/authenticate`;
    return `${PROMISE_AUTHORIZE}?redirect_uri=${encodeURIComponent(redirect)}&prompt=login`;
  }

  /** Start the callback server (idempotent). Returns the login URL to open. */
  async start(preferredPort = 8765): Promise<string> {
    if (this.server) return this.loginUrl;
    this.token = null;

    const page = this.extractorPage();
    const server = http.createServer((req, res) => {
      const url = new URL(req.url || "/", "http://localhost");
      if (url.pathname === "/capture") {
        const tok = url.searchParams.get("id_token") || "";
        if (tok) this.deliver(tok);
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("ok");
        return;
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(page);
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      // Bind the preferred port so the redirect URL is stable; fall back to an
      // ephemeral port if it's taken.
      server.listen(preferredPort, "127.0.0.1", () => {
        server.removeListener("error", reject);
        resolve();
      });
    }).catch(async (err: NodeJS.ErrnoException) => {
      if (err.code !== "EADDRINUSE") throw err;
      await new Promise<void>((resolve) =>
        server.listen(0, "127.0.0.1", () => resolve()),
      );
    });

    this.server = server;
    this.port = (server.address() as AddressInfo).port;
    return this.loginUrl;
  }

  /** Resolve once a token arrives, or reject on timeout. */
  waitForToken(timeoutMs = 240_000): Promise<string> {
    if (this.token) return Promise.resolve(this.token);
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== onToken);
        reject(
          new Error(
            "Timed out waiting for the Promise login. Open the login URL and " +
              "complete sign-in, then try again.",
          ),
        );
      }, timeoutMs);
      const onToken = (t: string) => {
        clearTimeout(timer);
        resolve(t);
      };
      this.waiters.push(onToken);
    });
  }

  stop(): void {
    this.server?.close();
    this.server = null;
    this.token = null;
    this.waiters = [];
  }

  private deliver(token: string): void {
    this.token = token;
    const waiters = this.waiters;
    this.waiters = [];
    for (const w of waiters) w(token);
  }

  private extractorPage(): string {
    return `<!doctype html><html><head><meta charset="utf-8"><title>Oase MCP login</title>
<style>body{font-family:system-ui;padding:2rem;max-width:40rem;margin:auto;line-height:1.5}</style></head>
<body><h2>Oase MCP — Promise login</h2><p id="s">Capturing token…</p>
<script>
(function(){
  function grab(str){ if(!str) return null; str=str.replace(/^[#?]/,'');
    for(const kv of str.split('&')){ const p=kv.split('='); if(p[0]==='id_token') return decodeURIComponent(p[1]||''); } return null; }
  var tok = grab(location.hash) || grab(location.search);
  var s = document.getElementById('s');
  if(!tok){ s.textContent='No id_token found in the redirect. URL was: '+location.href; return; }
  fetch('/capture?id_token='+encodeURIComponent(tok),{method:'POST'})
    .then(function(){ s.innerHTML='\\u2705 Token captured. You can close this tab and return to Claude.'; })
    .catch(function(e){ s.textContent='Capture failed: '+e; });
})();
</script></body></html>`;
  }
}
