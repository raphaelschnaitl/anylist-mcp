/**
 * OAuth / login flow tests for the HTTP server. Runs the real routers against a
 * temporary SQLite DB; no network, no AnyList credentials.
 */
import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { createHash, randomBytes } from "crypto";
import { fileURLToPath } from "url";

const tmp = mkdtempSync(path.join(tmpdir(), "anylist-oauth-test-"));
const allowedFile = path.join(tmp, "allowed-emails.txt");
writeFileSync(allowedFile, "alice@example.com\nbob@example.com\n");
process.env.DATA_DIR = tmp;
process.env.ALLOWED_EMAILS_FILE = allowedFile;
process.env.SERVER_SECRET_KEY = randomBytes(32).toString("hex");

const express = (await import("express")).default;
const session = (await import("express-session")).default;
const db = await import("../src/http/db.js");
const { default: oauthRouter } = await import("../src/http/auth/oauth.js");
const { default: onboardingRouter } = await import("../src/http/onboarding.js");
const { registerWithPassword } = await import("../src/http/auth/providers/password.js");
const { renderTemplate, escapeHtml } = await import("../src/http/template.js");

const viewsDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "http", "views");
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";

let server;
let base;
let host;

before(async () => {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(session({ secret: "test", resave: false, saveUninitialized: false }));
  app.set("views", viewsDir);
  app.set("view engine", "html");
  app.engine("html", renderTemplate);
  app.use(oauthRouter);
  app.use(onboardingRouter);
  await new Promise(resolve => { server = app.listen(0, "127.0.0.1", resolve); });
  host = `127.0.0.1:${server.address().port}`;
  base = `http://${host}`;

  for (const email of ["alice@example.com", "bob@example.com"]) {
    const user = await registerWithPassword(email, "correct horse");
    db.upsertAnyListCredentials(user.id, { username: email, password: "x", defaultListName: null });
  }
});

after(() => {
  server.close();
  rmSync(tmp, { recursive: true, force: true });
});

beforeEach(() => {
  writeFileSync(allowedFile, "alice@example.com\nbob@example.com\n");
  db.loadAllowedEmails();
});

// ── Helpers ──────────────────────────────────────────────────────────────────

/** fetch with a cookie jar and manual redirects. */
function browser() {
  let cookie = "";
  async function request(urlPath, { method = "GET", form, headers = {} } = {}) {
    const res = await fetch(base + urlPath, {
      method,
      redirect: "manual",
      headers: {
        ...(cookie ? { cookie } : {}),
        ...(form ? { "content-type": "application/x-www-form-urlencoded" } : {}),
        ...headers,
      },
      body: form ? new URLSearchParams(form).toString() : undefined,
    });
    const setCookie = res.headers.get("set-cookie");
    if (setCookie) cookie = setCookie.split(";")[0];
    return res;
  }
  return { request, cookie: () => cookie };
}

async function registerClient(body = { redirect_uris: [REDIRECT], client_name: "Claude" }) {
  const res = await fetch(`${base}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function authorizeUrl(params) {
  return "/oauth/authorize?" + new URLSearchParams({ state: "st", ...params }).toString();
}

async function token(body) {
  const res = await fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

/** Full browser flow up to the redirect back to the client; returns the code. */
async function getCode({ clientId, challenge, email = "alice@example.com", redirectUri = REDIRECT }) {
  const b = browser();
  const params = { client_id: clientId, redirect_uri: redirectUri };
  if (challenge) Object.assign(params, { code_challenge: challenge, code_challenge_method: "S256" });
  let res = await b.request(authorizeUrl(params));
  assert.equal(res.headers.get("location"), "/login");
  res = await b.request("/auth/login", { method: "POST", form: { email, password: "correct horse" } });
  assert.equal(res.headers.get("location"), "/oauth/consent");
  res = await b.request("/oauth/consent");
  const html = await res.text();
  const requestId = html.match(/name="request_id" value="([0-9a-f]+)"/)[1];
  res = await b.request("/oauth/consent", { method: "POST", form: { approve: "yes", request_id: requestId } });
  const location = new URL(res.headers.get("location"));
  assert.equal(location.origin + location.pathname, redirectUri);
  return location.searchParams.get("code");
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("dynamic client registration", () => {
  it("rejects a non-http redirect_uri", async () => {
    const { status } = await registerClient({ redirect_uris: ["javascript:alert(1)"] });
    assert.equal(status, 400);
  });

  it("rejects a registration without redirect_uri", async () => {
    const { status } = await registerClient({ client_name: "x" });
    assert.equal(status, 400);
  });
});

describe("authorization endpoint", () => {
  it("rejects an unknown client_id", async () => {
    const res = await browser().request(authorizeUrl({ client_id: "nope", redirect_uri: REDIRECT, code_challenge: "c" }));
    assert.equal(res.status, 400);
  });

  it("rejects a redirect_uri other than the registered one", async () => {
    const { body } = await registerClient();
    const res = await browser().request(authorizeUrl({
      client_id: body.client_id, redirect_uri: "https://evil.example/cb", code_challenge: "c",
    }));
    assert.equal(res.status, 400);
  });

  it("rejects the plain PKCE method", async () => {
    const { body } = await registerClient();
    const res = await browser().request(authorizeUrl({
      client_id: body.client_id, redirect_uri: REDIRECT, code_challenge: "c", code_challenge_method: "plain",
    }));
    assert.equal(res.status, 400);
  });

  it("asks for consent even when the user signs in during the flow", async () => {
    const { body } = await registerClient();
    const b = browser();
    await b.request(authorizeUrl({ client_id: body.client_id, redirect_uri: REDIRECT, code_challenge: pkce().challenge }));
    const res = await b.request("/auth/login", { method: "POST", form: { email: "alice@example.com", password: "correct horse" } });
    assert.equal(res.headers.get("location"), "/oauth/consent");
  });

  it("escapes the client name and shows the redirect host on the consent page", async () => {
    const { body } = await registerClient({ redirect_uris: [REDIRECT], client_name: "<script>alert(1)</script>" });
    const b = browser();
    await b.request(authorizeUrl({ client_id: body.client_id, redirect_uri: REDIRECT, code_challenge: pkce().challenge }));
    await b.request("/auth/login", { method: "POST", form: { email: "alice@example.com", password: "correct horse" } });
    const html = await (await b.request("/oauth/consent")).text();
    assert.ok(!html.includes("<script>alert(1)</script>"));
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert.ok(html.includes("claude.ai"));
  });

  it("rejects a consent post for a request it was not shown for", async () => {
    const { body } = await registerClient();
    const b = browser();
    await b.request(authorizeUrl({ client_id: body.client_id, redirect_uri: REDIRECT, code_challenge: pkce().challenge }));
    await b.request("/auth/login", { method: "POST", form: { email: "alice@example.com", password: "correct horse" } });
    const res = await b.request("/oauth/consent", { method: "POST", form: { approve: "yes", request_id: "stale" } });
    assert.equal(res.status, 400);
  });
});

describe("login", () => {
  it("issues a new session ID on login", async () => {
    const { body } = await registerClient();
    const b = browser();
    await b.request(authorizeUrl({ client_id: body.client_id, redirect_uri: REDIRECT, code_challenge: pkce().challenge }));
    const before = b.cookie();
    assert.ok(before);
    await b.request("/auth/login", { method: "POST", form: { email: "alice@example.com", password: "correct horse" } });
    assert.notEqual(b.cookie(), before);
  });

  it("rejects cross-origin form posts", async () => {
    const res = await browser().request("/auth/login", {
      method: "POST",
      form: { email: "alice@example.com", password: "correct horse" },
      headers: { origin: "https://evil.example" },
    });
    assert.equal(res.status, 403);
  });

  it("accepts same-origin form posts", async () => {
    const res = await browser().request("/auth/login", {
      method: "POST",
      form: { email: "alice@example.com", password: "correct horse" },
      headers: { origin: base },
    });
    assert.equal(res.status, 302);
  });

  it("rejects cross-origin posts to /setup", async () => {
    const res = await browser().request("/setup", {
      method: "POST", form: { anylist_username: "a", anylist_password: "b" }, headers: { origin: "https://evil.example" },
    });
    assert.equal(res.status, 403);
  });

  it("refuses users removed from the allowlist", async () => {
    writeFileSync(allowedFile, "bob@example.com\n");
    db.loadAllowedEmails();
    const res = await browser().request("/auth/login", { method: "POST", form: { email: "alice@example.com", password: "correct horse" } });
    assert.equal(res.status, 200); // login page with an error, no redirect
    assert.match(await res.text(), /no longer authorized/);
  });
});

describe("token endpoint", () => {
  it("exchanges a code with the right client, redirect_uri and verifier", async () => {
    const { body } = await registerClient();
    const { verifier, challenge } = pkce();
    const code = await getCode({ clientId: body.client_id, challenge });
    const res = await token({ grant_type: "authorization_code", code, client_id: body.client_id, redirect_uri: REDIRECT, code_verifier: verifier });
    assert.equal(res.status, 200);
    assert.ok(res.body.access_token);
  });

  it("rejects a code redeemed by another client", async () => {
    const { body } = await registerClient();
    const { body: other } = await registerClient();
    const { verifier, challenge } = pkce();
    const code = await getCode({ clientId: body.client_id, challenge });
    const res = await token({ grant_type: "authorization_code", code, client_id: other.client_id, redirect_uri: REDIRECT, code_verifier: verifier });
    assert.equal(res.body.error, "invalid_grant");
  });

  it("rejects a code redeemed with a different redirect_uri", async () => {
    const { body } = await registerClient();
    const { verifier, challenge } = pkce();
    const code = await getCode({ clientId: body.client_id, challenge });
    const res = await token({ grant_type: "authorization_code", code, client_id: body.client_id, redirect_uri: "https://evil.example/cb", code_verifier: verifier });
    assert.equal(res.body.error, "invalid_grant");
  });

  it("rejects a code without its PKCE verifier", async () => {
    const { body } = await registerClient();
    const code = await getCode({ clientId: body.client_id, challenge: pkce().challenge });
    const res = await token({ grant_type: "authorization_code", code, client_id: body.client_id, redirect_uri: REDIRECT });
    assert.equal(res.status, 400);
    assert.ok(!res.body.access_token);
  });

  it("requires the client secret for codes issued to a confidential client", async () => {
    const bcrypt = (await import("bcrypt")).default;
    const alice = db.getUserByEmail("alice@example.com");
    const clientId = "conf-" + randomBytes(4).toString("hex");
    db.createConfidentialClient({ clientId, clientSecretHash: await bcrypt.hash("s3cret", 4), userId: alice.id, clientName: "HA" });
    const redirectUri = "https://my.home-assistant.io/redirect/oauth";

    const code = await getCode({ clientId, redirectUri });
    let res = await token({ grant_type: "authorization_code", code, client_id: clientId, redirect_uri: redirectUri });
    assert.equal(res.status, 401);

    const code2 = await getCode({ clientId, redirectUri });
    res = await token({ grant_type: "authorization_code", code: code2, client_id: clientId, client_secret: "s3cret", redirect_uri: redirectUri });
    assert.equal(res.status, 200);
  });

  it("binds refresh tokens to their client and to the allowlist", async () => {
    const { body } = await registerClient();
    const { body: other } = await registerClient();
    const { verifier, challenge } = pkce();
    const code = await getCode({ clientId: body.client_id, challenge });
    const { body: tokens } = await token({ grant_type: "authorization_code", code, client_id: body.client_id, redirect_uri: REDIRECT, code_verifier: verifier });

    let res = await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: other.client_id });
    assert.equal(res.body.error, "invalid_grant");

    res = await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: body.client_id });
    assert.equal(res.status, 200);

    writeFileSync(allowedFile, "bob@example.com\n");
    db.loadAllowedEmails();
    res = await token({ grant_type: "refresh_token", refresh_token: res.body.refresh_token, client_id: body.client_id });
    assert.equal(res.body.error, "invalid_grant");
  });
});

describe("template rendering", () => {
  it("HTML-escapes substituted values", () => {
    assert.equal(escapeHtml(`<a href="x">'&'</a>`), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
  });
});
