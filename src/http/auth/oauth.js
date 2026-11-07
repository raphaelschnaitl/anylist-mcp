import { Router } from "express";
import { createHash, randomBytes, randomUUID } from "crypto";
import bcrypt from "bcrypt";
import {
  getOAuthClient,
  registerOAuthClient,
  getOAuthClientWithSecret,
  saveOAuthCode,
  consumeOAuthCode,
  saveOAuthTokens,
  getTokenRecord,
  getTokenByRefresh,
  deleteTokensByRefresh,
  getAnyListCredentials,
  isUserAllowed,
} from "../db.js";
import { loginWithPassword, registerWithPassword } from "./providers/password.js";
import { loginWithGoogle, isGoogleEnabled } from "./providers/google.js";
import { isOidcEnabled, startOidcLogin, finishOidcLogin } from "./providers/oidc.js";

export function renderLogin(res, error = "") {
  const oidcEnabled = isOidcEnabled();
  res.render("login", {
    error,
    oidcEnabled,
    passwordEnabled: !oidcEnabled,
    googleEnabled: !oidcEnabled && isGoogleEnabled(),
    googleClientId: process.env.GOOGLE_CLIENT_ID || "",
  });
}

/** With single sign-on configured, the local password / Google sign-in routes are off. */
function requireLocalLogin(req, res, next) {
  if (isOidcEnabled()) return res.status(404).send("Not found");
  next();
}

const router = Router();

// BASE_URL is optional: if not set, derive from the incoming request so the
// server works behind any proxy (including a Cloudflare quick tunnel) without
// needing to know its public URL at startup.
function baseUrl(req) {
  if (process.env.BASE_URL) return process.env.BASE_URL;
  if (req) return `${req.protocol}://${req.get("host")}${req.baseUrl || ""}`;
  return "http://localhost:3000";
}

function isHttpUrl(value) {
  try {
    const { protocol } = new URL(value);
    return protocol === "https:" || protocol === "http:";
  } catch {
    return false;
  }
}

/**
 * Rejects browser form posts sent from another origin (login CSRF and friends).
 * Browsers always send Origin on cross-origin POSTs; requests without one are not
 * from a cross-site page.
 */
export function requireSameOrigin(req, res, next) {
  const origin = req.get("origin");
  if (origin !== undefined) {
    let host = null;
    try { host = new URL(origin).host; } catch { /* "null" or malformed */ }
    if (host !== req.get("host")) {
      console.log(`[auth] ANOMALOUS cross-origin form post: path=${req.path} origin=${origin} ip=${req.ip}`);
      return res.status(403).send("Cross-origin request rejected.");
    }
  }
  next();
}

// ── OAuth AS Metadata (RFC 8414) ──────────────────────────────────────────────

router.get("/.well-known/oauth-authorization-server", (req, res) => {
  const base = baseUrl(req);
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
  });
});

// MCP protected resource metadata (RFC 9728)
// Handle both /.well-known/oauth-protected-resource and /.well-known/oauth-protected-resource/<path>
// so that HA (which appends the resource path per RFC 9728) gets the right resource URL.
router.get(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/*path"], (req, res) => {
  const base = baseUrl(req);
  const suffix = req.params.path ? `/${req.params.path}` : "";
  res.json({
    resource: `${base}${suffix}`,
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"],
  });
});

// ── Dynamic Client Registration (RFC 7591) ────────────────────────────────────
// Home ASsistent expects /register, but Claude expects /oauth/register, so we support both.
router.post(["/oauth/register", "/register"], (req, res) => {
  const { redirect_uris, client_name } = req.body || {};
  const clientId = randomUUID();
  const redirectUri = Array.isArray(redirect_uris) ? redirect_uris[0] : redirect_uris || null;
  if (!isHttpUrl(redirectUri)) {
    return res.status(400).json({ error: "invalid_redirect_uri", error_description: "An http(s) redirect_uri is required" });
  }
  registerOAuthClient({ clientId, redirectUri, clientName: client_name });
  res.status(201).json({
    client_id: clientId,
    client_secret: null,
    redirect_uris: redirectUri ? [redirectUri] : [],
    client_name: client_name || "MCP Client",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
});

// ── Authorization Endpoint ────────────────────────────────────────────────────
// Home ASsistent expects /authorize, but Claude expects /oauth/authorize, so we support both.

router.get(["/oauth/authorize", "/authorize"], (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, scope } = req.query;

  if (!client_id) {
    return res.status(400).send("Missing required parameter: client_id");
  }

  const clientRecord = getOAuthClientWithSecret(client_id);
  if (!clientRecord) {
    return res.status(400).send("Unknown client_id");
  }
  if (!isHttpUrl(redirect_uri)) {
    return res.status(400).send("Missing or invalid parameter: redirect_uri");
  }
  // Public clients must use the redirect URI they registered. Confidential clients
  // (scripts/create-client.js) have none on record, but their codes are useless
  // without the client secret.
  const isConfidential = !!clientRecord.client_secret_hash;
  if (clientRecord.redirect_uri ? redirect_uri !== clientRecord.redirect_uri : !isConfidential) {
    return res.status(400).send("redirect_uri does not match the registered redirect URI");
  }

  // Confidential clients (those with a client_secret) don't use PKCE
  if (!isConfidential && !code_challenge) {
    return res.status(400).send("Missing required parameter: code_challenge");
  }
  if (code_challenge && (code_challenge_method || "S256") !== "S256") {
    return res.status(400).send("Unsupported code_challenge_method (only S256 is supported)");
  }

  // Store OAuth params in session. requestId ties the consent form to this request.
  req.session.oauthParams = {
    client_id, redirect_uri, state, code_challenge, code_challenge_method: "S256", scope,
    requestId: randomBytes(16).toString("hex"),
  };

  // If the user already has an active session, skip the login step
  if (req.session.userId) {
    const hasCreds = !!getAnyListCredentials(req.session.userId);
    return res.redirect(hasCreds ? "/oauth/consent" : "/setup");
  }

  res.redirect("/login");
});

// ── Token Endpoint ────────────────────────────────────────────────────────────

router.post(["/oauth/token", "/token"], async (req, res) => {
  const body = req.body || {};
  const { grant_type, client_id } = body;
  const bodyKeys = Object.keys(body);
  console.log(`[oauth] token request grant_type=${grant_type} client_id=${client_id ? client_id.slice(0, 8) + "…" : "none"} fields=${bodyKeys.join(",")}`);

  if (grant_type === "authorization_code") {
    return handleAuthCodeGrant(req, res);
  }
  if (grant_type === "refresh_token") {
    return handleRefreshGrant(req, res);
  }
  if (grant_type === "client_credentials") {
    return handleClientCredentialsGrant(req, res);
  }
  console.log(`[oauth] ANOMALOUS token request: unknown grant_type=${grant_type} ip=${req.ip} fields=${bodyKeys.join(",")}`);
  return res.status(400).json({ error: "unsupported_grant_type" });
});

async function handleAuthCodeGrant(req, res) {
  const { code, redirect_uri, code_verifier, client_id, client_secret } = req.body;

  if (!code) {
    return res.status(400).json({ error: "invalid_request", error_description: "Missing code" });
  }

  const codeRow = consumeOAuthCode(code);
  if (!codeRow) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Code invalid or expired" });
  }

  // The code is bound to the client and redirect URI it was issued for.
  if ((client_id && client_id !== codeRow.client_id) || redirect_uri !== codeRow.redirect_uri) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Code was issued to another client or redirect_uri" });
  }

  if (codeRow.code_challenge) {
    if (!code_verifier) {
      return res.status(400).json({ error: "invalid_request", error_description: "Missing code_verifier" });
    }
    const verifierHash = createHash("sha256").update(code_verifier).digest("base64url");
    if (verifierHash !== codeRow.code_challenge) {
      return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
    }
  }

  // Confidential clients must authenticate, whether or not they also used PKCE.
  if (!(await authenticateConfidentialClient(codeRow.client_id, client_secret))) {
    return res.status(401).json({ error: "invalid_client" });
  }

  if (!isUserAllowed(codeRow.user_id)) {
    return res.status(400).json({ error: "invalid_grant", error_description: "User is no longer authorized" });
  }

  const accessToken = randomBytes(32).toString("hex");
  const refreshToken = randomBytes(32).toString("hex");
  saveOAuthTokens({
    accessToken,
    refreshToken,
    userId: codeRow.user_id,
    clientId: codeRow.client_id,
    scope: codeRow.scope,
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: codeRow.scope || "mcp",
  });
}

async function handleRefreshGrant(req, res) {
  const { refresh_token, client_id, client_secret } = req.body;
  if (!refresh_token) {
    return res.status(400).json({ error: "invalid_request" });
  }
  const tokenRow = getTokenByRefresh(refresh_token);
  if (!tokenRow || tokenRow.refresh_expires_at < Math.floor(Date.now() / 1000)) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Refresh token invalid or expired" });
  }
  if (client_id && client_id !== tokenRow.client_id) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Refresh token was issued to another client" });
  }
  if (!(await authenticateConfidentialClient(tokenRow.client_id, client_secret))) {
    return res.status(401).json({ error: "invalid_client" });
  }
  if (!isUserAllowed(tokenRow.user_id)) {
    deleteTokensByRefresh(refresh_token);
    return res.status(400).json({ error: "invalid_grant", error_description: "User is no longer authorized" });
  }

  deleteTokensByRefresh(refresh_token);

  const accessToken = randomBytes(32).toString("hex");
  const newRefreshToken = randomBytes(32).toString("hex");
  saveOAuthTokens({
    accessToken,
    refreshToken: newRefreshToken,
    userId: tokenRow.user_id,
    clientId: tokenRow.client_id,
    scope: tokenRow.scope,
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    refresh_token: newRefreshToken,
    scope: tokenRow.scope || "mcp",
  });
}

async function handleClientCredentialsGrant(req, res) {
  const { client_id, client_secret } = req.body;

  if (!client_id || !client_secret) {
    console.log(`[oauth] client_credentials missing fields: client_id=${!!client_id} client_secret=${!!client_secret}`);
    return res.status(400).json({ error: "invalid_request", error_description: "Missing client_id or client_secret" });
  }

  const client = getOAuthClientWithSecret(client_id);
  if (!client || !client.client_secret_hash) {
    console.log(`[oauth] client_credentials client not found or not confidential: client_id=${client_id.slice(0, 8)}…`);
    return res.status(401).json({ error: "invalid_client" });
  }

  const valid = await bcrypt.compare(client_secret, client.client_secret_hash);
  if (!valid) {
    console.log(`[oauth] client_credentials secret mismatch: client_id=${client_id.slice(0, 8)}…`);
    return res.status(401).json({ error: "invalid_client" });
  }
  if (!isUserAllowed(client.user_id)) {
    return res.status(400).json({ error: "invalid_grant", error_description: "User is no longer authorized" });
  }

  const accessToken = randomBytes(32).toString("hex");
  const refreshToken = randomBytes(32).toString("hex");
  saveOAuthTokens({
    accessToken,
    refreshToken,
    userId: client.user_id,
    clientId: client_id,
    scope: "mcp",
  });

  console.log(`[oauth] client_credentials token issued for client_id=${client_id.slice(0, 8)}… user_id=${client.user_id}`);
  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "mcp",
  });
}

/**
 * Returns false if clientId belongs to a confidential client and clientSecret does
 * not match it. Public clients pass (they are bound by PKCE / the refresh token).
 */
async function authenticateConfidentialClient(clientId, clientSecret) {
  const client = getOAuthClientWithSecret(clientId);
  if (!client || !client.client_secret_hash) return true;
  return !!clientSecret && bcrypt.compare(clientSecret, client.client_secret_hash);
}

// ── Login / Registration form handlers ───────────────────────────────────────

router.post("/auth/login", requireLocalLogin, requireSameOrigin, async (req, res) => {
  const { email, password } = req.body || {};
  console.log(`[auth] login attempt: ${email}`);
  if (!email || !password) {
    return renderLogin(res, "Email and password are required.");
  }
  try {
    const user = await loginWithPassword(email, password);
    console.log(`[auth] login success: ${email} (${user.id})`);
    return completeAuth(req, res, user);
  } catch (err) {
    console.log(`[auth] login failed: ${email} — ${err.message}`);
    return renderLogin(res, err.message);
  }
});

router.post("/auth/register", requireLocalLogin, requireSameOrigin, async (req, res) => {
  const { email, password } = req.body || {};
  console.log(`[auth] register attempt: ${email}`);
  if (!email || !password) {
    return renderLogin(res, "Email and password are required.");
  }
  try {
    const user = await registerWithPassword(email, password);
    console.log(`[auth] register success: ${email} (${user.id})`);
    return completeAuth(req, res, user);
  } catch (err) {
    console.log(`[auth] register failed: ${email} — ${err.message}`);
    return renderLogin(res, err.message);
  }
});

router.post("/auth/google", requireLocalLogin, requireSameOrigin, async (req, res) => {
  const { credential } = req.body || {};
  try {
    const user = await loginWithGoogle(credential);
    return completeAuth(req, res, user);
  } catch (err) {
    console.log(`[auth] google failed — ${err.message}`);
    return renderLogin(res, err.message);
  }
});

// ── Single sign-on (OIDC) ────────────────────────────────────────────────────

router.get("/auth/oidc/login", async (req, res) => {
  if (!isOidcEnabled()) return res.status(404).send("Not found");
  try {
    res.redirect(await startOidcLogin(req.session));
  } catch (err) {
    console.error("[auth] oidc start failed:", err);
    res.status(502).send("Sign-in is unavailable right now.");
  }
});

router.get("/auth/oidc/callback", async (req, res) => {
  if (!isOidcEnabled()) return res.status(404).send("Not found");
  try {
    const user = await finishOidcLogin(req.session, new URL(req.originalUrl, process.env.BASE_URL));
    console.log(`[auth] oidc login success: ${user.email} (${user.id})`);
    return completeAuth(req, res, user);
  } catch (err) {
    console.log(`[auth] oidc login failed — ${err.message}`);
    res.status(403);
    return renderLogin(res, err.message);
  }
});

/**
 * After successful authentication, check if the user has AnyList credentials.
 * If yes: ask for consent before issuing an OAuth code.
 * If no: redirect to /setup to collect them first.
 */
function completeAuth(req, res, user) {
  const oauth = req.session.oauthParams;
  // Fresh session ID on login, so a session cookie planted before login is worthless.
  req.session.regenerate((err) => {
    if (err) {
      console.error("[auth] session regenerate failed:", err);
      return res.status(500).send("Internal server error");
    }
    req.session.userId = user.id;
    if (oauth) req.session.oauthParams = oauth;
    const hasCreds = !!getAnyListCredentials(user.id);
    console.log(`[auth] completeAuth user:${user.id} oauthPending:${!!oauth} hasCreds:${hasCreds}`);

    if (!oauth || !hasCreds) {
      return res.redirect("/setup");
    }
    return res.redirect("/oauth/consent");
  });
}

/**
 * OAuth consent page — shown after AnyList setup if an OAuth flow is pending.
 */
router.get("/oauth/consent", (req, res) => {
  if (!req.session.userId || !req.session.oauthParams) {
    return res.redirect("/login");
  }
  const oauth = req.session.oauthParams;
  const client = getOAuthClient(oauth.client_id);
  res.render("consent", {
    clientId: oauth.client_id,
    clientName: client?.client_name || "An MCP client",
    redirectHost: new URL(oauth.redirect_uri).host,
    requestId: oauth.requestId,
    scope: oauth.scope || "mcp",
  });
});

router.post("/oauth/consent", requireSameOrigin, (req, res) => {
  const { approve, request_id } = req.body || {};
  const oauth = req.session.oauthParams;
  const userId = req.session.userId;

  if (!userId || !oauth) return res.redirect("/login");

  // Another /authorize request may have replaced the one this form was shown for.
  if (request_id !== oauth.requestId) {
    return res.status(400).send("This authorization request has changed or expired. Start again from your client.");
  }

  if (approve !== "yes") {
    delete req.session.oauthParams;
    const redirectUri = oauth.redirect_uri;
    const state = oauth.state;
    const url = new URL(redirectUri);
    url.searchParams.set("error", "access_denied");
    if (state) url.searchParams.set("state", state);
    return res.redirect(url.toString());
  }

  return issueCodeAndRedirect(req, res, userId, oauth);
});

function issueCodeAndRedirect(req, res, userId, oauth) {
  const code = randomBytes(16).toString("hex");
  saveOAuthCode({
    code,
    clientId: oauth.client_id,
    userId,
    redirectUri: oauth.redirect_uri,
    codeChallenge: oauth.code_challenge,
    challengeMethod: oauth.code_challenge_method || "S256",
    scope: oauth.scope,
  });
  delete req.session.oauthParams;

  const url = new URL(oauth.redirect_uri);
  url.searchParams.set("code", code);
  if (oauth.state) url.searchParams.set("state", oauth.state);
  res.redirect(url.toString());
}

// ── Bearer token validation middleware ────────────────────────────────────────

/**
 * Express middleware that validates Bearer tokens on the /mcp endpoint.
 * Sets req.userId on success; sends 401 on failure.
 */
export function requireBearerToken(req, res, next) {
  const auth = req.headers["authorization"] || "";
  if (!auth.startsWith("Bearer ")) {
    console.log(`[oauth] ANOMALOUS bearer missing/wrong auth header: method=${req.method} path=${req.path} auth=${auth ? auth.slice(0, 20) + "…" : "none"} ip=${req.ip}`);
    res.setHeader("WWW-Authenticate", `Bearer realm="${baseUrl(req)}", resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource"`);
    return res.status(401).json({ error: "unauthorized" });
  }
  const token = auth.slice(7);
  const record = getTokenRecord(token);
  if (!record) {
    console.log(`[oauth] ANOMALOUS unknown bearer token ip=${req.ip}`);
    res.setHeader("WWW-Authenticate", `Bearer realm="${baseUrl(req)}", error="invalid_token"`);
    return res.status(401).json({ error: "invalid_token" });
  }
  if (record.expires_at < Math.floor(Date.now() / 1000)) {
    console.log(`[oauth] ANOMALOUS expired bearer token user_id=${record.user_id} ip=${req.ip}`);
    res.setHeader("WWW-Authenticate", `Bearer realm="${baseUrl(req)}", error="invalid_token"`);
    return res.status(401).json({ error: "invalid_token" });
  }
  req.userId = record.user_id;
  next();
}

export default router;
