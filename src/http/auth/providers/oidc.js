import * as oidc from "openid-client";
import { randomUUID } from "crypto";
import { getUserByOidcSub, getUserByEmail, createUser, linkOidcSub } from "../../db.js";

// Single sign-on through an OIDC provider (e.g. a Cognito user pool). When enabled it
// replaces password and Google sign-in, and OIDC_REQUIRED_GROUP gates who may sign in.
const GROUPS_CLAIM = "cognito:groups";

export function isOidcEnabled() {
  return !!process.env.OIDC_ISSUER;
}

let _config;

async function getConfig() {
  if (!_config) {
    const issuer = new URL(process.env.OIDC_ISSUER);
    // Plain http only for a local test issuer.
    const execute = issuer.protocol === "http:" && issuer.hostname === "127.0.0.1" ? [oidc.allowInsecureRequests] : [];
    _config = await oidc.discovery(issuer, process.env.OIDC_CLIENT_ID, process.env.OIDC_CLIENT_SECRET, undefined, { execute });
  }
  return _config;
}

function callbackUrl() {
  return `${process.env.BASE_URL}/auth/oidc/callback`;
}

/** Builds the provider's authorization URL and remembers state, nonce and PKCE verifier in the session. */
export async function startOidcLogin(session) {
  const config = await getConfig();
  const codeVerifier = oidc.randomPKCECodeVerifier();
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  session.oidc = { codeVerifier, state, nonce };
  return oidc.buildAuthorizationUrl(config, {
    redirect_uri: callbackUrl(),
    scope: "openid email",
    code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state,
    nonce,
  }).href;
}

/**
 * Completes the callback: validates state, nonce, PKCE and the ID token, checks the
 * required group, and returns the local user (created or linked on first sign-in).
 */
export async function finishOidcLogin(session, currentUrl) {
  const pending = session.oidc;
  delete session.oidc;
  if (!pending) throw new Error("Sign-in session expired. Start again.");

  const config = await getConfig();
  const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
    pkceCodeVerifier: pending.codeVerifier,
    expectedState: pending.state,
    expectedNonce: pending.nonce,
    idTokenExpected: true,
  });
  const claims = tokens.claims();
  const { sub, email } = claims;

  const required = process.env.OIDC_REQUIRED_GROUP;
  if (required && !(claims[GROUPS_CLAIM] || []).includes(required)) {
    throw new Error("Your account is not authorized to use this server.");
  }

  let user = getUserByOidcSub(sub);
  if (user) return user;
  if (!email) throw new Error("The identity provider returned no email address.");

  // An account from before single sign-on: take it over (keeps the stored AnyList login).
  // linkOidcSub drops its password and every token issued before, since the account was
  // created by unverified self-registration.
  user = getUserByEmail(email);
  if (user) {
    if (user.oidc_sub) throw new Error("This email is already linked to another identity.");
    return linkOidcSub(user.id, sub);
  }

  return createUser({ id: randomUUID(), email, oidcSub: sub });
}
