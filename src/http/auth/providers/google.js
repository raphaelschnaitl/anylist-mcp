import { OAuth2Client } from "google-auth-library";
import { randomUUID } from "crypto";
import { getUserByGoogleSub, getUserByEmail, createUser, isEmailAllowed } from "../../db.js";

let _client;

function getGoogleClient() {
  if (!_client) {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId) throw new Error("GOOGLE_CLIENT_ID is not configured.");
    _client = new OAuth2Client(clientId);
  }
  return _client;
}

/**
 * Verify a Google ID token (from the frontend sign-in button).
 * Returns the user row, creating it on first login if the email is whitelisted.
 * @param {string} idToken - Google credential from the Sign In With Google button
 */
export async function loginWithGoogle(idToken) {
  const client = getGoogleClient();
  const ticket = await client.verifyIdToken({
    idToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  const payload = ticket.getPayload();
  const { sub, email, email_verified } = payload;

  if (!email || !email_verified) throw new Error("Google account has no verified email.");

  // Check if user already exists by Google sub
  let user = getUserByGoogleSub(sub);
  if (user) {
    if (!isEmailAllowed(user.email)) throw new Error("This Google account is not authorized.");
    return user;
  }

  // Never sign a Google identity into an account created another way: password
  // registration does not verify the email, so that account may belong to someone else.
  if (getUserByEmail(email)) {
    throw new Error("An account with this email already exists. Sign in with your password.");
  }

  // New user — check whitelist before creating
  if (!isEmailAllowed(email)) {
    throw new Error("This Google account is not authorized.");
  }

  return createUser({ id: randomUUID(), email, googleSub: sub });
}

/**
 * Returns true if Google OAuth is configured.
 */
export function isGoogleEnabled() {
  return !!process.env.GOOGLE_CLIENT_ID;
}
