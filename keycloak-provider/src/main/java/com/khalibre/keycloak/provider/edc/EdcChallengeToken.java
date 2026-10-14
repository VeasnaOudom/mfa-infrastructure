package com.khalibre.keycloak.provider.edc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Short-lived signed token proving "this browser already passed the first factor for this user",
 * handed to the OTP page as an HttpOnly cookie.
 *
 * Authentication-session notes would be the natural place for this, but they are unreachable from
 * both FreeMarker and a plain REST endpoint: Keycloak only resolves the authentication session for
 * login-action requests, and its cookie value is signed in a way that cannot be decoded from a
 * provider. A self-contained token avoids depending on those internals.
 *
 * <p>It also carries the client the user is signing in to. The OTP page's endpoints are plain REST
 * calls with no authentication session and no token of their own, so without this they cannot tell
 * which application's channel policy applies - and a per-application switch that both the delivery
 * path and the page ignore is not a switch.
 */
public final class EdcChallengeToken {

  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

  /** Separator between payload fields. Neither a username nor a client id may contain one. */
  private static final String SEPARATOR = "\\|";

  private EdcChallengeToken() {
  }

  /**
   * What a valid challenge token proves.
   *
   * @param username who passed the first factor
   * @param clientId the client they are signing in to, or {@code null} where the token was issued
   *     with no client
   */
  public record Challenge(String username, String clientId) {
  }

  /**
   * @param ttlSeconds how long the token stays valid; keep it near the OTP validity
   * @param clientId the client being signed in to; null or blank is stored as absent
   * @return {@code base64url(user|issuedAtMs[|clientId]).base64url(hmac)}, or {@code null} if not
   *     signable
   */
  public static String issue(String username, String clientId, String secret, long ttlSeconds) {
    if (username == null || username.isBlank() || secret == null || secret.isBlank()) {
      return null;
    }
    String payload = username + "|" + System.currentTimeMillis()
        + (clientId == null || clientId.isBlank() ? "" : "|" + clientId);
    return ENCODER.encodeToString(payload.getBytes(StandardCharsets.UTF_8))
        + "." + ENCODER.encodeToString(hmac(secret, payload));
  }

  /**
   * @return the username the token was issued for, or {@code null} if it is missing, forged,
   *         tampered with, or older than {@code ttlSeconds}
   */
  public static String verify(String token, String secret, long ttlSeconds) {
    Challenge challenge = verifyChallenge(token, secret, ttlSeconds);
    return challenge == null ? null : challenge.username();
  }

  /**
   * Everything a valid token says.
   *
   * <p>Every check {@link #verify} did still runs first: nothing here trusts a field it has not
   * authenticated.
   *
   * @return the challenge, or {@code null} if the token is missing, forged, tampered with, or older
   *     than {@code ttlSeconds}
   */
  public static Challenge verifyChallenge(String token, String secret, long ttlSeconds) {
    if (token == null || token.isBlank() || secret == null || secret.isBlank()) {
      return null;
    }
    int dot = token.lastIndexOf('.');
    if (dot <= 0 || dot == token.length() - 1) {
      return null;
    }

    String payload;
    byte[] signature;
    try {
      payload = new String(DECODER.decode(token.substring(0, dot)), StandardCharsets.UTF_8);
      signature = DECODER.decode(token.substring(dot + 1));
    } catch (IllegalArgumentException e) {
      return null;
    }

    byte[] expected = hmac(secret, payload);
    if (!MessageDigest.isEqual(expected, signature)) {
      return null;
    }

    // Three fields, the third optional: a cookie issued before this field existed still proves a
    // first factor, it simply cannot name a client and so reads as the realm default. The split
    // limit matters - an unbounded one would let a client id containing a separator shift the
    // timestamp and be read as the issued-at instead.
    String[] parts = payload.split(SEPARATOR, 3);
    if (parts.length < 2 || parts[0].isBlank()) {
      return null;
    }
    long issuedAt;
    try {
      issuedAt = Long.parseLong(parts[1]);
    } catch (NumberFormatException e) {
      return null;
    }

    long ageMillis = System.currentTimeMillis() - issuedAt;
    // Reject tokens stamped in the future as well as stale ones.
    if (ageMillis < 0 || ageMillis > ttlSeconds * 1000L) {
      return null;
    }
    return new Challenge(parts[0], parts.length > 2 && !parts[2].isBlank() ? parts[2] : null);
  }

  /**
   * Builds the {@code Set-Cookie} header for the challenge proof. Kept here so the authenticator
   * and the resend endpoint emit an identical cookie.
   */
  public static String cookieHeader(String realmName, String token, int ttlSeconds) {
    return EdcMfaChannelsAuthenticator.CHALLENGE_COOKIE + "=" + token
        + "; Path=/realms/" + realmName + "/"
        + "; Max-Age=" + ttlSeconds
        + "; HttpOnly; SameSite=Lax";
  }

  /**
   * Milliseconds since the epoch when {@code token} was issued, or -1 if it is not valid.
   *
   * <p>Signed but deliberately not age-checked: the caller uses this for the OTP page's countdown,
   * which describes the <em>code</em> rather than the challenge, and the two have different
   * lifetimes - the challenge cookie deliberately outlives the code so that "Send a new code" still
   * works once the old one lapses. Expiring this would take the countdown away at exactly that point.
   */
  public static long issuedAtMillis(String token, String secret) {
    if (token == null || secret == null) {
      return -1;
    }
    int dot = token.lastIndexOf('.');
    if (dot <= 0) {
      return -1;
    }
    try {
      String payload = new String(DECODER.decode(token.substring(0, dot)), StandardCharsets.UTF_8);
      if (!MessageDigest.isEqual(hmac(secret, payload), DECODER.decode(token.substring(dot + 1)))) {
        return -1;
      }
      // Field 2, not the last field: the payload carries the client id after it.
      String[] parts = payload.split(SEPARATOR, 3);
      return parts.length < 2 ? -1 : Long.parseLong(parts[1]);
    } catch (IllegalArgumentException e) {
      return -1;
    }
  }

  private static byte[] hmac(String secret, String payload) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
      return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException("Unable to sign the MFA challenge token", e);
    }
  }
}