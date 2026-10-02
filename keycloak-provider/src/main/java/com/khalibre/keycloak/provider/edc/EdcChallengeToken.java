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
 */
public final class EdcChallengeToken {

  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

  private EdcChallengeToken() {
  }

  /**
   * @param ttlSeconds how long the token stays valid; keep it near the OTP validity
   * @return {@code base64url(user|issuedAtMs).base64url(hmac)}, or {@code null} if not signable
   */
  public static String issue(String username, String secret, long ttlSeconds) {
    if (username == null || username.isBlank() || secret == null || secret.isBlank()) {
      return null;
    }
    String payload = username + "|" + System.currentTimeMillis();
    return ENCODER.encodeToString(payload.getBytes(StandardCharsets.UTF_8))
        + "." + ENCODER.encodeToString(hmac(secret, payload));
  }

  /**
   * @return the username the token was issued for, or {@code null} if it is missing, forged,
   *         tampered with, or older than {@code ttlSeconds}
   */
  public static String verify(String token, String secret, long ttlSeconds) {
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

    int sep = payload.lastIndexOf('|');
    if (sep <= 0) {
      return null;
    }
    String username = payload.substring(0, sep);
    long issuedAt;
    try {
      issuedAt = Long.parseLong(payload.substring(sep + 1));
    } catch (NumberFormatException e) {
      return null;
    }

    long ageMillis = System.currentTimeMillis() - issuedAt;
    // Reject tokens stamped in the future as well as stale ones.
    if (ageMillis < 0 || ageMillis > ttlSeconds * 1000L) {
      return null;
    }
    return username;
  }

  /** Milliseconds since the epoch when {@code token} was issued, or -1 if it is not valid. */
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
      int sep = payload.lastIndexOf('|');
      return sep <= 0 ? -1 : Long.parseLong(payload.substring(sep + 1));
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