package com.khalibre.keycloak.provider.telegram.state;

import org.keycloak.models.KeycloakSession;

/**
 * Associates a caller with the scan it started.
 *
 * <p>Two callers exist and they key differently, which is the whole point of this class:
 *
 * <ul>
 * <li><b>The login flow</b> keys on the root authentication session id, because a browser mid-sign-in
 * has exactly one.
 * <li><b>The account console</b> keys on the user id. A plain REST request has <em>no</em>
 * authentication session at all - Keycloak only populates one for login-action requests - so there
 * would be nothing to key on there. The user id comes from the verified bearer token and is just as
 * unforgeable.
 * </li>
 * </ul>
 *
 * <p>The mapping lives in {@link AuthStateCache}, in-process. That was not a free choice: it was
 * reading and writing {@code session.singleUseObjects()} instead, and a key written by one request
 * was not there for the next one to read - the account console's Telegram scan reported "no scan in
 * progress" seconds after starting one. See the note on {@link AuthStateCache#putKeyed}.
 *
 * <p>{@code session} is retained on every method even though nothing uses it, so the three existing
 * call sites read the same as before. Dropping it would be tidier and would touch unrelated files for
 * no behaviour change.
 */
public class AuthStateSession extends AuthStateCache {

  public static AuthState create(KeycloakSession session, String sessionId) {
    AuthState authState = createEmpty();
    putKeyed(sessionId, authState.getId());
    return authState;
  }

  public static AuthState get(KeycloakSession session, String sessionId) {
    return getKeyed(sessionId);
  }

  public static void remove(KeycloakSession session, String sessionId) {
    removeKeyed(sessionId);
  }
}