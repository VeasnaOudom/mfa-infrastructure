package com.khalibre.keycloak.provider.telegram.state;

import java.util.HashMap;
import java.util.Map;
import org.keycloak.models.KeycloakSession;

public class AuthStateSession extends AuthStateCache {

  private static final String KEY_AUTH_STATE_ID = "authStateId";

  public static AuthState create(KeycloakSession session, String sessionId) {
    AuthState authState = createEmpty();
    setAuthStateId(session, sessionId, authState.getId());
    return authState;
  }

  public static AuthState get(KeycloakSession session, String sessionId) {
    return get(getAuthStateId(session, sessionId));
  }

  public static void remove(KeycloakSession session, String sessionId) {
    remove(getAuthStateId(session, sessionId));
  }

  private static String getAuthStateId(KeycloakSession session, String sessionId) {
    // Null here is normal, not exceptional: a plain REST request has no root authentication session,
    // so there is no session id to look the state up by. singleUseObjects().get(null) throws rather
    // than returning nothing, so guard it and let the caller see a missing state - which is what
    // /status already reports as EXPIRED.
    if (session == null || sessionId == null || sessionId.isBlank()) {
      return null;
    }
    Map<String, String> notes = session.singleUseObjects().get(sessionId);
    if (notes != null) {
      return notes.get(KEY_AUTH_STATE_ID);
    }
    return null;
  }

  private static void setAuthStateId(KeycloakSession session, String sessionId, String id) {
    if (session == null || sessionId == null || sessionId.isBlank()) {
      return;
    }
    Map<String, String> notes = session.singleUseObjects().get(sessionId);
    if (notes == null) {
      notes = new HashMap<>();
    } else {
      notes = new HashMap<>(notes);
    }
    notes.put(KEY_AUTH_STATE_ID, id);
    session.singleUseObjects().put(sessionId, AuthState.LIFESPAN_SECONDS + 60, notes);
  }
}
