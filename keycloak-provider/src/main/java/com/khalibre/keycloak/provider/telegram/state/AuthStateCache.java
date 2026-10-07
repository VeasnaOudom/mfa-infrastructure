package com.khalibre.keycloak.provider.telegram.state;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AuthStateCache {

  private static final ConcurrentHashMap<String, AuthState> cache = new ConcurrentHashMap<>();

  /**
   * Which state belongs to a caller, keyed by that caller's own identifier.
   *
   * <p>Deliberately in this class rather than in {@code singleUseObjects}. That provider writes
   * through {@code InfinispanKeycloakTransaction}, and a key written during one request was not
   * there to be read by the next one - which made the account console's Telegram scan report "no scan
   * in progress" seconds after it had started one. This map is plain and in-process, and that is
   * sound here because {@link #cache} already requires a single JVM: the bot's long-poll handler
   * reads states written by REST requests, so nothing in the Telegram link flow would work across
   * nodes in the first place. Keying here adds no constraint that was not already there.
   *
   * <p>Swept on the same 30s schedule as the states themselves.
   */
  private static final ConcurrentHashMap<String, String> keyedIds = new ConcurrentHashMap<>();

  private static final ScheduledExecutorService scheduler =
    Executors.newSingleThreadScheduledExecutor();

  static {
    scheduler.scheduleAtFixedRate(() -> {
      cache.entrySet().removeIf(entry -> isRemoved(entry.getValue()));
      // A caller's key is only useful while the state behind it is still usable, so drop the two
      // together. Leaving the mapping behind would let a later request find an already-dead state
      // and report it as an expiry rather than as nothing to do.
      keyedIds.entrySet().removeIf(entry -> {
        AuthState state = cache.get(entry.getValue());
        return state == null || isRemoved(state);
      });
    }, 30, 30, TimeUnit.SECONDS);
  }

  protected static AuthState createEmpty() {
    AuthState state = new AuthState(null, null, null, null, null);
    cache.put(state.getId(), state);
    return state;
  }

  public static AuthState create(String telegramUserId, String firstName,
    String lastName, String username, String phoneNumber) {
    AuthState state = new AuthState(telegramUserId, firstName, lastName, username, phoneNumber);
    cache.put(state.getId(), state);
    return state;
  }

  public static void store(String id, AuthState state) {
    cache.put(id, state);
  }

  public static AuthState get(String id) {
    if (id == null) {
      return null;
    }
    AuthState state = cache.get(id);
    if (state == null) {
      return null;
    }
    if (isRemoved(state)) {
      cache.remove(id);
      return null;
    }
    return state;
  }

  private static boolean isRemoved(AuthState state) {
    return state.getExpiresAt() + 60 < Instant.now().getEpochSecond();
  }

  public static AuthState findByTelegramUserId(String telegramUserId) {
    if (telegramUserId == null) {
      return null;
    }
    for (AuthState state : cache.values()) {
      if (telegramUserId.equals(state.getTelegramUserId())) {
        return state;
      }
    }
    return null;
  }

  /** Records that {@code key}'s scan is {@code id}. */
  public static void putKeyed(String key, String id) {
    if (key != null && id != null) {
      keyedIds.put(key, id);
    }
  }

  /** @return the state id recorded for {@code key}, or {@code null} if there is none */
  public static AuthState getKeyed(String key) {
    return get(idFor(key));
  }

  /** Forgets {@code key}. Safe to call for a key that was never there. */
  public static void removeKeyed(String key) {
    if (key != null) {
      keyedIds.remove(key);
    }
  }

  private static String idFor(String key) {
    return key == null ? null : keyedIds.get(key);
  }

  protected static void remove(String id) {
    // Null-tolerant on purpose, and for the same reason get(String) above is: ConcurrentHashMap
    // throws on a null key rather than treating it as absent. Callers reach here by looking the id
    // up first, and "not found" is a normal answer - removing a state that is not there is what a
    // second attempt, an expired scan, or a start-again already does. Without this guard the
    // removal NPEs instead of doing nothing.
    if (id == null) {
      return;
    }
    cache.remove(id);
  }

  public static void shutdown() {
    scheduler.shutdownNow();
  }
}
