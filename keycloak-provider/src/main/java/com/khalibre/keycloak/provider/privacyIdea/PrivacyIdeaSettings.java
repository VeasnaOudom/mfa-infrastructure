package com.khalibre.keycloak.provider.privacyIdea;

import java.util.HashMap;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * The single source of truth for the privacyIDEA connection settings, shared by the webhook
 * resource and the MFA channel detector.
 *
 * Both consumers used to read the same environment variables independently, which meant an
 * operator could change the webhook's idea of the server or secret without changing the
 * detector's, and the failure showed up as a subtle half-working sign-in. There is now exactly one
 * editable copy - the "EDC MFA Channels" execution in the authentication flow - and both sides
 * resolve it from here, so they cannot drift.
 *
 * Resolution order: admin configuration, then environment variables, then a built-in default.
 */
public final class PrivacyIdeaSettings {

  private static final Logger log = Logger.getLogger(PrivacyIdeaSettings.class);

  public static final String KEY_BASE_URL = "piBaseUrl";
  public static final String KEY_ADMIN_USERNAME = "piAdminUsername";
  public static final String KEY_ADMIN_PASSWORD = "piAdminPassword";
  public static final String KEY_WEBHOOK_SECRET = "webhookSecret";
  public static final String KEY_EXPIRY_MINUTES = "spassExpiryMinutes";
  public static final String KEY_CHALLENGE_TTL_MINUTES = "challengeTtlMinutes";

  /** Provider id of the execution whose configuration holds the canonical values. */
  private static final String OWNING_PROVIDER_ID = "edc-mfa-channels";

  private PrivacyIdeaSettings() {
  }

  public static Settings resolve(KeycloakSession session) {
    Map<String, String> admin = findAdminConfig(session);
    return new Settings(
        pick(admin, KEY_BASE_URL, "PRIVACYIDEA_URL", "http://mfa-privacyidea:8080"),
        pick(admin, KEY_ADMIN_USERNAME, "PI_ADMIN_USER", "admin"),
        pick(admin, KEY_ADMIN_PASSWORD, "PI_ADMIN_PASSWORD", "secret"),
        pick(admin, KEY_WEBHOOK_SECRET, "PRIVACYIDEA_WEBHOOK_SECRET", ""),
        parseInt(pick(admin, KEY_EXPIRY_MINUTES, null, "5"), 5),
        parseInt(pick(admin, KEY_CHALLENGE_TTL_MINUTES, "PRIVACYIDEA_CHALLENGE_TTL_MINUTES", "30"),
            30));
  }

  /**
   * Walks every flow, including subflows, looking for the one execution that owns this
   * configuration.
   *
   * @return the stored values, or an empty map when the execution has no configuration yet
   */
  public static Map<String, String> findAdminConfig(KeycloakSession session) {
    RealmModel realm = session.getContext().getRealm();
    if (realm == null) {
      return Map.of();
    }
    return findInFlows(realm, null, new java.util.HashSet<>());
  }

  private static Map<String, String> findInFlows(RealmModel realm, String flowId,
      java.util.Set<String> visited) {
    var executions = flowId == null ? realm.getAuthenticationFlowsStream()
        .map(AuthenticationFlowModel::getId)
        : java.util.stream.Stream.of(flowId);

    for (String id : (Iterable<String>) executions::iterator) {
      if (!visited.add(id)) {
        continue;
      }
      for (AuthenticationExecutionModel execution : realm.getAuthenticationExecutionsStream(id)
          .toList()) {
        if (OWNING_PROVIDER_ID.equals(execution.getAuthenticator())) {
          String configId = execution.getAuthenticatorConfig();
          if (configId != null) {
            AuthenticatorConfigModel config = realm.getAuthenticatorConfigById(configId);
            if (config != null && config.getConfig() != null) {
              return new HashMap<>(config.getConfig());
            }
          }
        } else if (execution.getAuthenticator() == null && execution.getFlowId() != null) {
          // A subflow binding: recurse so the execution is found wherever it was placed.
          Map<String, String> nested = findInFlows(realm, execution.getFlowId(), visited);
          if (!nested.isEmpty()) {
            return nested;
          }
        }
      }
    }
    return Map.of();
  }

  private static String pick(Map<String, String> admin, String key, String envName,
      String fallback) {
    String value = admin.get(key);
    if (value != null && !value.isBlank()) {
      return value.trim();
    }
    if (envName != null) {
      String fromEnv = System.getenv(envName);
      if (fromEnv != null && !fromEnv.isBlank()) {
        return fromEnv.trim();
      }
    }
    return fallback;
  }

  private static int parseInt(String value, int fallback) {
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException | NullPointerException e) {
      log.warnf("key=spassExpiryMinutes value=%s is not a number, using %d", value, fallback);
      return fallback;
    }
  }

  /** Immutable snapshot of the resolved settings. */
  public record Settings(String baseUrl, String adminUsername, String adminPassword,
      String webhookSecret, int spassExpiryMinutes, int challengeTtlMinutes) {

    public String baseUrlTrimmed() {
      return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }

    public boolean hasSecret() {
      return webhookSecret != null && !webhookSecret.isBlank();
    }

    /**
     * How long the browser's challenge proof stays valid. Deliberately independent of the OTP
     * validity: it asserts "this browser passed the first factor", not "this code is still fresh",
     * so it has to outlive the code or "Send a new code" breaks exactly when it is needed.
     */
    public int challengeTtlSeconds() {
      return Math.max(120, challengeTtlMinutes * 60);
    }
  }
}