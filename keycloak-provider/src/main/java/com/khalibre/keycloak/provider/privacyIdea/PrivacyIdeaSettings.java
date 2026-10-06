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
  public static final String KEY_PUBLIC_BASE_URL = "publicBaseUrl";
  public static final String KEY_EXPIRY_MINUTES = "spassExpiryMinutes";
  public static final String KEY_CHALLENGE_TTL_MINUTES = "challengeTtlMinutes";
  public static final String KEY_BACKUP_CODE_COUNT = "backupCodeCount";
  public static final String KEY_BACKUP_CODE_LENGTH = "backupCodeLength";
  public static final String KEY_ENROLMENT_GROUP = "enrolmentGroup";

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
        pick(admin, KEY_PUBLIC_BASE_URL, "KEYCLOAK_PUBLIC_BASE_URL", ""),
        parseInt(pick(admin, KEY_EXPIRY_MINUTES, null, "5"), 5),
        parseInt(pick(admin, KEY_CHALLENGE_TTL_MINUTES, "PRIVACYIDEA_CHALLENGE_TTL_MINUTES", "30"),
            30),
        parseInt(pick(admin, KEY_BACKUP_CODE_COUNT, "PRIVACYIDEA_BACKUP_CODE_COUNT", "10"), 10),
        parseInt(pick(admin, KEY_BACKUP_CODE_LENGTH, "PRIVACYIDEA_BACKUP_CODE_LENGTH", "6"), 6),
        pick(admin, KEY_ENROLMENT_GROUP, "PRIVACYIDEA_ENROLMENT_GROUP", "MFA"));
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
      String webhookSecret, String publicBaseUrl, int spassExpiryMinutes,
      int challengeTtlMinutes, int backupCodeCount, int backupCodeLength,
      String enrolmentGroup) {

    public Settings {
      // Clamped here rather than at each use site: a bad admin-console value would otherwise turn
      // into a zero-code enrolment, and zero codes is exactly the state that locks staff out.
      backupCodeCount = backupCodeCount < 1 ? 10 : Math.min(backupCodeCount, 100);
      backupCodeLength = backupCodeLength < 4 ? 6 : Math.min(backupCodeLength, 12);
      // A blank group name would silently record nothing, which reads as success. Fall back to the
      // name this realm already uses rather than joining nothing and claiming it worked.
      if (enrolmentGroup == null || enrolmentGroup.isBlank()) {
        enrolmentGroup = "MFA";
      }
    }

    public String baseUrlTrimmed() {
      return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }

    public boolean hasSecret() {
      return webhookSecret != null && !webhookSecret.isBlank();
    }

    /**
     * Parameters for enrolling a TAN token of backup codes.
     *
     * <p>Two things are pinned deliberately. {@code otplen} because privacyIDEA derives an eight
     * digit length otherwise and the code field here is six boxes wide. {@code tantoken_count}
     * because that is the name the token class actually reads - the intuitive {@code tan.count} is
     * silently ignored and you get the 100-code default.
     */
    public Map<String, String> backupCodeTokenParams() {
      return Map.of("tantoken_count", Integer.toString(backupCodeCount),
          "otplen", Integer.toString(backupCodeLength));
    }

    /** Parameters matching the TOTP tokens this deployment already issues. */
    public Map<String, String> totpTokenParams() {
      return Map.of("timeStep", "30", "hashlib", "sha1", "timeWindow", "180");
    }

    /**
     * Public origin for links and images in mail this provider sends. Falls back to KC_HOSTNAME,
     * which Traefik's public hostname already is, so a deployment only has to set this when it
     * needs something other than {@code https://<hostname>}.
     */
    public String publicBaseUrl() {
      String configured = publicBaseUrl == null ? "" : publicBaseUrl.trim();
      if (!configured.isEmpty()) {
        return configured.endsWith("/") ? configured.substring(0, configured.length() - 1)
            : configured;
      }
      String hostname = System.getenv("KC_HOSTNAME");
      if (hostname == null || hostname.isBlank()) {
        return "";
      }
      return hostname.startsWith("http") ? hostname : "https://" + hostname;
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