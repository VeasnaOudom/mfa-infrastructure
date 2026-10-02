package com.khalibre.keycloak.provider.edc;

import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

/**
 * Works out which MFA channels a user can actually receive a code on: an active privacyIDEA SPASS
 * token enables Email, an active HOTP/TOTP token enables the authenticator app, and a linked
 * Telegram account enables Telegram.
 *
 * Shared by the authenticator (which writes the result into authentication-session notes) and the
 * channels endpoint, so the page and the flow can never disagree.
 *
 * Every lookup is best-effort: a privacyIDEA outage must not block sign-in, so failures degrade to
 * "channel unavailable".
 */
public final class EdcChannelDetector {

  private static final Logger log = Logger.getLogger(EdcChannelDetector.class);

  /** Keycloak user attributes written when a Telegram account is linked. */
  public static final String TELEGRAM_USER_ID_ATTR = "telegram-user-id";
  public static final String TELEGRAM_USERNAME_ATTR = "telegram-username";

  /** Alias of the Telegram identity provider whose links make the channel available. */
  public static final String TELEGRAM_IDP_ALIAS = "telegram";

  private EdcChannelDetector() {
  }

  /** @return channel flags keyed by the note names the template and endpoint exchange */
  public static Map<String, String> detect(KeycloakSession session, PrivacyIdeaService privacyIdea,
      UserModel user) {
    Map<String, String> channels = new LinkedHashMap<>();
    channels.put(EdcMfaChannelsAuthenticator.NOTE_EMAIL, "0");
    channels.put(EdcMfaChannelsAuthenticator.NOTE_TOTP, "0");
    channels.put(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM, "0");
    channels.put(EdcMfaChannelsAuthenticator.NOTE_MASKED, "0");

    if (user == null) {
      return channels;
    }
    detectTelegram(session, user, channels);
    detectPrivacyIdeaTokens(session, privacyIdea, user, channels);
    return channels;
  }

  /**
   * Telegram counts as available when the user has a linked Telegram identity.
   *
   * The link is detected from the federated identity rather than a {@code telegram-user-id}
   * attribute: this realm federates to LDAP with editMode=Writable, which discards attributes that
   * are not mapped in the directory, so a locally written attribute silently disappears. The
   * federated-identity row is managed by Keycloak itself and survives LDAP sync.
   */
  private static void detectTelegram(KeycloakSession session, UserModel user,
      Map<String, String> channels) {
    String chatId = telegramChatId(session, user);
    if (chatId == null) {
      return;
    }
    channels.put(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM, "1");
    // Prefer the Telegram handle for display; fall back to the chat id because a Telegram account
    // need not have a username set.
    String handle = user.getFirstAttribute(TELEGRAM_USERNAME_ATTR);
    if (handle == null || handle.isBlank()) {
      handle = telegramUsername(session, user);
    }
    channels.put(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM_HANDLE,
        handle == null || handle.isBlank() ? chatId : handle);
    // Without this the page would advertise a channel the sender cannot deliver to.
    channels.put(EdcMfaChannelsAuthenticator.NOTE_MASKED, "1");
  }

  /** The @username of the linked Telegram account, or {@code null} if it has none. */
  static String telegramUsername(KeycloakSession session, UserModel user) {
    if (session == null || session.getContext().getRealm() == null) {
      return null;
    }
    try {
      return session.users()
          .getFederatedIdentitiesStream(session.getContext().getRealm(), user)
          .filter(id -> TELEGRAM_IDP_ALIAS.equals(id.getIdentityProvider()))
          .map(FederatedIdentityModel::getUserName)
          .filter(name -> name != null && !name.isBlank())
          .findFirst()
          .orElse(null);
    } catch (Exception e) {
      log.warnf("method=telegramUsername user=%s error=%s", user.getUsername(), e.getMessage());
      return null;
    }
  }

  /**
   * @return the Telegram chat id of the user's linked Telegram account, or {@code null} when not
   *         linked or the stored identity does not carry a usable Telegram id
   */
  public static String telegramChatId(KeycloakSession session, UserModel user) {
    String attribute = user.getFirstAttribute(TELEGRAM_USER_ID_ATTR);
    if (attribute != null && !attribute.isBlank()) {
      return attribute;
    }
    if (session == null || session.getContext().getRealm() == null) {
      return null;
    }
    try {
      return session.users()
          .getFederatedIdentitiesStream(session.getContext().getRealm(), user)
          .filter(id -> TELEGRAM_IDP_ALIAS.equals(id.getIdentityProvider()))
          .map(FederatedIdentityModel::getUserId)
          .filter(id -> id != null && !id.isBlank())
          .findFirst()
          .orElse(null);
    } catch (Exception e) {
      log.warnf("method=telegramChatId user=%s error=%s", user.getUsername(), e.getMessage());
      return null;
    }
  }

  private static void detectPrivacyIdeaTokens(KeycloakSession session,
      PrivacyIdeaService privacyIdea, UserModel user, Map<String, String> channels) {
    if (privacyIdea == null) {
      log.warn("method=detectPrivacyIdeaTokens reason=serviceNotConfigured");
      return;
    }
    String username = user.getUsername();
    if (username == null || username.isBlank()) {
      return;
    }

    try {
      String adminToken = privacyIdea.getPrivacyIdeaAuthToken();
      if (adminToken == null || adminToken.isBlank()) {
        log.warnf("method=detectPrivacyIdeaTokens user=%s reason=noAdminToken", username);
        return;
      }

      if (!privacyIdea.getActiveTokenSerials(username, "spass", adminToken).isEmpty()) {
        channels.put(EdcMfaChannelsAuthenticator.NOTE_EMAIL, "1");
        String masked = maskEmail(user.getFirstAttribute("email"));
        if (masked != null) {
          channels.put(EdcMfaChannelsAuthenticator.NOTE_EMAIL_MASKED, masked);
        }
      }

      for (String type : List.of("hotp", "totp")) {
        if (!privacyIdea.getActiveTokenSerials(username, type, adminToken).isEmpty()) {
          channels.put(EdcMfaChannelsAuthenticator.NOTE_TOTP, "1");
          break;
        }
      }
    } catch (Exception e) {
      log.errorf("method=detectPrivacyIdeaTokens user=%s error=%s", username, e.getMessage());
    }
  }

  /** Hides all but the first and last character of the local part, e.g. {@code s•••a@edc.com.kh}. */
  static String maskEmail(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    int at = value.indexOf('@');
    if (at <= 0 || at == value.length() - 1) {
      return value.length() <= 2 ? "\u2022\u2022" : value.charAt(0) + "\u2022";
    }
    String local = value.substring(0, at);
    String domain = value.substring(at);
    String head = local.substring(0, 1);
    String tail = local.length() > 2 ? local.substring(local.length() - 1) : "";
    int hidden = Math.max(1, local.length() - head.length() - tail.length());
    return head + "\u2022".repeat(hidden) + tail + domain;
  }
}