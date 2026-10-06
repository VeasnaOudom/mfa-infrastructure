package com.khalibre.keycloak.provider.edc;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.email.EmailException;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.khalibre.keycloak.provider.privacyIdea.PrivacyIdeaSettings;
import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;
import com.khalibre.keycloak.provider.telegram.bot.TelegramBotClient;

/**
 * Gets a one-time code to the user over whichever channels they have.
 *
 * <p>Deliberately the single implementation: the privacyIDEA webhook calls this at sign-in, and MFA
 * enrolment calls it when it enrols an email channel. Two copies would be two places for the mail
 * and the bot message to drift apart, and enrolment is exactly where nobody would notice.
 *
 * <p>Failure to <em>deliver</em> is never fatal. A missing Telegram bot or a mail server outage must
 * not stop someone signing in, so each channel is best-effort and only the PIN write - which decides
 * whether the code works at all - is allowed to throw.
 */
public final class EdcOtpDelivery {

  private static final Logger log = Logger.getLogger(EdcOtpDelivery.class);

  private static final String TELEGRAM_IDP_ALIAS = EdcChannelDetector.TELEGRAM_IDP_ALIAS;

  private static final ZoneId OTP_TIME_ZONE = ZoneId.systemDefault();

  private static final DateTimeFormatter OTP_DATE_FORMAT =
      DateTimeFormatter.ofPattern("d MMMM yyyy", Locale.ENGLISH);

  private static final DateTimeFormatter OTP_TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm");

  private EdcOtpDelivery() {
  }

  /**
   * Writes a fresh PIN to the user's SPASS token and sends it by every available channel.
   *
   * @param serial the SPASS token to drive
   * @param clientIp the address the request came from, shown in the mail so a user can tell an
   *     unexpected sign-in from their own
   * @return the code that was issued
   * @throws Exception if privacyIDEA would not accept the PIN, which means the code cannot work
   */
  public static String issue(KeycloakSession session, RealmModel realm, UserModel user,
      PrivacyIdeaSettings.Settings settings, PrivacyIdeaService privacyIdea, String adminToken,
      String serial, String clientIp) throws Exception {
    String otpCode = String.format("%06d", new java.security.SecureRandom().nextInt(1000000));
    privacyIdea.setPin(serial, otpCode, adminToken);
    privacyIdea.setPinExpiry(serial, adminToken, settings.spassExpiryMinutes());
    sendEmail(session, realm, user, settings, otpCode, clientIp);
    sendTelegram(session, user, settings, otpCode);
    return otpCode;
  }

  private static void sendEmail(KeycloakSession session, RealmModel realm, UserModel user,
      PrivacyIdeaSettings.Settings settings, String otpCode, String clientIp) {
    try {
      EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
      if (emailProvider == null) {
        log.warn("method=sendEmail message=NoEmailTemplateProvider");
        return;
      }
      emailProvider.setRealm(realm);
      emailProvider.setUser(user);

      // send() takes a message key for the subject and a freemarker template file name, not raw
      // HTML. Keycloak renders text/<template> and html/<template> from the realm's email theme;
      // both are provided by themes/khalibre/email. The map must be mutable: processTemplate adds
      // locale, msg, properties, realmName, user and url to it.
      ZonedDateTime issuedAt = ZonedDateTime.now(OTP_TIME_ZONE);
      Map<String, Object> attributes = new HashMap<>();
      attributes.put("otp", otpCode);
      // Grouped in threes so a mistyped digit is obvious, e.g. 492 718.
      attributes.put("otpFormatted",
          otpCode.replaceFirst("^(\\p{Digit}{3})(\\p{Digit}{3})$", "$1\u2002$2"));
      attributes.put("expiryMinutes", settings.spassExpiryMinutes());
      attributes.put("requestDate", issuedAt.format(OTP_DATE_FORMAT));
      attributes.put("requestTime", issuedAt.format(OTP_TIME_FORMAT));
      attributes.put("clientIp", clientIp == null || clientIp.isBlank() ? "unknown" : clientIp);
      attributes.put("appName", realm.getDisplayName() != null && !realm.getDisplayName().isBlank()
          ? realm.getDisplayName()
          : realm.getName());
      attributes.put("otpEmailBaseUrl", settings.publicBaseUrl());
      emailProvider.send("otpEmailSubject", "privacyidea-otp.ftl", attributes);
      log.infof("method=sendEmail status=SENT username=%s", user.getUsername());
    } catch (EmailException | RuntimeException e) {
      log.errorf(e, "method=sendEmail status=ERROR username=" + user.getUsername());
    }
  }

  /**
   * Sends the code through the Telegram bot when the user has linked Telegram and the bot is
   * configured. Both are optional: without a telegram identity provider there is no bot token, and
   * without a linked account the user never asked, so this is a no-op in both cases rather than an
   * error.
   */
  private static void sendTelegram(KeycloakSession session, UserModel user,
      PrivacyIdeaSettings.Settings settings, String otpCode) {
    // Falls back to the linked Telegram identity because LDAP federation discards the attribute.
    String chatId = EdcChannelDetector.telegramChatId(session, user);
    if (chatId == null || chatId.isBlank()) {
      log.debugf("method=sendTelegram user=%s message=NoTelegramIdentity", user.getUsername());
      return;
    }

    IdentityProviderModel idp = session.identityProviders().getByAlias(TELEGRAM_IDP_ALIAS);
    if (idp == null) {
      log.warnf("method=sendTelegram username=%s message=No telegram IdP configured, skipping",
          user.getUsername());
      return;
    }

    String botToken = new OAuth2IdentityProviderConfig(idp).getClientSecret();
    if (botToken == null || botToken.isBlank()) {
      log.warnf("method=sendTelegram username=%s message=Telegram IdP has no bot token, skipping",
          user.getUsername());
      return;
    }

    try {
      // HTML so the code stands out; otpCode is digits only, so no entity escaping is needed.
      String text = String.format("Your EDC verification code is <b>%s</b>. It is valid for %d minutes.",
          otpCode, settings.spassExpiryMinutes());
      new TelegramBotClient(botToken).sendMessage(chatId, text, null, "HTML");
      log.infof("method=sendTelegram status=SENT username=%s", user.getUsername());
    } catch (Exception e) {
      log.errorf(e, "method=sendTelegram status=ERROR username=" + user.getUsername());
    }
  }
}
