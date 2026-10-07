package com.khalibre.keycloak.provider.telegram.bot;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

import com.khalibre.keycloak.provider.edc.EdcChannelDetector;

/**
 * Sends a message to a Telegram chat through the configured bot.
 *
 * <p>Holds the one implementation of "look the bot token up and send a message by message key". It
 * was in {@code TelegramIdentityProvider} and is needed by the MFA link path too, and two copies of a
 * bot-token lookup is two places for a masked or missing token to be handled differently.
 *
 * <p>Delivery is always best-effort. The link itself has already been written by the time anything
 * here runs, and a bot failure must not turn a successful link into an error the user sees - that
 * would leave them re-scanning a QR for a channel that is already working.
 */
public final class TelegramNotifier {

  private static final Logger log = Logger.getLogger(TelegramNotifier.class);

  private TelegramNotifier() {
  }

  /**
   * Sends the message behind {@code messageKey} to {@code chatId}.
   *
   * @return whether it was sent; {@code false} for every reason it might not have been
   */
  public static boolean send(KeycloakSession session, String chatId, String messageKey) {
    if (session == null || chatId == null || chatId.isBlank() || messageKey == null) {
      return false;
    }
    String botToken = botToken(session);
    if (botToken == null) {
      log.warnf("method=send messageKey=%s message=NoTelegramBotToken", messageKey);
      return false;
    }
    try {
      // Plain text, deliberately: no parse_mode means Telegram never rejects the text for containing
      // a stray < or &, and a rejected message is one that must not be retried.
      LoginFormsProvider formProvider = session.getProvider(LoginFormsProvider.class);
      String message = formProvider == null ? messageKey : formProvider.getMessage(messageKey);
      new TelegramBotClient(botToken).sendMessage(chatId, message, null);
      log.infof("method=send chat=%s messageKey=%s status=SENT", chatId, messageKey);
      return true;
    } catch (Exception e) {
      log.warnf("method=send chat=%s messageKey=%s error=%s", chatId, messageKey, e.getMessage());
      return false;
    }
  }

  /**
   * The bot token, read from the Telegram identity provider.
   *
   * <p>Read from the provider rather than from anywhere a caller might have seen it, because the
   * admin API masks this value as {@code **********} in {@code identity-provider/instances}. Testing
   * the bot with the masked value gets a 404 from {@code getMe} and looks exactly like a bot that
   * does not exist.
   *
   * @return the token, or {@code null} when there is no usable Telegram identity provider
   */
  private static String botToken(KeycloakSession session) {
    try {
      IdentityProviderModel idp =
          session.identityProviders().getByAlias(EdcChannelDetector.TELEGRAM_IDP_ALIAS);
      if (idp == null) {
        return null;
      }
      String token = new OAuth2IdentityProviderConfig(idp).getClientSecret();
      return token == null || token.isBlank() ? null : token;
    } catch (Exception e) {
      log.warnf("method=botToken error=%s", e.getMessage());
      return null;
    }
  }
}
