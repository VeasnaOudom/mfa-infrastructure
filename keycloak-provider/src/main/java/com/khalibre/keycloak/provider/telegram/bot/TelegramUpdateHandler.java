package com.khalibre.keycloak.provider.telegram.bot;

import org.jboss.logging.Logger;

import com.khalibre.keycloak.provider.telegram.bot.TelegramWebhookPayload.Contact;
import com.khalibre.keycloak.provider.telegram.bot.TelegramWebhookPayload.From;
import com.khalibre.keycloak.provider.telegram.state.AuthState;
import com.khalibre.keycloak.provider.telegram.state.AuthStateCache;

public class TelegramUpdateHandler {

  /**
   * Every update the bot accepts is logged, and none of them were before. That silence is what made a
   * failed link undiagnosable: "Telegram never delivered the scan" and "the scan arrived but matched
   * no pending QR" are indistinguishable from the outside, and both present to the user as a QR that
   * scans and then does nothing. The two are logged separately below for exactly that reason.
   */
  private static final Logger LOG = Logger.getLogger(TelegramUpdateHandler.class);

  private static final String COMMAND_START_LOGIN = "/start login_";

  private final String botToken;

  public TelegramUpdateHandler(String botToken) {
    this.botToken = botToken;
  }

  public void handleUpdate(TelegramWebhookPayload update) {
    if (update.getMessage() == null) {
      return;
    }

    TelegramWebhookPayload.From from = update.getMessage().getFrom();
    String text = update.getMessage().getText();

    LOG.infof("method=handleUpdate chat=%s text=%s contact=%s",
        from == null ? null : from.getId(),
        text == null ? null : text,
        update.getMessage().getContact() != null);

    if (text != null && text.startsWith(COMMAND_START_LOGIN)) {
      handleStartLoginCommand(from, text);
    } else if (update.getMessage().getContact() != null) {
      handleContact(from, update.getMessage().getContact());
    }
  }

  private void handleStartLoginCommand(TelegramWebhookPayload.From from, String text) {
    String authStateId = text.substring(COMMAND_START_LOGIN.length());

    AuthState state = AuthStateCache.get(authStateId);
    if (state == null) {
      LOG.warnf("method=handleStartLoginCommand chat=%s state=%s message=NoSuchScan",
          from == null ? null : from.getId(), authStateId);
      return;
    }

    state.setTelegramUserId(from.getId());
    state.setFirstName(from.getFirstName());
    state.setLastName(from.getLastName());
    state.setUsername(from.getUsername());
    state.setPhoneNumberRequested(false);
    state.setStatus(state.isExpired() ? "EXPIRED" : "BOT_STARTED");
    AuthStateCache.store(authStateId, state);
    LOG.infof("method=handleStartLoginCommand chat=%s state=%s status=%s",
        from.getId(), authStateId, state.getStatus());
  }

  private void handleContact(TelegramWebhookPayload.From from,
    TelegramWebhookPayload.Contact contact) {
    AuthState state = AuthStateCache.findByTelegramUserId(from.getId());
    if (state != null && isUserContact(from, contact)) {
      state.setPhoneNumber(contact.getPhoneNumber());
      state.setStatus(state.isExpired() ? "EXPIRED" : "COMPLETED");
      AuthStateCache.store(state.getId(), state);
      LOG.infof("method=handleContact chat=%s state=%s status=%s", from.getId(), state.getId(),
          state.getStatus());
    } else {
      LOG.warnf("method=handleContact chat=%s message=NoScanInProgressForChat", from.getId());
    }
  }

  private boolean isUserContact(From from, Contact contact) {
    return from.getId().equals(String.valueOf(contact.getUserId()));
  }
}
