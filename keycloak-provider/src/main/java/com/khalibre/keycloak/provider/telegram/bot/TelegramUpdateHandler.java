package com.khalibre.keycloak.provider.telegram.bot;

import com.khalibre.keycloak.provider.telegram.bot.TelegramWebhookPayload.Contact;
import com.khalibre.keycloak.provider.telegram.bot.TelegramWebhookPayload.From;
import com.khalibre.keycloak.provider.telegram.state.AuthState;
import com.khalibre.keycloak.provider.telegram.state.AuthStateCache;

public class TelegramUpdateHandler {

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
      return;
    }

    state.setTelegramUserId(from.getId());
    state.setFirstName(from.getFirstName());
    state.setLastName(from.getLastName());
    state.setUsername(from.getUsername());
    state.setPhoneNumberRequested(false);
    state.setStatus(state.isExpired() ? "EXPIRED" : "BOT_STARTED");
    AuthStateCache.store(authStateId, state);
  }

  private void handleContact(TelegramWebhookPayload.From from,
    TelegramWebhookPayload.Contact contact) {
    AuthState state = AuthStateCache.findByTelegramUserId(from.getId());
    if (state != null && isUserContact(from, contact)) {
      state.setPhoneNumber(contact.getPhoneNumber());
      state.setStatus(state.isExpired() ? "EXPIRED" : "COMPLETED");
      AuthStateCache.store(state.getId(), state);
    }
  }

  private boolean isUserContact(From from, Contact contact) {
    return from.getId().equals(String.valueOf(contact.getUserId()));
  }
}
