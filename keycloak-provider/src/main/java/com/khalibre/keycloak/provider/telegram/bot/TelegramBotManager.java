package com.khalibre.keycloak.provider.telegram.bot;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TelegramBotManager {

  private static final String MODE_ENV = "TELEGRAM_BOT_MODE";

  private static volatile TelegramBotManager instance;

  private final TelegramBotMode mode;
  private final Map<String, TelegramPollingService> pollingServices =
    new ConcurrentHashMap<>();

  private TelegramBotManager() {
    this.mode = TelegramBotMode.fromString(System.getenv(MODE_ENV));
  }

  public static synchronized TelegramBotManager getInstance() {
    if (instance == null) {
      instance = new TelegramBotManager();
    }
    return instance;
  }

  public void startPolling(String alias, String botToken) {
    if (pollingServices.containsKey(alias)) {
      return;
    }
    TelegramPollingService service = new TelegramPollingService(alias, botToken);
    service.start();
    pollingServices.put(alias, service);
    System.out.println("[TelegramBotManager] Started polling for bot: " + alias);
  }

  public void setWebhook(String alias, String botToken, String webhookUrl) {
    TelegramBotClient botClient = new TelegramBotClient(botToken);
    botClient.setWebhook(webhookUrl);
    System.out.println("[TelegramBotManager] Webhook registered for bot: "
      + alias + " at " + webhookUrl);
  }

  public void shutdown() {
    pollingServices.values().forEach(TelegramPollingService::stop);
    pollingServices.clear();
    System.out.println("[TelegramBotManager] Shutdown complete");
  }

  public TelegramBotMode getMode() {
    return mode;
  }
}
