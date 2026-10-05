package com.khalibre.keycloak.provider.telegram.bot;

import java.util.List;

public class TelegramPollingService {

  private static final int LONG_POLL_TIMEOUT_SECONDS = 30;
  private static final long ERROR_BACKOFF_MS = 5000;

  private final String alias;
  private final TelegramBotClient botClient;
  private final TelegramUpdateHandler updateHandler;
  private volatile Thread pollingThread;
  private volatile boolean running;

  public TelegramPollingService(String alias, String botToken) {
    this.alias = alias;
    this.botClient = new TelegramBotClient(botToken);
    this.updateHandler = new TelegramUpdateHandler(botToken);
  }

  public void start() {
    if (running) {
      return;
    }
    running = true;
    pollingThread = new Thread(this::pollLoop,
      "telegram-bot-polling-" + alias);
    pollingThread.setDaemon(true);
    pollingThread.start();
  }

  private void pollLoop() {
    long offset = 0;
    while (running) {
      try {
        List<TelegramWebhookPayload> updates =
          botClient.getUpdates(offset, LONG_POLL_TIMEOUT_SECONDS);
        for (TelegramWebhookPayload update : updates) {
          try {
            updateHandler.handleUpdate(update);
          } catch (Exception e) {
            System.err.println("[" + alias + "] Failed to handle update: "
              + e.getMessage());
          }
          offset = update.getUpdateId() + 1;
        }
      } catch (Exception e) {
        System.err.println("[" + alias + "] Polling error, retrying in "
          + ERROR_BACKOFF_MS + "ms: " + e.getMessage());
        try {
          Thread.sleep(ERROR_BACKOFF_MS);
        } catch (InterruptedException ie) {
          Thread.currentThread().interrupt();
          break;
        }
      }
    }
  }

  public void stop() {
    running = false;
    if (pollingThread != null) {
      pollingThread.interrupt();
    }
  }

  public boolean isRunning() {
    return running;
  }
}
