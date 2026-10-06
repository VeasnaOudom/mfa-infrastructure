package com.khalibre.keycloak.provider.telegram.bot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.jboss.logging.Logger;

public class TelegramBotClient {

  private static final Logger LOG = Logger.getLogger(TelegramBotClient.class);

  /**
   * Headroom added to a long-poll's server-side hold before the request is given up on.
   *
   * <p>Telegram holds a {@code getUpdates} request open for the full {@code timeout} *after* the
   * connection is established, so the client's budget has to cover the connect as well. Measured on
   * this deployment the whole call takes 30.3-39.6s for a 30s poll, because the connect alone
   * varies between 0.3s and 10s. A budget of {@code timeout + 5} therefore threw away roughly half
   * of every poll, and each one that failed was 30s of the user's waiting for nothing - which
   * presented as "I scanned the code and nothing happened".
   */
  private static final int LONG_POLL_HEADROOM_SECONDS = 20;

  /** Connect budget on its own, so a slow connect is distinguishable from a long hold. */
  private static final int CONNECT_TIMEOUT_SECONDS = 15;

  /**
   * Budget for a short request such as {@code sendMessage}. Generous because the cost of the
   * connect dominates, and failing to deliver an OTP code locks someone out of their account.
   */
  private static final int SEND_TIMEOUT_SECONDS = 25;

  /** One retry. An intermittent connect failure should not decide the outcome. */
  private static final int ATTEMPTS = 2;

  private final String botToken;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;

  public TelegramBotClient(String botToken) {
    this.botToken = botToken;
    this.httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS))
        .build();
    this.objectMapper = new ObjectMapper();
  }

  public void sendMessage(String chatId, String text, String replyMarkup) {
    sendMessage(chatId, text, replyMarkup, null);
  }

  /**
   * @param parseMode Telegram entity parser for {@code text}, e.g. "HTML" or "MarkdownV2", or
   *                  {@code null} to send plain text
   */
  public void sendMessage(String chatId, String text, String replyMarkup, String parseMode) {
    String url = "https://api.telegram.org/bot" + botToken + "/sendMessage";
    String json = "{\"chat_id\":\"" + chatId + "\","
      + "\"text\":\"" + escapeJson(text) + "\""
      + (parseMode != null ? ",\"parse_mode\":\"" + parseMode + "\"" : "")
      + (replyMarkup != null ? ",\"reply_markup\":" + replyMarkup : "")
      + "}";

    HttpRequest request = HttpRequest.newBuilder()
      .uri(URI.create(url))
      .timeout(Duration.ofSeconds(SEND_TIMEOUT_SECONDS))
      .header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(json))
      .build();

    for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
      try {
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        // Telegram rejects the whole message on a bad parse_mode or unknown chat, so surface it
        // instead of silently dropping the code.
        if (response.statusCode() / 100 != 2) {
          throw new RuntimeException("Telegram sendMessage returned HTTP "
              + response.statusCode() + ": " + response.body());
        }
        return;
      } catch (IOException e) {
        // Transport-level trouble only: retried. A 4xx from Telegram throws above and is not.
        if (attempt == ATTEMPTS) {
          throw new RuntimeException("Failed to send message to Telegram", e);
        }
        logRetry("sendMessage", attempt, e);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new RuntimeException("Interrupted while sending a message to Telegram", e);
      }
    }
  }

  public void requestPhoneNumber(String chatId, String message, String buttonText) {
    String replyMarkup = "{\"keyboard\":[[{\"text\":\"" + buttonText + "\","
      + "\"request_contact\":true}]],\"one_time_keyboard\":true,"
      + "\"resize_keyboard\":true}";
    sendMessage(chatId, message, replyMarkup);
  }

  public boolean setWebhook(String webhookUrl) {
    String url = "https://api.telegram.org/bot" + botToken + "/setWebhook";
    String json = "{\"url\":\"" + escapeJson(webhookUrl) + "\"}";

    HttpRequest request = HttpRequest.newBuilder()
      .uri(URI.create(url))
      .timeout(Duration.ofSeconds(10))
      .header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(json))
      .build();

    try {
      HttpResponse<String> response = httpClient.send(request,
        HttpResponse.BodyHandlers.ofString());
      JsonNode node = objectMapper.readTree(response.body());
      return node.get("ok").asBoolean();
    } catch (Exception e) {
      throw new RuntimeException("Failed to set Telegram webhook", e);
    }
  }

  public boolean deleteWebhook() {
    String url = "https://api.telegram.org/bot" + botToken + "/deleteWebhook";

    HttpRequest request = HttpRequest.newBuilder()
      .uri(URI.create(url))
      .timeout(Duration.ofSeconds(10))
      .POST(HttpRequest.BodyPublishers.ofString(""))
      .build();

    try {
      HttpResponse<String> response = httpClient.send(request,
        HttpResponse.BodyHandlers.ofString());
      JsonNode node = objectMapper.readTree(response.body());
      return node.get("ok").asBoolean();
    } catch (Exception e) {
      throw new RuntimeException("Failed to delete Telegram webhook", e);
    }
  }

  public List<TelegramWebhookPayload> getUpdates(long offset, int timeoutSeconds) {
    String url = "https://api.telegram.org/bot" + botToken + "/getUpdates"
      + "?offset=" + offset
      + "&limit=100"
      + "&timeout=" + timeoutSeconds;

    Duration budget = Duration.ofSeconds(timeoutSeconds + LONG_POLL_HEADROOM_SECONDS);
    IOException last = null;
    for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
      HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .timeout(budget)
        .GET()
        .build();
      try {
        HttpResponse<String> response = httpClient.send(request,
          HttpResponse.BodyHandlers.ofString());
        JsonNode node = objectMapper.readTree(response.body());
        if (node.get("ok") != null && node.get("ok").asBoolean()) {
          JsonNode result = node.get("result");
          if (result != null && result.isArray()) {
            List<TelegramWebhookPayload> updates = new ArrayList<>();
            for (JsonNode updateNode : result) {
              TelegramWebhookPayload update = objectMapper.treeToValue(
                updateNode, TelegramWebhookPayload.class);
              updates.add(update);
            }
            return updates;
          }
        }
        // A 409 means a webhook is set, which the caller resolves by switching mode rather than
        // by retrying. Anything else with ok:false is logged here and treated as "nothing yet".
        LOG.infof("method=getUpdates offset=%d ok=false body=%s", offset, abbreviate(response.body()));
        return Collections.emptyList();
      } catch (IOException e) {
        // Worth one retry: a long-poll that is thrown away costs the user the full wait, and the
        // update is still queued on Telegram's side because the offset was never acknowledged.
        last = e;
        logRetry("getUpdates", attempt, e);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new RuntimeException("Interrupted while polling Telegram", e);
      } catch (Exception e) {
        throw new RuntimeException("Failed to get updates from Telegram", e);
      }
    }
    throw new RuntimeException("Failed to get updates from Telegram", last);
  }

  private void logRetry(String method, int attempt, Exception e) {
    LOG.infof("method=%s attempt=%d/%d reason=%s message=%s",
        method, attempt, ATTEMPTS, e.getClass().getSimpleName(), e.getMessage());
  }

  private static String abbreviate(String body) {
    return body == null ? "" : body.substring(0, Math.min(200, body.length()));
  }

  private String escapeJson(String s) {
    return s.replace("\\", "\\\\").replace("\"", "\\\"");
  }
}
