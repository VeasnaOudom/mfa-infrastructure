package com.khalibre.keycloak.provider.telegram.bot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TelegramBotClient {

  private final String botToken;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;

  public TelegramBotClient(String botToken) {
    this.botToken = botToken;
    this.httpClient = HttpClient.newHttpClient();
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
      .timeout(Duration.ofSeconds(10))
      .header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(json))
      .build();

    try {
      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      // Telegram rejects the whole message on a bad parse_mode or unknown chat, so surface it
      // instead of silently dropping the code.
      if (response.statusCode() / 100 != 2) {
        throw new RuntimeException("Telegram sendMessage returned HTTP "
            + response.statusCode() + ": " + response.body());
      }
    } catch (RuntimeException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException("Failed to send message to Telegram", e);
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

    HttpRequest request = HttpRequest.newBuilder()
      .uri(URI.create(url))
      .timeout(Duration.ofSeconds(timeoutSeconds + 5))
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
      return Collections.emptyList();
    } catch (Exception e) {
      throw new RuntimeException("Failed to get updates from Telegram", e);
    }
  }

  private String escapeJson(String s) {
    return s.replace("\\", "\\\\").replace("\"", "\\\"");
  }
}
