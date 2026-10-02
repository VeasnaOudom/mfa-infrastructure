package com.khalibre.keycloak.provider.privacyIdea.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.http.HttpStatus;
import org.jboss.logging.Logger;

public class PrivacyIdeaService {

  private static final Logger log = Logger.getLogger(PrivacyIdeaService.class);
  private static final ObjectMapper objectMapper = new ObjectMapper();
  private static final HttpClient httpClient = HttpClient.newHttpClient();

  private final String baseUrl;
  private final String adminUsername;
  private final String adminPassword;

  public PrivacyIdeaService(String baseUrl, String adminUsername, String adminPassword) {
    this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    this.adminUsername = adminUsername;
    this.adminPassword = adminPassword;
  }

  /**
   * Serials of the user's active tokens of one type, used to decide which MFA channels are
   * actually available before showing the method chooser.
   *
   * @return active serials, empty when the user has none of that type
   */
  public List<String> getActiveTokenSerials(String username, String type, String adminToken)
      throws Exception {
    String endpoint = String.format("%s/token/?user=%s&type=%s", baseUrl,
        URLEncoder.encode(username, StandardCharsets.UTF_8),
        URLEncoder.encode(type, StandardCharsets.UTF_8));

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(endpoint))
        .header("Authorization", adminToken)
        .GET()
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != HttpStatus.SC_OK) {
      log.warnf("method=getActiveTokenSerials user=%s type=%s httpStatus=%d", username, type,
          response.statusCode());
      return List.of();
    }

    List<String> serials = new ArrayList<>();
    for (JsonNode token : objectMapper.readTree(response.body())
        .path("result").path("value").path("tokens")) {
      if (token.path("active").asBoolean(false) && !token.path("revoked").asBoolean(false)) {
        String serial = token.path("serial").asText(null);
        if (serial != null && !serial.isBlank()) {
          serials.add(serial);
        }
      }
    }
    return serials;
  }

  public String getSpassTokenSerial(String username, String adminToken) throws Exception {
    String endpoint = String.format("%s/token/?user=%s&type=spass", baseUrl, username);

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(endpoint))
        .header("Authorization", adminToken)
        .GET()
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() == HttpStatus.SC_OK) {
      JsonNode root = objectMapper.readTree(response.body());
      JsonNode tokens = root.path("result").path("value").path("tokens");
      if (tokens.isArray() && !tokens.isEmpty()) {
        // Return serial of the first active token
        return tokens.get(0).path("serial").asText(null);
      }
    }
    log.errorf("method=getSpassTokenSerial httpStatus=%d body=%s", response.statusCode(),
        response.body());
    return null;
  }

  public String getPrivacyIdeaAuthToken() throws Exception {
    Map<String, String> creds = Map.of(
        "username", adminUsername,
        "password", adminPassword
    );
    String requestBody = objectMapper.writeValueAsString(creds);

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl + "/auth"))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(requestBody))
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() == HttpStatus.SC_OK) {
      JsonNode root = objectMapper.readTree(response.body());
      return root.path("result").path("value").path("token").asText(null);
    }
    log.errorf("method=getPrivacyIdeaAuthToken httpStatus=%d body=%s", response.statusCode(),
        response.body());
    return null;
  }
}