package com.khalibre.keycloak.provider.privacyIdea.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import org.apache.http.HttpStatus;
import org.jboss.logging.Logger;

public class PrivacyIdeaService {

  private static final Logger log = Logger.getLogger(PrivacyIdeaService.class);
  private static final ObjectMapper objectMapper = new ObjectMapper();
  private static final HttpClient httpClient = HttpClient.newHttpClient();

  /** privacyIDEA parses {@code validity_period_end} as a date, so it has to be one. */
  private static final DateTimeFormatter PIN_EXPIRY_FORMAT =
      DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssxxx");

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
    List<String> serials = new ArrayList<>();
    for (TokenInfo token : getActiveTokens(username, type, adminToken)) {
      serials.add(token.serial());
    }
    return serials;
  }

  /**
   * One privacyIDEA token, as far as this integration cares about it.
   *
   * @param serial the token serial, as it appears in {@code PISP…}/{@code TOTP…}/{@code PITN…}
   * @param type privacyIDEA's own type name, which is how it is filtered and deleted
   * @param since when the token was enrolled, or {@code null} when privacyIDEA did not say. Used to
   *     show "added 12 August 2026" on the account page
   * @param count number of unused codes, only reported by privacyIDEA for a TAN token. {@code null}
   *     means "not reported", which the account page renders as no count rather than as zero - a
   *     TAN token out of codes goes inactive on its own, so zero here would be misleading anyway
   */
  public record TokenInfo(String serial, String type, Instant since, Integer count) {
  }

  /**
   * The user's active tokens of one type, with the metadata the account page needs.
   *
   * <p>Separate from {@link #getActiveTokenSerials} rather than replacing it: the sign-in path only
   * ever needs to know whether a token exists, and asking for the whole token document on every
   * login for a field two screens away is a round trip spent for nothing.
   *
   * <p>privacyIDEA reports enrolment time as an epoch <em>milliseconds</em> value on the token
   * document, which is not documented as such and has been seen as seconds elsewhere in the same API
   * surface. A value small enough to be seconds is promoted, because the alternative is a date in
   * January 1970 shown to the user as when they set up their authenticator app.
   *
   * @return active tokens of that type, empty when the user has none
   */
  public List<TokenInfo> getActiveTokens(String username, String type, String adminToken)
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
      log.warnf("method=getActiveTokens user=%s type=%s httpStatus=%d", username, type,
          response.statusCode());
      return List.of();
    }

    List<TokenInfo> tokens = new ArrayList<>();
    for (JsonNode token : objectMapper.readTree(response.body())
        .path("result").path("value").path("tokens")) {
      if (!token.path("active").asBoolean(false) || token.path("revoked").asBoolean(false)) {
        continue;
      }
      String serial = token.path("serial").asText(null);
      if (serial == null || serial.isBlank()) {
        continue;
      }
      String tokenType = token.path("tokentype").asText(type);
      Integer count = token.hasNonNull("count") && token.path("count").canConvertToInt()
          ? token.path("count").asInt()
          : null;
      tokens.add(new TokenInfo(serial, tokenType, readEnrolledAt(token), count));
    }
    return tokens;
  }

  /**
   * When a token was enrolled, from whichever field privacyIDEA put it in.
   *
   * <p>Returns {@code null} rather than an epoch instant when nothing usable is present, so a caller
   * can leave the date out of the page instead of printing 1 January 1970.
   */
  private static Instant readEnrolledAt(JsonNode token) {
    for (String field : new String[] { "created", "timestamp", "enrolled" }) {
      JsonNode node = token.path(field);
      if (node.isMissingNode() || node.isNull()) {
        continue;
      }
      if (node.isNumber()) {
        long raw = node.asLong();
        // Anything below this is seconds rather than milliseconds: no enrolment happened in 1970.
        long millis = raw > 0 && raw < 100_000_000_000L ? raw * 1000L : raw;
        if (millis > 0) {
          return Instant.ofEpochMilli(millis);
        }
      } else if (node.isTextual()) {
        try {
          return Instant.parse(node.asText());
        } catch (Exception ignored) {
          // Not an ISO-8601 instant. Try the next field rather than failing the whole read.
        }
      }
    }
    return null;
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

  /**
   * What {@code /token/init} reports back for a freshly enrolled token.
   *
   * @param serial serial of the new token, as it appears in {@code PISP…}/{@code TOTP…}/{@code PITN…}
   * @param otps the token's own secrets, returned exactly once. A TAN token reports its whole
   *     pre-generated list here and nothing else, ever again, because it only stores them hashed
   * @param googleUrl {@code otpauth://} enrolment URI, only for time-based tokens
   */
  public record InitialisedToken(String serial, List<String> otps, String googleUrl) {
  }

  /**
   * Enrols a token for a user.
   *
   * <p>Used for both second-step channels: {@code type=totp} for an authenticator app, and
   * {@code type=tan} for a set of backup codes. Callers pass the type-specific parameters in
   * {@code extraParams} - {@code otplen} and {@code tantoken_count} for backup codes, {@code
   * timeStep} and {@code hashlib} for an authenticator app - because privacyIDEA's defaults for those
   * are not the ones this deployment presents to the user. In particular a TAN token is 100
   * eight-digit codes by default, where the code field here is six boxes wide.
   *
   * @return the new token's serial and its one-time secrets
   * @throws IllegalStateException if privacyIDEA refuses to enrol, or answers with no serial
   */
  public InitialisedToken initToken(String username, String type, String adminToken,
      Map<String, String> extraParams) throws Exception {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("type", type);
    params.put("user", username);
    if (extraParams != null) {
      params.putAll(extraParams);
    }

    HttpResponse<String> response = formPost("/token/init", params, adminToken);

    // Verified against privacyIDEA 3.12: on this endpoint result.value is a boolean, not an object.
    // Everything useful - serial, one-time secrets, enrolment URI - arrives under detail.
    JsonNode root = objectMapper.readTree(response.body());
    JsonNode result = root.path("result");
    if (!result.path("status").asBoolean(false) || !result.path("value").asBoolean(false)) {
      throw new IllegalStateException("privacyIDEA enrolled no " + type + " token for " + username
          + ": " + result.path("error").path("message").asText(response.body()));
    }

    JsonNode detail = root.path("detail");
    // detail.serial is where it actually lives; the object branch is only a guard against a future
    // privacyIDEA moving it back into result.value, and avoids reading "false" out of a boolean.
    String serial = detail.path("serial").asText(null);
    if ((serial == null || serial.isBlank()) && result.path("value").isObject()) {
      serial = result.path("value").path("serial").asText(null);
    }
    if (serial == null || serial.isBlank()) {
      throw new IllegalStateException(
          "privacyIDEA enrolled a " + type + " token for " + username + " but reported no serial");
    }

    // detail.otps is an object keyed by position ("0", "1", ...) for a TAN token. Iterating a
    // JsonNode walks its values either way, so a list-shaped response would also be read correctly.
    List<String> otps = new ArrayList<>();
    for (JsonNode otp : detail.path("otps")) {
      String code = otp.asText(null);
      if (code != null && !code.isBlank()) {
        otps.add(code.trim());
      }
    }

    String googleUrl = detail.path("googleurl").path("value").asText(null);
    log.infof("method=initToken username=%s type=%s serial=%s otpCount=%d", username, type, serial,
        otps.size());
    return new InitialisedToken(serial, otps,
        googleUrl == null || googleUrl.isBlank() ? null : googleUrl);
  }

  /**
   * Checks a code the user typed against the tokens they hold.
   *
   * <p>This is the same call the OTP page makes on sign-in, with no serial: privacyIDEA tries every
   * active token belonging to the user. That is exactly what enrolment needs too - a code from the
   * authenticator app they have just scanned must be accepted before they are let past - and it is
   * why a backup code needs no separate validation path.
   *
   * <p>Consumes the code, so this must not be used to check a backup code: doing so would burn one
   * before the user ever needed it.
   *
   * @return {@code true} if privacyIDEA accepted the code
   */
  public boolean validateCheck(String username, String code, String adminToken) throws Exception {
    if (code == null || code.isBlank()) {
      return false;
    }
    HttpResponse<String> response = formPost("/validate/check",
        Map.of("user", username, "pass", code.trim()), adminToken);

    JsonNode root = objectMapper.readTree(response.body());
    return root.path("result").path("value").asBoolean(false);
  }

  /**
   * Removes a token.
   *
   * <p>Must stay exactly as it is: privacyIDEA answers {@code 405} for {@code /token/delete}, and
   * for {@code DELETE /token/} carrying a body or a {@code Content-Type} header.
   */
  public void deleteToken(String serial, String adminToken) throws Exception {
    if (serial == null || serial.isBlank()) {
      return;
    }
    HttpResponse<String> response = httpRequest(String.format("%s/token/?serial=%s", baseUrl,
        URLEncoder.encode(serial, StandardCharsets.UTF_8)), adminToken, true, null);
    if (response.statusCode() != HttpStatus.SC_OK) {
      throw new IllegalStateException(
          "privacyIDEA refused to delete token " + serial + ": HTTP " + response.statusCode());
    }
    log.infof("method=deleteToken serial=%s", serial);
  }

  /** Deletes every active token of one type, so the replacement set is the only set left. */
  public void deleteTokens(String username, String type, String adminToken) throws Exception {
    for (String serial : getActiveTokenSerials(username, type, adminToken)) {
      deleteToken(serial, adminToken);
    }
  }

  /**
   * Overwrites a token's current PIN, which is how a one-time code is delivered to a SPASS token.
   *
   * <p>A bodyless POST: privacyIDEA reads the value from the query string, so no form data and no
   * {@code Content-Type}.
   */
  public void setPin(String serial, String pin, String adminToken) throws Exception {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(String.format("%s/token/setpin/%s?otppin=%s", baseUrl, serial,
            URLEncoder.encode(pin, StandardCharsets.UTF_8))))
        .header("Authorization", adminToken)
        .POST(HttpRequest.BodyPublishers.noBody())
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != HttpStatus.SC_OK) {
      throw new IllegalStateException(
          "privacyIDEA refused the PIN for token " + serial + ": HTTP " + response.statusCode());
    }
  }

  /**
   * Caps how long a token's current PIN stays usable.
   *
   * <p>The value must be an ISO-8601 timestamp. privacyIDEA accepts anything when writing it, but
   * {@code /validate/check} later parses it as a date, so epoch seconds make every subsequent check
   * fail with {@code ValueError: year <epoch> is out of range} - which looks like a broken code
   * rather than a malformed setting.
   */
  public void setPinExpiry(String serial, String adminToken, int minutes) throws Exception {
    OffsetDateTime expiry = OffsetDateTime.ofInstant(
        Instant.now().plusSeconds(minutes * 60L), ZoneOffset.UTC);
    HttpResponse<String> response = httpRequest(String.format(
        "%s/token/info/%s/validity_period_end?value=%s", baseUrl, serial,
        URLEncoder.encode(expiry.format(PIN_EXPIRY_FORMAT), StandardCharsets.UTF_8)), adminToken,
        false, HttpRequest.BodyPublishers.noBody());
    if (response.statusCode() != HttpStatus.SC_OK) {
      log.warnf("method=setPinExpiry serial=%s httpStatus=%d", serial, response.statusCode());
    }
  }

  private HttpResponse<String> httpRequest(String url, String adminToken, boolean delete,
      HttpRequest.BodyPublisher body) throws Exception {
    HttpRequest.Builder builder = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .header("Authorization", adminToken);
    HttpRequest request = delete ? builder.DELETE().build() : builder.POST(body).build();
    return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> formPost(String path, Map<String, String> params, String adminToken)
      throws Exception {    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(baseUrl + path))
        .header("Authorization", adminToken)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(formEncode(params)))
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != HttpStatus.SC_OK) {
      log.warnf("method=formPost path=%s httpStatus=%d body=%s", path, response.statusCode(),
          response.body());
      throw new IllegalStateException(
          "privacyIDEA answered HTTP " + response.statusCode() + " for " + path);
    }
    return response;
  }

  private static String formEncode(Map<String, String> params) {
    StringJoiner joiner = new StringJoiner("&");
    params.forEach((key, value) -> {
      if (value != null && !value.isBlank()) {
        joiner.add(URLEncoder.encode(key, StandardCharsets.UTF_8)
            + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8));
      }
    });
    return joiner.toString();
  }
}