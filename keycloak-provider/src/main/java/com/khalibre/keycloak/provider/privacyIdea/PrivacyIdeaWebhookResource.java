package com.khalibre.keycloak.provider.privacyIdea;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;
import java.util.List;
import java.util.Map;
import org.apache.http.HttpStatus;
import org.jboss.logging.Logger;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resource.RealmResourceProvider;

public class PrivacyIdeaWebhookResource implements RealmResourceProvider {

  private static final Logger log = Logger.getLogger(PrivacyIdeaWebhookResource.class);
  private static final HttpClient httpClient = HttpClient.newHttpClient();
  private static final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * The webhook handler's "data" option is configured as {@code {"username": "{logged_in_user}"}}.
   * Probed in order so the field can be renamed in privacyIDEA without a code change.
   */
  private static final List<String> USERNAME_FIELDS = List.of("username", "logged_in_user");

  private static final List<String> CLIENT_IP_FIELDS = List.of("client_ip", "client", "ip");

  private static final ZoneId OTP_TIME_ZONE = ZoneId.systemDefault();

  private static final DateTimeFormatter OTP_DATE_FORMAT =
      DateTimeFormatter.ofPattern("d MMMM yyyy", Locale.ENGLISH);

  private static final DateTimeFormatter OTP_TIME_FORMAT =
      DateTimeFormatter.ofPattern("HH:mm");

  private static final DateTimeFormatter OTP_EXPIRY_FORMAT =
      DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssxxx");

  private final KeycloakSession session;
  private final String baseUrl;
  private final String adminUsername;
  private final String adminPassword;
  private final int spassExpiryMinutes;

  public PrivacyIdeaWebhookResource(
      KeycloakSession session,
      String baseUrl,
      String adminUsername,
      String adminPassword,
      int spassExpiryMinutes) {
    this.session = session;
    this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    this.adminUsername = adminUsername;
    this.adminPassword = adminPassword;
    this.spassExpiryMinutes = spassExpiryMinutes;
  }

  @Override
  public Object getResource() {
    return this;
  }

  @POST
  @Path("/ipn")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response processIpn(String body) {
    String username = extractUsername(body);
    if (username == null || username.isBlank()) {
      log.warn("method=processIpn message=Missing or null username in payload");
      return Response.status(Response.Status.BAD_REQUEST).build();
    }

    RealmModel realm = session.getContext().getRealm();

    UserModel user = session.users().getUserByUsername(realm, username);
    if (user == null) {
      user = session.users().getUserByEmail(realm, username);
    }

    if (user == null || !user.isEnabled()) {
      log.warnf("method=processIpn message=User not found or disabled username=%s", username);
      return Response.status(Response.Status.NOT_FOUND).build();
    }

    try {
      PrivacyIdeaService service = new PrivacyIdeaService(baseUrl, adminUsername, adminPassword);
      // 1. Authenticate with privacyIDEA to get Admin Authorization Token
      String adminAuthToken = service.getPrivacyIdeaAuthToken();
      if (adminAuthToken == null || adminAuthToken.isBlank()) {
        log.error("method=processIpn message=Failed to acquire admin token from privacyIDEA");
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
      }

      // 2. Fetch the active SPASS token serial for this user
      String tokenSerial = service.getSpassTokenSerial(username, adminAuthToken);
      if (tokenSerial == null || tokenSerial.isBlank()) {
        log.warnf("method=processIpn message=No active SPASS token found for username=%s",
            username);
        return Response.status(Response.Status.NOT_FOUND).build();
      }

      // 3. Generate a random 6-digit OTP code
      String otpCode = String.format("%06d", new SecureRandom().nextInt(1000000));

      // 4. Update SPASS PIN and Expiration in privacyIDEA
      setPrivacyIdeaPin(tokenSerial, otpCode, adminAuthToken);
      setPrivacyIdeaPinExpiry(tokenSerial, adminAuthToken);

      // 5. Send OTP Email using Keycloak's Email Service
      sendOtpEmail(realm, user, otpCode, extractClientIp(body));

      log.infof("method=processIpn status=SUCCESS username=%s serial=%s", username, tokenSerial);
      // Must carry an entity: Keycloak rejects a body-less response with status 200, see
      // DefaultSecurityHeadersProvider#isEmptyMediaTypeAllowed, which turns it into a 500.
      return Response.ok(Map.of("status", "ok", "username", username), MediaType.APPLICATION_JSON)
          .build();

    } catch (Exception e) {
      log.error("method=processIpn status=ERROR username=" + username, e);
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }

  /**
   * Reads the login from the configured payload {@code {"username": "{logged_in_user}"}}.
   *
   * <p>Note the header is not inspected: privacyIDEA is configured with a proper
   * {@code application/json} Content-Type, and calling {@code HttpHeaders#getMediaType()} on the
   * bare {@code json} value older privacyIDEA builds send throws IllegalArgumentException.
   */
  private String extractField(String body, List<String> fields) {
    if (body == null || body.isBlank()) {
      return null;
    }

    try {
      JsonNode root = objectMapper.readTree(body);
      for (String field : fields) {
        JsonNode node = root.get(field);
        if (node != null && node.isValueNode() && !node.asText().isBlank()) {
          return node.asText();
        }
      }
    } catch (Exception e) {
      log.error("method=extractField message=Malformed JSON payload body=" + body, e);
    }
    return null;
  }

  private String extractUsername(String body) {
    return extractField(body, USERNAME_FIELDS);
  }

  /**
   * privacyIDEA forwards the end user's browser IP as {@code client_ip} when the Keycloak
   * provider's piforwardclientip option is enabled.
   */
  private String extractClientIp(String body) {
    String ip = extractField(body, CLIENT_IP_FIELDS);
    return ip == null || ip.isBlank() ? "unknown" : ip;
  }

  private void setPrivacyIdeaPin(String serial, String otpCode, String adminToken)
      throws Exception {
    String endpoint = String.format("%s/token/setpin/%s?otppin=%s", baseUrl, serial, otpCode);

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(endpoint))
        .header("Authorization", adminToken)
        .POST(HttpRequest.BodyPublishers.noBody())
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != HttpStatus.SC_OK) {
      log.errorf("method=setPrivacyIdeaPin serial=%s httpStatus=%d", serial, response.statusCode());
      throw new RuntimeException("Failed to set OTP PIN in privacyIDEA");
    }
  }

  private void setPrivacyIdeaPinExpiry(String serial, String adminToken) throws Exception {
    // validity_period_end must be an ISO-8601 timestamp, not epoch seconds. privacyIDEA accepts
    // any value when writing it, but /validate/check parses it as a date, so an epoch integer
    // makes every later OTP check fail with
    // ValueError: year <epoch> is out of range.
    OffsetDateTime expiry = OffsetDateTime.ofInstant(
        Instant.now().plusSeconds(spassExpiryMinutes * 60L), ZoneOffset.UTC);
    String endpoint = String.format("%s/token/info/%s/validity_period_end?value=%s", baseUrl,
        serial, URLEncoder.encode(expiry.format(OTP_EXPIRY_FORMAT), StandardCharsets.UTF_8));

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(endpoint))
        .header("Authorization", adminToken)
        .POST(HttpRequest.BodyPublishers.noBody())
        .build();

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != HttpStatus.SC_OK) {
      log.warnf("method=setPrivacyIdeaPinExpiry serial=%s httpStatus=%d", serial,
          response.statusCode());
    }
  }

  private void sendOtpEmail(RealmModel realm, UserModel user, String otpCode, String clientIp)
      throws EmailException {
    EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
    emailProvider.setRealm(realm);
    emailProvider.setUser(user);

    // send() takes a message key for the subject and a freemarker template file name, not raw HTML.
    // Keycloak renders text/<template> and html/<template> from the realm's email theme; both are
    // provided by themes/khalibre/email. The map must be mutable: processTemplate adds locale,
    // msg, properties, realmName, user and url to it.
    ZonedDateTime issuedAt = ZonedDateTime.now(OTP_TIME_ZONE);
    Map<String, Object> attributes = new HashMap<>();
    attributes.put("otp", otpCode);
    // Grouped in threes so a mistyped digit is obvious, e.g. 492 718.
    attributes.put("otpFormatted",
        otpCode.replaceFirst("^(\\p{Digit}{3})(\\p{Digit}{3})$", "$1\u2002$2"));
    attributes.put("expiryMinutes", spassExpiryMinutes);
    attributes.put("requestDate", issuedAt.format(OTP_DATE_FORMAT));
    attributes.put("requestTime", issuedAt.format(OTP_TIME_FORMAT));
    attributes.put("clientIp", clientIp);
    attributes.put("appName", realm.getDisplayName() != null && !realm.getDisplayName().isBlank()
        ? realm.getDisplayName()
        : realm.getName());
    emailProvider.send("otpEmailSubject", "privacyidea-otp.ftl", attributes);
  }

  @Override
  public void close() {
    // Resource cleanup if required
  }
}
