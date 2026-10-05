package com.khalibre.keycloak.provider.privacyIdea;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.khalibre.keycloak.provider.edc.EdcChallengeToken;
import com.khalibre.keycloak.provider.edc.EdcChannelDetector;
import com.khalibre.keycloak.provider.edc.EdcMfaChannelsAuthenticator;
import com.khalibre.keycloak.provider.privacyIdea.PrivacyIdeaSettings.Settings;
import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;
import com.khalibre.keycloak.provider.telegram.bot.TelegramBotClient;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.http.HttpStatus;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.IdentityProviderModel;
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

  private static final String TELEGRAM_IDP_ALIAS = "telegram";

  private static final DateTimeFormatter OTP_EXPIRY_FORMAT =
      DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssxxx");

  private final KeycloakSession session;
  private final PrivacyIdeaSettings.Settings settings;
  private final String baseUrl;
  private final String adminUsername;
  private final String adminPassword;
  private final int spassExpiryMinutes;
  private final String webhookSecret;

  public PrivacyIdeaWebhookResource(
      KeycloakSession session,
      String baseUrl,
      String adminUsername,
      String adminPassword,
      int spassExpiryMinutes,
      String webhookSecret) {
    this.session = session;
    this.settings = PrivacyIdeaSettings.resolve(session);
    this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    this.adminUsername = adminUsername;
    this.adminPassword = adminPassword;
    this.spassExpiryMinutes = spassExpiryMinutes;
    this.webhookSecret = webhookSecret == null ? "" : webhookSecret.trim();
  }

  @Override
  public Object getResource() {
    return this;
  }

  /**
   * privacyIDEA's webhook handler cannot send custom headers, so the shared secret travels as a
   * query parameter. Compared in constant time. An unconfigured secret fails closed: the endpoint
   * rejects every request rather than defaulting to open.
   */
  /**
   * Username proven by the signed cookie the OTP page carries, or {@code null}.
   *
   * Keycloak only resolves the authentication session for login-action requests, so a plain REST
   * call cannot see one; the edc-mfa-channels execution issues this cookie instead.
   */
  private String challengeCookieUser() {
    if (webhookSecret.isEmpty()) {
      return null;
    }
    java.util.Map<String, jakarta.ws.rs.core.Cookie> cookies =
        session.getContext().getHttpRequest().getHttpHeaders().getCookies();
    jakarta.ws.rs.core.Cookie cookie = cookies.get(EdcMfaChannelsAuthenticator.CHALLENGE_COOKIE);
    if (cookie == null) {
      return null;
    }
    return EdcChallengeToken.verify(cookie.getValue(), webhookSecret, challengeTtlSeconds());
  }

  private int challengeTtlSeconds() {
    return settings.challengeTtlSeconds();
  }

  private void refreshChallengeCookie(RealmModel realm, String username) {
    if (!settings.hasSecret()) {
      return;
    }
    String token =
        EdcChallengeToken.issue(username, webhookSecret, challengeTtlSeconds());
    if (token == null) {
      return;
    }
    session.getContext().getHttpResponse().addHeader("Set-Cookie",
        EdcChallengeToken.cookieHeader(realm.getName(), token, challengeTtlSeconds()));
  }

  private boolean secretValid(@QueryParam("secret") String supplied) {
    if (webhookSecret.isEmpty()) {
      log.error("method=secretValid status=REJECTED "
          + "message=No webhook secret configured; set PRIVACYIDEA_WEBHOOK_SECRET");
      return false;
    }
    if (supplied == null || supplied.length() != webhookSecret.length()) {
      return false;
    }
    int diff = 0;
    for (int i = 0; i < supplied.length(); i++) {
      diff |= supplied.charAt(i) ^ webhookSecret.charAt(i);
    }
    return diff == 0;
  }

  @POST
  @Path("/ipn")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response processIpn(@QueryParam("secret") String secret, String body) {
    if (!secretValid(secret)) {
      log.warn("method=processIpn status=UNAUTHORIZED message=Invalid or missing secret");
      return Response.status(Response.Status.UNAUTHORIZED).build();
    }

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
      String adminAuthToken = service.getPrivacyIdeaAuthToken();
      if (adminAuthToken == null || adminAuthToken.isBlank()) {
        log.error("method=processIpn message=Failed to acquire admin token from privacyIDEA");
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
      }

      String tokenSerial = service.getSpassTokenSerial(username, adminAuthToken);
      if (tokenSerial == null || tokenSerial.isBlank()) {
        // Not an error: the user may authenticate with an authenticator app or push token, which
        // generate their own codes. A 404 here would be recorded as a failed webhook by
        // privacyIDEA on every such login, so report success-with-nothing-to-deliver instead.
        log.infof("method=processIpn status=SKIPPED username=%s "
            + "message=NoActiveSpassTokenDeliveringNothing", username);
        return Response.ok(Map.of("status", "skipped", "reason", "no-active-spass-token", "username",
            username), MediaType.APPLICATION_JSON).build();
      }

      issueOtp(realm, user, tokenSerial, adminAuthToken, extractClientIp(body));

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
   * Regenerates the SPASS PIN for the token, stores its expiry and delivers the code over every
   * channel the user has set up.
   *
   * @return the freshly issued code
   */
  private String issueOtp(RealmModel realm, UserModel user, String tokenSerial,
      String adminAuthToken, String clientIp) throws Exception {
    String otpCode = String.format("%06d", new SecureRandom().nextInt(1000000));
    setPrivacyIdeaPin(tokenSerial, otpCode, adminAuthToken);
    setPrivacyIdeaPinExpiry(tokenSerial, adminAuthToken);
    sendOtpEmail(realm, user, otpCode, clientIp);
    sendOtpTelegram(user, otpCode, spassExpiryMinutes);
    return otpCode;
  }

  /**
   * Reports which MFA channels the current OTP challenge can deliver to.
   *
   * Auth notes are not reachable from FreeMarker - Keycloak exposes only an id/tabId bean as
   * "authenticationSession" - so the template fetches this instead. Authorised exactly like
   * {@link #resend}: the caller must be the user already mid-challenge.
   */
  @GET
  @Path("/channels")
  @Produces(MediaType.APPLICATION_JSON)
  public Response channels() {
    String username = challengeCookieUser();
    if (username == null || username.isBlank()) {
      log.warn("method=channels status=UNAUTHORIZED message=No valid challenge cookie");
      return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    RealmModel realm = session.getContext().getRealm();
    UserModel user = session.users().getUserByUsername(realm, username);
    if (user == null) {
      user = session.users().getUserByEmail(realm, username);
    }
    if (user == null || !user.isEnabled()) {
      return Response.status(Response.Status.NOT_FOUND).build();
    }

    Map<String, String> detected = EdcChannelDetector.detect(session,
        new PrivacyIdeaService(baseUrl, adminUsername, adminPassword), user);

    Map<String, Object> channels = new LinkedHashMap<>();
    channels.put("email", "1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_EMAIL)));
    channels.put("totp", "1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_TOTP)));
    channels.put("telegram", "1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM)));
    channels.put("backupCode", "1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_BACKUP_CODE)));
    channels.put("masked", "1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_MASKED)));
    channels.put("telegramHandle", detected.get(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM_HANDLE));
    channels.put("emailMasked", detected.get(EdcMfaChannelsAuthenticator.NOTE_EMAIL_MASKED));

    // The code is issued by the webhook moments after the detector runs, so its validity ends
    // this far from now. Without this the page would guess a countdown.
    java.util.Map<String, jakarta.ws.rs.core.Cookie> cookies =
        session.getContext().getHttpRequest().getHttpHeaders().getCookies();
    jakarta.ws.rs.core.Cookie cookie = cookies.get(EdcMfaChannelsAuthenticator.CHALLENGE_COOKIE);
    long issuedAt =
        EdcChallengeToken.issuedAtMillis(cookie == null ? null : cookie.getValue(), webhookSecret);
    if (issuedAt > 0) {
      // The countdown must describe the CODE, not the browser's challenge proof. These have
      // different lifetimes: the code is valid for spassExpiryMinutes, while the challenge cookie
      // deliberately outlives it so a new code can still be requested once the old one lapses.
      // issuedAt is in milliseconds; the browser's countdown works in seconds.
      // 60_000 converts the configured minutes into milliseconds, to match issuedAt.
      long codeExpiresAt = (issuedAt + spassExpiryMinutes * 60_000L) / 1000L;
      channels.put("expiresAt", codeExpiresAt);
    }

    log.infof("method=channels status=SUCCESS username=%s email=%s totp=%s telegram=%s",
        user.getUsername(), channels.get("email"), channels.get("totp"), channels.get("telegram"));
    return Response.ok(channels, MediaType.APPLICATION_JSON).build();
  }

  @POST
  @Path("/resend")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response resend(@QueryParam("secret") String secret, String body) {
    // Two callers: privacyIDEA's webhook authenticates with the shared secret, while the
    // browser posts from the OTP page and is authorized by its own login session. The secret is
    // never exposed to the page, so it cannot be used there.
    boolean trustedCaller = secretValid(secret);
    String username = trustedCaller ? extractUsername(body) : challengeCookieUser();
    if (!trustedCaller && (username == null || username.isBlank())) {
      log.warn("method=resend status=UNAUTHORIZED message=No valid secret or challenge cookie");
      return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    RealmModel realm = session.getContext().getRealm();
    UserModel user = session.users().getUserByUsername(realm, username);
    if (user == null) {
      user = session.users().getUserByEmail(realm, username);
    }
    if (user == null || !user.isEnabled()) {
      return Response.status(Response.Status.NOT_FOUND).build();
    }

    try {
      PrivacyIdeaService service = new PrivacyIdeaService(baseUrl, adminUsername, adminPassword);
      String adminAuthToken = service.getPrivacyIdeaAuthToken();
      if (adminAuthToken == null || adminAuthToken.isBlank()) {
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
      }
      String tokenSerial = service.getSpassTokenSerial(username, adminAuthToken);
      if (tokenSerial == null || tokenSerial.isBlank()) {
        return Response.status(Response.Status.NOT_FOUND).build();
      }

      issueOtp(realm, user, tokenSerial, adminAuthToken, extractClientIp(body));
      // Sliding the window while the user is actively requesting codes, so someone mid-way
      // through an MFA session is not cut off while a code is still valid.
      refreshChallengeCookie(realm, username);
      log.infof("method=resend status=SUCCESS username=%s serial=%s", username, tokenSerial);
      // The code itself is never echoed back, only the fact that a new one was issued.
      return Response.ok(Map.of("status", "ok"), MediaType.APPLICATION_JSON).build();
    } catch (Exception e) {
      log.error("method=resend status=ERROR username=" + username, e);
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

  /**
   * Delivers the code through the Telegram bot when the user has linked Telegram and the bot is
   * configured. Both are optional: without a telegram identity provider there is no bot token, and
   * without the telegram-user-id attribute the user never linked, so this is a no-op in both cases
   * rather than an error.
   */
  private void sendOtpTelegram(UserModel user, String otpCode, int expiryMinutes) {
    // Falls back to the linked Telegram identity because LDAP federation discards the attribute.
    String chatId = EdcChannelDetector.telegramChatId(session, user);
    if (chatId == null || chatId.isBlank()) {
      log.infof("method=sendOtpTelegram user=%s message=NoTelegramIdentity", user.getUsername());
      return;
    }

    IdentityProviderModel idp = session.identityProviders().getByAlias(TELEGRAM_IDP_ALIAS);
    if (idp == null) {
      log.warnf("method=sendOtpTelegram username=%s message=No telegram IdP configured, skipping",
          user.getUsername());
      return;
    }

    String botToken = new OAuth2IdentityProviderConfig(idp).getClientSecret();
    if (botToken == null || botToken.isBlank()) {
      log.warnf("method=sendOtpTelegram username=%s message=Telegram IdP has no bot token, skipping",
          user.getUsername());
      return;
    }

    try {
      // HTML so the code stands out; otpCode is digits only, so no entity escaping is needed.
      String text = String.format("Your EDC verification code is <b>%s</b>. It is valid for %d minutes.",
          otpCode, expiryMinutes);
      new TelegramBotClient(botToken).sendMessage(chatId, text, null, "HTML");
      log.infof("method=sendOtpTelegram status=SENT username=%s", user.getUsername());
    } catch (Exception e) {
      log.errorf(e, "method=sendOtpTelegram status=ERROR username=" + user.getUsername());
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
    attributes.put("otpEmailBaseUrl", settings.publicBaseUrl());
    emailProvider.send("otpEmailSubject", "privacyidea-otp.ftl", attributes);
  }

  /**
   * Origin that email clients should use to fetch theme resources such as the logo.
   *
   * The {@code url} bean available to email templates is built from the server's own request base
   * URI, so it yields the internal host and port (for example {@code http://keycloak:8080}) rather
   * than the address recipients can reach. It is therefore per-environment configuration, not
   * something a locale message file can carry.
   *
   * <p>Resolved by {@link Settings#publicBaseUrl()}: the {@code publicBaseUrl} field on the EDC MFA
   * Channels execution wins, then {@code KEYCLOAK_PUBLIC_BASE_URL}, then {@code https://} plus
   * {@code KC_HOSTNAME}.
   */

  @Override
  public void close() {
    // Resource cleanup if required
  }
}
