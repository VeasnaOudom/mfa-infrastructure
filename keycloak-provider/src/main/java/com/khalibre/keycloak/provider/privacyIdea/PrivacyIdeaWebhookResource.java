package com.khalibre.keycloak.provider.privacyIdea;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.khalibre.keycloak.provider.edc.EdcChallengeToken;
import com.khalibre.keycloak.provider.edc.EdcChannelDetector;
import com.khalibre.keycloak.provider.edc.EdcMfaChannelsAuthenticator;
import com.khalibre.keycloak.provider.edc.EdcOtpDelivery;
import com.khalibre.keycloak.provider.edc.EdcTelegramLink;
import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;
import com.khalibre.keycloak.provider.telegram.state.AuthState;
import com.khalibre.keycloak.provider.telegram.state.AuthStateSession;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

public class PrivacyIdeaWebhookResource implements RealmResourceProvider {

  private static final Logger log = Logger.getLogger(PrivacyIdeaWebhookResource.class);
  private static final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * The webhook handler's "data" option is configured as {@code {"username": "{logged_in_user}"}}.
   * Probed in order so the field can be renamed in privacyIDEA without a code change.
   */
  private static final List<String> USERNAME_FIELDS = List.of("username", "logged_in_user");

  private static final List<String> CLIENT_IP_FIELDS = List.of("client_ip", "client", "ip");

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

  /**
   * Regenerates the SPASS PIN for the token and delivers the code over every channel the user has.
   *
   * @return the freshly issued code
   */
  private String issueOtp(RealmModel realm, UserModel user, String tokenSerial,
      String adminAuthToken, String clientIp) throws Exception {
    // Now only /resend uses this. Sign-in issues its own code from edc-mfa-channels, and enrolment
    // calls EdcOtpDelivery.issue directly, so this is a thin wrapper over the one implementation
    // rather than a second delivery path.
    return EdcOtpDelivery.issue(session, realm, user, settings,
        new PrivacyIdeaService(baseUrl, adminUsername, adminPassword), adminAuthToken,
        tokenSerial, clientIp);
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
    channels.put("enrolmentRequired",
        "1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_ENROLMENT_REQUIRED)));
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

  /**
   * Completes Telegram linking during MFA enrolment.
   *
   * <p>The enrolment screen shows the same QR code and polls the same endpoints the identity
   * provider uses, so the bot side needed no changes. What it cannot do is hand the result to the
   * identity provider's callback: that only runs for a broker round trip, and enrolment is not one.
   * So the link is written here instead - the same federated identity and the same attributes the
   * broker would have written - from the AuthState the scan produced.
   *
   * <p>Authorised exactly like {@link #channels}: the caller must be the user already past the
   * first factor, proven by the signed challenge cookie.
   */
  @POST
  @Path("/enrolment/telegram-link")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response linkTelegram() {
    String username = challengeCookieUser();
    if (username == null || username.isBlank()) {
      log.warn("method=linkTelegram status=UNAUTHORIZED message=No valid challenge cookie");
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

    // The AuthState is filed under the root authentication session, the same key the QR endpoint
    // wrote it under. Without that session there is no completed scan to read, and claiming
    // otherwise would let anyone link any Telegram account to any account.
    RootAuthenticationSessionModel rootSession =
        new AuthenticationSessionManager(session).getCurrentRootAuthenticationSession(realm);
    if (rootSession == null) {
      return Response.status(Response.Status.BAD_REQUEST)
          .entity(Map.of("error", "No active sign-in for this browser")).build();
    }

    AuthState state = AuthStateSession.get(session, rootSession.getId());
    if (state == null) {
      return Response.status(Response.Status.NOT_FOUND)
          .entity(Map.of("error", "No Telegram scan in progress")).build();
    }

    EdcTelegramLink.Outcome outcome = EdcTelegramLink.apply(session, realm, user, state);
    if (outcome != EdcTelegramLink.Outcome.LINKED) {
      if (outcome == EdcTelegramLink.Outcome.EXPIRED) {
        AuthStateSession.remove(session, rootSession.getId());
      }
      return Response.status(EdcTelegramLink.statusOf(outcome))
          .entity(EdcTelegramLink.problem(outcome)).build();
    }

    // Single use: a second enrolment attempt must start from a fresh scan.
    AuthStateSession.remove(session, rootSession.getId());

    log.infof("method=linkTelegram status=SUCCESS username=%s", user.getUsername());
    return Response.ok(Map.of("status", "ok"), MediaType.APPLICATION_JSON).build();
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

  @Override
  public void close() {
    // Resource cleanup if required
  }
}
