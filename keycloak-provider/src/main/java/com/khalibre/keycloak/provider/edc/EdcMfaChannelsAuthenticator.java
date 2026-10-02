package com.khalibre.keycloak.provider.edc;

import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Publishes the MFA channels available to the signed-in user as authentication-session notes, and
 * hands the browser a short-lived signed cookie so the OTP page can read them back.
 *
 * Runs as its own execution before the privacyIDEA authenticator. It deliberately implements
 * {@code Authenticator} rather than {@code FormAuthenticator} so it can never render a page or
 * challenge: it only records state and lets the privacyIDEA execution own the challenge.
 *
 * Channel detection is best-effort. A privacyIDEA outage or misconfiguration must never block
 * sign-in, so every lookup failure degrades to "channel unavailable".
 */
public class EdcMfaChannelsAuthenticator implements org.keycloak.authentication.Authenticator {

  private static final Logger log = Logger.getLogger(EdcMfaChannelsAuthenticator.class);

  public static final String NOTE_EMAIL = "edc_channel_email";
  public static final String NOTE_EMAIL_MASKED = "edc_channel_email_masked";
  public static final String NOTE_TOTP = "edc_channel_totp";
  public static final String NOTE_TELEGRAM = "edc_channel_telegram";
  public static final String NOTE_TELEGRAM_HANDLE = "edc_channel_telegram_handle";
  public static final String NOTE_MASKED = "edc_channel_masked";

  /** Cookie the OTP page presents to the channels and resend endpoints. */
  public static final String CHALLENGE_COOKIE = "edc_otp_challenge";

  private final PrivacyIdeaService privacyIdea;
  private final String challengeSecret;
  private final int challengeTtlSeconds;

  public EdcMfaChannelsAuthenticator(PrivacyIdeaService privacyIdea, String challengeSecret,
      int challengeTtlSeconds) {
    this.privacyIdea = privacyIdea;
    this.challengeSecret = challengeSecret;
    this.challengeTtlSeconds = challengeTtlSeconds;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    try {
      UserModel user = context.getUser();
      if (user == null) {
        log.warnf("method=authenticate realm=%s reason=noUser", context.getRealm().getName());
        return;
      }

      Map<String, String> channels =
          EdcChannelDetector.detect(context.getSession(), privacyIdea, user);
      AuthenticationSessionModel authSession = context.getAuthenticationSession();
      channels.forEach(authSession::setAuthNote);

      issueChallengeCookie(context.getSession(), context.getRealm(), user);
    } finally {
      // REQUIRED pass-through: the execution never challenges, it only records state, so it must
      // always resolve the context or the flow engine dereferences a null FlowStatus.
      context.success();
    }
  }

  /**
   * Gives the browser a signed proof that it already cleared the first factor for this user.
   *
   * Without this the channels and resend endpoints have no way to identify the caller: Keycloak
   * resolves the authentication session only for login-action requests, so a plain REST call sees
   * no session at all.
   */
  private void issueChallengeCookie(KeycloakSession session, RealmModel realm, UserModel user) {
    if (challengeSecret == null || challengeSecret.isBlank()) {
      log.warn("method=issueChallengeCookie reason=noSharedSecretConfigured");
      return;
    }
    String token = EdcChallengeToken.issue(user.getUsername(), challengeSecret, challengeTtlSeconds);
    if (token == null) {
      return;
    }
    session.getContext().getHttpResponse().addHeader("Set-Cookie",
        EdcChallengeToken.cookieHeader(realm.getName(), token, challengeTtlSeconds));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    // Nothing to submit: this execution renders no form. The context still has to be resolved
    // because the flow engine calls processResult() on the result of action().
    context.success();
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public void close() {
  }
}