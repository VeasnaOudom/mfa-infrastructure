package com.khalibre.keycloak.provider.edc;

import com.khalibre.keycloak.provider.privacyIdea.PrivacyIdeaSettings;
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
  public static final String NOTE_BACKUP_CODE = "edc_channel_backup_code";
  public static final String NOTE_ENROLMENT_REQUIRED = "edc_enrolment_required";
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

      // Whether this login still owes the user a set-up step, decided here rather than in the
      // required action because this execution has already paid for the privacyIDEA lookups. The
      // answer goes into the shared map so the note, the required action and the /channels response
      // can never disagree.
      boolean enrolmentRequired =
          EdcEnrolmentState.requiresEnrolment(context.getSession(), privacyIdea, user);
      channels.put(NOTE_ENROLMENT_REQUIRED, enrolmentRequired ? "1" : "0");

      // Only once the user is known to be enrolled. While enrolment is owed the required action
      // runs instead of the OTP page, and a code pushed now would arrive with nowhere to enter it.
      if (!enrolmentRequired) {
        issueSignInCode(context, user, channels);
      }

      // Required actions are what actually stop the sign-in; the note alone only skips the
      // challenge. Adding and removing rather than leaving it in place means a user who has since
      // finished is not dragged through the wizard on every subsequent login.
      boolean alreadyPending = user.getRequiredActionsStream()
          .anyMatch(EdcMfaEnrolmentRequiredActionFactory.PROVIDER_ID::equals);
      if (enrolmentRequired && !alreadyPending) {
        user.addRequiredAction(EdcMfaEnrolmentRequiredActionFactory.PROVIDER_ID);
        log.infof("method=authenticate user=%s message=EnrolmentRequired", user.getUsername());
      } else if (!enrolmentRequired && alreadyPending) {
        user.removeRequiredAction(EdcMfaEnrolmentRequiredActionFactory.PROVIDER_ID);
        log.infof("method=authenticate user=%s message=EnrolmentCleared", user.getUsername());
      }

      channels.forEach(authSession::setAuthNote);

      issueChallengeCookie(context.getSession(), context.getRealm(), user);
    } finally {
      // REQUIRED pass-through: the execution never challenges, it only records state, so it must
      // always resolve the context or the flow engine dereferences a null FlowStatus.
      context.success();
    }
  }

  /**
   * Writes a fresh code to the user's SPASS token and sends it, so the OTP page always has a code
   * that works.
   *
   * <p>This is here because the privacyIDEA execution cannot deliver one. It creates the challenge
   * and calls {@code /validate/triggerchallenge}, relying on privacyIDEA to fire the
   * {@code validate_triggerchallenge} event our webhook listens for. privacyIDEA only re-triggers
   * that event while the token's current challenge is still live, so the first code arrives and every
   * code after it does not: {@code triggerchallenge} answers {@code 0}, no event fires, no PIN is
   * set, no mail is sent - while the OTP page still renders, so the user is shown a code field that
   * can never be completed.
   *
   * <p>Issuing the PIN here removes that dependency, and it is the same path enrolment and
   * {@code /resend} already use, both of which work every time.
   *
   * <p>Best-effort, like the rest of this execution: if privacyIDEA cannot be reached the sign-in
   * continues and the OTP page falls back to the resend button.
   */
  private void issueSignInCode(AuthenticationFlowContext context, UserModel user,
      Map<String, String> channels) {
    boolean hasSpassChannel = "1".equals(channels.get(NOTE_EMAIL))
        || "1".equals(channels.get(NOTE_TELEGRAM));
    if (!hasSpassChannel) {
      // TOTP needs nothing sent: the authenticator app generates the code itself.
      return;
    }
    try {
      String username = user.getUsername();
      String adminToken = privacyIdea.getPrivacyIdeaAuthToken();
      if (adminToken == null || adminToken.isBlank()) {
        log.warnf("method=issueSignInCode user=%s reason=noAdminToken", username);
        return;
      }
      String serial = privacyIdea.getSpassTokenSerial(username, adminToken);
      if (serial == null || serial.isBlank()) {
        log.warnf("method=issueSignInCode user=%s reason=noSpassToken", username);
        return;
      }
      EdcOtpDelivery.issue(context.getSession(), context.getRealm(), user,
          PrivacyIdeaSettings.resolve(context.getSession()), privacyIdea, adminToken, serial,
          context.getConnection().getRemoteAddr());
      log.infof("method=issueSignInCode user=%s serial=%s", username, serial);
    } catch (Exception e) {
      log.errorf(e, "method=issueSignInCode user=" + user.getUsername()
          + " message=Code not issued, the OTP page will need the resend button");
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