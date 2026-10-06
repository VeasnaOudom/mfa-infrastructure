package com.khalibre.keycloak.provider.edc;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Decides whether the OTP challenge runs at all.
 *
 * <p>Placed as the first execution of the second-factor subflow, so it gates the
 * {@code privacyidea-authenticator} execution sitting beneath it. When it matches, the subflow is
 * skipped and the user goes straight on to enrolment - which is the whole point: a user with no
 * channel must not be shown a code field they can do nothing with.
 *
 * <p>The answer comes from the note {@code edc-mfa-channels} has already written, which had to query
 * privacyIDEA to know. Reading it here rather than asking again costs nothing, and it matters at
 * this scale: a second privacyIDEA round trip on every single sign-in, for six thousand people, to
 * learn something the previous execution already learned.
 *
 * <p>If the note is missing - the action being driven from somewhere that did not run the channel
 * detector, such as the account console - it falls back to the enrolment marker on the user record.
 */
public class EdcMfaEnrolledCondition implements ConditionalAuthenticator {

  private static final Logger log = Logger.getLogger(EdcMfaEnrolledCondition.class);

  /** Stateless, so one instance serves every login. */
  static final EdcMfaEnrolledCondition SINGLETON = new EdcMfaEnrolledCondition();

  @Override
  public boolean matchCondition(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    if (user == null) {
      // Nothing to verify and nobody to verify it for. Letting the subflow run would challenge an
      // anonymous session, which cannot type a code.
      return false;
    }

    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String note = authSession == null ? null
        : authSession.getAuthNote(EdcMfaChannelsAuthenticator.NOTE_ENROLMENT_REQUIRED);
    if (note != null) {
      return "0".equals(note);
    }

    boolean enrolled = EdcEnrolmentState.isComplete(user) && !EdcEnrolmentState.isExempt(user);
    log.debugf("method=matchCondition user=%s source=userRecord enrolled=%s", user.getUsername(),
        enrolled);
    return enrolled;
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

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    // Not reached: the flow engine decides on matchCondition() alone. Guarded anyway, because an
    // Authenticator that returns without resolving its context leaves the engine dereferencing a
    // null FlowStatus.
    if (context.getStatus() == null) {
      context.success();
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    context.success();
  }
}
